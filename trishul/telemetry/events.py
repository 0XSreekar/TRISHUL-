# SPDX-License-Identifier: Apache-2.0
"""In-process event bus with sequence numbers, replay ring, dedup and bounded subscribers."""

import asyncio
import contextlib
import re
import threading
from collections import OrderedDict, deque
from collections.abc import AsyncIterator
from typing import Any

from trishul.contracts.patterns import contains_secret, scrub_text

SCHEMA_VERSION = 2
REDACTED = "[REDACTED]"
_CTRL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")
_SECRET_KEY = re.compile(
    r"(?i)(pass(word|wd)?|secret|token|api[_-]?key|authorization|bearer|private[_-]?key)"
)
_ESCAPES = {"&": "&amp;", "<": "&lt;", ">": "&gt;"}
_MAX_DEPTH = 12


def _escape(text: str) -> str:
    text = _CTRL.sub("", text)
    text = scrub_text(text)
    return "".join(_ESCAPES.get(c, c) for c in text)


def _raw_text(text: str) -> str:
    """Untrusted display text kept verbatim (the UI renders it as a text node, never as HTML):
    control characters and secret patterns are removed but ``<``/``&`` are NOT entity-escaped."""
    return scrub_text(_CTRL.sub("", text))


def _sanitize(value: object, depth: int = 0) -> object:
    if depth > _MAX_DEPTH:
        return REDACTED
    if isinstance(value, str):
        return _escape(value)
    if isinstance(value, dict):
        out: dict[str, object] = {}
        for k, v in value.items():
            key = _escape(str(k))
            if _SECRET_KEY.search(str(k)) or contains_secret(str(k)):
                out[key] = REDACTED
            else:
                out[key] = _sanitize(v, depth + 1)
        return out
    if isinstance(value, list | tuple | set | frozenset):
        return [_sanitize(v, depth + 1) for v in value]
    if value is None or isinstance(value, bool | int | float):
        return value
    return _escape(str(value))


class Subscription:
    """Async iterator over bus events with a bounded queue (overflow drops oldest + gap)."""

    def __init__(self, bus: "EventBus", loop: asyncio.AbstractEventLoop, capacity: int) -> None:
        self._bus = bus
        self._loop = loop
        self._cap = capacity
        self._q: deque[dict[str, object]] = deque()
        self._wake = asyncio.Event()
        self._closed = False
        self._last_seq = -1
        self._gap: tuple[int, int] | None = None

    def _extend_gap(self, lo: int, hi: int) -> None:
        self._gap = (
            (lo, hi) if self._gap is None else (min(self._gap[0], lo), max(self._gap[1], hi))
        )

    def _push(self, event: dict[str, object]) -> None:
        seq = event.get("seq")
        if self._closed or not isinstance(seq, int) or seq <= self._last_seq:
            return
        self._last_seq = seq
        if len(self._q) >= self._cap:
            dropped = self._q.popleft()
            ds = dropped.get("seq")
            if isinstance(ds, int):
                self._extend_gap(ds, ds)
        self._q.append(event)
        self._wake.set()

    def _mark_gap(self, lo: int, hi: int) -> None:
        self._extend_gap(lo, hi)
        self._wake.set()

    def close(self) -> None:
        self._closed = True
        self._bus._remove(self)
        self._wake.set()

    def __aiter__(self) -> AsyncIterator[dict[str, object]]:
        return self

    async def __anext__(self) -> dict[str, object]:
        while True:
            if self._gap is not None:
                lo, hi = self._gap
                self._gap = None
                return {"type": "gap", "from": lo, "to": hi, "schema_version": SCHEMA_VERSION}
            if self._q:
                return self._q.popleft()
            if self._closed:
                raise StopAsyncIteration
            self._wake.clear()
            await self._wake.wait()


class EventBus:
    def __init__(self, ring_size: int = 4096, client_queue: int = 256) -> None:
        self._ring: deque[dict[str, object]] = deque(maxlen=ring_size)
        self._client_queue = client_queue
        self._lock = threading.Lock()
        self._seq = 0
        self._calls: OrderedDict[str, int] = OrderedDict()
        self._subs: list[Subscription] = []
        self._closed = False

    @property
    def seq(self) -> int:
        return self._seq

    def snapshot(self, after: int = 0) -> list[dict[str, object]]:
        """Copy of the replay ring, restricted to events with ``seq > after``."""
        with self._lock:
            return [e for e in self._ring if isinstance(e["seq"], int) and e["seq"] > after]

    def publish(self, event: dict[str, object], *, raw_keys: tuple[str, ...] = ()) -> int:
        """Sanitise and broadcast. ``raw_keys`` names top-level string fields that hold untrusted
        display text and must reach the client unescaped (rendered as text nodes only)."""
        clean = _sanitize(event)
        if not isinstance(clean, dict):
            raise TypeError("event must be a dict")
        for key in raw_keys:
            value = event.get(key)
            if isinstance(value, str):
                clean[key] = _raw_text(value)
        with self._lock:
            cid = clean.get("id")
            is_call = clean.get("type") == "call" and isinstance(cid, str)
            if isinstance(cid, str) and is_call and cid in self._calls:
                return self._calls[cid]
            self._seq += 1
            seq = self._seq
            clean["seq"] = seq
            clean["schema_version"] = SCHEMA_VERSION
            if is_call and isinstance(cid, str):
                self._calls[cid] = seq
                while len(self._calls) > (self._ring.maxlen or 4096) * 4:
                    self._calls.popitem(last=False)
            self._ring.append(clean)
            subs = list(self._subs)
        for sub in subs:
            self._deliver(sub, clean)
        return seq

    @staticmethod
    def _deliver(sub: Subscription, event: dict[str, object]) -> None:
        try:
            running = asyncio.get_running_loop()
        except RuntimeError:
            running = None
        if running is sub._loop:
            sub._push(event)
        else:
            with contextlib.suppress(RuntimeError):
                sub._loop.call_soon_threadsafe(sub._push, event)

    def subscribe(self, resume_from: int | None = None) -> Subscription:
        loop = asyncio.get_running_loop()
        sub = Subscription(self, loop, self._client_queue)
        with self._lock:
            replay: list[dict[str, Any]] = []
            if resume_from is not None:
                replay = [e for e in self._ring if e["seq"] > resume_from]  # type: ignore[operator]
                oldest = self._ring[0]["seq"] if self._ring else self._seq + 1
                if isinstance(oldest, int) and resume_from + 1 < oldest:
                    sub._mark_gap(resume_from + 1, oldest - 1)
            else:
                sub._last_seq = self._seq
            if self._closed:
                sub._closed = True
            else:
                self._subs.append(sub)
        for e in replay:
            sub._push(e)
        if self._closed:
            sub._wake.set()
        return sub

    def _remove(self, sub: Subscription) -> None:
        with self._lock:
            if sub in self._subs:
                self._subs.remove(sub)

    def close(self) -> None:
        with self._lock:
            self._closed = True
            subs, self._subs = self._subs, []
        for sub in subs:
            sub._closed = True
            with contextlib.suppress(RuntimeError):
                sub._loop.call_soon_threadsafe(sub._wake.set)
