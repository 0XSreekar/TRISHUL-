"""Opaque handles for the planner / quarantined-reader split (A12)."""

import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol

from trishul.provenance.labeled import Labeled, derive

HANDLE_PREFIXES = ("DOC", "EMAIL", "VOICE")
_HANDLE_RE = re.compile(r"^\$(?:DOC|EMAIL|VOICE)_[1-9][0-9]*$")


@dataclass(frozen=True, slots=True)
class OpaqueHandle:
    """What the planner sees: a name and nothing else. No value, no label."""

    id: str

    def __post_init__(self) -> None:
        if not _HANDLE_RE.fullmatch(self.id):
            raise ValueError("handle id must look like $DOC_<n>, $EMAIL_<n> or $VOICE_<n>")

    def __str__(self) -> str:
        return self.id


class QuarantinedReader(Protocol):
    """The only component allowed to dereference handles."""

    def extract[R](self, handle: OpaqueHandle, extractor: Callable[[object], R]) -> Labeled[R]: ...


class HandleStore:
    """Gateway-side storage. The planner-facing surface is ``put`` only."""

    def __init__(self) -> None:
        self._items: dict[str, Labeled[object]] = {}
        self._counters = dict.fromkeys(HANDLE_PREFIXES, 0)

    def put(self, item: Labeled[object], prefix: str = "DOC") -> OpaqueHandle:
        if prefix not in self._counters:
            raise ValueError(f"unknown handle prefix {prefix!r}")
        self._counters[prefix] += 1
        handle = OpaqueHandle(f"${prefix}_{self._counters[prefix]}")
        self._items[handle.id] = item
        return handle

    def __contains__(self, handle: object) -> bool:
        return isinstance(handle, OpaqueHandle) and handle.id in self._items

    def __len__(self) -> int:
        return len(self._items)

    def reader(self) -> QuarantinedReader:
        return _StoreReader(self)


class _StoreReader:
    def __init__(self, store: HandleStore) -> None:
        self._store = store

    def extract[R](self, handle: OpaqueHandle, extractor: Callable[[object], R]) -> Labeled[R]:
        try:
            item = self._store._items[handle.id]
        except KeyError:
            raise KeyError(f"unknown handle {handle.id}") from None
        return derive(extractor, item)
