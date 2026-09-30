"""Opaque handles for the planner / quarantined-reader split (A12)."""

import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol

from trishul.provenance.labeled import Labeled, derive

_HANDLE_RE = re.compile(r"^\$DOC_[1-9][0-9]*$")


@dataclass(frozen=True, slots=True)
class OpaqueHandle:
    """What the planner sees: a name and nothing else. No value, no label."""

    id: str

    def __post_init__(self) -> None:
        if not _HANDLE_RE.fullmatch(self.id):
            raise ValueError("handle id must look like $DOC_<n>")

    def __str__(self) -> str:
        return self.id


class QuarantinedReader(Protocol):
    """The only component allowed to dereference handles."""

    def extract[R](self, handle: OpaqueHandle, extractor: Callable[[object], R]) -> Labeled[R]: ...


class HandleStore:
    """Gateway-side storage. The planner-facing surface is ``put`` only."""

    def __init__(self) -> None:
        self._items: dict[str, Labeled[object]] = {}
        self._counter = 0

    def put(self, item: Labeled[object]) -> OpaqueHandle:
        self._counter += 1
        handle = OpaqueHandle(f"$DOC_{self._counter}")
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
