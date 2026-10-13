# SPDX-License-Identifier: Apache-2.0
"""Seeded deterministic id generator so ``demo reset --seed N`` reproduces event ids."""

import hashlib
import threading


class IdGen:
    """``<prefix>_<counter:06d><4 hex of sha256(seed:prefix:counter)>``; sortable and stable."""

    def __init__(self, seed: int, start: int = 0) -> None:
        self.seed = seed
        self._n = start
        self._lock = threading.Lock()

    def restart(self, start: int = 0) -> None:
        """Rewind the counter in place (``demo reset``: same seed => same ids again)."""
        with self._lock:
            self._n = start

    @property
    def counter(self) -> int:
        return self._n

    def new(self, prefix: str) -> str:
        if not prefix or not prefix.isascii() or "_" in prefix:
            raise ValueError("prefix must be non-empty ASCII without underscores")
        with self._lock:
            self._n += 1
            n = self._n
        tag = hashlib.sha256(f"{self.seed}:{prefix}:{n}".encode()).hexdigest()[:4]
        return f"{prefix}_{n:06d}{tag}"
