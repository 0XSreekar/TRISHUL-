"""Deterministic stand-ins for the injection classifier (unit tests never load the real model)."""

import re
import time

from trishul.ml.injection import InjectionClassifier, ModelUnavailable

_INJECTION = re.compile(
    r"ignore (?:all |the )?(?:previous|prior)|disregard|system note|transfer .* to", re.I
)


class FakeClassifier(InjectionClassifier):
    """Keyword scorer; ``mode`` can simulate an unavailable / failing / slow model."""

    def __init__(self, mode: str = "ok", **kw: object) -> None:
        super().__init__(**kw)  # type: ignore[arg-type]
        self.mode = mode
        self.calls = 0

    def _load(self) -> None:
        if self.mode == "unavailable":
            raise ModelUnavailable("fake: model not installed")

    def _score_sync(self, text: str) -> float:
        self.calls += 1
        self._load()
        if self.mode == "error":
            raise RuntimeError("fake inference failure")
        if self.mode == "slow":
            time.sleep(0.5)
        return 0.99 if _INJECTION.search(text) else 0.01
