"""Prompt-injection classifier service (``protectai/deberta-v3-base-prompt-injection-v2``).

Long text is cut into 512-token windows (stride 64); the signal is the MAX injection probability
over the windows. Everything fails closed: a timeout, an error or a model that is not installed
yields ``escalate=True`` with a logged reason, never a pass. The signal is only ever used to
tighten a decision (see ``Pipeline._ml``).

Backend: CPU p50 latency per full 512-token chunk was measured on this Apple-silicon dev machine
(2026-10-01, machine shared with other workers, load average ~4): ONNX 274-310 ms, PyTorch
279-335 ms. Both are above the 150 ms threshold, so the repo's ONNX export is preferred when
``onnxruntime`` and the pinned ONNX file are present; PyTorch transformers is the fallback. An
earlier quiet-machine run (not reproduced) reported 159.5 ms ONNX / 163 ms PyTorch. Latency is
machine-load dependent; the 2 s gate timeout covers a short document (1-3 chunks).
"""

import asyncio
import hashlib
import json
import logging
import os
import re
import threading
from collections import OrderedDict
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Any, Literal

from trishul.ml.models import CLASSIFIER_PINS

log = logging.getLogger("trishul.ml")

type MLStatus = Literal["ok", "timeout", "error", "unavailable", "disabled"]

DEFAULT_THRESHOLD = 0.5
DEFAULT_TIMEOUT_S = 2.0
MAX_TOKENS = 512
STRIDE = 64
BATCH = 8
_CACHE_SIZE = 256
_TAG = re.compile(r"<[^>]+>")


@dataclass(frozen=True)
class MLSignal:
    status: MLStatus
    score: float | None
    threshold: float
    escalate: bool
    reason: str

    def to_event(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "score": None if self.score is None else round(self.score, 4),
            "threshold": self.threshold,
            "escalate": self.escalate,
            "reason": self.reason,
        }

    def to_audit(self) -> dict[str, Any]:
        """JCS forbids floats: scores are recorded in thousandths."""
        return {
            "status": self.status,
            "score_milli": None if self.score is None else int(self.score * 1000),
            "threshold_milli": int(self.threshold * 1000),
            "escalate": self.escalate,
            "reason": self.reason,
        }


class ModelUnavailable(RuntimeError):
    """The pinned model (or its runtime) is not installed locally."""


def plain_text(text: str) -> str:
    """Strip markup so the classifier sees prose (hidden text stays: it is text)."""
    return re.sub(r"\s+", " ", _TAG.sub(" ", text)).strip()


class InjectionClassifier:
    """Real classifier. Subclass and override ``_score_sync`` for a fake in tests."""

    def __init__(
        self,
        *,
        threshold: float | None = None,
        timeout_s: float = DEFAULT_TIMEOUT_S,
        backend: str | None = None,
    ) -> None:
        self.threshold = (
            threshold
            if threshold is not None
            else float(os.environ.get("TRISHUL_INJECTION_THRESHOLD", DEFAULT_THRESHOLD))
        )
        self.timeout_s = timeout_s
        self.backend = backend or os.environ.get("TRISHUL_INJECTION_BACKEND", "auto")
        self.pin = CLASSIFIER_PINS["injection"]
        self._load_lock = threading.Lock()
        self._runner: Callable[[list[list[int]]], list[float]] | None = None
        self._tok: Any = None
        self._load_error: str | None = None
        self._cache: OrderedDict[str, float] = OrderedDict()
        self._pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix="trishul-injection")
        self.backend_used: str | None = None

    # -- loading -----------------------------------------------------------------------------

    def _load(self) -> None:
        with self._load_lock:
            if self._runner is not None:
                return
            if self._load_error is not None:
                raise ModelUnavailable(self._load_error)
            try:
                self._do_load()
            except ModelUnavailable as exc:
                self._load_error = str(exc)
                raise
            except Exception as exc:
                self._load_error = f"{type(exc).__name__}: {exc}"
                raise ModelUnavailable(self._load_error) from exc

    def _do_load(self) -> None:
        try:
            from huggingface_hub import snapshot_download
            from transformers import AutoTokenizer
        except ImportError as exc:
            raise ModelUnavailable(f"ml extra not installed ({exc.name})") from exc
        hf_id, rev = self.pin["hf_id"], self.pin["revision"]
        base = ["config.json", "tokenizer.json", "tokenizer_config.json", "special_tokens_map.json"]
        onnx = [self.pin["onnx_file"], "onnx/config.json"]
        torch_files = ["model.safetensors"]
        want = self.backend
        attempts: list[list[str]] = []
        if want in ("auto", "onnx"):
            attempts.append(base + onnx)
        if want in ("auto", "transformers"):
            attempts.append(base + torch_files)
        path = None
        for patterns in attempts:
            try:
                path = snapshot_download(
                    hf_id, revision=rev, local_files_only=True, allow_patterns=patterns
                )
                break
            except Exception:  # noqa: S112 - try the next backend's file set
                continue
        if path is None:
            raise ModelUnavailable(
                f"{hf_id}@{rev[:12]} not in local cache; run: {self.pin['download_hint']}"
            )
        self._tok = AutoTokenizer.from_pretrained(path)
        onnx_path = os.path.join(path, self.pin["onnx_file"])
        if want in ("auto", "onnx") and os.path.exists(onnx_path):
            try:
                self._runner = self._onnx_runner(onnx_path)
                self.backend_used = "onnx"
                return
            except ImportError:
                if want == "onnx":
                    raise ModelUnavailable("onnxruntime not installed") from None
        if want == "onnx":
            raise ModelUnavailable("ONNX export not in local cache")
        self._runner = self._torch_runner(path)
        self.backend_used = "transformers"

    @staticmethod
    def _softmax_pos(logits: Any, pos: int) -> list[float]:
        import numpy as np

        arr = np.asarray(logits, dtype="float64")
        arr = arr - arr.max(axis=-1, keepdims=True)
        p = np.exp(arr)
        p = p / p.sum(axis=-1, keepdims=True)
        return [float(x) for x in p[:, pos]]

    @staticmethod
    def _label_index(id2label: dict[int, str]) -> int:
        for idx, name in id2label.items():
            if str(name).upper() == "INJECTION":
                return int(idx)
        raise ModelUnavailable("model has no INJECTION label")

    def _onnx_runner(self, onnx_path: str) -> Callable[[list[list[int]]], list[float]]:
        import numpy as np
        import onnxruntime as ort

        cfg_path = os.path.join(os.path.dirname(onnx_path), "config.json")
        with open(cfg_path, encoding="utf-8") as fh:
            id2label = {int(k): v for k, v in json.load(fh)["id2label"].items()}
        pos = self._label_index(id2label)
        sess = ort.InferenceSession(onnx_path, providers=["CPUExecutionProvider"])
        names = {i.name for i in sess.get_inputs()}

        def run(batch: list[list[int]]) -> list[float]:
            width = max(len(r) for r in batch)
            ids = np.zeros((len(batch), width), dtype="int64")
            mask = np.zeros((len(batch), width), dtype="int64")
            for i, row in enumerate(batch):
                ids[i, : len(row)] = row
                mask[i, : len(row)] = 1
            feed = {"input_ids": ids, "attention_mask": mask}
            out = sess.run(None, {k: v for k, v in feed.items() if k in names})[0]
            return self._softmax_pos(out, pos)

        return run

    def _torch_runner(self, path: str) -> Callable[[list[list[int]]], list[float]]:
        try:
            import torch
            from transformers import AutoModelForSequenceClassification
        except ImportError as exc:
            raise ModelUnavailable(f"torch not installed ({exc.name})") from exc
        model = AutoModelForSequenceClassification.from_pretrained(path).eval()
        pos = self._label_index({int(k): v for k, v in model.config.id2label.items()})

        def run(batch: list[list[int]]) -> list[float]:
            width = max(len(r) for r in batch)
            ids = torch.zeros((len(batch), width), dtype=torch.long)
            mask = torch.zeros((len(batch), width), dtype=torch.long)
            for i, row in enumerate(batch):
                ids[i, : len(row)] = torch.tensor(row)
                mask[i, : len(row)] = 1
            with torch.inference_mode():
                logits = model(input_ids=ids, attention_mask=mask).logits
            return self._softmax_pos(logits.numpy(), pos)

        return run

    def available(self) -> bool:
        try:
            self._load()
        except ModelUnavailable:
            return False
        return True

    def warmup(self) -> bool:
        """Load the model now (outside any per-call timeout). False when unavailable."""
        if not self.available():
            return False
        try:
            self._score_sync("warm up")
        except Exception:  # pragma: no cover - best effort
            return False
        return True

    # -- scoring -----------------------------------------------------------------------------

    def chunks(self, text: str) -> list[list[int]]:
        """512-token windows (special tokens included), 64 tokens of overlap."""
        self._load()
        enc = self._tok(
            text,
            truncation=True,
            max_length=MAX_TOKENS,
            stride=STRIDE,
            return_overflowing_tokens=True,
            add_special_tokens=True,
        )
        return [list(ids) for ids in enc["input_ids"]]

    def _score_sync(self, text: str) -> float:
        """Max INJECTION probability over the windows of ``text``."""
        self._load()
        assert self._runner is not None  # noqa: S101
        windows = self.chunks(text)
        best = 0.0
        for i in range(0, len(windows), BATCH):
            best = max([best, *self._runner(windows[i : i + BATCH])])
        return best

    async def classify(self, text: str, *, timeout_s: float | None = None) -> MLSignal:
        limit = self.timeout_s if timeout_s is None else timeout_s
        text = plain_text(text)
        if not text:
            return MLSignal("ok", 0.0, self.threshold, False, "empty text")
        key = hashlib.sha256(text.encode()).hexdigest()
        cached = self._cache.get(key)
        if cached is not None:
            self._cache.move_to_end(key)
            return self._ok(cached)
        loop = asyncio.get_running_loop()
        try:
            score = await asyncio.wait_for(
                loop.run_in_executor(self._pool, self._score_sync, text), limit
            )
        except ModelUnavailable as exc:
            log.warning("injection classifier unavailable: %s", exc)
            return MLSignal("unavailable", None, self.threshold, True, f"model unavailable: {exc}")
        except TimeoutError:
            log.warning("injection classifier timed out after %.2fs", limit)
            return MLSignal("timeout", None, self.threshold, True, f"timed out after {limit:.2f}s")
        except Exception as exc:
            log.warning("injection classifier error: %s", type(exc).__name__)
            return MLSignal("error", None, self.threshold, True, type(exc).__name__)
        self._cache[key] = score
        while len(self._cache) > _CACHE_SIZE:
            self._cache.popitem(last=False)
        return self._ok(score)

    def _ok(self, score: float) -> MLSignal:
        esc = score >= self.threshold
        return MLSignal(
            "ok",
            score,
            self.threshold,
            esc,
            "injection probability >= threshold" if esc else "below threshold",
        )


_default: InjectionClassifier | None = None


def get_default_classifier() -> InjectionClassifier:
    global _default
    if _default is None:
        _default = InjectionClassifier()
    return _default


def set_default_classifier(clf: InjectionClassifier | None) -> None:
    """Install (or clear) the process-wide classifier; tests install a fake."""
    global _default
    _default = clf
