"""ASR and anti-spoof adapters for VoiceTrust.

Honesty contract: an adapter reports ``ran=True`` only if inference actually executed on the
audio. Every heavy dependency is imported lazily and is used only when the package is importable
AND the weights are already in the local Hugging Face cache (nothing is ever downloaded here).
"""

from __future__ import annotations

import importlib
import importlib.util
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, ClassVar, Protocol

from trishul.domains.voice_audio import Samples


def _importable(name: str) -> bool:
    try:
        return importlib.util.find_spec(name) is not None
    except (ImportError, ValueError):
        return False


def hf_cache_dir() -> Path:
    home = os.environ.get("HF_HUB_CACHE") or os.path.join(
        os.environ.get("HF_HOME", str(Path.home() / ".cache" / "huggingface")), "hub"
    )
    return Path(home)


# Reviewed snapshot revisions (remote code for DF_Arena was read by the lead: wav2vec2 + conformer,
# benign). Weights are only ever loaded from exactly these commit hashes.
REVISIONS: dict[str, str] = {
    "mlx-community/whisper-large-v3-turbo": "a4aaeec0636e6fef84abdcbe3544cb2bf7e9f6fb",
    "Speech-Arena-2025/DF_Arena_500M_V_1": "8258fa8e74ff9b8ad20d4c939c1a7f694a6e4080",
    "Speech-Arena-2025/DF_Arena_1B_V_1": "fb6ce85de12c2c5a509d89114adaf827dd75f49f",
    "facebook/wav2vec2-xls-r-300m": "1a640f32ac3e39899438a2931f9924c02f080a54",
    "Systran/faster-whisper-small": "536b0662742c02347bc0e980a01041f333bce120",
}
WHISPER_REPO = "mlx-community/whisper-large-v3-turbo"


def local_snapshot(repo_id: str, revision: str | None = None) -> Path | None:
    """Path of a fully-cached snapshot for ``repo_id`` (local_files_only semantics), else None.

    A repo with a pinned revision in ``REVISIONS`` resolves only to that exact snapshot.
    """
    root = hf_cache_dir() / ("models--" + repo_id.replace("/", "--")) / "snapshots"
    revision = revision or REVISIONS.get(repo_id)
    if revision is not None:
        pinned = root / revision
        return pinned if pinned.is_dir() and any(pinned.iterdir()) else None
    try:
        snaps = sorted(p for p in root.iterdir() if p.is_dir() and any(p.iterdir()))
    except OSError:
        return None
    return snaps[-1] if snaps else None


# ---------------------------------------------------------------- ASR


@dataclass(frozen=True)
class ASRResult:
    text: str | None
    ran: bool
    backend: str
    latency_ms: float | None
    detail: str = ""


class ASR(Protocol):
    name: str

    def available(self) -> bool: ...

    def transcribe(self, samples: Samples) -> ASRResult: ...


class UnavailableASR:
    """Terminal fallback: no transcript, ``ran=False`` (decision table then yields STEP_UP)."""

    name = "unavailable"

    def available(self) -> bool:
        return True

    def transcribe(self, samples: Samples) -> ASRResult:
        return ASRResult(None, False, self.name, None, "no ASR backend available")


class ScriptedASR:
    """TEST DOUBLE ONLY: returns a fixed transcript. Never wired into production chains."""

    name = "scripted-test-double"

    def __init__(self, text: str | None, *, ran: bool = True) -> None:
        self._text = text
        self._ran = ran

    def available(self) -> bool:
        return True

    def transcribe(self, samples: Samples) -> ASRResult:
        if not self._ran:
            return ASRResult(None, False, self.name, None, "scripted: not run")
        return ASRResult(self._text, True, self.name, 0.0, "scripted transcript (test double)")


class MlxWhisperASR:
    name = "mlx-whisper"

    def __init__(self, repo_id: str = WHISPER_REPO) -> None:
        self.repo_id = repo_id

    def available(self) -> bool:
        return _importable("mlx_whisper") and local_snapshot(self.repo_id) is not None

    def transcribe(self, samples: Samples) -> ASRResult:
        snap = local_snapshot(self.repo_id)
        if not _importable("mlx_whisper") or snap is None:
            return ASRResult(None, False, self.name, None, "mlx_whisper or weights not local")
        try:
            import mlx_whisper  # type: ignore[import-not-found,import-untyped,unused-ignore]

            t0 = time.perf_counter()
            out = mlx_whisper.transcribe(
                samples, path_or_hf_repo=str(snap), language=None, verbose=None
            )
            ms = (time.perf_counter() - t0) * 1000
            return ASRResult(str(out.get("text", "")).strip(), True, self.name, ms)
        except Exception as exc:
            return ASRResult(None, False, self.name, None, f"error: {type(exc).__name__}")


class FasterWhisperASR:
    name = "faster-whisper"

    def __init__(self, repo_id: str = "Systran/faster-whisper-small") -> None:
        self.repo_id = repo_id

    def available(self) -> bool:
        return _importable("faster_whisper") and local_snapshot(self.repo_id) is not None

    def transcribe(self, samples: Samples) -> ASRResult:
        snap = local_snapshot(self.repo_id)
        if not _importable("faster_whisper") or snap is None:
            return ASRResult(None, False, self.name, None, "faster_whisper or weights not local")
        try:
            whisper_model: Any = importlib.import_module("faster_whisper").WhisperModel

            model = whisper_model(
                str(snap), device="cpu", compute_type="int8", local_files_only=True
            )
            t0 = time.perf_counter()
            segments, _info = model.transcribe(samples)
            text = " ".join(s.text.strip() for s in segments).strip()
            return ASRResult(text, True, self.name, (time.perf_counter() - t0) * 1000)
        except Exception as exc:
            return ASRResult(None, False, self.name, None, f"error: {type(exc).__name__}")


class ChainASR:
    """Try each backend in order; first one that actually ran wins, else UnavailableASR."""

    name = "chain"

    def __init__(self, backends: list[ASR] | None = None) -> None:
        self.backends: list[ASR] = (
            backends if backends is not None else [MlxWhisperASR(), FasterWhisperASR()]
        )

    def available(self) -> bool:
        return any(b.available() for b in self.backends)

    def transcribe(self, samples: Samples) -> ASRResult:
        for b in self.backends:
            if not b.available():
                continue
            res = b.transcribe(samples)
            if res.ran:
                return res
        return UnavailableASR().transcribe(samples)


# ---------------------------------------------------------------- anti-spoof


@dataclass(frozen=True)
class SpoofResult:
    score: float | None  # P(spoof) in [0,1]; None iff not ran
    ran: bool
    label: str
    device: str | None = None
    latency_ms: float | None = None
    detail: str = ""


class SpoofAdapter(Protocol):
    def available(self) -> bool: ...

    def score(self, samples: Samples) -> SpoofResult: ...


class DeterministicSpoofAdapter:
    """No detector present: score None, ran False. Never lowers a decision."""

    label = "deterministic-adapter"

    def available(self) -> bool:
        return True

    def score(self, samples: Samples) -> SpoofResult:
        return SpoofResult(None, False, self.label, None, None, "no anti-spoof model available")


class DFArenaSpoof:
    """DF_Arena (Speech-Arena-2025, non-commercial licence) via transformers, local weights only.

    Prefers mps and falls back to cpu. Uses the 1B model unless its measured p50 latency
    exceeds 2 s, then the 500M model. ``trust_remote_code`` is enabled only for a local snapshot.
    """

    label = "df-arena"
    REPOS: ClassVar[dict[str, str]] = {
        "1B": "Speech-Arena-2025/DF_Arena_1B_V_1",
        "500M": "Speech-Arena-2025/DF_Arena_500M_V_1",
    }
    P50_LIMIT_MS: ClassVar[float] = 2000.0

    def __init__(self, size: str | None = None, device: str | None = None) -> None:
        self.size_override = size  # benchmarks only; production uses ``choose_size``
        self.device_override = device
        self._latencies: dict[str, list[float]] = {"1B": [], "500M": []}
        self._pipes: dict[str, object] = {}

    def _deps(self) -> bool:
        return _importable("torch") and _importable("transformers")

    def choose_size(self) -> str | None:
        """Model size per spec: 1B, degrading to 500M if 1B p50 > 2 s; None if none is cached."""
        have = [s for s, r in self.REPOS.items() if local_snapshot(r) is not None]
        if self.size_override is not None:
            return self.size_override if self.size_override in have else None
        if not have:
            return None
        lat = sorted(self._latencies["1B"])
        slow = bool(lat) and lat[len(lat) // 2] > self.P50_LIMIT_MS
        if "1B" in have and not slow:
            return "1B"
        return "500M" if "500M" in have else have[0]

    def available(self) -> bool:
        return self._deps() and self.choose_size() is not None

    def score(self, samples: Samples) -> SpoofResult:
        size = self.choose_size()
        if not self._deps() or size is None:
            return SpoofResult(None, False, self.label, None, None, "torch/weights not local")
        snap = local_snapshot(self.REPOS[size])
        assert snap is not None  # noqa: S101 - choose_size() guarantees a cached snapshot
        try:
            import torch  # type: ignore[import-not-found,import-untyped,unused-ignore]

            device = self.device_override or ("mps" if torch.backends.mps.is_available() else "cpu")
            pipe = self._pipes.get(size + device)
            if pipe is None:
                # Loading from the pinned snapshot directory is equivalent to
                # ``revision=<hash>`` and avoids a transformers dynamic-module bug that drops
                # transitive relative imports (conformer.py) for hub-id loads.
                try:
                    pipe = _make_pipe(snap, device)
                except Exception:
                    device = "cpu"
                    pipe = self._pipes.get(size + device) or _make_pipe(snap, device)
                self._pipes[size + device] = pipe
            t0 = time.perf_counter()
            try:
                out = pipe(samples)  # type: ignore[operator]
            except Exception:
                if device == "cpu":
                    raise
                device = "cpu"  # MPS runtime failure: fall back to cpu
                pipe = self._pipes.get(size + device) or _make_pipe(snap, device)
                self._pipes[size + device] = pipe
                t0 = time.perf_counter()
                out = pipe(samples)  # type: ignore[operator]
            ms = (time.perf_counter() - t0) * 1000
            self._latencies[size].append(ms)
            spoof = _spoof_probability(out)
            if spoof is None:
                return SpoofResult(None, False, self.label, device, ms, "unparseable output")
            return SpoofResult(spoof, True, f"{self.label}-{size}", device, ms)
        except Exception as exc:
            return SpoofResult(None, False, self.label, None, None, f"error: {type(exc).__name__}")


def _spoof_probability(out: object) -> float | None:
    """Extract P(spoof) from a pipeline output ({label, score} or list thereof)."""
    items = out if isinstance(out, list) else [out]
    for it in items:
        if not isinstance(it, dict):
            continue
        scores = it.get("all_scores")
        if isinstance(scores, dict):
            p = scores.get("spoof")
            if isinstance(p, int | float) and 0.0 <= float(p) <= 1.0:
                return float(p)
            continue
        # {label, score}: ``score`` is the probability of the *named* label
        s = it.get("score")
        if isinstance(s, int | float) and 0.0 <= float(s) <= 1.0:
            label = str(it.get("label", "")).lower()
            if "spoof" in label:
                return float(s)
            if "bonafide" in label:
                return 1.0 - float(s)
    return None


def _make_pipe(snap: Path, device: str) -> object:
    import transformers  # type: ignore[import-not-found,import-untyped,unused-ignore]

    factory: Any = transformers.pipeline
    return factory("antispoofing", model=str(snap), trust_remote_code=True, device=device)


def default_spoof_adapter() -> SpoofAdapter:
    df = DFArenaSpoof()
    return df if df.available() else DeterministicSpoofAdapter()
