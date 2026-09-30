"""Audio ingest for VoiceTrust: 16 kHz mono PCM wav loading, quality gate, energy VAD.

Deliberately resample-free and ffmpeg-free (`wave` + numpy). Any file that is not 16 kHz,
mono, 16-bit PCM is *rejected* and reported as ``quality=unknown`` rather than converted.
"""

from __future__ import annotations

import io
import math
import wave
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

import numpy as np
from numpy.typing import NDArray

SAMPLE_RATE = 16_000
FRAME = 320  # 20 ms
MIN_DURATION_S = 1.0
MAX_DURATION_S = 15.0
MIN_SNR_DB = 10.0
MIN_FRAMES_FOR_SNR = 10

type Quality = Literal["ok", "low", "unknown"]
type Samples = NDArray[np.float32]


@dataclass(frozen=True)
class AudioLoad:
    """Result of loading a wav. ``samples`` is ``None`` iff ``reason`` explains the rejection."""

    samples: Samples | None
    rate: int
    reason: str | None


@dataclass(frozen=True)
class QualityReport:
    quality: Quality
    duration_s: float
    snr_db: float | None
    reason: str


def load_wav(source: bytes | str | Path) -> AudioLoad:
    """Load 16 kHz mono 16-bit PCM. Everything else is rejected (never resampled)."""
    try:
        raw = io.BytesIO(source) if isinstance(source, bytes) else str(source)
        with wave.open(raw, "rb") as w:
            rate, ch, width, n = (
                w.getframerate(),
                w.getnchannels(),
                w.getsampwidth(),
                w.getnframes(),
            )
            if w.getcomptype() != "NONE":
                return AudioLoad(None, rate, "compressed wav unsupported")
            if rate != SAMPLE_RATE:
                return AudioLoad(None, rate, f"unsupported sample rate {rate} (need 16000)")
            if ch != 1:
                return AudioLoad(None, rate, f"unsupported channel count {ch} (need mono)")
            if width != 2:
                return AudioLoad(None, rate, f"unsupported sample width {width * 8} bit")
            frames = w.readframes(n)
    except (wave.Error, EOFError, OSError, ValueError) as exc:
        return AudioLoad(None, 0, f"unreadable wav: {type(exc).__name__}")
    pcm = np.frombuffer(frames, dtype="<i2").astype(np.float32) / 32768.0
    return AudioLoad(pcm, SAMPLE_RATE, None)


def write_wav(path: str | Path, samples: Samples) -> None:
    """Write float32 samples in [-1, 1] as 16 kHz mono 16-bit PCM."""
    pcm = (np.clip(samples, -1.0, 1.0) * 32767.0).astype("<i2")
    with wave.open(str(path), "wb") as w:
        w.setnchannels(1)
        w.setsampwidth(2)
        w.setframerate(SAMPLE_RATE)
        w.writeframes(pcm.tobytes())


def frame_energies(samples: Samples) -> NDArray[np.float64]:
    n = len(samples) // FRAME
    if n == 0:
        return np.zeros(0, dtype=np.float64)
    frames = samples[: n * FRAME].astype(np.float64).reshape(n, FRAME)
    return np.asarray((frames**2).mean(axis=1), dtype=np.float64)


def _deciles(energies: NDArray[np.float64]) -> tuple[float, float]:
    ordered = np.sort(energies)
    k = max(1, len(ordered) // 10)
    return float(ordered[-k:].mean()), float(ordered[:k].mean())


def quality_gate(load: AudioLoad) -> QualityReport:
    """Duration 1-15 s and SNR >= 10 dB (top-decile vs bottom-decile frame energy)."""
    if load.samples is None:
        return QualityReport("unknown", 0.0, None, load.reason or "no audio")
    duration = len(load.samples) / SAMPLE_RATE
    if not (MIN_DURATION_S <= duration <= MAX_DURATION_S):
        return QualityReport("low", duration, None, f"duration {duration:.2f}s outside 1-15s")
    energies = frame_energies(load.samples)
    if len(energies) < MIN_FRAMES_FOR_SNR or not np.isfinite(energies).all():
        return QualityReport("unknown", duration, None, "cannot estimate SNR")
    top, bottom = _deciles(energies)
    snr = 10.0 * math.log10(max(top, 1e-12) / max(bottom, 1e-12))
    if snr < MIN_SNR_DB:
        return QualityReport("low", duration, snr, f"snr {snr:.1f} dB < {MIN_SNR_DB:.0f} dB")
    return QualityReport("ok", duration, snr, "ok")


def vad_trim(samples: Samples) -> Samples:
    """Energy VAD: drop leading/trailing frames below an adaptive threshold."""
    energies = frame_energies(samples)
    if len(energies) == 0:
        return samples
    top, bottom = _deciles(energies)
    threshold = max(bottom * 4.0, top * 0.02)
    active = np.flatnonzero(energies > threshold)
    if len(active) == 0:
        return samples
    return samples[int(active[0]) * FRAME : (int(active[-1]) + 1) * FRAME]


def synth_clip(
    seconds: float, *, snr_db: float | None = 30.0, seed: int = 0, freq: float = 220.0
) -> Samples:
    """Deterministic synthetic 'speech-like' clip: syllable-gated tone over white noise.

    Test material only (no speech content). ``snr_db=None`` yields pure noise.
    """
    rng = np.random.default_rng(seed)
    n = int(seconds * SAMPLE_RATE)
    t = np.arange(n) / SAMPLE_RATE
    noise = rng.standard_normal(n).astype(np.float32) * 0.01
    if snr_db is None:
        return noise
    gate = (np.sin(2 * np.pi * 3.0 * t) > -0.2).astype(np.float32)
    amp = 0.01 * 10 ** (snr_db / 20.0) * math.sqrt(2)
    tone = (amp * gate * np.sin(2 * np.pi * freq * t)).astype(np.float32)
    out: Samples = np.clip(noise + tone, -1.0, 1.0).astype(np.float32)
    return out
