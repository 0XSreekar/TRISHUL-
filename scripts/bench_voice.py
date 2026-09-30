"""Measure available VoiceTrust backends only. Writes bench/voice.json (never fabricates)."""

from __future__ import annotations

import json
import statistics
import sys
from collections.abc import Callable
from pathlib import Path

from trishul.domains.voice_adapters import (
    ASRResult,
    DFArenaSpoof,
    FasterWhisperASR,
    MlxWhisperASR,
    SpoofResult,
)
from trishul.domains.voice_audio import Samples, synth_clip, vad_trim

RUNS = 5
OUT = Path(__file__).resolve().parent.parent / "bench" / "voice.json"
NOT_LOCAL = "package not importable or weights not in local HF cache"


def _timed(fn: Callable[[Samples], ASRResult | SpoofResult]) -> dict[str, object]:
    samples = vad_trim(synth_clip(4.0, seed=0))
    lat: list[float] = []
    for _ in range(RUNS):
        r = fn(samples)
        if not r.ran or r.latency_ms is None:
            return {"status": "unavailable", "reason": r.detail or "did not run"}
        lat.append(r.latency_ms)
    lat.sort()
    return {
        "status": "measured",
        "runs": RUNS,
        "p50_ms": statistics.median(lat),
        "max_ms": lat[-1],
        "input": "synthetic 4 s tone/noise (not speech; latency only, no accuracy claim)",
    }


def main() -> int:
    results: dict[str, object] = {}
    for asr in (MlxWhisperASR(), FasterWhisperASR()):
        if asr.available():
            results[asr.name] = _timed(asr.transcribe)
        else:
            results[asr.name] = {"status": "unavailable", "reason": NOT_LOCAL}
    df = DFArenaSpoof()
    results["df-arena"] = (
        _timed(df.score) if df.available() else {"status": "unavailable", "reason": NOT_LOCAL}
    )
    measured = any(isinstance(v, dict) and v.get("status") == "measured" for v in results.values())
    doc: dict[str, object] = {
        "status": "measured" if measured else "unavailable",
        "backends": results,
    }
    if not measured:
        doc["reason"] = "no ASR or spoof backend available locally; nothing measured"
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n")
    print(json.dumps(doc, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
