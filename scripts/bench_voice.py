"""Measure real VoiceTrust backends on generated TTS samples. Writes bench/voice.json.

Only measured numbers are written; a backend that cannot run is recorded as unavailable.
Samples come from ``scripts/make_voice_samples.py`` (synthetic TTS, no bonafide human speech).
"""

from __future__ import annotations

import json
import platform
import re
import statistics
import sys
from pathlib import Path
from typing import Any

from trishul.domains.voice_adapters import (
    REVISIONS,
    ASRResult,
    DFArenaSpoof,
    FasterWhisperASR,
    MlxWhisperASR,
)
from trishul.domains.voice_audio import Samples, load_wav, vad_trim

RUNS = 10
ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "bench" / "voice.json"
MANIFEST = ROOT / "tests" / "fixtures" / "media" / "manifest.json"
NOT_LOCAL = "package not importable or weights not in local HF cache"


def _edit(a: list[str] | str, b: list[str] | str) -> int:
    prev = list(range(len(b) + 1))
    for i, x in enumerate(a, 1):
        cur = [i]
        for j, y in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (x != y)))
        prev = cur
    return prev[-1]


def _norm(t: str) -> str:
    return re.sub(r"[^\w\s]", "", t.lower(), flags=re.UNICODE).strip()


def wer(ref: str, hyp: str) -> float:
    r = _norm(ref).split()
    return _edit(r, _norm(hyp).split()) / max(len(r), 1)


def cer(ref: str, hyp: str) -> float:
    r = re.sub(r"\s+", "", _norm(ref))
    return _edit(r, re.sub(r"\s+", "", _norm(hyp))) / max(len(r), 1)


def pct(lat: list[float], q: float) -> float:
    s = sorted(lat)
    return s[min(len(s) - 1, max(0, round(q * (len(s) - 1))))]


def stats(lat: list[float]) -> dict[str, float]:
    return {
        "p50_ms": round(statistics.median(lat), 1),
        "p99_ms": round(pct(lat, 0.99), 1),
        "max_ms": round(max(lat), 1),
    }


def load_samples() -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for e in json.loads(MANIFEST.read_text())["entries"]:
        f = e.get("file")
        if e.get("kind") != "tts" or not f or not (ROOT / f).exists():
            continue
        load = load_wav(ROOT / f)
        if load.samples is None:
            continue
        out[Path(f).stem] = {"samples": vad_trim(load.samples), "entry": e}
    return out


def bench_asr(asr: Any, samples: dict[str, dict[str, Any]]) -> dict[str, Any]:
    if not asr.available():
        return {"status": "unavailable", "reason": NOT_LOCAL}
    pooled: list[float] = []
    per: dict[str, Any] = {}
    for name, s in samples.items():
        x: Samples = s["samples"]
        first: ASRResult = asr.transcribe(x)  # warm-up (model load / compile)
        if not first.ran:
            return {"status": "unavailable", "reason": first.detail or "did not run"}
        lat: list[float] = []
        res = first
        for _ in range(RUNS):
            res = asr.transcribe(x)
            if not res.ran or res.latency_ms is None:
                return {"status": "unavailable", "reason": res.detail or "did not run"}
            lat.append(res.latency_ms)
        pooled += lat
        ref = s["entry"]["text"]
        per[name] = {
            "language": s["entry"]["language"],
            "audio_s": round(len(x) / 16000, 2),
            "reference": ref,
            "hypothesis": res.text,
            "wer": round(wer(ref, res.text or ""), 3),
            "cer": round(cer(ref, res.text or ""), 3),
            **stats(lat),
        }
    return {"status": "measured", "runs_per_sample": RUNS, "pooled": stats(pooled), "samples": per}


def bench_spoof(size: str, device: str, samples: dict[str, dict[str, Any]]) -> dict[str, Any]:
    df = DFArenaSpoof(size=size, device=device)
    if not df.available():
        return {"status": "unavailable", "reason": NOT_LOCAL}
    pooled: list[float] = []
    scores: dict[str, float] = {}
    used: set[str] = set()
    for name, s in samples.items():
        first = df.score(s["samples"])  # warm-up
        if not first.ran:
            return {"status": "unavailable", "reason": first.detail or "did not run"}
        for _ in range(RUNS):
            r = df.score(s["samples"])
            if not r.ran or r.latency_ms is None or r.score is None:
                return {"status": "unavailable", "reason": r.detail or "did not run"}
            pooled.append(r.latency_ms)
            scores[name] = round(r.score, 4)
            used.add(r.device or "?")
    return {
        "status": "measured",
        "requested_device": device,
        "actual_device": sorted(used),
        "runs_per_sample": RUNS,
        **stats(pooled),
        "spoof_scores": scores,
    }


def main() -> int:
    samples = load_samples()
    if not samples:
        doc: dict[str, object] = {
            "status": "unavailable",
            "reason": "no samples: run scripts/make_voice_samples.py",
        }
    else:
        asr = {
            "mlx-whisper-large-v3-turbo (Metal)": bench_asr(MlxWhisperASR(), samples),
            "faster-whisper-small (CPU int8)": bench_asr(FasterWhisperASR(), samples),
        }
        spoof: dict[str, Any] = {}
        for size in ("500M", "1B"):
            for device in ("mps", "cpu"):
                spoof[f"DF_Arena_{size}/{device}"] = bench_spoof(size, device, samples)
        p1b = [
            v["p50_ms"]
            for k, v in spoof.items()
            if k.startswith("DF_Arena_1B") and v["status"] == "measured"
        ]
        selected = None
        if p1b:
            selected = "1B" if min(p1b) <= DFArenaSpoof.P50_LIMIT_MS else "500M"
        doc = {
            "status": "measured",
            "machine": f"{platform.machine()} {platform.platform()}",
            "revisions": REVISIONS,
            "corpus": "synthetic Apple-TTS clips only; NO bonafide human speech",
            "asr": asr,
            "spoof": spoof,
            "spoof_selected": {"size": selected, "rule": "1B unless best-device p50 > 2000 ms"},
        }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(doc, indent=2, sort_keys=True, ensure_ascii=False) + "\n")
    print(json.dumps(doc, indent=2, sort_keys=True, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
