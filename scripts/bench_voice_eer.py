"""Measure DF_Arena anti-spoof EER on real (bonafide) vs TTS (spoof) speech, clean and through a
phone codec, and mlx-whisper WER/CER for Hindi/Telugu with auto vs forced language.

Prerequisite: ``uv run --with pyarrow python scripts/prepare_voice_corpus.py``.
Run: ``uv run python scripts/bench_voice_eer.py`` -> writes bench/voice_eer.json (measured only).
"""

from __future__ import annotations

import datetime as dt
import json
import platform
import statistics
import subprocess
import time
from pathlib import Path
from typing import Any

import numpy as np
import soundfile as sf

from trishul.domains.voice_adapters import WHISPER_REPO, DFArenaSpoof, local_snapshot

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "bench" / "audio" / "eer" / "manifest.json"
OUT = ROOT / "bench" / "voice_eer.json"
THRESHOLD = 0.5  # VoiceTrust: spoof >= 0.5 -> DENY (trishul/domains/voicetrust.py)
ASR_PER_LANG = 10


def phone_codec(x: np.ndarray) -> np.ndarray:
    """Narrowband telephone channel: 300-3400 Hz band-pass, 8 kHz, G.711 mu-law 8-bit, back to
    16 kHz. Approximates a PSTN leg; not a model of any specific VoIP codec (e.g. Opus/AMR)."""
    spec = np.fft.rfft(x)
    f = np.fft.rfftfreq(len(x), 1 / 16000)
    spec[(f < 300) | (f > 3400)] = 0
    y = np.fft.irfft(spec, len(x))[::2]
    mu = 255.0
    y = np.clip(y, -1, 1)
    c = np.sign(y) * np.log1p(mu * np.abs(y)) / np.log1p(mu)
    c = np.round(c * 127) / 127
    d = np.sign(c) * np.expm1(np.abs(c) * np.log1p(mu)) / mu
    return np.repeat(d, 2)[: len(x)].astype(np.float32)


def eer(bona: list[float], spoof: list[float]) -> tuple[float, float]:
    """Equal error rate over all observed thresholds (score = P(spoof); flag if >= t)."""
    ts = sorted(set(bona) | set(spoof) | {0.0, 1.0 + 1e-9})
    best = (2.0, 0.0, 0.5)
    for t in ts:
        frr = sum(s >= t for s in bona) / len(bona)  # real speech flagged as spoof
        far = sum(s < t for s in spoof) / len(spoof)  # spoof accepted as real
        if abs(frr - far) < best[0]:
            best = (abs(frr - far), (frr + far) / 2, t)
    return round(best[1], 4), round(best[2], 6)


def at_threshold(bona: list[float], spoof: list[float]) -> dict[str, Any]:
    frr = sum(s >= THRESHOLD for s in bona) / len(bona) if bona else None
    far = sum(s < THRESHOLD for s in spoof) / len(spoof) if spoof else None
    correct = sum(s < THRESHOLD for s in bona) + sum(s >= THRESHOLD for s in spoof)
    n = len(bona) + len(spoof)
    return {
        "threshold": THRESHOLD,
        "frr_real_flagged": None if frr is None else round(frr, 4),
        "far_spoof_accepted": None if far is None else round(far, 4),
        "accuracy": round(correct / n, 4) if n else None,
        "n_bonafide": len(bona),
        "n_spoof": len(spoof),
    }


def load(path: str) -> np.ndarray:
    x, sr = sf.read(ROOT / path, dtype="float32")
    assert sr == 16000  # noqa: S101
    return x


def edit(a: list[str], b: list[str]) -> int:
    d = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        prev, d[0] = d[0], i
        for j, cb in enumerate(b, 1):
            prev, d[j] = d[j], min(d[j] + 1, d[j - 1] + 1, prev + (ca != cb))
    return d[len(b)]


def norm(t: str) -> str:
    return " ".join("".join(ch for ch in t.lower() if ch.isalnum() or ch.isspace()).split())


def asr_eval(items: list[dict[str, Any]]) -> dict[str, Any]:
    snap = local_snapshot(WHISPER_REPO)
    if snap is None:
        return {"status": "not_run", "reason": "mlx-whisper weights not cached"}
    import mlx_whisper  # type: ignore[import-not-found,import-untyped,unused-ignore]

    out: dict[str, Any] = {"status": "measured", "model": WHISPER_REPO, "per_lang": ASR_PER_LANG}
    for lang in ("hi", "te"):
        sel = [i for i in items if i["label"] == "bonafide" and i["lang"] == lang][:ASR_PER_LANG]
        res: dict[str, Any] = {}
        for mode, language in (("auto", None), ("forced", lang)):
            wers, cers, detected = [], [], []
            for it in sel:
                r = mlx_whisper.transcribe(
                    load(it["path"]), path_or_hf_repo=str(snap), language=language, verbose=None
                )
                hyp, ref = norm(str(r.get("text", ""))), norm(it["text"])
                wers.append(edit(ref.split(), hyp.split()) / max(1, len(ref.split())))
                cers.append(edit(list(ref), list(hyp)) / max(1, len(ref)))
                detected.append(str(r.get("language")))
            res[mode] = {
                "wer_mean": round(statistics.mean(wers), 4),
                "cer_mean": round(statistics.mean(cers), 4),
                "detected_language_counts": {k: detected.count(k) for k in sorted(set(detected))},
            }
        out[lang] = res
    return out


def main() -> None:
    manifest = json.loads(MANIFEST.read_text())
    items: list[dict[str, Any]] = manifest["items"]
    audio = {i["path"]: load(i["path"]) for i in items}
    results: dict[str, Any] = {}
    for size in ("1B", "500M"):
        det = DFArenaSpoof(size=size)
        if not det.available():
            results[size] = {"status": "not_run", "reason": "torch/weights not local"}
            continue
        det.warmup(audio[items[0]["path"]])
        per_cond: dict[str, Any] = {}
        for cond, fn in (("clean", lambda x: x), ("phone_mulaw_8k", phone_codec)):
            scores: dict[str, float | None] = {}
            lat: list[float] = []
            for it in items:
                r = det.score(fn(audio[it["path"]]))
                scores[it["path"]] = r.score if r.ran else None
                if r.latency_ms is not None:
                    lat.append(r.latency_ms)
            failed = [p for p, s in scores.items() if s is None]

            def grp(
                pred: Any, sc: dict[str, float | None] = scores
            ) -> tuple[list[float], list[float]]:
                b = [sc[i["path"]] for i in items if i["label"] == "bonafide" and pred(i)]
                s = [sc[i["path"]] for i in items if i["label"] == "spoof" and pred(i)]
                return [v for v in b if v is not None], [v for v in s if v is not None]

            bona, spoof = grp(lambda i: True)
            e, t = eer(bona, spoof)
            by_lang = {}
            for lang in ("en", "hi", "te"):
                b, s = grp(lambda i, lang=lang: i["lang"] == lang)
                el, _ = eer(b, s) if b and s else (None, None)
                by_lang[lang] = {"eer": el, **at_threshold(b, s)}
            owner = [
                {"path": i["path"], "label": i["label"], "score": scores[i["path"]]}
                for i in items
                if str(i["source"]).startswith("project-owner")
            ]
            per_cond[cond] = {
                "eer": e,
                "eer_threshold": t,
                **at_threshold(bona, spoof),
                "by_lang": by_lang,
                "owner_clips": owner,
                "score_failures": len(failed),
                "latency_ms_p50": round(statistics.median(lat), 1) if lat else None,
            }
        results[size] = {"status": "measured", "conditions": per_cond}

    doc = {
        "schema_version": 1,
        "generated_at": dt.datetime.now(dt.UTC).isoformat(timespec="seconds"),
        "git_commit": subprocess.run(
            ["git", "rev-parse", "HEAD"],  # noqa: S607
            capture_output=True,
            text=True,
            cwd=ROOT,
        ).stdout.strip(),
        "environment": {"machine": platform.machine(), "os": platform.platform()},
        "corpus": {
            "sources_sha256": manifest["sources_sha256"],
            "counts": {
                f"{lab}_{lang}": sum(1 for i in items if i["label"] == lab and i["lang"] == lang)
                for lab in ("bonafide", "spoof")
                for lang in ("en", "hi", "te")
            },
            "notes": [
                "bonafide en = LibriSpeech dev-clean dummy subset: 73 clips, ONE speaker",
                "bonafide hi/te = FLEURS validation, 30 clips each, multiple speakers",
                "spoof = macOS `say` TTS speaking the same sentences (content-matched); "
                "no neural voice clone is included unless bench/audio/user/clone/ has clips",
                "owner clip = one WhatsApp voice note (Opus-compressed at ~18 kbit/s before "
                "decoding), reported individually, not a population estimate",
                "phone_mulaw_8k is a synthetic PSTN approximation, not a VoIP/Opus/AMR codec",
            ],
        },
        "detector": results,
        "asr": asr_eval(items),
    }
    OUT.write_text(json.dumps(doc, indent=1, ensure_ascii=False) + "\n")
    print(f"wrote {OUT}")


if __name__ == "__main__":
    t0 = time.time()
    main()
    print(f"{time.time() - t0:.0f}s")
