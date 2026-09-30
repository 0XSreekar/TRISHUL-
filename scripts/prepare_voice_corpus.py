"""Build the bonafide-vs-spoof voice corpus used by ``scripts/bench_voice_eer.py``.

Run (pyarrow is only needed for this one-off extraction):
    uv run --with pyarrow python scripts/prepare_voice_corpus.py

Inputs (all git-ignored under bench/audio/, see docs/phase-3-report.md for sources/licences):
- bench/audio/librispeech/dev-clean-dummy.parquet   hf-internal-testing/librispeech_asr_dummy
  (73 LibriSpeech dev-clean clips, CC BY 4.0; NOTE: a single speaker)
- bench/audio/fleurs/{hi_in,te_in}-validation.parquet   google/fleurs validation, CC BY 4.0
- bench/audio/user/*.wav         bonafide clips supplied by the project owner (optional)
- bench/audio/user/clone/*.wav   consented clones of the owner's voice (optional, spoof)

Spoof side: macOS ``say`` TTS speaking the *same sentences* as the bonafide clips
(content-matched), converted with ``afconvert`` to 16 kHz mono PCM. No voice cloning of anyone.
Writes bench/audio/eer/{bonafide,spoof}/*.wav and bench/audio/eer/manifest.json.
"""

from __future__ import annotations

import hashlib
import io
import json
import subprocess
import tempfile
from pathlib import Path

import numpy as np
import pyarrow.parquet as pq
import soundfile as sf

ROOT = Path(__file__).resolve().parents[1]
AUDIO = ROOT / "bench" / "audio"
OUT = AUDIO / "eer"
PER_LANG = 30
EN_VOICES = ["Samantha", "Daniel", "Karen", "Moira", "Tessa", "Rishi", "Aman", "Tara"]
TTS_VOICE = {"hi": "Lekha", "te": "Geeta"}


def sha256(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def write16k(path: Path, x: np.ndarray, sr: int) -> float:
    if x.ndim > 1:
        x = x.mean(axis=1)
    if sr != 16000:  # linear resample; all sources here are already 16 kHz
        n = round(len(x) * 16000 / sr)
        x = np.interp(np.linspace(0, len(x) - 1, n), np.arange(len(x)), x)
    sf.write(path, np.clip(x, -1, 1), 16000, subtype="PCM_16")
    return len(x) / 16000


def tts(text: str, voice: str, dst: Path) -> float:
    with tempfile.TemporaryDirectory() as td:
        aiff = Path(td) / "t.aiff"
        subprocess.run(["say", "-v", voice, "-o", str(aiff), text], check=True)  # noqa: S603,S607
        subprocess.run(  # noqa: S603
            ["afconvert", "-f", "WAVE", "-d", "LEI16@16000", "-c", "1", str(aiff), str(dst)],  # noqa: S607
            check=True,
        )
    return float(sf.info(dst).duration)


def main() -> None:
    for d in ("bonafide", "spoof"):
        (OUT / d).mkdir(parents=True, exist_ok=True)
        for old in (OUT / d).glob("*.wav"):
            old.unlink()
    items: list[dict[str, object]] = []
    sources: dict[str, str] = {}

    ls = AUDIO / "librispeech" / "dev-clean-dummy.parquet"
    sources[str(ls.relative_to(ROOT))] = sha256(ls)
    rows = sorted(pq.read_table(ls).to_pylist(), key=lambda r: r["id"])
    for i, r in enumerate(rows):
        x, sr = sf.read(io.BytesIO(r["audio"]["bytes"]))
        p = OUT / "bonafide" / f"en_ls_{r['id']}.wav"
        dur = write16k(p, x, sr)
        items.append(
            {
                "path": str(p.relative_to(ROOT)),
                "label": "bonafide",
                "lang": "en",
                "source": "librispeech",
                "speaker": str(r["speaker_id"]),
                "dur_s": round(dur, 2),
            }
        )
        if i < PER_LANG:  # content-matched TTS, cycling voices
            v = EN_VOICES[i % len(EN_VOICES)]
            q = OUT / "spoof" / f"en_tts_{v}_{r['id']}.wav"
            items.append(
                {
                    "path": str(q.relative_to(ROOT)),
                    "label": "spoof",
                    "lang": "en",
                    "source": f"macos-say:{v}",
                    "speaker": v,
                    "dur_s": round(tts(r["text"].lower(), v, q), 2),
                }
            )

    for lang in ("hi", "te"):
        pqf = AUDIO / "fleurs" / f"{lang}_in-validation.parquet"
        sources[str(pqf.relative_to(ROOT))] = sha256(pqf)
        rows = sorted(pq.read_table(pqf).to_pylist(), key=lambda r: (r["id"], r["path"] or ""))
        step = max(1, len(rows) // PER_LANG)
        for r in rows[::step][:PER_LANG]:
            x, sr = sf.read(io.BytesIO(r["audio"]["bytes"]))
            stem = Path(str(r["path"] or r["id"])).stem
            p = OUT / "bonafide" / f"{lang}_fleurs_{r['id']}_{stem}.wav"
            dur = write16k(p, x, sr)
            items.append(
                {
                    "path": str(p.relative_to(ROOT)),
                    "label": "bonafide",
                    "lang": lang,
                    "source": "fleurs",
                    "gender": r.get("gender"),
                    "dur_s": round(dur, 2),
                    "text": r["transcription"],
                }
            )
            v = TTS_VOICE[lang]
            q = OUT / "spoof" / f"{lang}_tts_{v}_{r['id']}_{stem}.wav"
            items.append(
                {
                    "path": str(q.relative_to(ROOT)),
                    "label": "spoof",
                    "lang": lang,
                    "source": f"macos-say:{v}",
                    "speaker": v,
                    "dur_s": round(tts(r["raw_transcription"], v, q), 2),
                    "text": r["transcription"],
                }
            )

    for label, sub in (("bonafide", AUDIO / "user"), ("spoof", AUDIO / "user" / "clone")):
        for w in sorted(sub.glob("*.wav")):
            x, sr = sf.read(w)
            p = OUT / label / f"user_{w.stem}.wav"
            items.append(
                {
                    "path": str(p.relative_to(ROOT)),
                    "label": label,
                    "lang": "en",
                    "source": "project-owner" + ("-clone" if label == "spoof" else ""),
                    "dur_s": round(write16k(p, x, sr), 2),
                }
            )

    manifest = {"sources_sha256": sources, "per_lang": PER_LANG, "items": items}
    (OUT / "manifest.json").write_text(json.dumps(manifest, indent=1, ensure_ascii=False))
    n = {k: sum(1 for i in items if i["label"] == k) for k in ("bonafide", "spoof")}
    print(json.dumps(n))


if __name__ == "__main__":
    main()
