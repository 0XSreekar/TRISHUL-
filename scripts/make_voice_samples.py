"""Generate SYNTHETIC TTS voice samples into the gitignored ``bench/audio/`` directory.

Uses the macOS ``say`` + ``afconvert`` (Apple system voices, generated locally, never
redistributed). There is no bonafide human speech here: every clip is text-to-speech. Also
refreshes ``tests/fixtures/media/manifest.json``.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
AUDIO = ROOT / "bench" / "audio"
MANIFEST = ROOT / "tests" / "fixtures" / "media" / "manifest.json"

TEXT_EN = "Please check the status of my order and send me a receipt."
SAMPLES: list[dict[str, str]] = [
    {"id": "en_us", "language": "en", "locale": "en_US", "voice": "Samantha", "text": TEXT_EN},
    {"id": "en_in", "language": "en", "locale": "en_IN", "voice": "Rishi", "text": TEXT_EN},
    {
        "id": "hi_in",
        "language": "hi",
        "locale": "hi_IN",
        "voice": "Lekha",
        "text": "कृपया मेरे ऑर्डर की स्थिति बताइए और रसीद भेजिए।",
    },
    {
        "id": "te_in",
        "language": "te",
        "locale": "te_IN",
        "voice": "Geeta",
        "text": "దయచేసి నా ఆర్డర్ స్థితిని చెప్పండి మరియు రసీదు పంపండి.",
    },
]


def voices() -> set[str]:
    out = subprocess.run(["say", "-v", "?"], capture_output=True, text=True, check=True).stdout  # noqa: S607
    return {line.split("  ")[0].strip() for line in out.splitlines() if line.strip()}


def synth(voice: str, text: str, wav: Path) -> None:
    aiff = wav.with_suffix(".aiff")
    subprocess.run(["say", "-v", voice, "-o", str(aiff), text], check=True)  # noqa: S603, S607
    subprocess.run(  # noqa: S603
        ["afconvert", "-f", "WAVE", "-d", "LEI16@16000", "-c", "1", str(aiff), str(wav)],  # noqa: S607
        check=True,
    )
    aiff.unlink()


def say_to_wav(voice: str, text: str, wav: Path) -> None:
    """Public helper (also used by the real-model tests)."""
    wav.parent.mkdir(parents=True, exist_ok=True)
    synth(voice, text, wav)


def main() -> int:
    AUDIO.mkdir(parents=True, exist_ok=True)
    have = voices()
    entries: list[dict[str, object]] = []
    for s in SAMPLES:
        name = f"{s['id']}.wav"
        entry: dict[str, object] = {
            "file": f"bench/audio/{name}",
            "kind": "tts",
            "language": s["language"],
            "speaker_consent": False,
            "model": f"Apple macOS system voice '{s['voice']}' ({s['locale']}) via say",
            "model_version": "macOS system TTS (local)",
            "license": "Apple system voice, generated locally; not redistributed",
            "text": s["text"],
            "notes": "SYNTHETIC TTS, not human speech; file is gitignored (regenerate with script)",
        }
        if s["voice"] in have:
            synth(s["voice"], s["text"], AUDIO / name)
        else:
            entry["file"] = None
            entry["notes"] = f"unavailable: voice {s['voice']} not installed"
        entries.append(entry)
    entries.append(
        {
            "file": None,
            "kind": "bonafide",
            "language": None,
            "speaker_consent": False,
            "model": None,
            "model_version": None,
            "license": None,
            "notes": "not produced - no consented human reference speaker; no bonafide sample",
        }
    )
    entries.append(
        {
            "file": None,
            "kind": "tts_clone",
            "language": None,
            "speaker_consent": False,
            "model": None,
            "model_version": None,
            "license": None,
            "notes": "not produced - no consented reference speaker for voice cloning",
        }
    )
    doc = json.loads(MANIFEST.read_text())
    doc["schema"]["kind"] = "enum: bonafide|replay|tts|tts_clone - media classification"
    doc["schema"]["text"] = "string: spoken reference text (WER ground truth)"
    doc["entries"] = entries
    MANIFEST.write_text(json.dumps(doc, indent=2, ensure_ascii=False) + "\n")
    print(f"wrote {len(entries)} manifest entries; audio in {AUDIO}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
