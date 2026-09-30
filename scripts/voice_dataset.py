# SPDX-License-Identifier: Apache-2.0
"""Voice dataset tooling: manifest validation and phone-channel simulation."""

from __future__ import annotations

import argparse
import csv
import shutil
import subprocess
import sys
import wave
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parent.parent
VOICE_DIR = ROOT / "data" / "voice"
COLUMNS = [
    "file",
    "speaker_id",
    "type",
    "condition",
    "language",
    "consent",
    "duration_s",
    "source_model",
    "source_license",
]
DURATION_TOLERANCE_S = 0.1


def validate(manifest: Path, base: Path) -> list[str]:
    """Return a list of problems; empty means the manifest is valid."""
    problems: list[str] = []
    if not manifest.is_file():
        return [f"manifest not found: {manifest}"]
    with manifest.open(newline="") as fh:
        reader = csv.DictReader(fh)
        if reader.fieldnames != COLUMNS:
            return [f"header must be {','.join(COLUMNS)}; got {reader.fieldnames}"]
        for n, row in enumerate(reader, start=2):
            where = f"row {n} ({row['file']})"
            if row["consent"].strip().lower() != "yes":
                problems.append(f"{where}: consent must be 'yes'")
            if row["type"] not in ("real", "clone"):
                problems.append(f"{where}: type must be real or clone")
            if row["type"] == "clone" and not (
                row["source_model"].strip() and row["source_license"].strip()
            ):
                problems.append(f"{where}: clone rows need source_model and source_license")
            path = base / row["file"]
            if not path.is_file():
                problems.append(f"{where}: file missing")
                continue
            try:
                declared = float(row["duration_s"])
                with wave.open(str(path), "rb") as w:
                    actual = w.getnframes() / w.getframerate()
            except (ValueError, wave.Error, EOFError) as exc:
                problems.append(f"{where}: unreadable duration or wav ({exc})")
                continue
            if abs(declared - actual) > DURATION_TOLERANCE_S:
                problems.append(f"{where}: duration_s {declared} != actual {actual:.2f}")
    return problems


def _read_wav(path: Path) -> tuple[np.ndarray, int]:
    with wave.open(str(path), "rb") as w:
        if w.getsampwidth() != 2:
            raise ValueError("only 16-bit PCM wav is supported")
        rate, ch = w.getframerate(), w.getnchannels()
        data = np.frombuffer(w.readframes(w.getnframes()), dtype="<i2").astype(np.float64)
    if ch > 1:
        data = data.reshape(-1, ch).mean(axis=1)
    return data / 32768.0, rate


def _write_wav(path: Path, x: np.ndarray, rate: int) -> None:
    pcm = (np.clip(x, -1.0, 1.0) * 32767.0).astype("<i2")
    with wave.open(str(path), "wb") as w:
        w.setnchannels(1)
        w.setsampwidth(2)
        w.setframerate(rate)
        w.writeframes(pcm.tobytes())


def _resample(x: np.ndarray, src: int, dst: int) -> np.ndarray:
    if src == dst:
        return x
    n = max(1, round(len(x) * dst / src))
    return np.interp(np.linspace(0, len(x) - 1, n), np.arange(len(x)), x)


def mulaw_roundtrip(x: np.ndarray, mu: int = 255) -> np.ndarray:
    """G.711-style mu-law compand, 8-bit quantise, expand."""
    x = np.clip(x, -1.0, 1.0)
    comp = np.sign(x) * np.log1p(mu * np.abs(x)) / np.log1p(mu)
    q = np.round((comp + 1.0) / 2.0 * 255.0)
    comp = q / 255.0 * 2.0 - 1.0
    return np.sign(comp) * ((1.0 + mu) ** np.abs(comp) - 1.0) / mu


def phone_codec(src: Path, dst: Path, amr: bool = False) -> None:
    """Simulate an 8 kHz narrowband mu-law channel; optionally an ffmpeg AMR-NB round trip."""
    x, rate = _read_wav(src)
    x8 = mulaw_roundtrip(_resample(x, rate, 8000))
    _write_wav(dst, x8, 8000)
    if amr:
        ffmpeg = shutil.which("ffmpeg")
        if ffmpeg is None:
            raise RuntimeError("ffmpeg not found; AMR step unavailable")
        tmp = dst.with_suffix(".amr")
        subprocess.run(  # noqa: S603 - fixed argv, no shell
            [ffmpeg, "-y", "-loglevel", "error", "-i", str(dst), "-ar", "8000", "-ac", "1",
             "-c:a", "libopencore_amrnb", str(tmp)],
            check=True,
        )  # fmt: skip
        subprocess.run(  # noqa: S603 - fixed argv, no shell
            [ffmpeg, "-y", "-loglevel", "error", "-i", str(tmp), "-ar", "8000", str(dst)],
            check=True,
        )
        tmp.unlink()


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)
    v = sub.add_parser("validate", help="check manifest.csv against files and consent rules")
    v.add_argument("--manifest", type=Path, default=VOICE_DIR / "manifest.csv")
    v.add_argument("--base", type=Path, default=VOICE_DIR)
    p = sub.add_parser("phone-codec", help="8 kHz mu-law narrowband simulation")
    p.add_argument("src", type=Path)
    p.add_argument("dst", type=Path)
    p.add_argument(
        "--amr", action="store_true", help="also round-trip through AMR-NB (needs ffmpeg)"
    )
    a = ap.parse_args(argv)
    if a.cmd == "validate":
        problems = validate(a.manifest, a.base)
        for line in problems:
            print(line, file=sys.stderr)
        print("manifest OK" if not problems else f"{len(problems)} problem(s)")
        return 1 if problems else 0
    try:
        phone_codec(a.src, a.dst, a.amr)
    except (RuntimeError, ValueError, subprocess.CalledProcessError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(f"wrote {a.dst}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
