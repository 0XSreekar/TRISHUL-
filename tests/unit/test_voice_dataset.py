# SPDX-License-Identifier: Apache-2.0
"""scripts/voice_dataset.py: manifest validation and phone-codec, using a generated sine wave."""

import importlib.util
import wave
from pathlib import Path

import numpy as np
import pytest

_spec = importlib.util.spec_from_file_location(
    "voice_dataset", Path(__file__).resolve().parents[2] / "scripts" / "voice_dataset.py"
)
assert _spec and _spec.loader
vd = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(vd)

HEADER = ",".join(vd.COLUMNS)


def _sine(path: Path, seconds: float = 1.0, rate: int = 16000) -> None:
    t = np.arange(int(seconds * rate)) / rate
    pcm = (0.5 * np.sin(2 * np.pi * 440 * t) * 32767).astype("<i2")
    with wave.open(str(path), "wb") as w:
        w.setnchannels(1)
        w.setsampwidth(2)
        w.setframerate(rate)
        w.writeframes(pcm.tobytes())


def _manifest(tmp_path: Path, *rows: str) -> Path:
    m = tmp_path / "manifest.csv"
    m.write_text("\n".join([HEADER, *rows]) + "\n")
    return m


def test_repo_manifest_header_is_valid() -> None:
    assert vd.validate(vd.VOICE_DIR / "manifest.csv", vd.VOICE_DIR) == []


def test_valid_manifest_passes(tmp_path: Path) -> None:
    _sine(tmp_path / "a.wav")
    m = _manifest(tmp_path, "a.wav,s1,real,clean,en-IN,yes,1.0,,")
    assert vd.validate(m, tmp_path) == []


def test_missing_consent_fails(tmp_path: Path) -> None:
    _sine(tmp_path / "a.wav")
    m = _manifest(tmp_path, "a.wav,s1,real,clean,en-IN,no,1.0,,")
    assert any("consent" in p for p in vd.validate(m, tmp_path))


def test_clone_without_model_and_licence_fails(tmp_path: Path) -> None:
    _sine(tmp_path / "a.wav")
    m = _manifest(tmp_path, "a.wav,s1,clone,clean,en-IN,yes,1.0,,")
    assert any("source_model" in p for p in vd.validate(m, tmp_path))


def test_missing_file_and_duration_mismatch(tmp_path: Path) -> None:
    _sine(tmp_path / "a.wav", seconds=1.0)
    m = _manifest(
        tmp_path,
        "gone.wav,s1,real,clean,en-IN,yes,1.0,,",
        "a.wav,s1,real,clean,en-IN,yes,3.0,,",
    )
    problems = vd.validate(m, tmp_path)
    assert any("file missing" in p for p in problems)
    assert any("duration_s" in p for p in problems)


def test_bad_header_fails(tmp_path: Path) -> None:
    m = tmp_path / "manifest.csv"
    m.write_text("file,speaker_id\n")
    assert vd.validate(m, tmp_path)


def test_phone_codec_is_8k_mono_and_close_to_source(tmp_path: Path) -> None:
    src, dst = tmp_path / "in.wav", tmp_path / "out.wav"
    _sine(src, seconds=1.0, rate=16000)
    vd.phone_codec(src, dst)
    with wave.open(str(dst), "rb") as w:
        assert w.getframerate() == 8000
        assert w.getnchannels() == 1
        assert w.getnframes() == 8000
    out, _ = vd._read_wav(dst)
    ref = 0.5 * np.sin(2 * np.pi * 440 * np.arange(8000) / 8000)
    assert float(np.sqrt(np.mean((out - ref) ** 2))) < 0.05


def test_mulaw_roundtrip_bounded() -> None:
    x = np.linspace(-1, 1, 1001)
    y = vd.mulaw_roundtrip(x)
    assert float(np.max(np.abs(x - y))) < 0.05


def test_amr_without_ffmpeg_fails_cleanly(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _sine(tmp_path / "in.wav")
    monkeypatch.setattr(vd.shutil, "which", lambda _n: None)
    with pytest.raises(RuntimeError):
        vd.phone_codec(tmp_path / "in.wav", tmp_path / "o.wav", amr=True)
    assert vd.main(["phone-codec", str(tmp_path / "in.wav"), str(tmp_path / "o.wav"), "--amr"]) == 1
