"""VoiceTrust against the REAL models (mlx-whisper on Metal, DF_Arena). Auto-skipped if absent.

Clips are synthetic macOS ``say`` TTS: there is no bonafide human speech in this repo, so the
anti-spoof model is *expected* to flag them (that is asserted, not hidden).
"""

from __future__ import annotations

import base64
import json
import shutil
import subprocess
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import pytest
from fastmcp import Client
from fastmcp.exceptions import ToolError

from tests.integration.test_gateway_harness import Env, make_env_sync
from trishul.domains.voice_adapters import DeterministicSpoofAdapter as NoSpoof
from trishul.domains.voice_adapters import DFArenaSpoof, MlxWhisperASR
from trishul.domains.voice_audio import load_wav, vad_trim
from trishul.domains.voicetrust import NonceService, VoiceTrust

MAX_TRIES = 3
_asr = MlxWhisperASR()
_spoof = DFArenaSpoof()
_READY = (
    _asr.available()
    and _spoof.available()
    and shutil.which("say") is not None
    and shutil.which("afconvert") is not None
)
pytestmark = [
    pytest.mark.voice_models,
    pytest.mark.skipif(not _READY, reason="real voice models / macOS say not available"),
]


def say_clip(text: str, path: Path) -> Path:
    aiff = path.with_suffix(".aiff")
    subprocess.run(["say", "-v", "Samantha", "-o", str(aiff), text], check=True)  # noqa: S603, S607
    subprocess.run(  # noqa: S603
        ["afconvert", "-f", "WAVE", "-d", "LEI16@16000", "-c", "1", str(aiff), str(path)],  # noqa: S607
        check=True,
    )
    return path


def issue(vt: VoiceTrust, session: str = "s1") -> tuple[str, str]:
    n = vt.nonces.issue(session)
    return n.nonce_id, n.phrase


def test_a_spoken_nonce_matches_with_real_asr(tmp_path: Path) -> None:
    vt = VoiceTrust(NonceService(), MlxWhisperASR(), NoSpoof())
    seen = []
    for _ in range(MAX_TRIES):  # real ASR occasionally mishears a rare word: user retries
        nid, phrase = issue(vt)
        a = vt.assess("s1", "c1", say_clip(phrase, tmp_path / "n.wav"), nid)
        assert a.asr.ran and a.asr.backend == "mlx-whisper" and a.asr.text
        seen.append((phrase, a.asr.text))
        if a.liveness == "match":
            return
    pytest.fail(f"no liveness match in {MAX_TRIES} fresh challenges: {seen}")


def test_b_replayed_clip_against_fresh_nonce_denied(tmp_path: Path) -> None:
    vt = VoiceTrust(NonceService(), MlxWhisperASR(), NoSpoof())
    for _ in range(MAX_TRIES):
        nid, phrase = issue(vt)
        wav = say_clip(phrase, tmp_path / "n.wav")
        if vt.assess("s1", "c1", wav, nid).liveness == "match":
            break
    else:
        pytest.fail("could not obtain a live match to replay")
    for _ in range(20):  # a fresh challenge that differs from the recorded phrase
        nid2, phrase2 = issue(vt)
        if not set(phrase2.split()) & set(phrase.split()):
            break
    replay = vt.assess("s1", "c2", wav, nid2)
    assert replay.liveness == "mismatch" and replay.decision.name == "DENY"
    assert "VOICETRUST.LIVENESS.MISMATCH" in replay.rule_ids


@pytest.mark.acceptance(12)
def test_c_spoof_adapter_ran_with_numeric_score_and_flags_tts(tmp_path: Path) -> None:
    x = vad_trim(
        load_wav(say_clip("Please check the status of my order.", tmp_path / "e.wav")).samples  # type: ignore[arg-type]
    )
    r = DFArenaSpoof().score(x)
    assert r.ran and isinstance(r.score, float) and 0.0 <= r.score <= 1.0
    assert r.device in {"mps", "cpu"}
    assert r.score >= 0.5  # synthetic TTS is flagged as spoof by the real detector


@pytest.fixture
async def real_env(tmp_path: Path) -> AsyncIterator[tuple[Env, VoiceTrust]]:
    vt = VoiceTrust(NonceService(), MlxWhisperASR(), NoSpoof())
    gw, conn, ids, keys, clock, events = make_env_sync(tmp_path, voice=vt)
    async with Client(gw.mcp) as client:
        env = Env(gw, client, conn, ids, keys, clock, events)
        env.gw.bind_task(purpose="order_support", category="VOICE", text="voice request")
        yield env, vt
    conn.close()


@pytest.mark.acceptance(13)
async def test_d_live_voice_never_allows_high_risk_sink(
    real_env: tuple[Env, VoiceTrust], tmp_path: Path
) -> None:
    env, _vt = real_env
    out: dict[str, Any] | None = None
    for _ in range(MAX_TRIES):
        nonce: dict[str, Any] = env.gw.backend.issue_voice_nonce(env.gw.pipeline.session)
        wav = say_clip(nonce["phrase"], tmp_path / "v.wav")
        args = {
            "clip_b64": base64.b64encode(wav.read_bytes()).decode(),
            "clip_id": "live1",
            "nonce_id": nonce["nonce_id"],
        }
        try:
            out = await env.call("voice_command", args)
            break
        except ToolError as exc:
            body = json.loads(str(exc))
            if body["decision"] != "STEP_UP" or not body.get("approval_id"):
                continue  # ASR mishear -> fail-closed DENY; retry with a fresh challenge
        # Phase 3: every voice command needs out-of-band approval of the exact call.
        env.gw.backend.resolve_approval(body["approval_id"], "approve", "console")
        out = await env.call("voice_command", args)
        break
    assert out is not None and out["summary"]["liveness"] == "match"
    # the voice-derived (UNTRUSTED) handle can never reach a payment sink
    env.gw.bind_task(purpose="payment_processing", category="PAYMENT", text="pay")
    body = await env.denied("upi_pay_upi", {"payee_vpa": out["handle"], "amount_paise": 100})
    assert body["decision"] in {"DENY", "STEP_UP"}
    assert env.ledger_rows() == 0


@pytest.mark.acceptance(12)
async def test_d2_real_spoof_detector_blocks_tts_through_gateway(
    tmp_path: Path,
) -> None:
    vt = VoiceTrust(NonceService(), MlxWhisperASR(), DFArenaSpoof())
    gw, conn, ids, keys, clock, events = make_env_sync(tmp_path, voice=vt)
    try:
        async with Client(gw.mcp) as client:
            env = Env(gw, client, conn, ids, keys, clock, events)
            env.gw.bind_task(purpose="order_support", category="VOICE", text="voice request")
            nonce = env.gw.backend.issue_voice_nonce(env.gw.pipeline.session)
            wav = say_clip(nonce["phrase"], tmp_path / "v.wav")
            body = await env.denied(
                "voice_command",
                {
                    "clip_b64": base64.b64encode(wav.read_bytes()).decode(),
                    "clip_id": "live2",
                    "nonce_id": nonce["nonce_id"],
                },
            )
            assert body["decision"] == "DENY" and "VOICETRUST.SPOOF.HIGH" in body["rules"]
    finally:
        conn.close()
