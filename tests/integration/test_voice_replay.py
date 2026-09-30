"""Voice replay / nonce-binding hardening (review D2, D3, D4)."""

import asyncio
import contextlib
from pathlib import Path
from typing import Any

from tests.integration.test_scenarios import FixedSpoof, PhraseASR, clip, voice_args, voice_env
from trishul.domains.voicetrust import NonceService
from trishul.gateway.pipeline import Pipeline

MISMATCH = "VOICETRUST.LIVENESS.MISMATCH"


async def _approved_args(tmp_path: Path) -> tuple[Any, PhraseASR, Any, dict[str, Any]]:
    env, asr, client = await voice_env(tmp_path, spoof=FixedSpoof(0.01), category="PAYMENT")
    args = voice_args(env, asr)
    body = await env.denied("voice_command", args)
    assert body["decision"] == "STEP_UP" and body["approval_id"]
    env.gw.backend.resolve_approval(body["approval_id"], "approve", "console")
    return env, asr, client, args


def _approvals(env: Any) -> int:
    return int(env.conn.execute("SELECT COUNT(*) FROM approvals").fetchone()[0])


async def test_a_concurrent_approved_retries_exactly_one_allow(tmp_path: Path) -> None:
    env, _asr, client, args = await _approved_args(tmp_path)
    try:

        async def attempt() -> str:
            try:
                await env.call("voice_command", args)
                return "ALLOW"
            except Exception:
                return "DENY"

        results = await asyncio.gather(*(attempt() for _ in range(5)))
        assert results.count("ALLOW") == 1
    finally:
        await client.__aexit__(None, None, None)


async def test_b_replay_after_consume_denied_mismatch_no_approval(tmp_path: Path) -> None:
    env, _asr, client, args = await _approved_args(tmp_path)
    try:
        assert "handle" in await env.call("voice_command", args)
        before = _approvals(env)
        body = await env.denied("voice_command", args)
        assert body["decision"] == "DENY" and MISMATCH in body["rules"]
        assert not body.get("approval_id") and _approvals(env) == before
    finally:
        await client.__aexit__(None, None, None)


async def test_c_other_clip_or_clip_id_same_nonce_denied(tmp_path: Path) -> None:
    for change in ({"clip_b64": clip("tone_noisy_3s.wav")}, {"clip_id": "clip_other"}):
        sub = tmp_path / ("a" if "clip_b64" in change else "b")
        sub.mkdir()
        env, _asr, client, args = await _approved_args(sub)
        try:
            assert "handle" in await env.call("voice_command", args)
            before = _approvals(env)
            body = await env.denied("voice_command", {**args, **change})
            assert body["decision"] == "DENY" and MISMATCH in body["rules"]
            assert _approvals(env) == before
        finally:
            await client.__aexit__(None, None, None)


async def test_d_replay_while_approval_pending_denied(tmp_path: Path) -> None:
    env, asr, client = await voice_env(tmp_path, spoof=FixedSpoof(0.01), category="PAYMENT")
    try:
        args = voice_args(env, asr)
        first = await env.denied("voice_command", args)
        assert first["decision"] == "STEP_UP" and first["approval_id"]  # pending, unapproved
        before = _approvals(env)
        body = await env.denied("voice_command", args)
        assert body["decision"] == "DENY" and MISMATCH in body["rules"]
        assert _approvals(env) == before
    finally:
        await client.__aexit__(None, None, None)


async def test_e_guards_failure_on_replay_mints_no_approval(tmp_path: Path) -> None:
    env, _asr, client, args = await _approved_args(tmp_path)
    try:
        assert "handle" in await env.call("voice_command", args)
        before = _approvals(env)

        def boom(*a: Any, **kw: Any) -> Any:  # guards die right after the rebuild
            raise RuntimeError("approvals down")

        env.gw.pipeline.approvals.check = boom  # type: ignore[method-assign]
        body = await env.denied("voice_command", args)
        assert body["decision"] in {"DENY", "STEP_UP"} and not body.get("approval_id")
        assert _approvals(env) == before
    finally:
        await client.__aexit__(None, None, None)


def test_d3_nonce_resume_requires_same_call_digest() -> None:
    svc = NonceService()
    n = svc.issue("s")
    assert svc.verify("s", n.nonce_id, n.phrase) == "match"
    assert not svc.was_matched("s", n.nonce_id, "dig")  # not yet bound to any call
    svc.bind_call("s", n.nonce_id, "dig")
    assert svc.was_matched("s", n.nonce_id, "dig")
    assert not svc.was_matched("s", n.nonce_id, "other")
    svc.bind_call("s", n.nonce_id, "other")  # first binding wins
    assert not svc.was_matched("s", n.nonce_id, "other")


async def test_d4_cancel_during_lock_reacquire_keeps_lock_consistent(tmp_path: Path) -> None:
    env, asr, client = await voice_env(tmp_path)
    try:
        pipe: Pipeline = env.gw.pipeline
        lock = pipe._lock
        args = voice_args(env, asr)
        holder = asyncio.Event()

        async def hold() -> None:
            await lock.acquire()
            holder.set()
            await asyncio.sleep(0.3)
            lock.release()

        orig = asr.transcribe

        def slow(samples: Any) -> Any:
            # while the worker runs, another task takes the lock so reacquire has to wait
            asyncio.run_coroutine_threadsafe(hold(), loop).result()
            return orig(samples)

        loop = asyncio.get_running_loop()
        asr.transcribe = slow  # type: ignore[method-assign]
        task = asyncio.ensure_future(
            env.client.call_tool("voice_command", args, raise_on_error=False)
        )
        await asyncio.sleep(0.1)
        task.cancel()
        with contextlib.suppress(BaseException):
            await task
        await asyncio.sleep(0.5)
        assert not lock.locked()  # nobody released a lock they did not hold, none leaked
    finally:
        await client.__aexit__(None, None, None)
