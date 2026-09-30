from pathlib import Path

import numpy as np
import pytest

from tests.conftest import POLICY_DIR, make_call, make_ctx
from trishul.contracts.decisions import Decision
from trishul.contracts.labels import Level
from trishul.domains.voice_adapters import (
    REVISIONS,
    ChainASR,
    DeterministicSpoofAdapter,
    DFArenaSpoof,
    FasterWhisperASR,
    MlxWhisperASR,
    ScriptedASR,
    SpoofResult,
    UnavailableASR,
    local_snapshot,
)
from trishul.domains.voice_audio import (
    load_wav,
    quality_gate,
    synth_clip,
    vad_trim,
    write_wav,
)
from trishul.domains.voicetrust import (
    WORDS,
    NonceService,
    VoiceTrust,
    best_window_distance,
    levenshtein,
    voice_decision,
    voicetrust_facts,
)
from trishul.policy.compiler import compile_files
from trishul.policy.evaluator import evaluate

AUDIO = Path(__file__).resolve().parent.parent / "fixtures" / "audio"


class Clock:
    def __init__(self) -> None:
        self.t = 1000.0

    def __call__(self) -> float:
        return self.t


class FixedSpoof:
    def __init__(self, score: float | None) -> None:
        self._s = score

    def available(self) -> bool:
        return True

    def score(self, samples: object) -> SpoofResult:
        return SpoofResult(self._s, self._s is not None, "fixed-test-double")


def wav_bytes(tmp_path: Path, name: str = "tone_clean_3s.wav") -> bytes:
    return (AUDIO / name).read_bytes()


def make_vt(
    text: str | None, spoof: float | None = None, ran: bool = True
) -> tuple[VoiceTrust, Clock]:
    clock = Clock()
    vt = VoiceTrust(NonceService(clock), ScriptedASR(text, ran=ran), FixedSpoof(spoof))  # type: ignore[arg-type]
    return vt, clock


# ---- audio


def test_word_list_is_256_unique() -> None:
    assert len(WORDS) == 256 == len(set(WORDS))


def test_wav_rejects_other_rates_and_channels() -> None:
    load = load_wav(AUDIO / "tone_44k_stereo.wav")
    assert load.samples is None
    assert quality_gate(load).quality == "unknown"
    assert quality_gate(load_wav(b"not a wav")).quality == "unknown"


def test_quality_gate_levels() -> None:
    assert quality_gate(load_wav(AUDIO / "tone_clean_3s.wav")).quality == "ok"
    assert quality_gate(load_wav(AUDIO / "tone_noisy_3s.wav")).quality == "low"
    assert quality_gate(load_wav(AUDIO / "noise_only_3s.wav")).quality == "low"
    short = quality_gate(load_wav(AUDIO / "tone_short_0p5s.wav"))
    assert short.quality == "low"
    assert "duration" in short.reason


def test_vad_trims_silence(tmp_path: Path) -> None:
    core = synth_clip(2.0, snr_db=30, seed=5)
    pad = np.zeros(16000, dtype=np.float32)
    padded = np.concatenate([pad, core, pad])
    p = tmp_path / "p.wav"
    write_wav(p, padded)
    out = vad_trim(load_wav(p).samples)  # type: ignore[arg-type]
    assert len(out) < len(padded) * 0.8


# ---- nonce / liveness


def test_levenshtein_basics() -> None:
    assert levenshtein("kitten", "sitting") == 3
    assert best_window_distance(["a", "b"], "um a b uh") == 0.0


def test_nonce_shape_ttl_and_single_use() -> None:
    clock = Clock()
    svc = NonceService(clock)
    n = svc.issue("s1")
    assert len(n.words) == 3 and all(w in WORDS for w in n.words)
    assert svc.verify("s1", n.nonce_id, "well " + n.phrase + " thanks") == "match"
    assert svc.verify("s1", n.nonce_id, n.phrase) == "mismatch"  # reused
    n2 = svc.issue("s1")
    clock.t += 10.5
    assert svc.verify("s1", n2.nonce_id, n2.phrase) == "expired"
    n3 = svc.issue("s1")
    assert svc.verify("s2", n3.nonce_id, n3.phrase) == "mismatch"  # cross-session
    assert svc.verify("s1", n3.nonce_id, None) == "unknown"
    assert svc.verify("s1", n3.nonce_id, n3.phrase) == "match"  # not consumed by unknown


def test_liveness_tolerates_small_asr_error() -> None:
    svc = NonceService(Clock())
    n = svc.issue("s")
    noisy = n.phrase.replace(n.words[0], n.words[0][:-1])
    assert svc.verify("s", n.nonce_id, noisy) == "match"
    n = svc.issue("s")
    assert svc.verify("s", n.nonce_id, "completely different words here") == "mismatch"


# ---- pipeline decisions


def test_happy_path_allows_and_labels_transcript() -> None:
    vt, _ = make_vt(None)
    n = vt.nonces.issue("s")
    vt.asr = ScriptedASR(n.phrase)
    a = vt.assess("s", "clip1", wav_bytes(Path()), n.nonce_id)
    assert a.decision == Decision.ALLOW and a.rule_ids == ()
    assert a.transcript is not None
    label = a.transcript.label
    assert label.level == Level.UNTRUSTED
    assert {(s.kind, s.id) for s in label.sources} == {("voice", "clip1")}


def test_replayed_nonce_denied() -> None:
    vt, _ = make_vt(None)
    n = vt.nonces.issue("s")
    vt.asr = ScriptedASR(n.phrase)
    assert vt.assess("s", "c1", wav_bytes(Path()), n.nonce_id).decision == Decision.ALLOW
    replay = vt.assess("s", "c2", wav_bytes(Path()), n.nonce_id)
    assert replay.decision == Decision.DENY
    assert "VOICETRUST.LIVENESS.MISMATCH" in replay.rule_ids


def test_expired_nonce_denied() -> None:
    vt, clock = make_vt(None)
    n = vt.nonces.issue("s")
    vt.asr = ScriptedASR(n.phrase)
    clock.t += 11
    a = vt.assess("s", "c", wav_bytes(Path()), n.nonce_id)
    assert a.decision == Decision.DENY and "VOICETRUST.LIVENESS.EXPIRED" in a.rule_ids


def test_low_snr_step_up() -> None:
    vt, _ = make_vt(None)
    n = vt.nonces.issue("s")
    vt.asr = ScriptedASR(n.phrase)
    a = vt.assess("s", "c", wav_bytes(Path(), "tone_noisy_3s.wav"), n.nonce_id)
    assert a.decision == Decision.STEP_UP and "VOICETRUST.QUALITY.INSUFFICIENT" in a.rule_ids


def test_unavailable_asr_step_up_and_honest() -> None:
    vt, _ = make_vt(None)
    vt.asr = UnavailableASR()
    n = vt.nonces.issue("s")
    a = vt.assess("s", "c", wav_bytes(Path()), n.nonce_id)
    assert a.decision == Decision.STEP_UP
    assert a.asr.ran is False and a.asr.text is None and a.transcript is None
    assert {"VOICETRUST.ASR.NOT_RUN", "VOICETRUST.LIVENESS.UNKNOWN"} <= set(a.rule_ids)


def test_unsupported_audio_is_unknown_quality_step_up() -> None:
    vt, _ = make_vt("x")
    n = vt.nonces.issue("s")
    a = vt.assess("s", "c", AUDIO / "tone_44k_stereo.wav", n.nonce_id)
    assert a.quality.quality == "unknown" and a.decision >= Decision.STEP_UP
    assert a.asr.ran is False


def test_spoof_thresholds_and_high_sink() -> None:
    for score, expected in [(0.1, Decision.ALLOW), (0.3, Decision.STEP_UP), (0.9, Decision.DENY)]:
        vt, _ = make_vt(None, spoof=score)
        n = vt.nonces.issue("s")
        vt.asr = ScriptedASR(n.phrase)
        assert vt.assess("s", "c", wav_bytes(Path()), n.nonce_id).decision == expected
    vt, _ = make_vt(None)
    n = vt.nonces.issue("s")
    vt.asr = ScriptedASR(n.phrase)
    a = vt.assess("s", "c", wav_bytes(Path()), n.nonce_id, sink_risk="high")
    assert a.decision == Decision.STEP_UP and a.rule_ids == ("VOICETRUST.SINK.HIGH_RISK",)


def test_table_rows() -> None:
    assert voice_decision("ok", "match", True, None, "low") == (Decision.ALLOW, ())
    assert voice_decision("ok", "match", True, 0.5, "low")[0] == Decision.DENY
    assert voice_decision("ok", "match", True, 0.2, "low")[0] == Decision.STEP_UP


# ---- adapters honesty


def test_adapters_report_not_ran_when_absent(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("HF_HUB_CACHE", str(tmp_path))  # empty cache: nothing is "local"
    samples = synth_clip(1.5, seed=9)
    assert local_snapshot("mlx-community/whisper-small-mlx") is None
    for asr in (MlxWhisperASR(), FasterWhisperASR(), ChainASR()):
        assert asr.available() is False
        r = asr.transcribe(samples)
        assert r.ran is False and r.text is None and r.latency_ms is None
    df = DFArenaSpoof()
    assert df.available() is False and df.choose_size() is None
    s = df.score(samples)
    assert s.ran is False and s.score is None
    d = DeterministicSpoofAdapter().score(samples)
    assert (d.score, d.ran, d.label) == (None, False, "deterministic-adapter")


def test_df_arena_size_selection(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    for repo in DFArenaSpoof.REPOS.values():
        rev = REVISIONS[repo]
        snap = tmp_path / ("models--" + repo.replace("/", "--")) / "snapshots" / rev
        snap.mkdir(parents=True)
        (snap / "config.json").write_text("{}")
    monkeypatch.setenv("HF_HUB_CACHE", str(tmp_path))
    df = DFArenaSpoof()
    assert df.choose_size() == "1B"
    df._latencies["1B"] = [2500.0, 3000.0, 2100.0]
    assert df.choose_size() == "500M"


# ---- policy integration


def test_policy_consumes_facts() -> None:
    policy = compile_files([POLICY_DIR / "voicetrust.yaml"])
    args = {"transcript": "pay", "clip_id": "c", "nonce_id": "n"}
    cases = [
        (("ok", "match", True, None, "low"), Decision.ALLOW),
        (("ok", "mismatch", True, None, "low"), Decision.DENY),
        (("ok", "expired", True, None, "low"), Decision.DENY),
        (("low", "match", True, None, "low"), Decision.STEP_UP),
        (("ok", "match", False, None, "low"), Decision.STEP_UP),
        (("ok", "match", True, 0.3, "low"), Decision.STEP_UP),
        (("ok", "match", True, 0.7, "low"), Decision.DENY),
        (("ok", "match", True, None, "high"), Decision.STEP_UP),
        (("ok", "unknown", False, None, "low"), Decision.STEP_UP),
    ]
    for inputs, expected in cases:
        facts = voicetrust_facts(*inputs)  # type: ignore[arg-type]
        ctx = make_ctx(facts=facts)
        verdict = evaluate(policy, make_call("voice_command", args), ctx)
        assert verdict.decision == expected, inputs
        assert verdict.decision == voice_decision(*inputs)[0]  # type: ignore[arg-type]
        assert {r.rule_id for r in verdict.reasons} == set(voice_decision(*inputs)[1])
