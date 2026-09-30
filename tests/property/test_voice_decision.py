from hypothesis import given
from hypothesis import strategies as st

from trishul.contracts.decisions import Decision
from trishul.domains.voicetrust import voice_decision, voicetrust_facts

quality = st.sampled_from(["ok", "low", "unknown"])
liveness = st.sampled_from(["match", "mismatch", "expired", "unknown"])
spoof = st.none() | st.floats(allow_nan=True, allow_infinity=True)
sink = st.sampled_from(["low", "high"])
args = st.tuples(quality, liveness, st.booleans(), spoof, sink)


@given(args)
def test_total_and_deterministic(a: tuple) -> None:  # type: ignore[type-arg]
    d, rules = voice_decision(*a)
    assert isinstance(d, Decision) and d == voice_decision(*a)[0]
    assert (d == Decision.ALLOW) == (rules == ())
    facts = voicetrust_facts(*a)
    assert all(isinstance(v, bool) for v in facts.values())


@given(quality | st.text(), liveness | st.text(), st.booleans(), spoof, sink | st.text())
def test_garbage_inputs_never_crash_and_never_allow(q, lv, ran, sp, sk) -> None:  # type: ignore[no-untyped-def]
    d, _ = voice_decision(q, lv, ran, sp, sk)
    if q not in ("ok",) or lv != "match" or sk != "low":
        assert d != Decision.ALLOW


@given(args, st.floats(allow_nan=True, allow_infinity=True))
def test_spoof_only_escalates(a: tuple, s: float) -> None:  # type: ignore[type-arg]
    q, lv, ran, _, sk = a
    assert voice_decision(q, lv, ran, s, sk)[0] >= voice_decision(q, lv, ran, None, sk)[0]


@given(args)
def test_high_sink_never_allow(a: tuple) -> None:  # type: ignore[type-arg]
    q, lv, ran, sp, _ = a
    assert voice_decision(q, lv, ran, sp, "high")[0] >= Decision.STEP_UP


@given(args, st.sampled_from(["mismatch", "expired"]))
def test_mismatch_expired_always_deny(a: tuple, lv: str) -> None:  # type: ignore[type-arg]
    q, _, ran, sp, sk = a
    assert voice_decision(q, lv, ran, sp, sk)[0] == Decision.DENY


@given(args)
def test_bad_quality_or_asr_or_unknown_liveness_never_allow(a: tuple) -> None:  # type: ignore[type-arg]
    q, lv, ran, sp, sk = a
    if q != "ok" or not ran or lv == "unknown":
        assert voice_decision(q, lv, ran, sp, sk)[0] >= Decision.STEP_UP


@given(args, st.sampled_from(["ok", "low", "unknown"]))
def test_worse_inputs_never_lower(a: tuple, q2: str) -> None:  # type: ignore[type-arg]
    q, lv, ran, sp, sk = a
    base = voice_decision(q, lv, ran, sp, sk)[0]
    # flipping to high sink / asr not ran / non-ok quality can only escalate
    assert voice_decision(q, lv, ran, sp, "high")[0] >= base
    assert voice_decision(q, lv, False, sp, sk)[0] >= base
    if q == "ok":
        assert voice_decision(q2, lv, ran, sp, sk)[0] >= base
