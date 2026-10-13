"""Acceptance 5: ML only tightens. With every ML component off the rules alone still block every
India-suite attack."""

import pytest

from trishul.bench.india import load_dataset, run_suite


@pytest.mark.acceptance(5)
async def test_ml_off_all_india_attacks_still_blocked() -> None:
    scenarios = load_dataset()["scenarios"]
    outcomes, events = await run_suite(42, scenarios, mode="on", ml=False, spoof_on=False)
    attacks = [s for s in scenarios if s["kind"] == "attack"]
    assert len(attacks) >= 30
    executed = [s["id"] for s in attacks if outcomes[s["id"]].executed]
    assert executed == []
    harness = [i for i, o in outcomes.items() if o.detail.startswith("harness_error")]
    assert harness == []
    calls = [e for e in events if e.get("type") == "call"]
    assert calls and all(e["ml_signal"] == "disabled" for e in calls)
