# SPDX-License-Identifier: Apache-2.0
"""Acceptance registry: canonical criterion number -> pytest node ids that prove it.

Numbering is the Phase 4 canonical list (docs/phase-4-plan.md section 7). Every test listed here
carries ``@pytest.mark.acceptance(n)``. A criterion is PASS only when every listed node id is
present and passes; a missing node id or a skipped test is reported NOT RUN, never PASS.

Node ids that belong to tests from parallel Phase 4 workers (W1 bypass, W2 approver auth, W3
classifier) may not exist on every branch; they are listed as expected and reported NOT RUN until
they land.
"""

import re
import subprocess
import sys
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

_SC = "tests/integration/test_scenarios.py"
_P3 = "tests/integration/test_phase3_demo.py"
_VR = "tests/integration/test_voice_real.py"
_VP = "tests/integration/test_voice_replay.py"
_RG = "tests/integration/test_reader_gateway.py"


@dataclass(frozen=True)
class Criterion:
    key: str
    title: str
    nodes: tuple[str, ...]
    supplementary: bool = False


CRITERIA: tuple[Criterion, ...] = (
    Criterion(
        "1",
        "Gateway-only: no tool reachable except through the gateway",
        ("tests/integration/test_gateway_bypass.py",),  # W1
    ),
    Criterion(
        "2",
        "Labels persist through the reader and variable handles",
        (
            "tests/unit/test_reader.py::test_llm_extracted_values_keep_untrusted_label_and_source",
            "tests/unit/test_reader.py::test_replay_extracted_values_keep_untrusted_label_and_are_labelled",
            "tests/unit/test_reader.py::test_var_handles_inherit_source_label_and_record_reader",
            f"{_RG}::test_reader_values_keep_untrusted_label_and_hijacked_payee_is_denied",
        ),
    ),
    Criterion(
        "3",
        "Untrusted data reaching a sink is DENY, with lineage",
        (f"{_SC}::test_1_injected_invoice_denied_with_lineage",),
    ),
    Criterion(
        "4",
        "Fail closed: a fault in any stage never allows or executes",
        (
            "tests/property/test_failclosed.py::test_fault_in_any_stage_never_allows_or_executes",
            "tests/property/test_failclosed.py::test_stage_timeout_fails_closed",
            "tests/integration/test_gateway.py::test_audit_failure_denies_and_never_executes",
        ),
    ),
    Criterion(
        "5",
        "ML only tightens: with ML off the top attacks still DENY",
        (
            f"{_P3}::test_at12_ml_off_top_attacks_still_denied",
            f"{_SC}::test_ml_anomaly_step_up_and_toggle_persisted",
            "tests/integration/test_ml_off_suite.py",  # W3
            "tests/integration/test_injection_gateway.py",  # W3
        ),
    ),
    Criterion(
        "6",
        "Tampered mandate signature is denied",
        (f"{_SC}::test_9_tampered_mandate_signature_denied",),
    ),
    Criterion(
        "7",
        "Over-limit payment is STEP_UP, approved retry only",
        (f"{_SC}::test_3_over_cap_step_up_approve_exact_retry",),
    ),
    Criterion(
        "8",
        "Approval binding: changed arguments after approval are denied",
        (
            f"{_SC}::test_4_amount_changed_after_approval_denied_on_binding",
            "tests/unit/test_approvals.py::test_argument_swap_is_binding_mismatch",
            "tests/integration/test_approver_auth.py",  # W2
            "tests/unit/test_auth.py",  # W2
        ),
    ),
    Criterion(
        "9",
        "Purpose mismatch is denied; agent-supplied purpose is ignored",
        (
            "tests/unit/test_purposelock.py::test_disallowed_purpose",
            "tests/unit/test_purposelock.py::test_agent_supplied_purpose_is_ignored",
            f"{_SC}::test_agent_purpose_argument_is_ignored_and_audited",
        ),
    ),
    Criterion(
        "10",
        "Consent withdrawal is denied immediately",
        (f"{_SC}::test_6_withdrawn_consent_denied_immediately",),
    ),
    Criterion(
        "11",
        "External PII email is denied",
        (f"{_SC}::test_5_crm_pii_to_disallowed_email_sink_denied",),
    ),
    Criterion(
        "12",
        "Cloned (TTS) voice is detected by the real spoof model and blocked",
        (
            f"{_VR}::test_c_spoof_adapter_ran_with_numeric_score_and_flags_tts",
            f"{_VR}::test_d2_real_spoof_detector_blocks_tts_through_gateway",
        ),
    ),
    Criterion(
        "13",
        "Real high-value voice command is STEP_UP, never ALLOW",
        (
            f"{_VR}::test_d_live_voice_never_allows_high_risk_sink",
            f"{_SC}::test_voice_payment_always_needs_out_of_band_approval",
        ),
    ),
    Criterion(
        "14",
        "Replayed voice nonce is denied",
        (
            f"{_SC}::test_7_replayed_voice_nonce_denied",
            f"{_VP}::test_b_replay_after_consume_denied_mismatch_no_approval",
            f"{_VP}::test_c_other_clip_or_clip_id_same_nonce_denied",
        ),
    ),
    Criterion(
        "15",
        "Z3: live policy UNSAT on violations; unsafe fixture SAT with counterexample",
        (
            "tests/unit/test_z3_policy.py::test_real_policies_proofs",
            "tests/unit/test_z3_policy.py::test_unsafe_fixture_gives_pay_upi_counterexample",
            "tests/unit/test_prove_api.py::test_at13_unsafe_fixture_sat_with_counterexample_and_live_untouched",
        ),
    ),
    Criterion(
        "16",
        "Merkle audit tamper reports the exact bad index; proofs verify",
        (
            f"{_SC}::test_10_tampered_audit_payload_reports_exact_index",
            "tests/unit/test_audit.py::test_leaf_tamper_reports_exact_index_and_covering_sths",
            f"{_P3}::test_at15_cli_tamper_reports_exact_bad_index_and_proofs_verify",
        ),
    ),
    Criterion(
        "17",
        "Benchmark numbers are real output: schema-valid results, no metric literals in the UI",
        (
            "tests/unit/test_bench_schema.py::test_results_validate_against_schema",
            "tests/unit/test_bench_schema.py::test_ui_has_no_hardcoded_metric_literals",
        ),
    ),
    # Supplementary (formerly Phase-3 AT-11, AT-14, AT-17).
    Criterion(
        "S-OFF",
        "OFF executes only in demo_off, visible in events and audit (was Phase-3 AT-11)",
        (
            f"{_P3}::test_at11_off_mode_executes_only_in_demo_off_and_is_audited",
            f"{_P3}::test_at11_off_audit_failure_refuses_the_call",
        ),
        True,
    ),
    Criterion(
        "S-RT",
        "Red-team rate limit, kill switch, moderation, XSS as text (was Phase-3 AT-14)",
        (
            "tests/unit/test_redteam.py::test_rate_limit_per_ip_then_refill",
            "tests/unit/test_redteam.py::test_global_rate_limit_across_clients",
            "tests/unit/test_redteam.py::test_kill_switch_via_rest_and_cli",
            "tests/unit/test_redteam.py::test_moderated_text_is_withheld_but_still_evaluated",
            "tests/unit/test_redteam.py::test_xss_payload_is_delivered_verbatim_as_data_never_interpreted",
            "tests/unit/test_ui_safety.py::test_console_and_landing_have_no_html_injection_sinks",
        ),
        True,
    ),
    Criterion(
        "S-WS",
        "WS reconnect/resume; CLI ml off pushed live (was Phase-3 AT-17)",
        (
            "tests/unit/test_ws_api.py::test_at17_ws_reconnect_resumes_after_last_seq",
            "tests/unit/test_ws_api.py::test_at17_cli_ml_off_is_pushed_live_via_control_table",
            "tests/unit/test_ws_api.py::test_at17_control_poller_task_publishes_within_interval",
        ),
        True,
    ),
)


def label(key: str) -> str:
    return f"AT-{int(key):02d}" if key.isdigit() else key


# --- runner ------------------------------------------------------------------------------------

PASS = "PASS"
FAIL = "FAIL"
NOT_RUN = "NOT RUN"

_RESULT_RE = re.compile(
    r"^(?P<node>\S+::\S+?)\s+(?P<out>PASSED|FAILED|SKIPPED|ERROR|XFAIL|XPASS)\b(?P<rest>.*)$"
)
_SKIP_REASON_RE = re.compile(r"\((?P<why>.*?)\)?\s*(\[\s*\d+%\])?\s*$")


@dataclass
class Outcome:
    key: str
    title: str
    status: str
    reason: str = ""
    supplementary: bool = False
    nodes: dict[str, str] = field(default_factory=dict)

    @property
    def text(self) -> str:
        return f"{self.status}({self.reason})" if self.reason else self.status


def _pytest(root: Path, *args: str) -> str:
    proc = subprocess.run(  # noqa: S603 - fixed argv, no shell
        [sys.executable, "-m", "pytest", "-p", "no:cacheprovider", *args],
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
    )
    return proc.stdout + proc.stderr


def collect_ids(root: Path) -> set[str]:
    out = _pytest(root, "--collect-only", "-q", "tests")
    return {ln.strip() for ln in out.splitlines() if "::" in ln and not ln.startswith(" ")}


def is_present(node: str, collected: set[str]) -> bool:
    """A function id matches itself or its parametrised variants; a file id, any test in it."""
    if "::" not in node:
        return any(c.startswith(node + "::") for c in collected)
    return node in collected or any(c.startswith(node + "[") for c in collected)


def parse_results(output: str) -> dict[str, str]:
    """node id -> ``PASSED`` / ``FAILED`` / ``SKIPPED: reason`` from ``pytest -v`` output."""
    results: dict[str, str] = {}
    for line in output.splitlines():
        m = _RESULT_RE.match(line.strip())
        if not m:
            continue
        out = m["out"]
        if out == "SKIPPED":
            why = _SKIP_REASON_RE.search(m["rest"].strip())
            out = f"SKIPPED: {why['why'].strip() if why and why['why'] else 'skipped'}"
        results[m["node"]] = out
    return results


def evaluate(
    crit: Criterion,
    collected: set[str],
    run: Callable[[list[str]], dict[str, str]],
) -> Outcome:
    present = [n for n in crit.nodes if is_present(n, collected)]
    missing = [n for n in crit.nodes if n not in present]
    results = run(present) if present else {}
    outcome = Outcome(crit.key, crit.title, NOT_RUN, supplementary=crit.supplementary)
    for n in missing:
        outcome.nodes[n] = "MISSING"
    outcome.nodes.update(results)
    failed = [n for n, r in results.items() if r in ("FAILED", "ERROR")]
    skipped = {n: r for n, r in results.items() if r.startswith("SKIPPED")}
    passed = [n for n, r in results.items() if r in ("PASSED", "XPASS")]
    if failed:
        outcome.status, outcome.reason = FAIL, "failed: " + ", ".join(failed)
    elif missing:
        outcome.reason = "test not present: " + ", ".join(missing)
    elif skipped:
        first = next(iter(skipped.values()))[len("SKIPPED: ") :]
        outcome.reason = f"skipped: {first}"
    elif present and len(passed) >= len(present):
        outcome.status = PASS
    else:
        outcome.status, outcome.reason = FAIL, "no result reported for every test"
    return outcome


def run_all(root: Path, only: list[str] | None = None) -> list[Outcome]:
    collected = collect_ids(root)

    def run(nodes: list[str]) -> dict[str, str]:
        return parse_results(_pytest(root, "-v", "--tb=no", "-rs", "-o", "addopts=", *nodes))

    return [
        evaluate(c, collected, run)
        for c in CRITERIA
        if only is None or c.key in only or label(c.key) in only
    ]


def render_table(outcomes: list[Outcome]) -> str:
    return "\n".join(f"{label(o.key):<6} {o.text}  -- {o.title}" for o in outcomes)


def render_evidence(outcomes: list[Outcome]) -> str:
    lines = [
        "# Acceptance evidence",
        "",
        f"Generated by `trishul acceptance` on {datetime.now(UTC):%Y-%m-%d %H:%M UTC}.",
        "Numbering: `docs/phase-4-plan.md` section 7. A criterion is PASS only when every listed",
        "test exists, ran and passed. A missing test or a skipped test is NOT RUN, never PASS.",
        "",
        "| ID | Criterion | Result |",
        "|---|---|---|",
    ]
    for o in outcomes:
        lines.append(f"| {label(o.key)} | {o.title} | {o.text.replace('|', '/')} |")
    lines += ["", "## Tests behind each result", ""]
    for o in outcomes:
        lines.append(f"### {label(o.key)} - {o.title}")
        lines.append("")
        for node, res in o.nodes.items():
            lines.append(f"- `{node}`: {res}")
        lines.append("")
    return "\n".join(lines)
