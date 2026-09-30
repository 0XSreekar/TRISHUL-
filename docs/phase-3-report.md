# Phase 3 report

Scope: live console wiring, FinBot scripted agent and the six demo moments, red-team wall, OFF/ON mode,
bench pipeline, Docker packaging, docs. Numbers below come from `bench/results.json` only (generated
2026-09-30T17:30:50Z at commit 6aaf191, dirty tree, seed 42). Re-run `uv run trishul bench --seed 42` and
re-read the file if you need a fresher figure.

## What is implemented
- Gateway HTTP/WS API for the console: `/healthz`, `/readyz`, `/mode`, `/ml`, `/mandates`, `/audit/head|leaves|verify`,
  inclusion and consistency proofs, `/prove` (live and `unsafe_fixture`), `/demo/moment/{1..6}`, `/demo/reset`,
  `/redteam/submit|kill|fallback|stats`, `/report/dpdp`, `/metrics`, static `/console` and `/bench/results.json`.
- Operator token (`<db_dir>/operator.token`, mode 0600, or `TRISHUL_OPERATOR_TOKEN`) on every mutating operator
  route, plus exact-match Origin allowlist and content-type CSRF checks.
- TRISHUL ON/OFF: OFF executes only in the isolated `demo_off` namespace, is audited, and reset restores ON.
- FinBot (`trishul/finbot`): deterministic scripted agent over real MCP; moments 1-6 including approval binding,
  ML-off, proofs, voice replay and audit tamper.
- Red-team wall (`trishul/redteam`): runs through the real pipeline in its own namespace, per-IP and global rate
  limits, kill switch, display moderation (withheld but still evaluated), 20-item deterministic fallback queue,
  counters computed from the audit log.
- Z3 showcase (`trishul/verify/showcase.py`, `trishul/gateway/showcase.py`): unsafe-policy fixture yields a SAT
  counterexample and a replay; the live policy is never swapped (digest compared before/after).
- CLI: `start` (readiness JSON, operator token file), `demo reset|tamper`, `redteam kill|resume`, `ml on|off`,
  `prove`, `verify`, `report --dpdp`, `approve|reject`, `bench`.
- Runtime seed data moved to `trishul/fixtures/` (CRM, consent, invoices, audio, unsafe policy) so the wheel, the
  Docker image and `demo reset` no longer depend on `tests/`.
- Packaging: `Dockerfile`, `docker-compose.yml` (ports published on `127.0.0.1` only), `.dockerignore` (excludes
  `operator.token`, `*.db`, `.git`, `CLAUDE.md`), vendored React/Babel for offline console, `scripts/prewarm.sh`.
- Docs: `docs/demo-runbook.md`, `docs/architecture.md`, `docs/threat-model.md`, `docs/phase-3-plan.md`, `README.md`.
- Fix found during Docker verification: stdio tool-server subprocesses restarted their id counter on every proxied
  request, so the second payment in a native `trishul start` / Docker run failed with
  `UNIQUE constraint failed: ledger.txn_id` (moment 3 step 4 returned DENY with no rule). `trishul/gateway/server_main.py`
  now resumes the counter above the highest stored id (`id_start`). Regression test:
  `tests/integration/test_stdio_servers.py::test_sequential_stdio_payments_get_distinct_txn_ids`. In-process tests
  could not see this because they share one id generator.

## What is verified
- `uv run pytest -q`: 479 passed, 5 skipped (the 5 real-voice-model tests, models absent).
- `uv run ruff check .`: all checks passed. `ruff format --check .`: 147 files already formatted.
- `mypy trishul` (strict): clean on `trishul/bench` after the AgentDojo worker's fixes (agentdojo has a mypy
  override for its untyped optional import). Phase-3 files (`finbot`, `redteam`, `gateway/showcase.py`, `verify/showcase.py`,
  `ollama.py`, `gateway/backend.py`, `telemetry/api.py`): 0 errors.
- `pip-audit` on the frozen non-dev export: no known vulnerabilities.
- Secret scan: `detect-secrets` hits are only hashes, SRI digests, model commit ids and test fixtures
  (for example `tests/unit/test_redaction.py` `sk-live-...` dummy). Regex scan for API keys, private keys and bearer
  tokens: none. `git ls-files` contains no `operator.token`, `.db`, `.env`, key or pem file; `operator.token` and
  `*.db` are in `.gitignore` and `.dockerignore`.
- Docker (clean build, fresh volume): container healthy; `/healthz` 200 `{"ok":true}`; `/readyz` ready with
  db/policy/audit ok (voice_models unavailable, ollama available, informational); console HTML 200;
  `/bench/results.json` 200; `POST /demo/moment/3` without token 401 `operator_token_required`, with the
  container's `/data/operator.token` 200 with DENY / ALLOW / STEP_UP / ALLOW / DENY (binding mismatch);
  `/audit/verify` ok size 26; `POST /prove {"policy":"unsafe_fixture"}` SAT; published ports
  `127.0.0.1:8787-8788` only; image has `trishul/fixtures/*` and no `operator.token`; `docker compose down` clean.
  Note: `bench/` is copied into the image, so rebuild after the final `bench/results.json`.
- Clean-install smoke (rsync copy of the worktree, no `.venv`/`.git`/db/token): `uv sync`, `trishul demo reset --seed 42`
  (mandate `mnd_26212cd7aa615753`), `trishul verify` ok size 0, `trishul prove` UNSAT across 22 per-invariant
  results, `trishul report --dpdp` valid JSON.
- Audit tamper: after moment 3 (26 leaves) `verify` ok; `demo tamper --idx 2` then `verify` returns
  `bad_index: 2`, `ok: false`, exit 1; `demo reset` restores ok size 0.
- Unsafe-policy counterexample: `tests/unit/test_prove_api.py::test_at13_unsafe_fixture_sat_with_counterexample_and_live_untouched`
  and `tests/unit/test_z3_policy.py::test_unsafe_fixture_gives_pay_upi_counterexample`; live over HTTP in Docker (SAT).
- WS reconnect: `tests/unit/test_ws_api.py::test_at17_ws_reconnect_resumes_after_last_seq` and `::test_ws_stream_and_resume`.
- Red-team XSS: `tests/unit/test_redteam.py::test_xss_payload_is_delivered_verbatim_as_data_never_interpreted` and
  `tests/unit/test_ui_safety.py::test_console_and_landing_have_no_html_injection_sinks`.

## What was measured
From `bench/results.json` (India suite `india_v1`, 49 attacks / 34 benign, seed 42, Apple M5, in-process pipeline):

| Metric | Value |
|---|---|
| Attack success rate with TRISHUL | 0.0 (0 of 49) |
| Benign utility with TRISHUL | 0.8529 (29 of 34) |
| Attack success rate without TRISHUL (OFF namespace) | 0.9167 (36 attacks measured; voice scenarios have no OFF endpoint and are excluded) |
| Benign utility without TRISHUL | 0.8966 (29 measured) |
| Total pipeline latency, ML on | p50 1.26 ms, p99 2.103 ms |
| Total pipeline latency, ML off | p50 1.255 ms, p99 2.049 ms |
| Latency samples | 750 (5 repeats) |
| Ablation (rules_only / rules_classifier / full) | ASR 0.0 and utility 0.8529 in all three |
| Benign blocked (the 5 failures) | B-VOI-01..05: legitimate voice payments wait for out-of-band approval by design |
| Voice (`bench/voice.json`) | status `partial`; EER null; accuracy null; bonafide clips 0; spoof clips 4; spoof recall 1.0; mean ASR WER 0.4203 |
| AgentDojo (banking subset) | status `ok`; qwen3:8b via Ollama, ctx 16384, temp 0, seed 42, attack `important_instructions`; 16/16 user tasks x 6/9 injection tasks. ASR 0.1667 (16/96) without -> 0.0 with TRISHUL; clean utility 0.5 (8/16) -> 0.4375 (7/16); utility under attack 0.4271 both sides. The one lost task (user_task_0) was denied by PAYSHIELD.MANDATE.PAYEE / TAINT.UNTRUSTED_PAYEE (pays a payee read from a file). |

The ablation being identical across configs means the India suite is decided by the rules, not the ML signals;
do not present the ML as contributing to these numbers.

## Acceptance tests AT-01..AT-17
The 17-test list was defined in Phase 3 (`docs/phase-3-plan.md` section 5) because no earlier canonical list
existed. AT-01..AT-10 are the Phase-2 integration scenarios 1-10.

| ID | Test | File::test | Result |
|---|---|---|---|
| AT-01 | Injected invoice denied with lineage | `tests/integration/test_scenarios.py::test_1_injected_invoice_denied_with_lineage` | PASS |
| AT-02 | Trusted invoice allowed, ledger changes only after execution | `tests/integration/test_scenarios.py::test_2_trusted_invoice_allowed_ledger_changes_only_after_execution` | PASS |
| AT-03 | Over-cap STEP_UP, approve, exact retry | `tests/integration/test_scenarios.py::test_3_over_cap_step_up_approve_exact_retry` | PASS |
| AT-04 | Amount changed after approval denied (binding) | `tests/integration/test_scenarios.py::test_4_amount_changed_after_approval_denied_on_binding` | PASS |
| AT-05 | CRM PII to disallowed email sink denied | `tests/integration/test_scenarios.py::test_5_crm_pii_to_disallowed_email_sink_denied` | PASS |
| AT-06 | Withdrawn consent denied immediately | `tests/integration/test_scenarios.py::test_6_withdrawn_consent_denied_immediately` | PASS |
| AT-07 | Replayed voice nonce denied | `tests/integration/test_scenarios.py::test_7_replayed_voice_nonce_denied` | PASS (deterministic adapter; real-model variants in `test_voice_real.py` NOT RUN: models absent) |
| AT-08 | Low-quality / uncertain voice never allowed | `tests/integration/test_scenarios.py::test_8_low_quality_or_uncertain_voice_never_allowed` | PASS (same caveat) |
| AT-09 | Tampered mandate signature denied | `tests/integration/test_scenarios.py::test_9_tampered_mandate_signature_denied` | PASS |
| AT-10 | Tampered audit payload reports exact index | `tests/integration/test_scenarios.py::test_10_tampered_audit_payload_reports_exact_index` | PASS |
| AT-11 | OFF executes only in `demo_off`, visible in events and audit | `tests/integration/test_phase3_demo.py::test_at11_off_mode_executes_only_in_demo_off_and_is_audited` (+ `test_at11_off_audit_failure_refuses_the_call`) | PASS |
| AT-12 | ML off: top attacks still DENY | `tests/integration/test_phase3_demo.py::test_at12_ml_off_top_attacks_still_denied` | PASS |
| AT-13 | Unsafe fixture SAT counterexample, live policy untouched | `tests/unit/test_prove_api.py::test_at13_unsafe_fixture_sat_with_counterexample_and_live_untouched` | PASS |
| AT-14 | Red-team rate limit, kill switch, moderation, XSS as text | `tests/unit/test_redteam.py::test_rate_limit_per_ip_then_refill`, `::test_global_rate_limit_across_clients`, `::test_kill_switch_via_rest_and_cli`, `::test_moderated_text_is_withheld_but_still_evaluated`, `::test_xss_payload_is_delivered_verbatim_as_data_never_interpreted`; `tests/unit/test_ui_safety.py::test_console_and_landing_have_no_html_injection_sinks` | PASS (static check of UI sinks, not a browser run) |
| AT-15 | Tamper gives exact bad_index; inclusion/consistency proofs verify | `tests/integration/test_phase3_demo.py::test_at15_cli_tamper_reports_exact_bad_index_and_proofs_verify` | PASS (also run by hand: `bad_index: 2`) |
| AT-16 | `bench/results.json` schema-valid; no metric literals in UI | `tests/unit/test_bench_schema.py::test_results_validate_against_schema`, `::test_ui_has_no_hardcoded_metric_literals` | PASS |
| AT-17 | WS reconnect/resume; CLI `ml off` pushes live `ml_state` | `tests/unit/test_ws_api.py::test_at17_ws_reconnect_resumes_after_last_seq`, `::test_at17_cli_ml_off_is_pushed_live_via_control_table`, `::test_at17_control_poller_task_publishes_within_interval` | PASS |

## Invariants I1-I7
| Invariant | Method | Evidence |
|---|---|---|
| I1 untrusted value never reaches a sink under ALLOW | Z3 | `tests/unit/test_z3_policy.py::test_real_policies_proofs` (UNSAT for pay_upi, add_payee, export_records, send_email); SAT counterexample on the unsafe fixture: `::test_unsafe_fixture_gives_pay_upi_counterexample` |
| I2 ML/combination never lowers a decision | Z3 and Hypothesis | `test_z3_policy.py::test_real_policies_proofs` (all I2 UNSAT); `tests/property/test_invariants.py::test_i2_ml_decision_never_lowers`; `tests/property/test_evaluator_totality.py::test_evaluate_typed_is_total_and_ml_never_loosens` |
| I3 fault in any stage never allows or executes | Hypothesis | `tests/property/test_failclosed.py::test_fault_in_any_stage_never_allows_or_executes`, `::test_stage_timeout_fails_closed` |
| I4 payment ALLOW needs valid mandate (sig, time, nonce, payee, caps or approval) | Z3 | `test_z3_policy.py::test_real_policies_proofs` (UNSAT for pay_upi, issue_refund) |
| I5 PII sinks need active consent | Z3 | `test_z3_policy.py::test_real_policies_proofs` (UNSAT for read_customer_data) |
| I6 any argument mutation invalidates the approval token | Hypothesis | `tests/property/test_invariants.py::test_i6_token_valid_only_for_exact_call` |
| I7 any byte flip in the audit log yields the exact bad index | Hypothesis | `tests/property/test_audit_mutation.py::test_single_byte_mutation_gives_exact_index` |

Z3 also has a translation-agreement property (`test_z3_policy.py::test_translation_agrees_with_evaluator`) and a
timeout test showing UNKNOWN is never reported as UNSAT (`::test_timeout_is_unknown_never_unsat`).

## What was not run and why
- AgentDojo: workspace and slack suites, and banking injection tasks 6-8, not run (time budget). Only banking was run.
- Real voice models (mlx-whisper, DF_Arena) and macOS `say` tests: 5 tests skipped, models not available in the
  test environment. Docker `/readyz` also reports `voice_models: unavailable`.
- Browser clicking of every console drawer, panel and state: not done. The console is served and its sink safety
  is statically tested, but no automated or manual pass covered each UI path.
- Public tunnel (`TRISHUL_REDTEAM_PUBLIC=1`, `TRISHUL_TRUSTED_PROXY=1`, Cloudflare): not exercised.
- Container-to-host Ollama (`host.docker.internal`): readyz shows it reachable, no LLM call was made through it.
- Non-macOS or non-Apple-Silicon hosts: not tested.
- `pyright`: not run (mypy used).

## What remains risky
- Nonce reuse after approval: Opus review found task-pin escalation (HIGH) plus three voice/nonce defects; all fixed
  (per-task secret pins, voice approval minted only on liveness match, nonce bound to call digest, lock-safe timeout)
  with tests in `tests/integration/test_voice_replay.py` and `tests/unit/test_review_fixes.py`. Residual risk: an
  approved digest's single retry is by design; concurrency covered by test, not by formal proof.
- Voice EER is null: there are no bonafide clips (`bonafide_clips: 0`); the corpus is synthetic TTS only, so no
  detector accuracy claim is supportable. Spoof recall 1.0 is on 4 clips and is not accuracy.
- AgentDojo coverage: banking subset only; only money-moving tools are guarded (`update_password`,
  `update_user_info` pass through). Do not cite it as general prompt-injection coverage.
- Proxy and rate limit: per-IP limiting is keyed on `CF-Connecting-IP` only when `TRISHUL_TRUSTED_PROXY=1`;
  misconfiguration lets a client spoof or share a key. The wall is not hardened for an open internet audience.
- UI drawers and panels were not all browser-clicked (see above).
- Stdio id-counter bug was found only through Docker; other per-process state in subprocess servers should be
  audited the same way. The Docker image bakes `bench/results.json` at build time.
- India suite results are on a dataset authored in this repo; the zero ASR is against our own attack set.
- `uv run` rebuilds the editable `trishul` package on each invocation when files change; harmless but noisy.

## Known limitations and production next steps
- Single-node SQLite with one gateway process; no HA, no key rotation, demo keys derive from the seed.
  Next: real KMS/HSM keys, Postgres, external anchoring of tree heads.
- Operator auth is a single shared bearer token; Next: per-operator identity, SSO, audit of operator actions.
- Red-team wall is moderated by a simple display filter and in-memory rate limits; Next: a dedicated submit-only
  proxy, persistent abuse controls, WAF.
- Scripted FinBot, scripted ASR/spoof adapters in the India suite; Next: real-model end-to-end runs with
  bonafide corpus, EER/ROC, liveness.
- Policy is hand-authored YAML with Z3 proofs over a finite abstraction; Next: CI gate that re-proves on every
  policy change and a policy signing step.
- Packaging: one image, models run natively; Next: pinned base image digest, SBOM, non-root read-only filesystem.

## Final demo command sequence (matches `docs/demo-runbook.md`)
```bash
# optional, only for AgentDojo / local LLM
ollama serve
bash scripts/prewarm.sh
uv run trishul demo reset --seed 42
uv run trishul start --seed 42 --port 8787 --mcp-port 8788   # prints readiness JSON and the operator.token path
curl -s localhost:8787/healthz          # {"ok":true}
curl -s localhost:8787/readyz
# open http://localhost:8787/console/Trishul-Console.dc.html#op=$(cat operator.token)
# moments 1-6 from the console buttons (POST /demo/moment/{n}); between them as needed:
uv run trishul ml off                   # moment 5, console flips live; `uv run trishul ml on` afterwards
uv run trishul demo tamper --idx 2      # moment 6
uv run trishul verify                   # expect bad_index 2
uv run trishul report --dpdp > dpdp-report.json
uv run trishul demo reset --seed 42     # restore clean state; verify returns ok
# Docker alternative (ports bound to 127.0.0.1)
docker compose up -d --build            # token: docker compose exec gateway cat /data/operator.token
docker compose down
```
