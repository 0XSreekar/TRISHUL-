# TRISHUL — Phase 4 Report (Gap Closure)

Branch `claude/trishul-phase-4-gaps-4856b0`, built on Phase 3 (`94ca85e`). Spec: `docs/phase-4-plan.md`.
Acceptance evidence: `docs/acceptance-evidence.md` (regenerate with `uv run trishul acceptance`).

## Final gate (2026-10-01, merged branch)
| Check | Result |
|---|---|
| `uv run pytest -q` | 640 passed, 2 skipped (live Ollama tests; Ollama not running) |
| `uv run ruff check .` / `ruff format --check .` | All checks passed / 190 files already formatted |
| `uv run mypy trishul` | Success: no issues found in 98 source files |
| `gitleaks detect` | no leaks found |
| `uv run trishul acceptance` | AT-01..AT-17 PASS; S-OFF, S-RT, S-WS PASS |

## What was added
| Area | Summary |
|---|---|
| Keys (§5) | Random Ed25519 keys per purpose in `$TRISHUL_HOME/keys` (dir 0700, files 0600, loose perms refused); kid = purpose + key hash; rotation keeps old kids verifiable; `demo reset --rotate-keys`, `trishul keys rotate`. Seed controls data only. |
| Gateway bypass (§1, AT-01) | Every gateway→tool call carries an Ed25519 token over tool, args hash, expiry and nonce; servers hold public keys only and reject missing, foreign-key, wrong-args, expired and replayed tokens (SQLite nonce table). Wildcard binds refused. Docker: internal `tools` network, no published tool ports. |
| Approver auth (§2) | argon2id accounts created at `demo reset` from env passwords; HttpOnly SameSite=Strict session + CSRF token; approver ID in the approval, the signed token and an `approval_resolved` audit leaf; operator actions audited. Separate audience app on :8789 with only `GET /` and `POST /submit`. |
| Injection classifier (§3, AT-05) | `protectai/deberta-v3-base-prompt-injection-v2` @ `90c9989b…`; 512-token chunks, max score; escalate-only; timeout/error/unavailable → escalate; `ml off` → `ml_signal: disabled`; ablation rows in `trishul bench`. |
| Quarantined reader (§4) | No-tool reader over `$DOC_n/$EMAIL_n/$VOICE_n` handles, Pydantic schemas with `extra="forbid"`; invalid output → DENY `CORE.READER.INVALID`; values keep UNTRUSTED labels. Replay mode uses the labelled deterministic fallback. |
| Local LLM (§7) | `Qwen/Qwen3-8B` (≥16 GiB RAM) else `Qwen/Qwen3-4B`, chosen at start, logged, written to `bench/results.json` and a `system_start` audit leaf. |
| Launch extras (§9) | Apache-2.0 LICENSE + SPDX headers, `.gitignore`, gitleaks in `scripts/quality.sh` and CI, voice-dataset tooling, `trishul bench --export-deck`. |
| Acceptance (§0) | `@pytest.mark.acceptance(n)`, registry `tests/acceptance.py`, `trishul acceptance` CLI, evidence doc; Phase-3 extras kept as S-OFF/S-RT/S-WS. |

## Integration fixes made while merging
- `approval_resolved` leaves recorded `kid: null` after the key and auth work met; they now record the key that signed the token.
- The classifier escalated plain document reads through the new `read_handle` reader tool (over-blocking); both reader tools are now exempt at read time and still scored at sink time.
- `httpx` declared as a direct dependency (imported at start).

## Live smoke run (`trishul start`, scratch state)
Moment 1 OFF pays the attacker (`demo_off` only); moment 3 injected invoice DENY, normal bill ALLOW, over-cap STEP_UP →
approved by a logged-in approver → retry ALLOW; moment 4 red-team queue all DENY; moment 5 ML-off attacks DENY, Z3 live
policy UNSAT and unsafe fixture SAT; moment 6 cloned voice and replayed nonce DENY; `audit/verify` ok.
Auth: approve with no session 401, with operator token 401, from audience origin 403, without CSRF 403.

## NOT RUN
| Item | Reason |
|---|---|
| UI design link (§8) | `TRISHUL_DASHBOARD_PROMPT.md` / `TRISHUL_LANDING_PROMPT.md` do not exist; existing `.dc.html` files remain the source of truth. |
| Voice clip dataset (§6) | Needs team recordings and written consent; tooling and manifest only. |
| Live Qwen reader | Ollama not running locally; reader runs the labelled deterministic fallback. |
| Ollama digests | Values in `trishul/ml/models.py` were not checked against a real `/api/tags`; a mismatch only keeps the fallback on. |
| Docker run | Compose networks verified by inspection, not by `docker compose up`. |
| Backup demo video | Manual recording. |
| Opus security review | Skipped at the owner's request (hackathon timeline). |

## Known limits and risks
- Classifier latency measured 275–335 ms per 512-token chunk on a loaded M-series laptop; with the 2 s timeout, very long documents can escalate (fail closed).
- Ablation: rules-only, rules + classifier and full all score ASR 0/49 and utility 29/34 on the India suite; the classifier adds no measurable separation there, and the `full` row does not include the voice-spoof signal.
- Running a whole demo moment auto-approves its STEP_UP steps for pacing (recorded as approver `console`); run moment 3 step by step to show a real approver login.
- The real voice-spoof test can time out under heavy load and return STEP_UP instead of DENY (still fail closed).
- The shared SQLite file is a single trust point (see `docs/threat-model.md`).
