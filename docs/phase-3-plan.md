# TRISHUL — Phase 3 Plan (Showcase, Evidence, Packaging)

Status: normative spec for Phase 3 workers. Written 2026-09-30 after merging Phase 2
(`claude/security-kernel-enforcement-f2e6a7`, 415 passed / 5 skipped).

## 0. Ground rules
- UI source of truth: `Landing page and dashboard implementation/Trishul-Console.dc.html`,
  `Trishul-Landing.dc.html`, `support.js`. Preserve layout, tokens, typography, motion. Only add
  states/sections that reuse existing classes and colour tokens. No new visual concept.
- Every number in the UI comes from a WS event, a REST response, or `bench/results.json`. Grep gate:
  no numeric metric literals in frontend JS except layout constants.
- Untrusted text (red-team, invoice, transcript, tool args) is rendered via React text children
  only. `dangerouslySetInnerHTML`, `innerHTML`, `insertAdjacentHTML` forbidden on those paths
  (test: `tests/unit/test_ui_safety.py` greps the HTML/JS).
- Nothing here weakens Phase 2 fail-closed behaviour. Exceptions never become ALLOW.
- Offline: scripted path must work with no network. `support.js` loads React/Babel from unpkg →
  vendor `react.production.min.js`, `react-dom.production.min.js`, `babel.min.js` into
  `Landing page and dashboard implementation/vendor/` and prefer local URLs with unpkg fallback.
  Google Fonts fall back to system fonts (acceptable offline degradation, documented).

## 1. Capability → UI mapping (console seams from phase-1-plan §7)
| Capability | Existing region / seam | Backend source |
|---|---|---|
| Live decision feed | timeline rows, `feed` | WS `call` events |
| Decision detail | drawer (row click) | `call` event fields |
| Animated lineage | SVG agent→gate→tool, `lineage-graph` | `call.lineage{nodes,edges}`; animate path source→derive→sink, label chips |
| Rule ID + explanation | drawer decision section | `call.rules[]`, `call.reason` |
| Stage latency + p99 ticker | header P99, panel p95 | WS `call.stage_ms`; `GET /metrics` |
| Approval queue + binding | APPROVALS drawer, `approval-state` | `GET /approvals`, `call.approval`, `resolution` (event id→approval_id via `call.approval.id`) |
| Mandate status + cap usage | PAYSHIELD domain button/drawer | `GET /mandates` (new) |
| Purpose/consent + withdrawal | PURPOSELOCK drawer | `GET /consent`, `POST /consent/{id}/withdraw` |
| VoiceTrust | VOICETRUST drawer | `call.liveness`, `call.scores`, `POST /voice/nonce` |
| Audit explorer + tree head | header AUDIT CHAIN, `audit-root` | `GET /audit/head`, `GET /audit/leaves?from&limit` (new) |
| Inclusion/consistency proofs | audit drawer | `GET /audit/proof/inclusion?idx`, `GET /audit/proof/consistency?old` (new, server-verified + client shows result) |
| Tamper verification | audit drawer | `GET /audit/verify` → `{ok,bad_index,tree_head}`; WS `audit_verify` |
| Z3 proof page | PROOF drawer, `proof-status` | `POST /prove` `{policy:"live"\|"unsafe_fixture"}` → per-invariant result, solve_ms, counterexample |
| Red-Team Wall | new section inside existing layout, reusing timeline row styles | WS `redteam` events, `GET /redteam/stats` |
| Benchmarks | landing stats block + console bench panel | `GET /bench/results.json` (file) |
| TRISHUL ON/OFF | header control, `domain-status` | `GET/POST /mode` → WS `mode` |
States for every region: `loading`, `empty`, `error`, `disconnected` (existing status message + amber token).
DevReplaySource: kept only for `?mode=replay`, banner "DEV REPLAY — synthetic data"; default is live.

## 2. New backend contracts (all REST mutations use existing `guarded` Origin/CSRF wrapper)
- `GET /healthz` → `{ok:true}`; `GET /readyz` → `{ready, checks:{db,policy,audit,voice_models,ollama}}`
  (voice/ollama are informational: `available|unavailable`, never block readiness of core demo).
- `GET /mode` / `POST /mode {mode:"on"|"off"}` → `{mode, namespace, disabled:[...]}`.
  OFF = explicit demo mode: calls go to an **isolated ledger namespace `demo_off`** (separate SQLite
  table rows keyed by namespace, never the protected ledger), every event carries
  `mode:"off"`, `decision:"UNGUARDED"`, and the UI shows the red warning banner. Audit still records
  OFF events (with `mode:"off"`), so OFF is never hidden. Default ON; `demo reset` restores ON.
- `GET /mandates` → mandates with `{id, payee, per_txn_cap, daily_cap, used_today, uses, max_uses, state}`.
- `GET /audit/head`, `/audit/leaves`, `/audit/proof/inclusion`, `/audit/proof/consistency` as above.
- `POST /prove {policy}`: `unsafe_fixture` compiles `trishul/fixtures/unsafe_policy/` **in a separate
  compiled object used only for the proof + a sandboxed replay evaluation**; the live gateway policy
  is never swapped. Response `{result, solver:"z3", policy_digest, per_invariant:[{id, result, solve_ms,
  counterexample|null}], replay:{call, decision_under_unsafe, decision_under_live}|null}`.
- Red team: `POST /redteam/submit {text}` (only when `TRISHUL_REDTEAM_PUBLIC=1` or localhost),
  token-bucket 5/min per client IP + 60/min global, max 2 000 chars, NFC-normalised, control chars
  stripped, moderation layer = deterministic blocklist (slurs/sexual/self-harm terms list in
  `trishul/redteam/moderation.py`) → hidden text `"[withheld by display filter]"` but still evaluated.
  Kill switch `POST /redteam/kill {on:bool}` + CLI `trishul redteam kill|resume`. Submissions run in
  namespace `redteam` through the real pipeline via FinBot's scripted agent (submission becomes the
  untrusted document content; agent attempts the tool call the text asks for, extracted by a fixed
  regex parser — no LLM required). Fallback: 20 deterministic submissions in
  `trishul/redteam/queue.json`, events labelled `source:"fallback_queue"`. Counters
  (`attempted`, `succeeded` = executed sink effect in the protected namespace) are computed from
  audit/events, never incremented client-side.
- `POST /demo/moment/{n}` (1–6, sub-steps via body `{step}`) — runs scripted FinBot steps; returns
  the resulting event ids. `POST /demo/reset {seed}`.
- `GET /report/dpdp` → downloadable signed JSON report (existing DPDP generator).
- WS new types: `mode{mode}`, `ml_state{enabled}` (now pushed live when toggled via REST **or** CLI —
  CLI writes a control row; the gateway polls the `control` table every 500 ms), `redteam{id, text,
  source, moderated, decision, rules, succeeded}`, `redteam_stats{attempted,succeeded,killed}`,
  `proof{...}`, `demo{moment, step, status}`.

## 3. FinBot (`trishul/finbot/`)
Deterministic agent: a script of MCP calls through `fastmcp.Client` to the real gateway URL.
No LLM in the scripted path. Moments:
1. OFF: mode off → read `inv_injected.html` → pay extracted hidden VPA → real `demo_off` ledger row.
2. Integration: UI shows two-line diff (`MCP_URL=http://127.0.0.1:8788/mcp`), mode on.
3. Same invoice → DENY (latency from event); normal bill ALLOW; over-cap STEP_UP → console approve →
   retry ALLOW; approve then change amount → DENY approval-binding mismatch.
4. Red-Team Wall (public route if enabled, else fallback queue).
5. `ml off` → re-run top 5 attacks → still DENY; `POST /prove {live}` I1; `{unsafe_fixture}` → counterexample
   + replay; restore (nothing to restore: live never swapped — UI states this).
6. Voice: TTS/cloned fixture → spoof DENY or STEP_UP (real `Speech-Arena-2025/DF_Arena_1B_V_1` if available, else
   deterministic adapter → STEP_UP, labelled); real voice path nonce+approval; replayed recording →
   nonce mismatch DENY. Audit tamper: `trishul demo tamper --idx N` does
   `UPDATE audit_leaves SET payload=? WHERE idx=?` via sqlite3 (payload JSON field mutated), then
   `trishul verify` shows `bad_index`. `trishul demo reset` restores. DPDP report download.

## 4. Benchmarks (`trishul/bench/`, `trishul bench`)
Writes `bench/results.json` (schema `bench/schema.json`, validated in tests):
`{schema_version, generated_at, git_commit, seed, environment{os, cpu, python, packages}, dataset_version,
suites:{india:{attacks:n>=30, benign:n>=30, with_trishul{asr, utility}, without{asr, utility}, per_category},
agentdojo:{status:"ok"|"not_run", reason, model, suites_run[], subset_note, with/without{asr, utility}},
latency:{ml_on:{stage:{p50,p99}}, ml_off:{...}, samples},
voice:{status, source:"bench/voice.json", eer|null, accuracy|null, note},
ablation:[{config:"rules_only"|"rules_classifier"|"full", asr, utility}]}, failures:[...]}`.
- India suite runs in-process against the real `Pipeline` (same policy core) — fast, deterministic.
- Without-TRISHUL = the same calls through the OFF namespace (executes, measures what would succeed).
- AgentDojo: adapter module `trishul/bench/agentdojo_adapter.py` with a `BasePipelineElement` placed
  before `ToolsExecutor` calling the policy core in-process. Runs only if `agentdojo` importable **and**
  a local OpenAI-compatible endpoint answers (`OLLAMA` `http://localhost:11434/v1`, model `Qwen/Qwen3-8B` (Ollama `qwen3:8b`),
  or vLLM `LOCAL_LLM_PORT=8000`). Otherwise `status:"not_run"` with reason. Never a paid API.
- Voice: EER needs bonafide clips; current corpus is TTS-only → `eer:null`, `status:"partial"`,
  note from phase-2 report. Never fabricate.
- Ablation: the classifier in this repo is the anomaly/PII ML signal set; configs toggle ML flags.

## 5. The 17 acceptance tests (defined here — no earlier canonical list existed in the repo)
| ID | Test | Evidence location |
|---|---|---|
| AT-01..AT-10 | Phase-2 integration scenarios 1–10 | `tests/integration/test_scenarios.py` |
| AT-11 | OFF mode executes only in `demo_off` namespace, visible in events + audit | `tests/integration/test_phase3_demo.py` |
| AT-12 | ML off: top attacks still DENY | same |
| AT-13 | Unsafe fixture → SAT counterexample; live policy untouched (digest equal before/after) | `tests/unit/test_prove_api.py` |
| AT-14 | Red-team: rate limit, kill switch, moderation, XSS payload rendered as text | `tests/unit/test_redteam.py`, `tests/unit/test_ui_safety.py` |
| AT-15 | SQLite payload tamper → `verify` exact bad_index; inclusion/consistency proofs verify | `tests/integration/test_phase3_demo.py` |
| AT-16 | `bench/results.json` generated and schema-valid; no metric literals in UI | `tests/unit/test_bench_schema.py` |
| AT-17 | WS reconnect/resume + CLI `ml off` pushes live `ml_state` | `tests/unit/test_ws_api.py` |
All 7 invariants: I1, I2, I4, I5 by Z3 (`trishul prove`); I3, I6, I7 by Hypothesis (`tests/property`).

## 6. Work split (model routing; low token budget)
| WP | Model | Scope |
|---|---|---|
| WP1 backend | Sonnet | §2 + FinBot §3 + `trishul/redteam` + CLI (`demo tamper`, `redteam`, `start` readiness) + AT-11..15,17 |
| WP2 bench | Sonnet | §4 + `bench/schema.json` + AT-16 (runs parallel to WP1; touches CLI only via one registration line) |
| WP3 UI | Sonnet | §1 wiring, vendoring, states, red-team wall, bench panel, landing results; after WP1 |
| WP4 packaging+docs | Sonnet | Dockerfile, compose, runbook, README, architecture/threat model, Pages workflow |
| Gate | Opus | review diffs vs this spec, security manual review list |
| Log | Haiku | CLAUDE.md task log |

## 7. Benchmark plan / demo runbook
See `docs/demo-runbook.md` (WP4). Bench command: `uv run trishul bench --seed 42` (india + latency +
voice-from-file always; agentdojo when local model present).
