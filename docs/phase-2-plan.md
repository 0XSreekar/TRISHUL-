# TRISHUL — Phase 2 Plan (Security kernel + enforcement domains)

Normative spec for all implementers. Read §0–§3 before any task; then only your task section.
Phase 1 (`docs/phase-1-plan.md`) decisions A1–A14 still hold unless overridden here.

## 0. Verification pass (2026-09-30)

- Phase 1 lived on unmerged branch `claude/trishul-foundation-setup-af60d0`; fast-forwarded into this branch. Baseline: 111 tests, ruff, mypy strict all green.
- FastMCP installed = 4.0.10 (see `docs/fastmcp-notes.md`). `create_proxy`, `FastMCP.mount(server, namespace)`, `Middleware.on_call_tool(context, call_next)`, `MiddlewareContext{message: CallToolRequestParams(name, arguments, meta), fastmcp_context, method}`, deny = raise `fastmcp.exceptions.ToolError`, `fastmcp.tools.ToolResult(content, structured_content, meta, is_error)`, `Client.call_tool(name, args, meta=...)`, `FastMCP.http_app(path=...)`. Pin `fastmcp>=4.0.10,<5`.

### Deviations from Phase 1 plan
| Phase 1 | Phase 2 | Why (one line) |
|---|---|---|
| `Mandate` = single payee, `max_uses` | New `SignedMandate` (§4) with `payees[]`, `per_txn_cap`, `daily_cap`, `categories`, `nbf/exp`; old `Mandate` kept for evaluator back-compat but unused by gateway | Spec requires multi-payee + daily cap from ledger. |
| `canonical_json` = Python `sort_keys` | Add `trishul/crypto/jcs.py` (RFC 8785: UTF-16 key order, reject lone surrogates, ints only) for **signed** payloads; keep `canonical_json` for digests (identical for BMP keys) | Signatures must be cross-language verifiable. |
| Evaluator reads mandates/approvals from context directly | Domain guards compute **facts** (booleans, crypto-verified) → policy rules consume them via new `fact` predicate | One AST for runtime + Z3; crypto stays out of the pure evaluator. |
| No sink notion in AST | `ArgSpec.sink: bool` | Needed to state/prove I1 generically. |

### Dependency / licence / environment risks
| Risk | Impact | Mitigation |
|---|---|---|
| `Speech-Arena-2025/DF_Arena_*_V_1` licence = **non-commercial research only**; `trust_remote_code=True` (code reviewed: wav2vec2-XLS-R-300m + conformer, no network/exec); weights 1.7 GB (500M) / 4.6 GB (1B); needs torch+transformers | Demo-only use; large download | Optional extra `voice-ml`; **download only after user approval**; default = labelled deterministic adapter (`detector_ran=false`). |
| mlx-whisper model weights not cached; no `ffmpeg` on host | ASR unavailable | Feed numpy float32 16 kHz arrays (no ffmpeg); faster-whisper CPU fallback; else transcript adapter labelled `asr=unavailable` → STEP_UP. |
| Hindi/Telugu and voice-clone samples not present | Coverage gap | Report as limitation; media manifest records model/licence/consent when added. |
| Python pinned 3.12 (host default 3.14) | Wheels (z3, mlx) | Always `uv run`. |
| z3-solver wheel size | Install time | One-time. |

## 1. Architecture

```
Agent runtime ──MCP──▶ TRISHUL Gateway (FastMCP proxy + PolicyMiddleware) ──MCP──▶ upi | crm | mail | files servers
                              │ pipeline stages 1–10 (§2)                         (separate FastMCP servers, SQLite WAL)
                              ├─▶ Merkle audit log (SQLite)   ├─▶ OTel spans   └─▶ EventBus ─▶ WS :8787/events (+REST)
```
Tests connect servers in-process (`FastMCP` instances, still MCP protocol). `trishul start` launches servers as stdio subprocesses via `create_proxy(MCPConfig)`; gateway MCP on `http://127.0.0.1:8788/mcp`, UI API/WS on `:8787`.

### Package layout (owner task in brackets)
```
trishul/crypto/     jcs.py, keys.py (Ed25519 KeyRing, deterministic from seed)            [T1]
trishul/store/      db.py (connect WAL, schema, reset(seed)), ids.py (seeded ULID-like)  [T1]
trishul/audit/      merkle.py (RFC 6962), log.py (AuditLog), verify.py                   [T1]
trishul/approvals.py  ApprovalService                                                     [T1]
trishul/policy/     + `fact` predicate, ArgSpec.sink                                      [T1]
trishul/servers/    upi.py, crm.py, mail.py, files.py                                     [T2]
trishul/domains/    payshield.py, anomaly.py                                              [T2]
trishul/domains/    purposelock.py, pii.py                                                [T3]
trishul/domains/    voicetrust.py, voice_adapters.py                                      [T4]
trishul/gateway/    pipeline.py, middleware.py, taint.py, app.py                          [T5]
trishul/telemetry/  otel.py, events.py (EventBus), api.py (Starlette REST+WS)             [T5]
trishul/cli/main.py  start|verify|prove|report --dpdp|ml on/off|demo reset|approve       [T5]
trishul/verify/     z3_policy.py, invariants.py                                           [T6]
tests/fixtures/     invoices, CRM seed, audio manifest                                    [T0 Haiku]
```
**File ownership is exclusive.** Only T5 edits `cli/main.py` and `pyproject.toml` after T1.

## 2. Gateway pipeline (T5) — normative

Each stage is a function `(PipelineState) -> PipelineState` timed by an OTel span `trishul.stage.<name>` (attrs: `correlation_id`, `tool`, `decision_so_far`). Wrapper `run_stage` catches `Exception` **and** enforces a per-stage timeout (default 2 s; `asyncio.wait_for`) → on failure append reason `CORE.FAILSAFE.<STAGE>` with decision **DENY** (stages 2,3,4) or **STEP_UP** (stages 5,6) and skip to stage 8. Nothing in stages 2–6 may set ALLOW; ALLOW is only the absence of escalating reasons (A7).

1. **ingress** — build `ToolCall` (call_id = seeded id, principal/task from the bound task (§3), `server` = mount namespace, ts = clock). Unknown task → DENY `CORE.TASK.UNBOUND`.
2. **handles** — replace any string arg exactly matching `$VAR_n`/`$DOC_n` with its stored raw value; record label for that JSON pointer. Unknown handle → DENY `CORE.HANDLE.UNKNOWN`. Raw values never returned to the planner.
3. **provenance** — for every leaf not set by stage 2, label = `TaintRegistry.label_for(value)` (§3). `arg_labels` = per-leaf labels; build `LineageGraph` (source nodes → derivation nodes (extract) → sink node for the tool).
4. **policy** — `evaluate(compiled_policy, call, EvalContext(now, purpose, facts=...))`.
5. **domain guards** — PayShield (PAYMENT tools), PurposeLock (READ of personal data, COMMUNICATION/EXPORT sinks), VoiceTrust (`voice_command`). Guards return `GuardResult(facts: dict[str,bool|None], reasons: list[DecisionReason], ctx_patch)`. Facts are fed into stage 4 — **order in code: 5 runs before 4** (facts needed by rules); stage numbering is for reporting only.
6. **ml** — if ML enabled: signals (amount anomaly, hidden-text/injection score from handle metadata, spoof score) produce `ml_decision`; combined by `max` (never lowers). ML off → skipped, recorded `ml=off`.
7. **preview** — only if decision so far ≤ STEP_UP and tool is side-effecting: call the server's `preview_<tool>` (SQLite `SAVEPOINT` … `ROLLBACK TO`), attach `effect={summary, balance_after}`. Preview failure → STEP_UP `CORE.FAILSAFE.PREVIEW`.
8. **decision** — `Verdict.build`. STEP_UP → create pending approval (§5), raise `ToolError` with JSON `{"decision":"STEP_UP","approval_id":…,"call_digest":…,"rules":[…]}`. DENY → `ToolError` with `{"decision":"DENY","rules":[…],"reason":…}`. ALLOW → `call_next`; then **result labelling**: result stored via `HandleStore`/`TaintRegistry` per server trust (§3); PurposeLock response minimisation applied before return.
9. **audit** — append canonical decision event to `AuditLog` **before** returning/raising (and a second `execution` event after an ALLOW'd call returns, with ledger delta).
10. **telemetry** — publish `GatewayEvent` (§7) to EventBus.

## 3. Provenance model (T5 implements `gateway/taint.py`)

- **Task binding** (trusted channel only: CLI `trishul task bind` / REST `POST /tasks` / test fixture): `Task{task_id, principal, purpose, category: ToolCategory, text, params: dict}`. Purpose/category come **only** from here. Its text tokens and params are registered TRUSTED_USER, source `user:<task_id>`. Amount tokens registered both as rupees and paise ints (`₹4,500`/`4500` → `450000`).
- **TaintRegistry** (per session): maps normalized value (str lowercased/stripped; int) → Label. `label_for(v)`: exact match → that label; substring match of any registered untrusted/PII string ≥ 6 chars inside a string arg → join; PII recognizers (§ T3) on string args → add tags; unmatched → `Label(UNTRUSTED, sources={model:<task_id>})` (fail-safe: planner literals of unknown origin are untrusted).
- **Tool results**: server trust table — `upi.list_payees`, `upi.get_balance` → TRUSTED_SYSTEM; `crm.*` → TRUSTED_SYSTEM + PII tags from recognizers/field map; `files.read_document` → by document `trust` column (`user_upload` → TRUSTED_SYSTEM source `document:<id>`, else UNTRUSTED); `mail.read_inbox` → UNTRUSTED `email:<id>`. Untrusted results are **not** returned raw: gateway returns `{"handle":"$DOC_n","summary":{safe metadata}}`. `extract_field($DOC_n, field)` is a gateway-native tool (quarantined reader, deterministic regex extractors for `payee_vpa`, `amount_paise`, `invoice_id`) returning `$VAR_n`; label via `derive()` (inherits). Hidden-text (white-on-white, `display:none`, font-size 0) detected at extraction → `injection_score` in handle metadata.

## 4. PayShield (T2)

`SignedMandate` JSON: `{principal, payees:[{vpa,name,cap}], per_txn_cap, daily_cap, categories:[str], nbf, exp, nonce, key_id, sig}`; amounts int paise; times RFC 3339 UTC. Signature = Ed25519 over `jcs(mandate without sig)`, base64url. Stored in `mandates` table; nonces in `mandate_nonces` (UNIQUE) — a *different* mandate re-using a nonce = replay.

Facts produced (each `None` if cannot be determined → UNKNOWN → rule fires):
`mandate_sig_valid, mandate_time_valid (nbf ≤ now < exp), mandate_nonce_fresh, payee_in_mandate, amount_within_payee_cap, amount_within_per_txn_cap, amount_within_daily_cap (SUM(ledger today for principal) + amount ≤ daily_cap, from real ledger), category_matches (task.category ∈ mandate.categories and tool category PAYMENT), approval_valid (§5), approval_binding_mismatch`.
Policy `policies/payshield.yaml` (T2) rules: DENY if any of sig/time/nonce/payee/category false/unknown; DENY on untrusted payee or amount label (existing); STEP_UP if over per-txn/payee/daily cap `and not approval_valid`; DENY if `approval_binding_mismatch`.
Anomaly (`anomaly.py`): robust z = |x − median| / (1.4826·MAD) over payee history (≥ 5 samples else z=None → no signal); z > 3.5 → ml STEP_UP; never ALLOW-producing.
UPI server tools: `pay_upi(payee_vpa, amount_paise, note)`, `get_balance()`, `list_payees()`, `add_payee(vpa, name)`, plus internal `preview_pay_upi` (SAVEPOINT/ROLLBACK). `pay_upi` success iff ledger row inserted and balance decreased in one transaction; returns `{txn_id, balance_after}`.

## 5. Approvals (T1)

`ApprovalService`: `request(call) -> approval_id` (row: id, task_id, tool, call_digest, canonical_call json, status=pending, created); `approve(id, approver)` signs `ApprovalToken{token_id, call_digest, scope, approver, issued_at, expires_at=issued+ttl(120s), nonce}` with approver Ed25519 key (JCS payload); `reject(id)`; `check(call, now) -> (approval_valid: bool, binding_mismatch: bool, token|None)`: find approved, unconsumed, unexpired tokens for (task_id, tool); valid iff signature verifies **and** `token.call_digest == call.call_digest()`; mismatch iff approved token(s) exist and none match. `consume(token_id)` after execution (single-use). Approval is out-of-band only (REST/CLI/console); never via MCP tool or voice.

## 6. PurposeLock (T3)

Consent table: `consent_id, principal_id, category, purposes(json), exp, withdrawn_at`. Facts: `consent_active` (exists, purpose ∈ purposes, now < exp, withdrawn_at null) , `sink_allowed_for_purpose` (purpose→allowed sinks map in `policies/purposelock.yaml` data section or Python const reviewed in plan: `order_support → {crm.read, mail.send_email to principal's own address}`; `marketing → {}`). Agent-supplied `purpose` arg: stripped before policy, reason `PURPOSELOCK.PURPOSE.IGNORED_AGENT_VALUE` (decision ALLOW-level, audited). Response minimisation: field allowlist per purpose applied to CRM responses; removed fields listed in redaction metadata. PII recognizers (`pii.py`): email, Indian mobile, PAN (`[A-Z]{3}[ABCFGHLJPT][A-Z]\d{4}[A-Z]`), Aadhaar 12 digits with **Verhoeff checksum** and first digit 2–9. Withdrawal: `withdraw(consent_id)` sets `withdrawn_at` and bumps `consent_epoch`; any decision cache keyed by epoch → invalidated immediately. `report --dpdp`: reads audit leaves with domain=purposelock, emits JSON with each event + inclusion proof + STH, and self-verifies.

## 7. Events & telemetry (T5)

`GatewayEvent` (JSON, schema_version 2) = UI-compatible superset: `{type:"call", id, seq, ts, session, agent, feature, tool, args(redacted summary), labels{arg: "TRUSTED_USER"|"UNTRUSTED_EXTERNAL:<kind>"…}, decision, rules[], reason, scores{}, latency_ms, stage_ms{}, lineage{nodes,edges}, audit_hash, tree_head{size,root}, approval{id,state}|null, mandate{id,state}|null, redaction{fields[],count}, effect|null, liveness|null}`. Other types: `ml_state`, `audit_verify{ok,bad_index}`, `resolution{id,decision}`. `seq` monotonic; WS client may send `{"resume_from":seq}` → replay from ring buffer (size 4096); per-client bounded queue (256), overflow → drop oldest + send `{type:"gap",from,to}`. Strings are escaped text only (no HTML). REST: `GET /consent`, `POST /consent/{id}/withdraw`, `GET /approvals`, `POST /approvals/{id}` `{decision}`, `POST /prove`, `POST /tasks`, `GET /metrics` (p50/p99 per stage from collected spans via in-memory SpanProcessor).

## 8. Merkle audit (T1)

RFC 6962: leaf = SHA256(0x00‖data), node = SHA256(0x01‖l‖r), MTH per RFC 6962 §2.1 (split at largest power of 2 < n). Table `audit_leaves(idx INTEGER PRIMARY KEY, payload BLOB NOT NULL, leaf_hash TEXT NOT NULL)`, `tree_heads(size, root, ts, sig, key_id)`. STH signed (Ed25519 over JCS `{size,root,ts}`) every `N` entries (default 16) and on `sth_now()`. Payload = JCS of redacted event (secrets removed, digests kept). `verify()` recomputes each leaf hash from payload: first mismatch → `{ok:false, bad_index:i}`; then every stored STH recomputed → list of invalid STH sizes. Inclusion & consistency proofs (RFC 6962 §2.1.1/2.1.2) with verifiers. Appends in a single transaction (`BEGIN IMMEDIATE`).

## 9. Formal (T6)

`verify/z3_policy.py` translates **the same `CompiledPolicy`** to Z3: each atom → Int in {0,1,2} (Tri); label atoms `LabelAtLeast(p,l)` ≡ `L_p ≥ l` with `L_p ∈ {0,1,2}` shared per path; `fact` atoms free Tri; `All/Any/Not` Kleene via min/max/2−x; rule fires iff value ≠ 0; decision = max of fired `then`. Final = max(decision, ml) with ml ∈ {0,1,2} free. Prove (UNSAT of negation) per tool: I1 (∃ sink arg with L=2 ∧ decision=0), I2 (final < decision), I4 (payment tool ∧ decision=0 ∧ ¬(sig∧time∧nonce∧payee∧caps-or-approval)), I5 (purposelock sink ∧ decision=0 ∧ ¬consent_active). Fixture `tests/fixtures/unsafe_policy.yaml` (drops the untrusted-payee rule) must yield a counterexample model. Hypothesis: I2, I3 (fault injection per stage 2–6 → never ALLOW), I6 (any arg mutation → token invalid), I7 (random byte flip → exact bad_index). `trishul prove` prints per-invariant result JSON (UI `proof` panel: `{result:"UNSAT"|"SAT", solver:"z3", property, per_invariant[]}`).

## 10. Implementation order, owners, acceptance

| Task | Model | Depends | Acceptance (all must pass: `uv run pytest`, `ruff check`, `ruff format --check`, `mypy trishul`) |
|---|---|---|---|
| T0 fixtures | Haiku | — | `tests/fixtures/`: `invoices/inv_trusted.html`, `inv_injected.html` (white-on-white second VPA), `crm_seed.json` (≥6 customers incl. valid-Verhoeff Aadhaar, PAN, phone, email), `media/manifest.json` (empty entries list + schema doc). No Python. |
| T1 foundation | Sonnet | — | deps added; JCS vectors (RFC 8785 key-order example, surrogate reject); Ed25519 sign/verify + tamper tests; store WAL + `reset(seed=42)` deterministic ids; Merkle: RFC 6962 test vectors, inclusion/consistency proofs n=1..40, single-byte mutation → exact index; STH verify; ApprovalService incl. argument-swap test; `fact` predicate + `sink` compile + evaluator tests. |
| T2 PayShield + servers | Sonnet | T1 | 4 FastMCP servers on T1 store; all §4 PayShield tests (tamper, nbf/exp, replay, payee swap, per-txn & daily cap, approval arg swap, untrusted payee, trusted allow, over-cap STEP_UP, preview doesn't commit); anomaly tests. |
| T3 PurposeLock | Sonnet | T1 | §6 tests (allowed, disallowed, agent purpose ignored, expiry, withdrawal+cache, minimisation, PII labelling incl. Verhoeff, email-sink block, DPDP proof verification). |
| T4 VoiceTrust | Sonnet | T1 | §VoiceTrust below; pure decision table total over all inputs (Hypothesis); replay, freshness, low SNR, high-risk sink always STEP_UP; adapters report `ran:false` honestly; benchmark script. |
| T5 gateway + telemetry + CLI | Sonnet (high) | T1–T4 | §2/§3/§7; 10 integration scenarios (phase-2 prompt §10) through real `Client → gateway proxy → servers`; fail-closed fault-injection test; WS reconnect/resume/dup/backpressure tests; CLI commands. |
| T6 formal | Sonnet | T5 | §9; unsafe fixture counterexample; `trishul prove`. |
| Gate | Opus | T6 | Review diff vs this spec (security, fail-closed, binding). |
| Docs | Haiku | Gate | `docs/phase-2-report.md` (test report, limitations, run commands) from actual output; CLAUDE.md log. |

### VoiceTrust (T4)
Pipeline: wav (16 kHz mono PCM via `wave`+numpy; no ffmpeg) → quality gate (duration 1–15 s; SNR estimate = energy of top-decile frames vs bottom-decile, dB; < 10 dB → `quality=low`) → energy VAD trim → ASR adapter chain `MlxWhisperASR` (Metal) → `FasterWhisperASR` (CPU) → `UnavailableASR` → transcript labelled `UNTRUSTED voice:<clip_id>` → normal gateway path. Nonce: server issues 3 random words (from a fixed 256-word list, `secrets`), TTL 10 s, single use. Liveness = normalized Levenshtein(nonce, transcript window) ≤ 0.25 and issued ≤ 10 s ago. Spoof adapters: `DFArenaSpoof` (tries `mps`, falls back to `cpu`, 500M if 1B p50 > 2 s) → `DeterministicSpoofAdapter` (returns `score=None, ran=false, label="deterministic-adapter"`). Decision table (pure, total): inputs `(quality∈{ok,low,unknown}, liveness∈{match,mismatch,expired,unknown}, asr_ran, spoof∈{None,float}, sink_risk∈{low,high})`: mismatch/expired → DENY; low/unknown quality or asr not ran or liveness unknown → STEP_UP; high sink → ≥ STEP_UP; spoof ≥ 0.5 → DENY, 0.2–0.5 → ≥ STEP_UP; spoof None → no change (never lowers); else ALLOW. Benchmark: `scripts/bench_voice.py` writes `bench/voice.json` only from measured runs.

## 11. Fallback strategy
- FastMCP proxy mount issues → gateway implemented as a `FastMCP` server whose tools are generated from backend `list_tools` and forward via `Client` (still real MCP); middleware logic unchanged.
- Z3 timeout → report `UNKNOWN`, never `UNSAT`.
- Voice models absent → deterministic adapter, VoiceTrust decisions ≥ STEP_UP for any voice-originated sink.
- OTel exporter unavailable → in-memory span processor only (metrics still real).
