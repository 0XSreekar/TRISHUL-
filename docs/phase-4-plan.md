# TRISHUL — Phase 4 Plan (Gap Closure)

Status: normative spec for Phase 4 workers. Written 2026-10-01 by the Opus planner on top of Phase 3
(`claude/trishul-phase-3-console-d87711` @ 94ca85e, 491 passed / 0 skipped).

## 0. Ground rules (all workers)
- Read `docs/phase-3-report.md`, `docs/threat-model.md`, and the files you own before editing.
- Do not undo Phase 1–3 decisions, redesign the UI, or add scope beyond this file.
- Fail closed: an exception, timeout, missing model, or missing key never becomes ALLOW or execution.
- No fake results. Anything that cannot run is reported as `NOT RUN: <reason>`.
- Quality gate for every worker before handing back: `uv run pytest -q`, `uv run ruff check .`,
  `uv run ruff format --check .`, `uv run mypy trishul` all green. Paste the summary lines in your report.
- Commit on your own branch with `feat:`/`fix:`/`test:` messages. Do not edit `CLAUDE.md` (the planner does).
- Full model IDs everywhere in docs/config: `Speech-Arena-2025/DF_Arena_1B_V_1`,
  `Speech-Arena-2025/DF_Arena_500M_V_1`, `protectai/deberta-v3-base-prompt-injection-v2`, `Qwen/Qwen3-8B`
  (Ollama tag `qwen3:8b`), fallback `Qwen/Qwen3-4B` (`qwen3:4b`).

## 1. Key management (W1) — §5 of the brief
Decision: demo keys are random (`os.urandom` via `Ed25519PrivateKey.generate()`), NOT derived from the
seed. The seed is public (`--seed 42`), so seed-derived keys would let anyone forge mandates, approvals,
and gateway->tool tokens. The seed still controls data ids and fixtures. `KeyRing.from_seed` may stay for
unit tests only; no runtime path may use it.
- Home: `TRISHUL_HOME` (default `./.trishul`); keys in `<home>/keys/`, dir mode 0700, files 0600.
- Purposes: `mandate-signer`, `approval-signer`, `tree-head-signer`, `gateway-tool`.
- Key id: `<purpose>-<first 12 hex of sha256(raw public key)>`. Files `<kid>.key` (base64url raw
  private) and `<kid>.pub`; `<home>/keys/keyring.json` = `{purpose: {active: kid, all: [kid,...]}}`.
- Load refuses (fail closed, clear error) if any key file or the dir is group/world accessible.
- `trishul demo reset --seed 42` generates a fresh key set if none exists (and `--rotate-keys` forces a
  new active kid per purpose, keeping the old ones for verification). `trishul keys rotate <purpose>` does
  the same for one purpose. Old signatures still verify because verification looks up the recorded kid.
- Every signature records its kid (mandates already do; approvals, tree heads and tool tokens must too).
- Keys are never logged (add to redaction), never sent over WS/REST. Public keys may be exposed via
  `GET /keys/public` (`{kid, purpose, public_b64url}`), optional.
- Docs: production note in `docs/threat-model.md` — keys belong in a KMS/HSM; the demo uses local files.

## 2. Gateway bypass protection (W1) — §1, acceptance test 1
- Tool servers stay stdio subprocesses by default (no socket at all). Add an HTTP transport to
  `trishul/gateway/server_main.py` for Docker: `--transport http --host H --port P`; `H` must be
  `127.0.0.1`, a unix socket path (`unix:/path`), or a specific non-wildcard address/hostname.
  `0.0.0.0` / `::` / empty are rejected at startup.
- Every gateway->tool `call_tool` carries a token:
  claims `{v:1, kid, aud:<server name>, tool:<unprefixed tool name>, args_sha256:hex(sha256(JCS(args))),
  iat:<unix ms>, exp:iat+30000, nonce:<128-bit b64url>}`; token = `b64url(JCS(claims)) + "." + sig`,
  Ed25519 by the active `gateway-tool` key. Carry it in MCP request `_meta["trishul/token"]` if FastMCP
  4.x client/proxy supports per-call meta (check `docs/fastmcp-notes.md` and the library); otherwise a
  reserved argument `__trishul_token` that the server middleware strips before tool validation. Record the
  choice in `docs/fastmcp-notes.md`.
- Tool servers hold only the public keys (`--keys <home>/keys`). A FastMCP middleware on every server
  (`build_*_server` — also used in-process by tests) rejects: missing/malformed token, unknown kid, bad
  signature, aud/tool/args mismatch, `exp` passed, `iat` > now+5 s, reused nonce. Nonce store: SQLite
  table `tool_nonces(nonce TEXT PRIMARY KEY, exp INTEGER)` in the shared DB; insert-or-fail is the
  atomic replay check across processes; prune expired rows opportunistically.
- Minting lives in the gateway forwarding path only (the executor used by `Pipeline._execute`), after
  ALLOW. The agent-facing MCP surface never sees a token.
- Docker: `docker-compose.yml` gets two networks: `edge` (gateway only, ports published on 127.0.0.1)
  and `tools` (`internal: true`, gateway + tools service). The tools service runs the four servers over
  HTTP with no `ports:`; gateway reaches them through `TRISHUL_TOOLS_URL`-style config.
- Tests (tag them acceptance 1): (a) an agent calling a tool server directly (in-process FastMCP client
  and a spawned `server_main` stdio process) without a token, with a token signed by a foreign key, and
  with a wrong-args token → rejected, ledger unchanged; (b) a replayed valid token → rejected;
  (c) a normal gateway call → accepted; (d) wildcard bind refused.
- Residual risk to document: the SQLite file is shared; any process with write access to the data dir
  bypasses everything. In Docker only gateway+tools mount the volume.

## 3. Approver authentication and route separation (W2) — §2
- New package `trishul/auth/`: `users(user_id, username UNIQUE, role CHECK in ('approver','operator'),
  pw_hash, created_at, disabled)`, `sessions(sid_sha256 PK, user_id, csrf, created_at, last_seen,
  expires_at)`. Passwords: argon2id (`argon2-cffi`, add to deps). Min length 12. Never logged
  (extend redaction), never echoed.
- `demo reset` creates `approver` (role approver) from `TRISHUL_APPROVER_PASSWORD` and `operator`
  (role operator) from `TRISHUL_OPERATOR_PASSWORD`. If an env var is unset, that account is not created
  and the command prints how to set it (approvals then fail closed with 401). Add `.env.example`
  (placeholders only).
- Routes: `POST /auth/login {username,password}` -> `Set-Cookie: trishul_session=<random 256-bit>;
  HttpOnly; SameSite=Strict; Path=/` (+`Secure` when `TRISHUL_COOKIE_SECURE=1`), body `{user_id, role,
  csrf}`; `GET /auth/me`; `POST /auth/logout`. Login rate limit 5/min per client key; uniform failure
  message; sessions idle 30 min / absolute 8 h.
- `POST /approvals/{id}` (approve/reject): requires an approver-role session + `X-CSRF-Token` equal to the
  session csrf (constant-time) + allowlisted Origin (existing `guarded`). No session -> 401; wrong role or
  CSRF missing/mismatch -> 403; disallowed Origin -> 403. The operator bearer token is NOT an approver
  credential. The approver's `user_id` is stored on the approval, included in the signed approval token
  claims, and written to a Merkle leaf `{type:"approval_resolved", approval_id, decision, approver_id,
  call_digest, kid}`.
- CLI `trishul approve|reject ID`: authenticates with `--user` + password (getpass or
  `TRISHUL_APPROVER_PASSWORD`) through the same service; records the same approver id.
- Operator role: operator bearer token (CLI/automation, unchanged) or an operator session + CSRF. Operator
  actions `ml on|off`, `mode`, `prove unsafe_fixture` (load unsafe policy), `demo reset`, `demo moment`,
  `redteam kill|fallback` append `{type:"operator_action", action, actor, params}` leaves. `demo reset`
  writes its record as the first leaf of the fresh log.
- Audience Red-Team app: `trishul/redteam/app.py`, separate Starlette app on its own port (default 8789,
  `trishul start --redteam-port`). Routes: exactly `GET /` (static submit form, no data) and
  `POST /submit {text}`. No cookies read or set, no access to approvals, policy, ml, reset, or audit APIs.
  The main API drops the public `/redteam/submit` path (operator-only remains). The red-team origin is
  never in the main API Origin allowlist. Note in the threat model: SameSite does not separate ports
  (same site), so Origin + CSRF token are the controls.
- Console: minimal approver login inside the existing APPROVALS drawer, reusing existing classes and
  tokens; approve/reject send cookie + `X-CSRF-Token`. No other UI change.
- Tests: unauthenticated approve -> 401; audience-origin approve -> 403; CSRF-less approve -> 403;
  operator token cannot approve; approver cannot run operator actions; approver id present in the audit
  leaf and approval token; red-team app route set is exactly the two routes; operator actions audited.

## 4. Prompt-injection classifier (W3) — §3
- `trishul/ml/injection.py`: model `protectai/deberta-v3-base-prompt-injection-v2` pinned to a commit
  sha (resolve with `huggingface_hub.model_info(...).sha` once, hardcode in `trishul/ml/models.py`).
  transformers on CPU/MPS; switch to the repo's ONNX export (onnxruntime) only if measured CPU p50 per
  512-token chunk > 150 ms — record the measurement either way. New optional extra `ml`.
- Chunking: 512-token windows, stride 64; the signal is the max INJECTION probability over chunks.
- Output `MLSignal{status: ok|timeout|error|unavailable|disabled, score: float|None, threshold, escalate,
  reason}`. Threshold default 0.5 (config). `timeout|error|unavailable` -> `escalate=True` and a logged
  reason (fail closed). Timeout default 2 s.
- Where it runs: on untrusted content when it becomes a handle (documents, emails, voice transcripts,
  untrusted tool results) — i.e. before planning — and again at sink time in `Pipeline._ml` over the
  handles feeding the call. The existing `hidden_text_score` heuristic stays as a separate signal.
- Monotone only: escalation = STEP_UP by default, DENY for payment/egress sink calls; combined with
  `Decision.combine` (never lowers). An approval waives only a classifier STEP_UP, never a DENY.
- `trishul ml off` -> the pipeline records `ml_signal: "disabled"` in the event and audit leaf.
- Bench ablation (`trishul bench`): `rules_only` (ML off), `rules_classifier` (rules + DeBERTa only),
  `full` (rules + DeBERTa + hidden-text + anomaly + voice spoof). Real numbers only; if the model is not
  installed the ablation row says `NOT RUN: model unavailable`.
- Tests: known injection escalates; benign text unchanged; model unavailable/timeout/exception ->
  escalation not ALLOW; ML off -> all India-suite attacks still blocked (acceptance 5); unit tests use
  a fake classifier; one real-model test marked `ml_models` (auto-skip when absent, but run it locally).

## 5. Quarantined reader + local LLM (W4) — §4, §7
- `trishul/llm.py`: `select_model()` reads RAM (`sysctl hw.memsize` / `/proc/meminfo`): >= 16 GiB ->
  `Qwen/Qwen3-8B` (Ollama `qwen3:8b`), else `Qwen/Qwen3-4B` (`qwen3:4b`). Pins (HF id, Ollama tag, Ollama
  digest from `/api/tags`) in `trishul/ml/models.py` next to W3's pin — W4 owns the LLM entries, W3 the
  classifier entry; keep them in separate dict literals to avoid merge conflicts. At start: log chosen
  model; digest mismatch or server down -> reader uses the deterministic fallback and `/readyz` says so.
  Write `{hf_id, ollama_tag, digest, selected_by}` into `bench/results.json` (`environment.llm`, update
  `bench/schema.json`) and an audit leaf `system_start` at `trishul start`.
- Handles: `$DOC_n`, `$EMAIL_n`, `$VOICE_n` (update `OpaqueHandle` regex and `SessionHandles`).
- `trishul/reader/`: typed schemas (Pydantic, `extra="forbid"`): `InvoiceFields{payee_vpa: str (VPA
  pattern), amount_paise: int > 0, due_date: date | None, invoice_id: str | None}`,
  `VoiceCommandFields{intent, payee_vpa, amount_paise}`, `EmailFields{sender, subject_intent}`.
  `QuarantinedReader.read(handle, schema) -> dict[str, Labeled]`: the LLM gets only the raw text + JSON
  schema (Ollama OpenAI-compatible chat, `response_format` json schema, temperature 0, seed 42, no tools,
  fresh context each call, no planner history). Output validated with `model_validate_json`; any failure
  -> `ExtractionError` -> the call is DENY with reason `CORE.READER.INVALID`. Each value becomes a
  `$VAR_n` handle labelled with the source handle's label (UNTRUSTED + source file).
- Modes: `TRISHUL_READER=llm|replay`. Scripted demo moments and `trishul bench` use `replay` (existing
  deterministic regex extractors), labelled `reader: "deterministic-fallback"` in events/audit, same
  labelling rules. The Red-Team Wall uses `llm` when available (reader over the audience text), with the
  existing 20-submission fallback queue.
- Gateway-native tool `read_handle(handle, schema)`; `extract_field` stays and delegates to the reader.
- Tests: an injection inside a document cannot change which tools the scripted planner calls, and no
  MCP response to the planner contains the raw untrusted text (scan every response); extracted values
  carry UNTRUSTED labels with the source; malformed / extra-field / wrong-type LLM output -> DENY (fake
  LLM); `select_model` picks by RAM; LLM down -> fallback, labelled.

## 6. Launch extras (W5) — §5 hygiene, §6, §9
- `LICENSE` Apache-2.0 (copyright "2026 TRISHUL contributors"); SPDX header
  `# SPDX-License-Identifier: Apache-2.0` on `trishul/**/*.py` and `scripts/*.py`.
- `.gitignore` adds: `.trishul/`, `.env` (keep), `models/`, `bench/raw/`, `recordings/`,
  `data/voice/*` except `data/voice/README.md` and `data/voice/manifest.csv`, `*.key`, `*.pem`.
- Secret scan: `.gitleaks.toml` (allowlist test dummies such as `tests/unit/test_redaction.py`, SRI
  hashes, model shas) and `scripts/quality.sh` running pytest, ruff, format check, mypy, and
  `gitleaks detect --no-banner` (fallback `uvx detect-secrets scan` if gitleaks is not installed, and say
  so). Add it to the GitHub workflow as a job.
- Voice dataset tooling: `data/voice/README.md` (consent rules, how to record, TTS/clone model + licence
  field, deletion-on-request, download/setup note), `data/voice/manifest.csv` header
  `file,speaker_id,type,condition,language,consent,duration_s` (+ `source_model,source_license` columns
  for clones), `scripts/voice_dataset.py` with `validate` (every row has consent=yes, clone rows name a
  model+licence, files exist, durations match) and `phone-codec` (8 kHz narrowband G.711 mu-law via
  numpy, ffmpeg AMR when available). Recording real people and generating clones is a human task: no
  clips are fabricated; report `NOT RUN: needs team recordings and written consent`.
- `trishul bench --export-deck` writes `docs/deck-numbers.md` from `bench/results.json` (every row cites
  its JSON path). Tests: export is deterministic and contains no number absent from the JSON.
- Replace short model names in docs/config with the full IDs listed in §0.

## 7. Acceptance numbering 1–17 (W6, after W1–W4 merge) — §0
Canonical list (docs, test markers, CLI output, evidence table):
1 gateway-only · 2 labels persist · 3 untrusted->sink DENY · 4 fail closed · 5 ML only tightens ·
6 tampered mandate · 7 over-limit STEP_UP · 8 approval binding · 9 purpose mismatch · 10 consent
withdrawal · 11 external PII email · 12 cloned voice · 13 real high-value voice STEP_UP · 14 replay ·
15 Z3 UNSAT + counterexample · 16 Merkle tamper · 17 real benchmark output.
- `@pytest.mark.acceptance(n)` marker; registry `tests/acceptance.py` maps n -> node ids.
- `trishul acceptance` runs them, prints `AT-01..AT-17 PASS/FAIL/NOT RUN(reason)`, writes
  `docs/acceptance-evidence.md`.
- The old Phase-3 AT-11 (OFF mode), AT-14 (red-team), AT-17 (WS) stay as supplementary tests `S-OFF`,
  `S-RT`, `S-WS`. Renumber `docs/phase-3-report.md` references with a mapping note, not a rewrite.

## 8. UI links — §8
`TRISHUL_DASHBOARD_PROMPT.md` and `TRISHUL_LANDING_PROMPT.md` do not exist anywhere under the project,
and `<CONSOLE_UI_PATH>`/`<LANDING_UI_PATH>` were not filled in. Per the brief, no design is invented. The
existing `Trishul-Console.dc.html` / `Trishul-Landing.dc.html` remain the visual source of truth (as in
Phase 3); only verification (live WS/API, stats from `bench/results.json`, missing values hidden) is done.

## 9. Work split
| Worker | Model | Owns |
|---|---|---|
| W1 keys + bypass | Sonnet | `trishul/crypto/*`, new `trishul/crypto/toolauth.py`, `trishul/servers/*`, `trishul/gateway/server_main.py`, `trishul/gateway/app.py`, `trishul/approvals.py` (kid only), `trishul/audit/*` (kid only), `docker-compose.yml`, `Dockerfile`, `cli/main.py` key/reset parts |
| W2 auth + red-team app | Sonnet | new `trishul/auth/`, `trishul/telemetry/api.py`, `trishul/redteam/app.py`, `trishul/approvals.py` (approver id), console APPROVALS drawer, `cli/main.py` approve/reject/start parts |
| W3 classifier | Sonnet | new `trishul/ml/`, `trishul/gateway/pipeline.py` (`_ml`, handle scoring), `trishul/bench/*` ablation |
| W4 reader + LLM | Sonnet | new `trishul/reader/`, `trishul/llm.py`, `trishul/gateway/taint.py`, `trishul/gateway/native_tools.py`, `trishul/provenance/handles.py`, `trishul/redteam/service.py`, `bench/schema.json` |
| W5 launch extras | Sonnet | `LICENSE`, headers, `.gitignore`, `.gitleaks.toml`, `scripts/quality.sh`, `scripts/voice_dataset.py`, `data/voice/*`, `.github/workflows/*`, `--export-deck` |
| W6 acceptance | Sonnet | `tests/acceptance.py`, markers, `trishul acceptance`, evidence doc |
| Gate review | Opus | diff vs this spec, security review of W1/W2 |
Shared-file rule: if you must touch a file owned by another worker, keep the edit minimal and mention it
in your report.
