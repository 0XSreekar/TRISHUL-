# TRISHUL — Phase 1 Plan (Foundation)

Scope: contracts, label lattice + provenance, policy YAML → typed AST → pure evaluator, redaction, UI integration seams. **Out of scope:** FastMCP proxy runtime, Merkle log implementation, Z3 translation, domain logic (PayShield/PurposeLock/VoiceTrust), ML signals. Those are Phase 2+; Phase 1 only fixes their contracts.

## 0. Repository state (inspected 2026-09-30)

- No backend, no manifests, no tests. Only `Landing page and dashboard implementation/` (static `.dc.html` prototypes + `support.js` + `replay/demo-session.json`).
- `demo-session.json` is a **recorded/synthetic** session that includes a `proof.result = "UNSAT"` claim and precomputed `audit_hash` values. These are not real results → must be isolated behind a labeled dev adapter (see §7).
- Toolchain available: `uv 0.12`, Python 3.12 at `~/.local/bin/python3.12`.

## 1. Architecture decisions

| # | Decision | Trade-off (one line) |
|---|----------|----------------------|
| A1 | Python 3.12 package `trishul/`, uv + hatchling, `src`-less flat layout | Flat layout keeps imports simple; src-layout isolation not needed for an app. |
| A2 | Pydantic v2 `frozen=True, extra="forbid", strict=True` for every contract | Strictness rejects coercion bugs at the boundary at the cost of more verbose fixtures. |
| A3 | Money is `int` minor units (paise); **floats are rejected** anywhere in canonical args | Floats break deterministic hashing and cap comparisons; callers must convert. |
| A4 | Canonical JSON = sorted keys, `(",", ":")` separators, UTF-8, `ensure_ascii=False`, no NaN; digest = SHA-256 | One canonical form feeds audit hashing, policy digests and replay equality. |
| A5 | Label = product lattice `(level, sources, tags)`; join = `(max, ∪, ∪)` | Product of lattices is a lattice, so the laws are provable; cost is set growth (bounded per call). |
| A6 | No declassification API in Phase 1 | Any downgrade path is a laundering vector; it will be added later only as an explicit, audited, rule-ID'd operation. |
| A7 | Policy rules may only **escalate** (`then ∈ {STEP_UP, DENY}`); ALLOW is the base result | Makes Unknown→fire (Kleene) always conservative and makes "ML may tighten, never loosen" a `max()` |
| A8 | Predicate evaluation is three-valued (TRUE/FALSE/UNKNOWN); a rule fires on TRUE **or UNKNOWN** | Missing/malformed data can only increase the decision; slightly more STEP_UPs on incomplete input. |
| A9 | One AST consumed by both runtime evaluator and (Phase 2) Z3 translator | Single source of truth; the AST must stay small and first-order. |
| A10 | Evaluator is pure: no I/O, no clock, no randomness; all context passed in `EvalContext` | Deterministic replay and property testing; caller must snapshot state. |
| A11 | Top-level `evaluate()` catches every exception → `DENY` with rule `TRISHUL.INTERNAL.ERROR` | Fail-closed totality; bugs surface as denials, not bypasses. |
| A12 | Planner sees only `OpaqueHandle` (`$DOC_1`); only `QuarantinedReader` dereferences, and its outputs inherit the source label | Enforces the dual-LLM boundary in types before the reader exists. |
| A13 | SQLite WAL deferred to Phase 2 (audit log); Phase 1 has no persistence | Nothing in Phase 1 needs storage; avoids speculative repositories. |
| A14 | UI stays static HTML; integration via `data-trishul-*` attributes + a small JS adapter interface | Zero visual change; the backend WebSocket plugs into the same interface in Phase 3. |

## 2. Package layout (only modules with implementation or tests)

```
trishul/
  contracts/      canonical.py (canonical JSON, digest, float rejection)
                  values.py    (Absent/Redacted sentinels)
                  labels.py    (Level, SourceRef, Label)
                  calls.py     (ToolCall, ToolResult, SourceMetadata, EgressMetadata)
                  decisions.py (Decision, DecisionReason, Stage)
                  lineage.py   (LineageNode, LineageEdge)
                  events.py    (PolicyEvent)
                  authz.py     (ApprovalToken, Mandate, Consent)
                  audit.py     (AuditLeaf, SignedTreeHead, InclusionProof, ConsistencyProof, ProofResult)
  provenance/     lattice.py   (join, leq, bottom)
                  labeled.py   (Labeled[T], derive())
                  handles.py   (OpaqueHandle, HandleStore, QuarantinedReader protocol)
  policy/         ast.py       (predicate + rule nodes)
                  schema.py    (YAML source model)
                  compiler.py  (YAML → CompiledPolicy, errors with line/col)
                  evaluator.py (pure, total evaluator)
  observability/  redaction.py (redact secrets/PII from events + logs), logging.py (structlog-free JSON logger w/ redaction filter)
  cli/            main.py      (`trishul policy compile|check|eval`)
policies/         payshield-untrusted-to-payment.yaml, purposelock-pii-egress.yaml, highrisk-approval.yaml, trusted-allow.yaml
tests/unit, tests/property, tests/integration
```
`gateway/`, `domains/`, `audit/` (implementation) are **not created** in Phase 1 — their contracts live in `contracts/`.

## 3. Contracts (normative)

Common: all models `ConfigDict(frozen=True, extra="forbid", strict=True)`; `model_dump(mode="json")` + `canonical_json()` is the only serialization used for hashing.

- **Level** `IntEnum`: `TRUSTED_USER=0 ⊑ TRUSTED_SYSTEM=1 ⊑ UNTRUSTED=2`.
- **SourceRef**: `kind: Literal["user","system","tool_result","document","web","email","voice","model"]`, `id: str` (non-empty). Hashable, ordered by `(kind,id)`.
- **Tag** `StrEnum`: `PII`, `PII_AADHAAR`, `PII_PAN`, `PII_PHONE`, `PII_EMAIL`, `FINANCIAL`, `SECRET`, `HEALTH`.
- **Label**: `level: Level`, `sources: frozenset[SourceRef]`, `tags: frozenset[Tag]`. Serialized with sorted lists. `Label.bottom()` = `(TRUSTED_USER, ∅, ∅)`.
- **Absent / Redacted**: `Redacted(reason: str, digest: str | None)` model with discriminator `"$redacted": True`. JSON `null` means explicit null; a missing key means absent; `""`/`[]` mean empty. Never conflate.
- **ToolCall**: `call_id` (ULID/uuid str), `server: str`, `tool: str`, `args: dict[str, JsonValue]` (canonicalised, floats rejected), `arg_labels: dict[str, Label]` (keyed by JSON-pointer arg path, e.g. `/payee/vpa`), `principal: str`, `task_id: str`, `declared_category: ToolCategory | None`, `source: SourceMetadata`, `ts: datetime` (tz-aware UTC required).
- **ToolCategory** `StrEnum`: `READ`, `WRITE`, `PAYMENT`, `COMMUNICATION`, `EXPORT`, `IDENTITY`, `VOICE`.
- **ToolResult**: `call_id`, `value: JsonValue`, `label: Label`, `provenance: tuple[LineageNode, ...]`, `egress: EgressMetadata | None`.
- **Decision** `IntEnum`: `ALLOW=0 < STEP_UP=1 < DENY=2`; `Decision.combine(*ds) = max`.
- **Stage** `StrEnum`: `PARSE`, `SCHEMA`, `LABEL`, `PURPOSE`, `MANDATE`, `APPROVAL`, `CAP`, `ML`, `INTERNAL`.
- **DecisionReason**: `rule_id` (regex `^[A-Z][A-Z0-9_]*(\.[A-Z0-9_]+)+$`), `stage`, `explanation`, `evidence: dict[str, JsonValue]` (must pass redaction), `lineage_refs: tuple[str, ...]`, `unknown: bool` (fired due to UNKNOWN).
- **Verdict**: `decision`, `reasons: tuple[DecisionReason, ...]` sorted by `(decision desc, rule_id)`, `policy_digest`.
- **LineageNode**: `id`, `kind: Literal["source","derivation","transformation","sink"]`, `label: Label`, `ref: str`. **LineageEdge**: `src`, `dst`, `op: str`.
- **PolicyEvent** (UI + audit): `schema_version: Literal[1]`, `event_id`, `ts`, `session`, `agent`, `domain: Literal["payshield","purposelock","voicetrust","core"]`, `tool`, `args: dict[str, JsonValue | Redacted]` (**already redacted**), `labels: dict[str, Label]`, `decision`, `reasons`, `lineage: {nodes, edges}`, `latency_us: int | None`, `audit_leaf_hash: str | None`. `None` = not yet available, never a placeholder.
- **ApprovalToken**: `token_id`, `call_digest` (binds to the exact canonical call), `scope`, `approver`, `issued_at`, `expires_at`, `nonce`, `signature: str | None`.
- **Mandate**: `mandate_id`, `principal`, `payee_vpa`, `max_amount_paise: int>0`, `currency: Literal["INR"]`, `valid_from`, `valid_until`, `max_uses: int>0`, `nonce`, `signature: str | None`.
- **Consent**: `consent_id`, `principal`, `purpose`, `fields: frozenset[str]`, `granted_at`, `withdrawn_at | None`, `status: Literal["active","withdrawn","expired"]`.
- **AuditLeaf** (`index`, `event_digest`, `prev_root | None`, `ts`), **SignedTreeHead** (`tree_size`, `root_hash`, `ts`, `signature | None`, `key_id | None`), **InclusionProof**, **ConsistencyProof**, **ProofResult** (`status: Literal["VERIFIED","FAILED","UNAVAILABLE"]`, `detail`).

## 4. Provenance

- `join(a, b)`, `leq(a, b)` (`level ≤ ∧ sources ⊆ ∧ tags ⊆`), `join_all(labels)` (bottom for empty).
- `Labeled[T]`: frozen `(value, label)`; **no public constructor that accepts a label lower than its parents**. Construction paths: `Labeled.source(value, label)` (ingress only) and `derive(fn, *parents, extra: Label | None) -> Labeled` whose label is `join_all(p.label for p in parents) ⊔ extra`. `map()`/`paraphrase()` go through `derive`.
- `HandleStore`: `put(Labeled) -> OpaqueHandle` (`$DOC_n`, monotonic counter), `get` not exposed to planner type; `QuarantinedReader` protocol `extract(handle, extractor) -> Labeled` inherits label via `derive`.

## 5. Policy

YAML (validated by `schema.py`):
```yaml
version: 1
id: payshield.untrusted_to_payment
tools:
  pay_upi: {category: PAYMENT, args: {payee_vpa: {type: string, required: true}, amount_paise: {type: integer, required: true}}}
rules:
  - id: PAYSHIELD.TAINT.UNTRUSTED_PAYEE
    stage: LABEL
    then: DENY
    explain: "Payee derived from untrusted content"
    when: {all: [{tool_category: PAYMENT}, {label_at_least: {arg: /payee_vpa, level: UNTRUSTED}}]}
```
AST node set (discriminated union, `kind` field): `Const`, `All`, `Any`, `Not`, `ToolIs`, `ToolCategoryIn`, `ArgExists`, `ArgCompare(path, op ∈ {eq,ne,lt,le,gt,ge}, value)`, `LabelAtLeast(path, level)`, `LabelHasTag(path, tag)`, `SourceKindIn(path, kinds)`, `PurposeIs`, `ConsentCovers(purpose, fields_path)`, `MandatePresent`, `MandateCovers(amount_path, payee_path)`, `ApprovalPresent(scope)`, `AmountExceeds(path, cap_paise)`. `Rule(id, stage, then ∈ {STEP_UP,DENY}, explain, when)`. `CompiledPolicy(version, id, tools, rules (sorted by id), digest)`.

Compiler: errors are `PolicyCompileError(path, line, col, message)`, collected (not first-only); duplicate rule IDs, unknown tools/args referenced in paths, `then: ALLOW` are compile errors. Output is canonical JSON; digest = SHA-256 of it. Multiple files merge; conflicts are errors.

Evaluator pipeline (pure): `PARSE/SCHEMA` (unknown tool → DENY `CORE.SCHEMA.UNKNOWN_TOOL`; unknown/missing-required/wrong-type arg → DENY `CORE.SCHEMA.*`; arg without label → treated as `UNTRUSTED` + reason `CORE.LABEL.MISSING`) → rules (Kleene) → `Verdict`. Wrapper catches all exceptions → DENY `TRISHUL.INTERNAL.ERROR`.

## 6. Redaction

`redact(value, label)`: values tagged `SECRET` → `Redacted(reason="secret", digest=None)`; `PII*` → `Redacted(reason="pii", digest=hmac-sha256 prefix with process key)`; plus pattern backstop (Aadhaar 12-digit, PAN `[A-Z]{5}[0-9]{4}[A-Z]`, bearer/API-key shapes, 10-digit Indian mobile, email). `PolicyEvent.from_call()` always redacts; the JSON log formatter runs the same backstop.

## 7. UI integration map

Visual source of truth: `Landing page and dashboard implementation/Trishul-Console.dc.html` and `Trishul-Landing.dc.html`, rendered by the bundled `support.js` (`dc-runtime`: React 18 UMD + Babel from unpkg, `<x-dc>` templates, `{{ }}` bindings, `<sc-if>`/`<sc-for>`). **Not moved, not redesigned.** No CSS/layout edits except state styles that reuse existing tokens.

| Seam (`data-trishul-*`) | Console region (approx. lines) | Phase 1 state |
|---|---|---|
| `feed` | decision timeline rows 197–222 | fed by adapter; empty text exists (`noRows`) |
| `decision-badge` | timeline row decision chip + drawer decision | from event `decision` |
| `lineage-graph` | SVG agent→gate→tool paths 112–139 | static topology from `AGENTS`/`TOOLS` |
| `latency` | header P99 / panel p95 31–67, 179–195 | computed from events; `—` + "unavailable" when none |
| `proof-status` | PROOF drawer view 227–389 | **UNAVAILABLE** unless adapter supplies a real `ProofResult` |
| `approval-state` | APPROVALS drawer | from events; empty state exists |
| `audit-root` | header AUDIT CHAIN 31–67 | **unavailable** unless adapter supplies a real STH |
| `domain-status` | header PAYSHIELD/PURPOSELOCK/VOICETRUST buttons | `unavailable` until domains exist |
| `connection` | status message 69–71 | `connecting` / `live` / `replay (dev)` / `disconnected` / `error` |

Existing mock sources: console `startReplay()` (~440) loads `replay/demo-session.json` (synthetic; includes fake `proof.result=UNSAT` and precomputed `audit_hash`); `AGENTS`/`TOOLS` (394–415) are topology constants, not metrics. Landing reads `bench/results.json` and already shows an explicit missing-stats state (no hardcoded numbers).

The console already contains a `mode: 'replay' | 'live'` switch with a WebSocket client (`connect()`, `wsUrl` prop default `ws://localhost:8787/events`) and REST calls (`/approvals`, `/consent`, `/prove`). These are preserved. In replay mode, `prove()` currently shows the recorded `UNSAT` as if real and the header `root` shows a recorded `audit_hash` — Phase 1 relabels both as synthetic.

Adapter boundary (target; implemented inside the component script if the dc-runtime cannot load an extra file cleanly): `trishul-adapter.js` defines `TrishulEventSource` (`connect(onEvent, onState)`, `close()`), a `WebSocketSource` (live, Phase 3 endpoint) and a `DevReplaySource` (wraps the demo JSON, sets `origin:"dev-replay"`, never forwards the demo `proof`/`audit_hash` as real). A visible "DEV REPLAY — synthetic data" marker uses existing amber token. Marked `// PHASE-3: remove DevReplaySource`.

## 8. Commands
```bash
uv sync --all-extras
uv run ruff format --check . && uv run ruff check .
uv run mypy trishul
uv run pytest
uv run trishul policy compile policies/
```

## 9. Risk register
| Risk | Impact | Mitigation |
|------|--------|-----------|
| FastMCP ≥2.9 proxy/middleware API differs from docs | Gateway design in Phase 2 | Phase 1 installs fastmcp and pins verified symbols in an integration test + notes |
| Z3 translation of `ConsentCovers`/set predicates | Proof coverage gaps | Keep AST first-order; model sets as finite enumerations |
| Kleene UNKNOWN-fires produces excess STEP_UP | UX friction | Emit `unknown=True` in reasons; measure in Phase 2 |
| Label source-set growth over long chains | Memory/latency | Cap + summarise into `kind:*` in Phase 2, never drop level/tags |
| Recorded demo data includes a fake `UNSAT` proof | Misleading UI | Dev adapter only, banner-labelled, removal in Phase 3 |
| Voice/ML model availability (ASR, anti-spoof) | VoiceTrust | Decide in Phase 2 plan; fail-safe to STEP_UP when model absent |
| Signatures (mandate/STH) unspecified | Replay/forgery | Ed25519 decision in Phase 2; fields exist now as `None` |

## 10. Phase 2 order (proposed)
1. Merkle audit log (SQLite WAL, RFC 6962 hashing) + STH signing (Ed25519).
2. FastMCP proxy gateway with policy middleware, wired to evaluator + audit.
3. QuarantinedReader + handle store in the gateway flow.
4. PayShield (mandates, replay nonces, caps, effect preview).
5. PurposeLock (consent store, field minimisation, egress).
6. Z3 translator from AST + proof status events.
7. VoiceTrust (after model-availability decision).
8. Phase 3: UI live adapter over WebSocket; remove dev adapter.
