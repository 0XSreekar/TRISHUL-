# TRISHUL — UI Refinement Plan (post Phase 4)

Owner request (2026-10-01): responsive, polished dashboard; every navbar item is its own page; each major
feature has 3 pages; no dead links; Landing → Dashboard → Feature → its 3 pages → back; final landing pass last.
This supersedes the Phase 4 "do not redesign the UI" rule for the UI files only. Backend behaviour is unchanged.

## 1. Hard constraints (keep tests green)
- Keep file names and paths: `Landing page and dashboard implementation/Trishul-Console.dc.html`,
  `Trishul-Landing.dc.html`, `support.js`, `vendor/*`. Served at `/console/...` (see `tests/unit/test_ws_api.py`).
- Keep the `.dc.html` runtime format (`<x-dc>`, `support.js`, React UMD + Babel). No build step, no new CDN.
- `tests/unit/test_ui_safety.py`: no `innerHTML`, `dangerouslySetInnerHTML`, `outerHTML`, `insertAdjacentHTML`,
  `document.write`, `eval` of data. All untrusted text rendered as text.
- `tests/unit/test_bench_schema.py`: no hardcoded metric literals. Every number comes from the API,
  the WebSocket, or `bench/results.json`; a missing value renders as an em dash or is hidden. No fake data,
  no placeholder numbers, no lorem ipsum.
- Keep all existing data wiring: WS `/events` with resume, every REST call, `#op=` token handling (read once and
  stripped before routing), approver login + CSRF, replay mode (`replay/demo-session.json`).
- Keep the design language: existing colour tokens (#45829B blue/ALLOW, #E8A33D amber/STEP_UP, #E5533D red/DENY,
  #4FD1C5 teal, #CAD9E2 text, #8B98A1 muted), Outfit + JetBrains Mono. Move them into CSS custom properties on
  `:root` if not already; one spacing scale (4/8/12/16/24/32/48).
- `prefers-reduced-motion` respected; keyboard focus visible; contrast AA for text.

## 2. Layout (console)
- Replace the fixed 1920×1080 scaled canvas and absolute positioning with a fluid layout:
  sticky top bar (logo → `#/`, mode/ML/connection status, approver sign-in state) + left sidebar nav
  (collapses to an icon rail < 1200 px and to a top menu button < 760 px) + scrollable main area using CSS grid
  (`auto-fit, minmax(...)`) cards. No overlapping elements, no horizontal page scroll at 360 px width.
- Each feature page: page header (title, one-line plain-English purpose, breadcrumb `Dashboard / Feature / Page`),
  a 3-tab sub-navigation (real routes, not hidden panels), then content. A "Back to dashboard" link on every page.
- The old right-edge drawer is retired: its sections become pages. The call-detail view (lineage, rule ids,
  latency) becomes a slide-over that any feed row can open, and is deep-linkable `#/call/<id>`.

## 3. Routes (hash router, `#/<feature>/<page>`; unknown route → Overview with a small notice)
| Nav item | Route | Page 1 | Page 2 | Page 3 |
|---|---|---|---|---|
| Overview | `#/` | Hub: KPI strip (calls, blocked, attacks stopped, p99 — live only), the three agents, lineage graph with the gate line, attacks/min chart, decision timeline. Feature cards link to each feature. | — | — |
| PayShield | `#/payshield/...` | `live` — payment calls feed + lineage of the selected call | `mandates` — signed mandates, caps, payees (`/mandates`) | `ledger` — OFF vs ON story: demo_off vs protected executions and their decisions |
| PurposeLock | `#/purposelock/...` | `live` — data-access calls + purpose decisions | `consent` — consent registry, withdraw (`/consent`, operator) | `dpdp` — DPDP report (`/report/dpdp`) |
| VoiceTrust | `#/voicetrust/...` | `live` — voice command calls, spoof/liveness verdicts | `challenge` — liveness phrase/nonce (`/voice/nonce`) and how replay is caught | `models` — detector pins (full model IDs), readiness, bench voice metrics if present |
| Approvals | `#/approvals/...` | `pending` — queue + approver login + approve/reject (cookie + CSRF) | `binding` — selected approval: call digest, scope, expiry, signed by kid, approver id; "change one rupee → void" explanation | `history` — resolved approvals with approver ids |
| Proof | `#/proof/...` | `z3` — run live / unsafe-fixture proofs, show UNSAT / SAT + counterexample | `audit` — Merkle leaves, tree head, verify, tamper result with bad index | `bench` — `bench/results.json`: India suite, ablation rows, latency |
| Red-Team | `#/redteam/...` | `wall` — live submissions and decisions (text only) | `stats` — attempted/succeeded, rules hit | `controls` — kill/resume, fallback queue, audience URL `:8789` |
| Demo | `#/demo/...` | `moments` — guided moments 1–6 with per-step buttons and the presenter line for each | `controls` — mode ON/OFF, ML on/off, reset (operator) | `system` — `/readyz`: models, reader mode, LLM pin, public key ids |

Operator-only actions show a clear "operator token required" state when `#op=` was not supplied (disabled
button + reason), never a silent failure. Approver actions show the sign-in form when signed out.

## 4. Landing (do last)
- Same tokens and type scale as the console; fix misalignments, spacing, overlap, responsiveness (360 px → 1920 px).
- Nav anchors work; "Open console" / "Live demo" CTAs go to `Trishul-Console.dc.html#/`; each feature card links
  to its console page (`#/payshield/live`, `#/purposelock/live`, `#/voicetrust/live`), proof section to `#/proof/bench`.
- Stats still only from `bench/results.json`; missing values hidden.
- Verify animations/transitions and reduced-motion.

## 5. Done means
- Every nav item and every tab routes to a real page with real content or a truthful empty state; no dead links.
- Back/forward browser buttons work; reload keeps the route.
- Checked at 375, 768, 1280, 1920 widths with headless screenshots; no overlap or horizontal scroll.
- `uv run pytest -q`, `ruff`, `mypy` still green; the console still loads at `/console/Trishul-Console.dc.html`
  against a running `trishul start` and receives live events.
