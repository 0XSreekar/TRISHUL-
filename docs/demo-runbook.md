# Demo runbook

All commands run from the repo root with `uv run`. Numbers quoted here come from `bench/results.json`
(India suite: 49 attacks / 34 benign; with TRISHUL attack success 0.0 = 0/49, utility 0.8529 = 29/34; gate
decision latency p99 1.754 ms in-process). Never quote a number that is not in that file.

## 1. Hardware and browser
- Apple Silicon Mac (measured on Apple M5), 16 GB+ RAM, charger connected, Do Not Disturb on.
- Chrome or Safari latest, one window, zoom 100%, extensions disabled, second tab for the landing page.
- Open the console only via `http://localhost:8787/console/Trishul-Console.dc.html` (Origin allowlist is
  exact-match on `localhost:8787` / `127.0.0.1:8787`; other hosts get 403 `forbidden_origin`).

## 2. Startup order
1. `ollama serve` (optional; only for AgentDojo/local LLM, not the scripted path).
2. `bash scripts/prewarm.sh` (skips anything absent; safe to run repeatedly).
3. `uv run trishul demo reset --seed 42`
4. `uv run trishul start --seed 42 --port 8787 --mcp-port 8788` (prints `readiness:` JSON; voice/ollama are
   informational and never block the core demo).
5. `curl -s localhost:8787/healthz` -> `{"ok":true}`; `curl -s localhost:8787/readyz`.
6. Open the console; header must show connected, TRISHUL ON, ML state.

## 3. Warm-up
`scripts/prewarm.sh` pings Ollama (`keep_alive` 30 min) and runs one silent clip through mlx-whisper and
DF_Arena so the first voice moment is not a cold load. Then run moment 3 once privately and reset.

## 4. Reset (between runs and rehearsals)
`uv run trishul demo reset --seed 42` (running gateway picks up the control row) or
`POST /demo/reset {seed:42}` from the console. Reset also restores mode ON. Deterministic ids mean the
same call ids each run.

## 5. Command reference
| Purpose | Command |
|---|---|
| Start | `uv run trishul start` (`--in-process` if subprocess servers misbehave) |
| Benchmarks | `uv run trishul bench --seed 42` (writes `bench/results.json`) |
| Z3 proofs | `uv run trishul prove` |
| Audit verify | `uv run trishul verify` |
| DPDP report | `uv run trishul report --dpdp > dpdp-report.json` |
| ML on/off | `uv run trishul ml off` / `ml on` (pushes live `ml_state` to the console) |
| Reset | `uv run trishul demo reset --seed 42` |
| Tamper | `uv run trishul demo tamper --idx 2` then `uv run trishul verify` (expect `bad_index`) |
| Red-team kill | `uv run trishul redteam kill` / `resume` |
| Approvals | `uv run trishul approve <id>` / `reject <id>` |

Backup/recovery: the state is one SQLite file (default `./trishul.db`, or `$TRISHUL_DB`; in Docker
`/data/trishul.db`). Stop the gateway, `cp trishul.db trishul.db.bak` (also copy `-wal`/`-shm` if present,
or copy after a clean stop). Recover with `cp trishul.db.bak trishul.db` or simply
`uv run trishul demo reset --seed 42` (re-derives keys from the seed). Docker:
`docker compose cp gateway:/data/trishul.db ./trishul.db.bak`.

## 6. Scripted 5-minute sequence and presenter script
Moments are driven by `POST /demo/moment/{n}` (console buttons) via FinBot. Timing is a guide.

**Moment 1 (0:00-0:45) Unprotected agent, TRISHUL OFF.** Toggle OFF (red banner). Run moment 1: FinBot reads
the injected invoice and pays the hidden VPA; a real `demo_off` ledger row appears.
Say: "This is a normal agent reading a normal-looking invoice. There is white text in it. The agent paid the
attacker. Nothing was hacked; it just believed its input. Note the banner: OFF is explicit, isolated and still
audited."

**Moment 2 (0:45-1:15) Integration is two lines.** Show the two-line diff (`MCP_URL=http://127.0.0.1:8788/mcp`),
toggle ON. Say: "TRISHUL is an MCP proxy. Your agent changes its server URL; nothing else changes."

**Moment 3 (1:15-2:15) Same invoice, blocked; benign allowed; approval binding.** Run the same invoice: DENY,
open the drawer: lineage document -> extract -> pay_upi sink, rule id, decision latency from the event. Normal
bill: ALLOW with preview. Over-cap payment: STEP_UP, approve in the console, retry succeeds. Approve then change
the amount: DENY approval-binding mismatch.
Say: "The deny is not a model opinion, it is a rule over provenance. Approvals are signed for the exact call;
change one rupee and it is void."

**Moment 4 (2:15-3:15) Red-Team Wall.** Takes about 40 s on the stdio gateway (20 queued attacks, each spawning a tool server); the demo drawer shows `RUNNING · STEP k/4`, so talk over it. Show the wall; let the audience submit (or the fallback queue runs).
Counters attempted/succeeded come from the audit log. Say: "Try to break it. Every attempt runs through the
same pipeline in a separate namespace. The counter is computed from audit events, not the browser."
Fallback: see section 7.

**Moment 5 (3:15-4:15) ML off, proofs.** `uv run trishul ml off` (console flips live). Re-run top 5 attacks:
still DENY. Click Prove (live): I1 UNSAT. Click Prove (unsafe fixture): SAT counterexample plus a replay.
Say: "Switch the ML off and the rules still block. Z3 proves no untrusted value reaches a payment sink. Here is
a deliberately broken policy and the exact call that breaks it. The live policy was never swapped."
Be candid: "Voice is different: a voice command can never pay on its own. Every voice-initiated payment needs a
fresh nonce and an out-of-band approval whatever the detector says, so on our India suite 0 of 49 attacks
succeed, at the cost of benign utility 0.8529 because legitimate voice payments wait for approval."

**Moment 6 (4:15-5:00) Voice, audit tamper, DPDP.** Voice fixture: DENY `VOICETRUST.SPOOF.HIGH` (real DF_Arena)
or STEP_UP (deterministic adapter, labelled). Real voice: speak the nonce phrase -> STEP_UP -> approve in the
console -> the exact retry runs (summary shows `liveness: match`, `resumed_after_approval: true`). Replayed
recording: nonce mismatch DENY. Check `/readyz` shows `voice_models: available` (not `warming`) before this
moment; the gateway warms the models itself at start (about 90 s on a cold Mac).
If asked about accuracy: "On clean audio 2 % of real voices get flagged; over a phone line it is 19 %, and 40 %
for Hindi and Telugu. That is why the detector can only escalate: a real person gets an approval prompt, never
a silent payment." Then
`uv run trishul demo tamper --idx 2` and `uv run trishul verify` -> exact `bad_index`. Download the DPDP report.
Say: "Every decision is in a signed Merkle log. Flip one byte and we tell you which record. Consent withdrawal
takes effect immediately and the DPDP report is generated from the same log."

## 7. Red-team fallback and kill switch
- Public submissions require `TRISHUL_REDTEAM_PUBLIC=1`; otherwise localhost only. With no network or no
  audience, use the 20 deterministic fallback submissions (`trishul/redteam/queue.json`, events labelled
  `source:"fallback_queue"`). Say so on stage.
- Kill switch: `uv run trishul redteam kill` (or `POST /redteam/kill {on:true}` / console button). Resume with
  `redteam resume`. Offensive text is shown as `[withheld by display filter]` but still evaluated.
- If moderation/abuse appears: kill first, explain after.

## 8. Offline behaviour
The scripted path needs no network. Landing/console vendor React/Babel under
`Landing page and dashboard implementation/vendor/` (prefer local, unpkg fallback); Google Fonts fall back to
system fonts (visual degradation only). Ollama/AgentDojo/voice models are optional. Public red-team needs
network; use the fallback queue.

## 9. Backup video and second-laptop hot standby
- Record a clean full run (screen + audio) after rehearsal 3; keep it local (not streamed) and opened in a
  player before you start. Switch to it on any unrecoverable failure.
- Second laptop: same repo commit (`git rev-parse HEAD` matches), `uv sync`, `trishul demo reset --seed 42`,
  `trishul start` already running, console open on a background window, copy of the latest
  `trishul.db.bak`. Same seed gives same ids, so the script is identical. Verify with `curl /healthz` before
  the session.

## 10. Failure symptoms -> one-command recovery
| Symptom | Recovery |
|---|---|
| Console shows disconnected / WS lost | Reload page (WS resumes); else `uv run trishul start` again |
| Port in use | `lsof -ti :8787 -ti :8788 \| xargs kill`; restart |
| Console actions return 403 `forbidden_origin` | Open via `http://localhost:8787/console/...` exactly |
| State looks wrong / leftover events | `uv run trishul demo reset --seed 42` |
| Audit shows tampered after a demo | `uv run trishul demo reset --seed 42` |
| Tool server subprocess fails | `uv run trishul start --in-process` |
| Voice moment slow or models unavailable | `bash scripts/prewarm.sh`; else use the labelled deterministic path |
| Red-team abuse or slow | `uv run trishul redteam kill` |
| DB corrupt | `cp trishul.db.bak trishul.db` or `demo reset` |
| Docker container unhealthy | `docker compose restart gateway` (or run natively) |
| Everything down | Play backup video; switch to standby laptop |

## 11. Three-rehearsal checklist
Rehearsal 1 (alone, natively): [ ] clean clone + `uv sync` works [ ] `uv run pytest -q` green [ ] prewarm
[ ] all six moments in order [ ] reset returns identical state [ ] `verify` ok after reset.
Rehearsal 2 (with a colleague, projector/resolution, offline): [ ] Wi-Fi off, scripted path works [ ] red-team
fallback queue [ ] kill switch [ ] timing under 5:00 [ ] recover from one deliberately injected failure from
section 10.
Rehearsal 3 (dress, final hardware): [ ] record backup video [ ] standby laptop matches commit and runs
[ ] `docker compose config` ok if Docker is used [ ] run `trishul bench --seed 42` and confirm numbers
quoted in the script match `bench/results.json` [ ] battery/charger, notifications off.

## 12. Docker status and tunnel
`docker-compose.yml` publishes only `127.0.0.1:8787` and `127.0.0.1:8788`; the container starts with
`trishul start --host 0.0.0.0`. The container never sees a loopback client, so the host-loopback publish
is the network boundary, and operator routes are additionally protected by the operator token.

**Operator token.** `trishul start` writes `<db_dir>/operator.token` (mode 0600; `/data/operator.token` in
Docker) and prints only its path. Or set `TRISHUL_OPERATOR_TOKEN`. All mutating operator routes need
`Authorization: Bearer <token>` from every client, including localhost. Open the console as
`http://localhost:8787/console/Trishul-Console.dc.html#op=<token>`.

**Tunnel (Cloudflare etc.).** Set `TRISHUL_REDTEAM_PUBLIC=1` and `TRISHUL_TRUSTED_PROXY=1` (rate limit keyed
on `CF-Connecting-IP`; never used for auth). Only the red-team submit route is public; every operator
route stays token-protected, so never share the `#op=` URL or the token file through the tunnel.
