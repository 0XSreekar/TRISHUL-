# TRISHUL

A policy gateway that sits between an AI agent and its tools (MCP). Every tool call is checked
against a compiled policy with provenance labels (untrusted content cannot reach a payment or
egress sink), payment mandates, purpose/consent rules (DPDP) and voice-trust checks, then written
to a Merkle-chained, Ed25519-signed audit log. Failures never turn into ALLOW.

**Thesis: ML can improve recall, but security does not depend on model correctness.** Classifiers
and the voice anti-spoof detector can only raise a decision (ALLOW → STEP_UP → DENY), never lower
it (invariant I2, Z3-proved). The blocks that matter come from provenance rules, signed mandates and
exact-call approvals, which is why `trishul ml off` changes nothing on the attack suite.

Landing page and operator console live in `Landing page and dashboard implementation/`
(served by the gateway at `/console`). Architecture: `docs/architecture.md`; threat model and the
seven invariants: `docs/threat-model.md`.

## Clean install (macOS, Apple Silicon recommended)

```bash
brew install uv                       # or: curl -LsSf https://astral.sh/uv/install.sh | sh
uv sync --extra dev                   # Python 3.12, core only
uv sync --all-extras                  # optional: voice models (mlx-whisper, DF_Arena, torch)
bash scripts/prewarm.sh               # optional: warm Ollama / voice models; skips when absent
uv run pytest -q                      # sanity check
```

## Run

```bash
uv run trishul demo reset --seed 42            # deterministic state (default DB: ./trishul.db)
uv run trishul start --port 8787 --mcp-port 8788
# Console:  http://localhost:8787/console/Trishul-Console.dc.html
# MCP:      http://127.0.0.1:8788/mcp        WS: ws://localhost:8787/events
```

Startup writes an operator token to `<db_dir>/operator.token` (mode 0600; the path is printed, never the
token). Set `TRISHUL_OPERATOR_TOKEN` to choose your own. Every state-changing operator route (mode, ML,
approvals, consent withdraw, prove, tasks, demo reset/moments, red-team kill/fallback) requires
`Authorization: Bearer <token>`, from any client address. The console reads the token from the URL
fragment: open `.../Trishul-Console.dc.html#op=<token>`. `trishul start --host` (default `127.0.0.1`)
sets the bind address for both the API and MCP servers. `TRISHUL_TRUSTED_PROXY=1` keys the red-team
rate limit on `CF-Connecting-IP` (never used for auth).

Other commands: `trishul verify`, `trishul prove`, `trishul report --dpdp`, `trishul ml on|off`,
`trishul bench --seed 42`, `trishul demo tamper --idx N`, `trishul redteam kill|resume`,
`trishul approve|reject <id>`, `trishul task bind ...`. Set `TRISHUL_DB` to change the database path.

## Docker (gateway, tool servers, console UI, SQLite volume only)

```bash
docker compose up --build
curl http://127.0.0.1:8787/healthz
```

Models are not in the container; run Ollama / mlx-whisper natively (container reaches Ollama at
`host.docker.internal:11434`). Ports are published to host loopback only; see
`docker-compose.yml` and `docs/threat-model.md` for why. The container runs `trishul start --host 0.0.0.0`;
the operator token file is written to the `/data` volume (`/data/operator.token`).

## Evidence

Every number below is copied from `bench/results.json` (commit a924c5b, clean tree, seed 42,
Apple M5) or `bench/voice_eer.json`; regenerate with `uv run trishul bench --seed 42`.

| Measure | Without TRISHUL | With TRISHUL |
|---|---|---|
| India suite attack success (49 attacks; 36 have an OFF path) | 0.9167 | **0.0** (0/49) |
| India suite benign utility (34 tasks) | 0.8966 | 0.8529 (29/34; the 5 misses are voice payments waiting for approval by design) |
| AgentDojo banking subset, local qwen3:8b (8 user tasks × 4 injections) | ASR 0.2188, utility 0.375 | ASR **0.0**, utility 0.25 |
| Gate decision latency, in-process (750 samples) | — | p50 0.837 ms, p99 1.754 ms (ML on); p99 1.798 ms (ML off) |

Ablation (rules only / rules + classifier / full): identical ASR 0.0 and utility 0.8529. The rules
decide this suite; the ML adds nothing measurable here, so it is not credited.

Voice anti-spoof (DF_Arena 1B, 134 real clips: LibriSpeech English, FLEURS Hindi and Telugu, one
owner clip; 90 content-matched macOS TTS clips), at the production threshold 0.5:

| Channel | Real voices wrongly flagged | TTS accepted | EER |
|---|---|---|---|
| Clean 16 kHz | 2.2 % | 0 % | 0.0 |
| Synthetic phone (8 kHz μ-law) | 19.4 % (Hindi 40 %, Telugu 40 %) | 0 % | 0.0 |

EER 0.0 only says Apple TTS is easy to separate (at a threshold near 0.99); it says nothing about
neural voice clones, which were not tested.

## Honest limitations

- Voice-initiated payments always need a fresh nonce plus out-of-band approval, whatever the
  detector says, so the detector is never the only barrier. That is also why the India suite has 0
  voice bypasses.
- Real-voice false rejects are high on phone-quality audio (19.4 %, 40 % for Hindi/Telugu), and the
  project owner's WhatsApp voice note was flagged as a spoof (0.91). Fail-closed, but real users get
  DENY. The detector is miscalibrated for 0.5 (clean separation sits near 0.99).
- Speech recognition: Telugu auto-detect picks Tamil (10/10, CER 0.94); forcing Telugu gives CER 0.22.
  Hindi WER 0.36 auto vs 0.19 forced. Production should pass the user's language.
- Not measured: neural voice clones, real VoIP codecs (Opus/AMR), live callers. The English real set is
  one LibriSpeech speaker.
- AgentDojo: banking only, 8 of 16 user tasks × 4 of 9 injections; only money-moving tools are
  guarded. Workspace and Slack suites were not run.
- DF_Arena is non-commercial and is loaded with `trust_remote_code=True`, only from a reviewed,
  pinned local snapshot (`trishul/domains/voice_adapters.py`).

## Demo quickstart

```bash
uv run trishul demo reset --seed 42
uv run trishul start            # prints a command that opens the console with the operator token
```

Then run moments 1–6 from the console's DEMO drawer (or `POST /demo/moment/{n}`). Moments 3–6
switch TRISHUL ON themselves if moment 2 was skipped. Full five-minute script, fallbacks and recovery:
`docs/demo-runbook.md`.

## Free static hosting (landing page only)

The landing page is static and reads `bench/results.json`; no backend is deployed anywhere.

- **GitHub Pages:** `.github/workflows/pages.yml` publishes the landing page plus `bench/results.json`
  on every push to `master` that touches them. Enable it once under *Settings → Pages → Source:
  GitHub Actions*.
- **Vercel (free tier, static only):** assemble the same folder and deploy it as a static site:

  ```bash
  mkdir -p _site/bench && cp -r "Landing page and dashboard implementation/." _site/ \
    && rm -rf _site/replay && cp bench/results.json _site/bench/ \
    && cp _site/Trishul-Landing.dc.html _site/index.html
  npx vercel deploy _site --prod     # no build step, no serverless functions
  ```

The operator console is never published: it needs a local gateway and an operator token.

## Recording plan (GIF / backup video)

1. `trishul demo reset --seed 42`, start the gateway, and open the console at 1440×900 with Wi-Fi off.
2. Record the whole screen with QuickTime (*File → New Screen Recording*) while running moments 1–6
   from the runbook; keep this full take as the backup video.
3. Cut three short GIFs (for example with `gifski`): OFF payment → ON DENY with animated lineage;
   STEP_UP → approve → changed amount DENY; `demo tamper` → `verify` failing at the exact leaf.
4. Never record the `#op=` console URL, the token file, or a terminal that has printed either.

Docs: `docs/architecture.md`, `docs/threat-model.md`, `docs/demo-runbook.md`, `docs/phase-3-plan.md`,
`docs/phase-3-report.md`.
