# Phase 2 Security Kernel Report

## Gate Checklist
✅ Invoice-injection payee blocked end-to-end through real MCP gateway (scenario 1 + live smoke: attacker VPA refund.desk@ybl → DENY PAYSHIELD.MANDATE…)
✅ Benign trusted payment ALLOW with preview and real ledger change (scenario 2)
✅ Step-up approval Ed25519-bound to exact call digest, single-use, consumed before execution
✅ Changed args → DENY (scenarios 3,4)
✅ Audit tamper detected with exact leaf index (live CLI: flipped a bit in leaf 2 → `{"bad_index": 2, "ok": false}` exit 1)
✅ Fail-closed Hypothesis test over stages 2–6
✅ UI HTML files unchanged (served read-only at /console)
✅ All tests, ruff, mypy strict pass

## Test Report
- **Unit + Integration Tests**: 415 passed in 21.37s
- **Formal Verification**: UNSAT (22 invariants)
- **Z3 Policy Analysis**: 4 real gaps initially found (I1 add_payee vpa, export_records destination, send_email to; I4 issue_refund without mandate) → fixed in gate commit; all invariants now UNSAT; deliberately unsafe fixture still yields a counterexample

## Review-Gate Fixes
- **CSRF on REST**: Origin allowlist exact-match, "null" removed, JSON required when body present
- **Universal Approval Binding**: Non-voice STEP_UP bound to exact call digest
- **Voice Calls**: Executed under gateway lock
- **I1 Refinement**: ALLOW resting on valid human approval for exact call excluded from I1 (documented trade-off)

## Integration Scenarios
All run through `fastmcp.Client → TRISHUL gateway → tool servers` in `tests/integration/test_scenarios.py` (`uv run pytest -q tests/integration/test_scenarios.py`).

| # | Scenario | Expected | Result |
|---|---|---|---|
| 1 | White-on-white invoice injection changes payee | DENY, lineage document → extract → pay_upi sink | ✅ |
| 2 | Normal trusted invoice | ALLOW, preview effect, ledger changes only after execution | ✅ |
| 3 | Over-cap payment | STEP_UP; approve; exact retry succeeds | ✅ |
| 4 | Amount changed after approval | DENY (approval binding) | ✅ |
| 5 | CRM PII to disallowed email sink | DENY `PURPOSELOCK.EGRESS.PII_WITHOUT_CONSENT` | ✅ |
| 6 | Withdrawn consent | immediate DENY | ✅ |
| 7 | Replayed voice recording | DENY (nonce mismatch) | ✅ |
| 8 | Low-quality / uncertain voice | STEP_UP, never ALLOW | ✅ |
| 9 | Tampered mandate signature | DENY | ✅ |
| 10 | Tampered Merkle leaf byte | verify fails with exact leaf index | ✅ |

Voice scenarios 7–8 still use a scripted ASR test double (deterministic, fast). The same behaviours are
also exercised against the real models in `tests/integration/test_voice_real.py` (marker `voice_models`,
auto-skipped when the models are absent).

## VoiceTrust on real models (measured, `bench/voice.json`)
Apple M5 (arm64), warm, 10 runs per sample x 4 samples pooled (p99 of 40 is effectively the max).
Reproduce: `uv sync --all-extras`, `uv run python scripts/make_voice_samples.py`, `uv run python scripts/bench_voice.py`.

| Backend | Device | p50 ms | p99 ms | Notes |
|---|---|---|---|---|
| mlx-whisper large-v3-turbo (multilingual, auto language) | Metal | 1108 | 1274 | primary ASR |
| faster-whisper small int8 | CPU | 3204 | 3857 | fallback; only used if MLX fails |
| DF_Arena 1B | mps | 398 | 513 | **selected** (p50 < 2 s) |
| DF_Arena 1B | cpu | 769 | 971 | |
| DF_Arena 500M | mps | 159 | 202 | |
| DF_Arena 500M | cpu | 399 | 454 | |

Transcription accuracy (mlx-whisper, synthetic Apple-TTS clips, one clip per language):

| Language | Voice | WER | CER |
|---|---|---|---|
| English (en-US) | Samantha | 0.00 | 0.00 |
| English (en-IN) | Rishi | 0.00 | 0.00 |
| Hindi | Lekha | 0.56 | 0.24 |
| Telugu | Geeta | 1.00 | 1.00 (output came back in Devanagari/garbled; language auto-detect failed) |

Anti-spoof (DF_Arena 500M and 1B, both devices): every TTS clip scored P(spoof) >= 0.999 (en-US, en-IN, Hindi,
Telugu), i.e. all were flagged as spoof, so a TTS clip through the real gateway gets DENY `VOICETRUST.SPOOF.HIGH`.
mps and cpu agree to 4 decimals of rounding.

Pinned revisions (weights loaded only from these snapshot hashes; see `REVISIONS` in `voice_adapters.py`):
whisper-large-v3-turbo `a4aaeec0`, DF_Arena_500M `8258fa8e`, DF_Arena_1B `fb6ce85d`,
xls-r-300m config `1a640f32`, faster-whisper-small `536b0662`. DF_Arena remote code (wav2vec2 + conformer)
was reviewed before `trust_remote_code=True`. Loading uses the pinned local snapshot directory rather than
`repo_id + revision=` because transformers 5.17 fails to stage the transitive `conformer.py` for hub-id loads.
Kokoro voice-clone TTS was not produced: it needs system espeak-ng (not installed), so it does not install cleanly.

## Known Limitations
- Voice corpus is TTS only (Apple system voices, gitignored, regenerated locally). There is NO bonafide human speech
  sample and no consented speaker, so false-reject rate for real humans and detection of real replay/clone
  attacks are unmeasured; only "TTS is flagged as spoof" (score >= 0.999) is demonstrated. No voice-clone sample.
- DF_Arena models are licensed non-commercial research use only; not usable in a commercial deployment.
- Telugu: TTS voice exists (Geeta) but mlx-whisper with auto language detect fails (CER 1.0); Hindi is weak
  (WER 0.56). Only English is reliable. Forcing `language=` per user would likely help (untested).
- Nonce liveness uses word-level edit distance on a bare 3-word phrase: real ASR misheard a word in a few
  percent of attempts (1/60 in one run, up to ~3/8 test runs in another), and run-together transcripts
  ("TurtlePalmSailor") also fail. This fails closed (DENY, user retries), never open.
- Latency figures vary by run and machine load (e.g. mlx-whisper p50 measured 760 ms in an earlier run).
- Approvals/tasks REST unauthenticated localhost (trusted channel assumption)
- CLI approve/reject/ml changes don't push live WS events to running gateway
- Demo clock fixed; TaintRegistry substring matching linear
- Document trust at reset set by filename heuristic ("inject" → external)
- Voice guard thread not cancelled on timeout
- Console `resolve()` posts to /approvals/{event id} — Phase 3 must map event id → approval_id

## Run Commands
```bash
uv sync --all-extras
uv run trishul demo reset --seed 42 --db trishul.db
uv run trishul start --db trishul.db --port 8787 --mcp-port 8788
# MCP: http://127.0.0.1:8788/mcp
# Console: http://localhost:8787/console/Trishul-Console.dc.html
# WS: ws://localhost:8787/events
uv run trishul task bind --purpose ... --category ... --text ...
uv run trishul approve <id>
uv run trishul verify --db trishul.db
uv run trishul prove
uv run trishul report --dpdp
uv run trishul ml on|off
uv run pytest
uv run ruff check . && uv run mypy trishul
```

## Commits (Phase 2)
- 7bf81ae fix: Allow bodyless same-origin console POSTs; keep Origin CSRF check
- eb7fc88 fix: Phase 2 gate - CSRF on REST, Z3 I1/I4 policy gaps, universal approval binding
- ba5158c feat: Phase 2 T6 - Z3 policy translation and invariant proofs
- 3801d72 feat: Phase 2 T5a - MCP gateway pipeline, CLI, integration scenarios
- e0c4271 feat: Phase 2 T5b - event bus, OTel stage metrics, REST/WS API
- 2f65bab feat: Phase 2 T3 - PurposeLock, PII recognizers, DPDP report
- 98015d9 feat: Phase 2 T4 - VoiceTrust with fail-safe adapters
- f33b632 feat: Phase 2 T2 - PayShield, demo MCP servers
- 73f3d14 feat: Phase 2 T1 - crypto, store, Merkle audit, approvals, fact/sink policy

**Phase 2 Complete** — Security kernel ready for Phase 3 (ASR integration, event-approval mapping, live WS broadcasting).
