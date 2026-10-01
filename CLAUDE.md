# TRISHUL Project - Claude Instructions

## 📋 Core Rule
**After EVERY single task (even small ones), update this file with progress.** No exceptions.

---

## 🎯 Project Overview
TRISHUL is an AI-powered landing page and dashboard implementation project. The project includes interactive components for both user-facing landing pages and console dashboards.

## 📁 Project Structure
```
/Users/guts/Projects /TRISHUL ai /
├── Landing page and dashboard implementation/
│   ├── Trishul-Landing.dc.html          # Landing page component
│   ├── Trishul-Console.dc.html          # Console/Dashboard component
│   ├── support.js                       # Shared utilities and support functions
│   └── replay/                          # Replay/history files
├── trishul/                             # Python package (contracts, provenance, policy, observability, cli)
├── policies/                            # Example YAML policies
├── tests/                               # unit / property / integration
├── docs/                                # phase-1-plan.md, fastmcp-notes.md
├── CLAUDE.md                            # This file - PROJECT INSTRUCTIONS
└── .git/                                # Git repository
```

## 🔑 Key Files

### Trishul-Landing.dc.html
- Landing page component
- Size: ~47KB
- Interactive UI for user onboarding/information
- Status: ⏳ To be reviewed

### Trishul-Console.dc.html
- Dashboard/console component
- Size: ~67KB
- Admin/user console with data visualization and controls
- Status: ⏳ To be reviewed

### support.js
- Shared JavaScript utilities
- Size: ~69KB
- Common functions used across components
- Status: ⏳ To be reviewed

---

## 📊 Task Log & Progress

| Date | Task | Status | Notes |
|------|------|--------|-------|
| 2026-09-30 | Initial git setup & repository sync | ✅ Complete | Created initial commit, pushed to GitHub master branch |
| 2026-09-30 | Create CLAUDE.md with task tracking system | ✅ Complete | Added task log table, update-after-every-task rule, git workflow guidelines, and commit templates |
| 2026-09-30 | Add Claude AI watermarks to GitHub | ✅ Complete | ✅ VERIFIED - Claude Code & Anthropic badges visible on GitHub; badges display in README with Project Status section |
| 2026-09-30 | Remove Claude watermarks (badges, README.md) | ✅ Complete | Deleted README.md, removed badges from CLAUDE.md; no Co-Authored-By trailer on new commits |
| 2026-09-30 | Phase 1 foundation: contracts, label lattice, policy YAML→AST→pure evaluator, redaction, CLI | ✅ Complete | See docs/phase-1-plan.md; 111 tests pass, mypy strict + ruff clean |
| 2026-09-30 | Console UI integration seams + dev-replay honesty fixes | ✅ Complete | data-trishul-* hooks, TrishulEventSource adapter; replay proof/audit root shown as synthetic |
| 2026-09-30 | Phase 1 gate re-verification (clean clone) | ✅ Complete | All checks green from fresh clone; fixed replay forwarding synthetic audit_verify (fake TAMPERED) and latency marked measured in replay |
| 2026-09-30 | Phase 2 security kernel (gateway, PayShield, PurposeLock, VoiceTrust, Merkle audit, Z3) | ✅ Complete | 415 tests passed, 22 invariants UNSAT, all CSRF/approval/audit fixes verified end-to-end |
| 2026-09-30 | VoiceTrust on real models (mlx-whisper Metal, DF_Arena 1B/500M, faster-whisper fallback) | ✅ Complete | Pinned revisions, TTS samples (en/en-IN/hi/te), bench/voice.json measured, voice_models tests; see docs/phase-2-report.md |
| 2026-10-01 | Phase 3 backend (ON/OFF demo ns, audit proofs API, /prove unsafe fixture, Red-Team Wall, FinBot 6 moments, CLI) | ✅ Complete | AT-11..15,17 pass; operator Bearer token on all mutating routes |
| 2026-10-01 | Phase 3 benchmarks (`trishul bench` -> bench/results.json) | ✅ Complete | India 49 attacks/34 benign ASR 0.0 on vs 0.9167 off; AgentDojo banking subset (qwen3:8b local) ASR 0.1667 -> 0.0, clean utility 0.5 -> 0.4375 |
| 2026-10-01 | Phase 3 console + landing wired to real WS/REST, vendored React/Babel | ✅ Complete | Headless-Chrome checked feed + bench panel; not every drawer clicked |
| 2026-10-01 | Opus gates: 13 backend fixes + task-pin/voice-nonce fixes; Docker, runbook, README, threat model, phase-3-report | ✅ Complete | 479 passed/5 skipped, 22 invariants UNSAT, docker compose smoke OK, pip-audit clean |
| 2026-10-01 | Phase 3 audit: 10 fixes (demo order safety, decision-latency semantics, console refresh/cache, operator URL, voice warm-up, resumed liveness, stale real-voice test, results traceability) | ✅ Complete | 491 passed / 0 skipped; addendum in docs/phase-3-report.md |
| 2026-10-01 | Real-voice evaluation (LibriSpeech + FLEURS hi/te + owner clip vs content-matched TTS) | ✅ Complete | bench/voice_eer.json: DF_Arena 1B real flagged 2.2 % clean / 19.4 % phone (hi/te 40 %); Telugu auto-ASR detects Tamil, forced language CER 0.22 |
| 2026-10-01 | bench/results.json regenerated at clean commit a924c5b | ✅ Complete | India ASR 0.0 (0/49), AgentDojo banking 8x4 subset ASR 0.2188 -> 0.0, decision p99 1.754 ms |
| 2026-10-01 | Live Chrome verification of console with operator token (moments 1-6, kill switch, XSS) | ✅ Complete | All moments correct; fixed moment-4 progress, [object Object] redacted args, empty audit label (98a5b6a, c26d287) |
| 2026-10-01 | Plain-English rule explanations in call detail | ✅ Complete | Console drawer shows what each rule hit means (RULE_TEXT map); 649 tests pass; commit 2941a1e |
| 2026-10-01 | Audience page (8789): Account owner vs Attacker modes | ✅ Complete | POST /owner binds the typed request as the user's trusted task; gateway decides ALLOW/STEP_UP/DENY; plain-English results + friendly errors; 656 tests pass; live-checked |
| 2026-10-01 | Console keeps operator token across refresh | ✅ Complete | Token kept in tab sessionStorage (cleared on tab close, dropped on 401 after server restart); `&amp;` links tolerated; browser-checked |
| 2026-10-01 | Moment 1 no longer leaves TRISHUL OFF | ✅ Complete | m1 switches OFF for the one unguarded payment then back ON (try/finally); operator token pinned in private .env so restarts keep the console link; 656 tests pass; live-checked |
| 2026-10-01 | Audience page: single box, analyse-then-decide (replaces owner/attacker buttons) | ✅ Complete | POST /analyse: DeBERTa injection model + red-flag rules; flagged → untrusted path (DENY on taint), clean → task-bound request (mandate/caps → ALLOW/STEP_UP/DENY). Moment 5 step 1 now restores ML on. 659 tests pass; live-checked with real model |
| 2026-10-01 | Call detail in plain English | ✅ Complete | "What happened" summary (action, verdict, where values came from, why); plain labels (NOT TRUSTED · from a message, Pay to, Amount, Data trail, Tamper-proof log record ID); browser-checked on PurposeLock DENY + PayShield ALLOW |
| 2026-10-01 | VoiceTrust call detail in plain English | ✅ Complete | Voice story ("A caller's voice said …"), voice-specific trust label, plain arg + detector names; Moment 6 steps 1-2 run live (DENY SPOOF.HIGH / LIVENESS.MISMATCH) |
| 2026-10-01 | Moment 6: play the cloned voice in the console | ✅ Complete | m6 step 1 returns the judged clip; Results shows an audio player (macOS `say` writes to a file, nothing was audible before); browser-checked 1.1 s WAV; 659 tests pass |
| 2026-10-01 | Fix: voice player vanished after Step 2 | ✅ Complete | Clip kept in its own state (cleared on reset) and auto-plays after Step 1; browser-checked playing + still shown after Step 2 |
| 2026-10-01 | Browser click-through: 2 bugs fixed | ✅ Complete | (1) audio `controls` attr dropped by template → player was 0×0; now visible + "▶ Play the cloned voice" button + auto-scroll; (2) pasting the #op= link into an open tab only fired hashchange → token ignored and shown as "Unknown route op=…"; token now taken on hashchange too. Screenshot-verified |
| 2026-10-01 | VoiceTrust full test in real Chrome | ✅ Complete | Moment 6 steps 1-3 (DENY spoof, DENY replay, audit OK), voice auto-plays + Play button, Live calls, detail panel, Liveness challenge (new phrase per click), Detector pins all OK. Fixed: single-step runs overwrote earlier step results (now merged) |

---

## 🛠️ Development Guidelines

### Git Workflow
- **Remote**: https://github.com/0XSreekar/TRISHUL-.git
- **Main Branch**: master
- **User**: Sreekar (sreekarkumar1206@gmail.com)
- **Commit Format**: Include descriptive messages with feature/fix details

### Commit Message Template
```
<type>: <description>

- Bullet point 1
- Bullet point 2

Co-Authored-By: Claude Haiku 4.5 <noreply@anthropic.com>
```

### Types
- `feat:` New feature
- `fix:` Bug fix
- `refactor:` Code refactoring
- `docs:` Documentation updates
- `test:` Test additions/updates

### Before Every Commit
- [ ] Run `git status` to review changes
- [ ] Check for secrets or sensitive data
- [ ] Ensure all files are intentionally staged
- [ ] Write clear, descriptive commit message
- [ ] Update this CLAUDE.md file with task progress

---

## ⚙️ Technology Stack
- HTML5 with embedded JavaScript
- JavaScript utilities (support.js)
- Interactive components and dashboards
- `.dc.html` extension (Design Component HTML)

---

## 📝 Task Update Instructions

**AFTER EVERY TASK (NO MATTER HOW SMALL):**

1. Update the Task Log table above with:
   - Date of completion
   - Task description
   - Status (✅ Complete, ⏳ Pending, 🔄 In Progress, ❌ Failed)
   - Brief notes about what was done

2. Run this command:
   ```bash
   cd "/Users/guts/Projects /TRISHUL ai " && git add CLAUDE.md && git commit -m "docs: Update CLAUDE.md - [task description]"
   ```

3. Push to repository:
   ```bash
   git push origin master
   ```

**Example after completing a task:**
```
| 2026-09-30 | Fixed console button click handler | ✅ Complete | Updated event listener in Trishul-Console.dc.html line 42 |
```

---

## 🔄 Current Phase
**Phase 1: Project Setup & Documentation**
- Initial git repository created ✅
- GitHub remote connected ✅
- CLAUDE.md with task tracking created ✅
- Next: Code review and feature planning

---

## 🚀 Next Steps (To be executed and logged)
1. [ ] Review Trishul-Landing.dc.html implementation
2. [ ] Review Trishul-Console.dc.html implementation
3. [ ] Analyze support.js for reusable utilities
4. [ ] Identify bugs or improvements needed
5. [ ] Create feature branches for development
6. [ ] Document findings and recommendations

---

## 📌 Important Notes
- All changes must be tracked in git
- Update CLAUDE.md after EVERY task
- Keep GitHub repository in sync
- Test changes locally before pushing
- Document all decisions and findings
- Use clear, descriptive commit messages

---

## 📞 Contact & Attribution
- **Developer**: Sreekar
- **Email**: sreekarkumar1206@gmail.com
- **Repository**: https://github.com/0XSreekar/TRISHUL-.git
- **Generated with**: Claude Code

---

**Last Updated**: 2026-10-01 (Phase 3 audit fixes + real-voice evaluation)
**Update Frequency**: After every task (MANDATORY)
