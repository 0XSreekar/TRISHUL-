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
| 2026-10-01 | Phase 4 gap closure (bypass tokens, keys, approver auth, injection classifier, quarantined reader, acceptance 1-17) | ✅ Complete | Branch claude/trishul-phase-4-gaps-4856b0; 640 tests pass; AT-01..17 PASS; report docs/phase-4-report.md; NOT RUN: voice clips, demo video, live Ollama, UI prompt files |
| 2026-10-01 | Dashboard multi-page refactor + landing polish + jury guide | ✅ Complete | Branch claude/trishul-ui-refine: responsive console, hash routes (Overview + 7 features x 3 pages), landing restyled + linked to console pages; plan docs/ui-plan.md; 640 tests pass |
| 2026-10-01 | Independent Opus verification of all features + real-data jury demo guide | 🔄 In Progress | |
| TBD | Review landing page implementation | ⏳ Pending | |
| TBD | Review dashboard implementation | ⏳ Pending | |
| TBD | Analyze support.js utilities | ⏳ Pending | |

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

**Last Updated**: 2026-10-01 (Phase 4 complete)
**Update Frequency**: After every task (MANDATORY)
