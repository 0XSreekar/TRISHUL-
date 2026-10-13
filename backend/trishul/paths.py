# SPDX-License-Identifier: Apache-2.0
"""Repository layout, resolved once. The package lives at ``backend/trishul``; everything the
running gateway reads from the repository (console, policies, benchmark results) is found here."""

from pathlib import Path

PACKAGE_DIR = Path(__file__).resolve().parent
REPO_ROOT = PACKAGE_DIR.parents[1]

FRONTEND_DIR = REPO_ROOT / "frontend"
POLICY_DIR = REPO_ROOT / "config" / "policies"
BENCH_DIR = REPO_ROOT / "bench"
DOCS_DIR = REPO_ROOT / "docs"
FIXTURES_DIR = PACKAGE_DIR / "fixtures"
