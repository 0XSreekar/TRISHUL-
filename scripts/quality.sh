#!/usr/bin/env bash
# Full quality gate: tests, lint, format, types, secret scan.
set -euo pipefail
cd "$(dirname "$0")/.."

uv run pytest -q
uv run ruff check .
uv run ruff format --check .
uv run mypy trishul

if command -v gitleaks >/dev/null 2>&1; then
  echo "secret scan: gitleaks"
  gitleaks detect --no-banner --config .gitleaks.toml
else
  echo "secret scan: gitleaks not installed, falling back to detect-secrets"
  out="$(uvx detect-secrets scan --all-files --exclude-files '(^uv\.lock$|^\.venv/|^\.git/)')"
  if echo "$out" | python3 -c 'import json,sys; sys.exit(1 if json.load(sys.stdin)["results"] else 0)'; then
    echo "detect-secrets: no findings"
  else
    echo "detect-secrets: findings present" >&2
    echo "$out" >&2
    exit 1
  fi
fi
echo "quality gate: OK"
