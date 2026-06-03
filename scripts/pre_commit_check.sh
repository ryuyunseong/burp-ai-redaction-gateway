#!/usr/bin/env sh
set -eu

PYTHON_BIN="${PYTHON:-python}"

"$PYTHON_BIN" -m compileall burp_ai_redaction_gateway tests
"$PYTHON_BIN" -m unittest discover -s tests

if [ -d out ]; then
  "$PYTHON_BIN" -m burp_ai_redaction_gateway verify --input out
fi

if command -v gitleaks >/dev/null 2>&1; then
  gitleaks detect --source . --no-git -v
fi

echo "Pre-commit checks passed."

