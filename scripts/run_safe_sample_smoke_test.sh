#!/usr/bin/env sh
set -eu

PYTHON_BIN="${PYTHON:-python}"

"$PYTHON_BIN" scripts/make_safe_burp_export_sample.py
"$PYTHON_BIN" -m burp_ai_redaction_gateway generate --input local_only/real_burp_history_sample.xml --output out/real_sample_check --project real_sample_alias
"$PYTHON_BIN" -m burp_ai_redaction_gateway verify --input out/real_sample_check
scripts/git_safety_check.sh
git -c "safe.directory=$(pwd)" status --short --untracked-files=all

