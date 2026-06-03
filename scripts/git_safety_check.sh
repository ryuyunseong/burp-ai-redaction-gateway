#!/usr/bin/env sh
set -eu

repo_safe="$(pwd)"
git_safe() {
  git -c "safe.directory=$repo_safe" "$@"
}

if git_safe rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  echo "Git status:"
  git_safe status --short --untracked-files=all

  safety_list="$(mktemp)"
  {
    git_safe ls-files
    git_safe diff --name-only --cached
  } > "$safety_list"

  if grep -E '^(out|local_only|raw|raw_vault)/|\.har$|\.burp$|\.burp-project$|_raw|raw_history|burp_history_raw' "$safety_list"; then
    echo "Unsafe tracked or staged paths found." >&2
    rm -f "$safety_list"
    exit 1
  fi

  rm -f "$safety_list"
else
  echo "Not a Git repository yet. Skipping tracked/staged raw-data check."
fi

scripts/pre_commit_check.sh
