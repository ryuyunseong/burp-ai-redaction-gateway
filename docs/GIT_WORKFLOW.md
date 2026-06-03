# Git Workflow

This repository handles security-test artifacts. Git must never contain real
Burp exports, raw HTTP history, customer data, tokens, cookies, or generated
outputs that have not passed verification.

## Before `git init`

Run the local checks first:

```bat
python -m compileall burp_ai_redaction_gateway tests
python -m unittest discover -s tests
python -m burp_ai_redaction_gateway verify --input out
scripts\pre_commit_check.bat
```

If `out/` does not exist yet, the pre-commit script skips output verification.

## Initialize Git

```bat
git init
git status --short --untracked-files=all
```

Stop immediately if `git status` shows raw or generated data that should be
ignored. In particular, do not stage `out/`, `local_only/`, `raw/`, `raw_vault/`,
real `.har` files, `.burp` files, `.burp-project` files, `*_raw.*`,
`*raw_history*`, or `*burp_history_raw*`.

## Check Ignore Rules

Use `git check-ignore` before the first commit:

```bat
git check-ignore -v out\demo
git check-ignore -v local_only\real_burp_history_sample.xml
git check-ignore -v raw_vault\sample.json
git check-ignore -v test.har
git check-ignore -v sample.burp
git check-ignore -v sample_raw.json
```

Each command should print the ignore rule that matched. If a raw-data path is
not ignored, update `.gitignore` before staging anything.

## Allowed `git add` Targets

Use explicit paths:

```bat
git add .gitignore .gitleaks.toml policy.json pyproject.toml README.md
git add burp_ai_redaction_gateway samples tests scripts docs
```

Synthetic files under `samples/` are allowed. Real customer files are not.

## Forbidden Patterns

Never stage or commit:

| Pattern | Reason |
| --- | --- |
| `out/` | Generated output must stay local. |
| `reports/`, `exports/` | Generated or copied evidence may contain sensitive values. |
| `local_only/` | Real Burp exports belong here and must stay local. |
| `raw/`, `raw_vault/` | Raw HTTP material is prohibited in Git. |
| `*.har`, `*.burp`, `*.burp-project` | Burp/browser exports can contain secrets and PII. |
| `*_raw.*`, `*raw_history*`, `*burp_history_raw*` | Raw-history naming patterns. |
| `.env`, `*.key`, `*.pem`, `*.p12`, `*.pfx`, `secrets.*` | Secrets and local credentials. |
| `client_*`, `customer_*` | Customer-identifying local artifacts. |

Actual customer data must not be included in commits, issues, prompts,
documentation, test names, filenames, or comments.

## Commit Gate

Run this before every commit:

```bat
scripts\git_safety_check.bat
```

The safety check prints `git status --short --untracked-files=all`, fails if an
unsafe path is already tracked or staged, and then runs
`scripts\pre_commit_check.bat`.

In Git Bash, WSL, or Linux:

```sh
scripts/git_safety_check.sh
```

## Commit

Only after the safety check passes:

```bat
git status --short
git commit -m "feat: add Burp history redaction gateway MVP"
```

Do not use `git add -A` when real exports or generated evidence are present in
the workspace. Prefer explicit `git add` commands for the known-safe project
paths above.

