# Operating Guide

This guide describes the safe local workflow for using Burp AI Redaction
Gateway. The goal is to help an operator turn Burp exploration history into
verified, sanitized AI analysis material without exposing raw HTTP data.

## Purpose

Raw Burp history can contain URLs, parameters, headers, cookies, authorization
values, tokens, domains, internal IPs, personal data, request bodies, and
response bodies. Do not send raw Burp history directly to ChatGPT, Codex, PRs,
issues, reports, or documentation.

The safe workflow is:

```text
Burp history
-> Montoya collector or local input
-> loopback receiver or generate
-> redaction
-> verify
-> finding candidates
-> analysis packet
-> review/export
-> report draft
-> audit review, retention, and HMAC verification
```

AI tools should only receive verified sanitized artifacts.

## Prerequisites

- Work in a private repository.
- Keep real Burp exports under `local_only/` only.
- Keep generated output under ignored directories such as `out/`, `exports/`,
  and `reports/`.
- Do not commit `local_only/`, `out/`, `raw/`, `raw_vault/`, generated audit
  logs, HMAC manifests, secret files, or real traffic samples.
- Use synthetic fixtures for tests and documentation.

## Basic Safe Flow

### 1. Start the Receiver

Run the receiver on loopback only:

```powershell
python -m burp_ai_redaction_gateway serve --host 127.0.0.1 --port 8765 --output out\receiver --project montoya_receiver_alias
```

The receiver accepts Montoya collector handoff payloads, applies redaction, and
writes sanitized output. It must not log raw request or response values.

### 2. Use the Burp Collector

In Burp, load the Montoya collector extension and use the HTTP history context
menu to send in-scope history to the local receiver.

Safe expectations:

- The collector exposes a context menu action in Burp HTTP history.
- Handoff is loopback-only.
- Raw request and response values are not printed in the extension output.
- If the receiver is not running, the extension reports a safe error type such
  as a connection failure without printing raw HTTP.

### 3. Verify Sanitized Output

Always run verification before using generated output:

```powershell
python -m burp_ai_redaction_gateway verify --input out\receiver
```

If verification fails, do not use the output with AI. Reproduce the issue with a
synthetic fixture and strengthen redaction or scanning rules.

### 4. Review and Export Safe Prompt Material

Use `review` only on verified output:

```powershell
python -m burp_ai_redaction_gateway review --input out\receiver --export-dir exports\receiver_review
```

The review step summarizes candidate findings and copies safe prompt files only
when the selected output passes `verify`.

### 5. Generate a Report Draft

Generate a cautious draft after verification:

```powershell
python -m burp_ai_redaction_gateway report --input out\receiver --output out\receiver\report_draft.md --profile conservative
```

All findings remain candidate or suspected findings until manual reproduction is
complete. `confidence` is evidence confidence, not severity. Severity requires a
separate risk rating step. Generated candidates may include `risk_rating_draft`
with likelihood, impact, and severity draft values, but those values are not a
final rating and must be reviewed after manual verification. Draft risk rating
profiles are `conservative`, `consultant`, and `strict`; `conservative` is the
default. Profiles adjust draft likelihood and impact handling for review
posture only. They do not assign a severity decision or CVSS scores.

### 6. Optional Local Dashboard

Run the local dashboard on loopback to inspect verified outputs in a browser:

```powershell
python -m burp_ai_redaction_gateway dashboard --host 127.0.0.1 --port 8766 --root out
```

The dashboard previews and downloads only verified `analysis_packet.json`,
`chatgpt_prompt.md`, `codex_task_prompt.md`, and `report_draft.md` files. It can
also run a small set of CSRF-protected actions: verify, review summary, report
draft generation, and safe file export. It does not show raw request or response
values, replay traffic, run active scans, delete files, edit findings, or expose
unverified output.

Dashboard state-changing actions write raw-free `dashboard_action` audit events
to `out/.audit/mcp_audit.jsonl`. The event may include action name, sanitized
output id, result status, blocked reason, report profile, and the safe exported
file allowlist. It must not include CSRF token values, raw HTTP values, stack
traces, real domains, internal IPs, or personal data.

The settings/status page is read-only. It shows only safe metadata such as root
alias, localhost-only mode, safe file allowlist, report profile names, risk
profile names, draft-only risk mode, audit schema version, HMAC configured
status, and CSRF enabled status. It must not display HMAC secrets, CSRF values,
environment variable values, full local paths, raw traffic, or personal data.

## AI-Safe Files

The following files may be used with ChatGPT, Codex, or another AI only after
the output directory passes `verify`:

- `finding_candidates.json`
- `analysis_packet.json`
- `chatgpt_prompt.md`
- `codex_task_prompt.md`
- `report_draft.md`
- safe exported copies produced by `review --export-dir`

Do not use these files if `verify` fails.

## Files Never To Send To AI

Never send these to ChatGPT, Codex, PRs, issues, reports, or documentation:

- real Burp XML exports
- raw request or response data
- `local_only/`
- `raw/`
- `raw_vault/`
- unverified `out/` output
- `out/.audit/` audit logs or HMAC manifests
- cookies
- Authorization headers
- bearer tokens, JWTs, API keys, passwords, CSRF values, or session IDs
- real domains, customer names, internal IPs, or personal data
- HMAC secrets or local secret files

## Audit Operations

Audit operations prove the sanitized workflow is observable without recording
raw HTTP values.

### Review Audit Logs

```powershell
python -m burp_ai_redaction_gateway review-audit --input out\.audit
```

`review-audit` validates schema `1.1`, UUID event ids, sequence continuity,
hash chain integrity, rotated suffix order, and raw-free audit content.

Legacy or pre-schema audit rows fail review by design. If local ignored
`out/.audit` contains old development rows, generate a fresh audit log before
using it as validation evidence.

### Apply Audit Retention

```powershell
python -m burp_ai_redaction_gateway audit-retention `
  --input out\.audit\mcp_audit.jsonl `
  --output out\.audit\mcp_audit.retained.jsonl `
  --retention-days 30 `
  --dry-run

python -m burp_ai_redaction_gateway audit-retention `
  --input out\.audit\mcp_audit.jsonl `
  --output out\.audit\mcp_audit.retained.jsonl `
  --retention-days 30
```

`audit-retention` validates the input with strict `review-audit`, forbids
in-place modification, writes a separate retained JSONL file, and revalidates
the retained output.

### Create and Verify an HMAC Manifest

```powershell
$env:BURP_AI_AUDIT_HMAC_KEY = "<LOCAL_ONLY_HMAC_SECRET>"

python -m burp_ai_redaction_gateway audit-hmac `
  --input out\.audit\mcp_audit.retained.jsonl `
  --manifest out\.audit\mcp_audit.retained.manifest.json

python -m burp_ai_redaction_gateway audit-hmac-verify `
  --input out\.audit\mcp_audit.retained.jsonl `
  --manifest out\.audit\mcp_audit.retained.manifest.json
```

HMAC is tamper detection, not encryption. It verifies that the retained audit
JSONL still matches the manifest and the local secret. The manifest must not
contain raw audit rows or the HMAC secret.

Manage the HMAC secret with `BURP_AI_AUDIT_HMAC_KEY` or an ignored local
`--key-file`. Do not commit, log, paste, or document the secret.

### Compress Audit JSONL for Archival Storage

```powershell
python -m burp_ai_redaction_gateway audit-compress `
  --input out\.audit\mcp_audit.retained.jsonl `
  --output out\.audit\mcp_audit.retained.jsonl.gz

python -m burp_ai_redaction_gateway audit-compress-verify `
  --input out\.audit\mcp_audit.retained.jsonl.gz
```

`audit-compress` validates the input with strict `review-audit`, writes a
separate `.jsonl.gz` package, and leaves the source JSONL in place.
`audit-compress-verify` decompresses the package in a temporary location and
requires the decompressed JSONL to pass `review-audit`.

Compression is for archival packaging. HMAC for the retained JSONL file remains
separate from HMAC for the compressed archive. The compression summary prints
only safe aliases, size counts, row count, compression ratio, and
`raw_data_included: false`.

### Create and Verify a Compressed Archive HMAC Manifest

```powershell
$env:BURP_AI_AUDIT_HMAC_KEY = "<LOCAL_ONLY_HMAC_SECRET>"

python -m burp_ai_redaction_gateway audit-compressed-hmac `
  --input out\.audit\mcp_audit.retained.jsonl.gz `
  --manifest out\.audit\mcp_audit.retained.jsonl.gz.manifest.json

python -m burp_ai_redaction_gateway audit-compressed-hmac-verify `
  --input out\.audit\mcp_audit.retained.jsonl.gz `
  --manifest out\.audit\mcp_audit.retained.jsonl.gz.manifest.json
```

`audit-compressed-hmac` first requires `audit-compress-verify` to pass, then
computes SHA-256 and HMAC-SHA256 over the compressed archive bytes. The
manifest contains only safe metadata such as archive alias, compressed size,
digest, HMAC, creation time, and `raw_data_included: false`. It must not contain
decompressed audit rows or the HMAC secret.

## Failure Handling

| Failure | Action |
| --- | --- |
| `verify` fails | Do not use the output with AI. Reproduce with synthetic data and improve redaction or scanning. |
| `review-audit` fails on legacy rows | Treat as expected for old local audit logs. Generate a fresh audit log for current validation. |
| `audit-retention` fails | Do not write retained output. Check that input passes strict `review-audit`. |
| `audit-hmac` fails | Do not create a manifest. Check input review status and secret availability. |
| `audit-hmac-verify` fails | Treat the file, manifest, or secret as mismatched. Do not use the manifest as integrity evidence. |
| `audit-compress` fails | Do not create or use the compressed package. Check that input passes strict `review-audit` and output uses `.jsonl.gz`. |
| `audit-compress-verify` fails | Treat the compressed package as invalid. Use the original retained JSONL and regenerate the package if needed. |
| `audit-compressed-hmac` fails | Do not create a compressed archive manifest. Check archive verification status and secret availability. |
| `audit-compressed-hmac-verify` fails | Treat the compressed archive, manifest, or secret as mismatched. Regenerate from the retained JSONL if needed. |
| Gitleaks fails | Do not commit or push. Remove or replace the detected value with synthetic placeholder data. |
| receiver fails | Keep raw payload local. Share only safe error type, not raw traffic. |

Failure messages must stay raw-free. Share only error types such as
`audit_review_failed`, `hmac_mismatch`, `hmac_secret_missing`, or
`compressed_gzip_read_failed`.

## Customer Report Checklist

Before using a draft in customer-facing material:

- Confirm `verify` passed for the source output.
- Confirm all findings remain candidate or suspected until manually reproduced.
- Do not claim confirmed exploitation, data breach, privilege escalation, or
  token reuse without proof.
- Treat `confidence` as evidence confidence only.
- Treat `risk_rating_draft` as draft-only.
- Perform a separate severity or risk rating review before using the severity draft.
- Remove any accidental raw URL, domain, IP, cookie, token, account identifier,
  or personal data.
- Keep HMAC manifest and audit logs local unless a separate safe export process
  is approved.

## Final Pre-Commit Gate

Before committing changes to this repository:

```powershell
python -m compileall burp_ai_redaction_gateway tests scripts
python -m unittest discover -s tests
python -m burp_ai_redaction_gateway verify --input out
python -m burp_ai_redaction_gateway review --input out\demo
python -m burp_ai_redaction_gateway report --input out\demo --output out\demo\report_draft.md --profile conservative
C:\Users\wuro1\bin\gitleaks.exe dir -v --redact=100 --config .gitleaks.toml .
C:\Users\wuro1\bin\gitleaks.exe git -v --redact=100 --config .gitleaks.toml .
scripts\git_safety_check.bat
git diff --check
git status --short --untracked-files=all
```

`local_only/`, `out/`, `raw/`, `raw_vault/`, audit manifests, and secret files
must not appear in Git status.
