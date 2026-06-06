# Audit Operations Guide

This guide is a focused runbook for local MCP and dashboard audit log
operations. It covers review, retention, JSONL HMAC, gzip archive packaging, and
compressed archive HMAC.

Use it after sanitized output is generated and before using audit evidence as
operational support for a report or review.

## Scope

Audit operations are local-only operational controls. They are not AI prompt
material.

Allowed audit inputs:

- schema `1.1` MCP or dashboard audit JSONL
- retained audit JSONL created by `audit-retention`
- gzip audit archive created by `audit-compress`
- HMAC manifests created by this toolchain

Do not include the following in audit summaries, manifests, PRs, issues, or
documentation:

- raw request or response data
- Cookie, Authorization, token, JWT, session, API key, password, or CSRF values
- real domains, internal IPs, customer names, or personal data
- HMAC secrets or local secret files
- full stack traces

## Required Order

Use this order for a full archive-ready audit package:

```text
review-audit
-> audit-retention
-> audit-hmac
-> audit-hmac-verify
-> audit-compress
-> audit-compress-verify
-> audit-compressed-hmac
-> audit-compressed-hmac-verify
```

Each step should stop if the previous step fails.

## 1. Review Current Audit Logs

```powershell
python -m burp_ai_redaction_gateway review-audit --input out\.audit
```

Expected result:

- schema version is `1.1`
- UUID event IDs are valid
- sequence numbers are contiguous within the retained boundary
- hash chain fields verify
- raw-free scan passes

Legacy or pre-schema rows fail by design. If ignored local `out/.audit`
contains older development rows, generate a fresh audit log before using audit
review output as validation evidence.

## 2. Create a Retained JSONL File

Run a dry run first:

```powershell
python -m burp_ai_redaction_gateway audit-retention `
  --input out\.audit\mcp_audit.jsonl `
  --output out\.audit\mcp_audit.retained.jsonl `
  --retention-days 30 `
  --dry-run
```

Then write the retained output:

```powershell
python -m burp_ai_redaction_gateway audit-retention `
  --input out\.audit\mcp_audit.jsonl `
  --output out\.audit\mcp_audit.retained.jsonl `
  --retention-days 30
```

Validate the retained file:

```powershell
python -m burp_ai_redaction_gateway review-audit --input out\.audit\mcp_audit.retained.jsonl
```

Retention writes a separate output file and never modifies the source audit
JSONL in place.

## 3. Create and Verify Retained JSONL HMAC

Set the local HMAC secret without printing it:

```powershell
$env:BURP_AI_AUDIT_HMAC_KEY = "<LOCAL_ONLY_HMAC_SECRET>"
```

Create the retained JSONL manifest:

```powershell
python -m burp_ai_redaction_gateway audit-hmac `
  --input out\.audit\mcp_audit.retained.jsonl `
  --manifest out\.audit\mcp_audit.retained.manifest.json
```

Verify it:

```powershell
python -m burp_ai_redaction_gateway audit-hmac-verify `
  --input out\.audit\mcp_audit.retained.jsonl `
  --manifest out\.audit\mcp_audit.retained.manifest.json
```

This HMAC detects changes to the retained JSONL bytes. It is not encryption.

## 4. Compress the Retained JSONL

Create the gzip archive:

```powershell
python -m burp_ai_redaction_gateway audit-compress `
  --input out\.audit\mcp_audit.retained.jsonl `
  --output out\.audit\mcp_audit.retained.jsonl.gz
```

Verify the archive by decompressing it in a temporary location and running
`review-audit` on the decompressed JSONL:

```powershell
python -m burp_ai_redaction_gateway audit-compress-verify `
  --input out\.audit\mcp_audit.retained.jsonl.gz
```

Compression is archival packaging. It is not encryption and it is not
tamper-detection by itself. The source JSONL remains in place.

## 5. Create and Verify Compressed Archive HMAC

Create the compressed archive HMAC manifest:

```powershell
python -m burp_ai_redaction_gateway audit-compressed-hmac `
  --input out\.audit\mcp_audit.retained.jsonl.gz `
  --manifest out\.audit\mcp_audit.retained.jsonl.gz.manifest.json
```

Verify it:

```powershell
python -m burp_ai_redaction_gateway audit-compressed-hmac-verify `
  --input out\.audit\mcp_audit.retained.jsonl.gz `
  --manifest out\.audit\mcp_audit.retained.jsonl.gz.manifest.json
```

Compressed archive HMAC detects changes to the gzip package bytes. It is not
encryption and it does not replace `review-audit` or retained JSONL HMAC.

## Safe Output Expectations

Successful command summaries may include only safe metadata such as:

- safe file alias
- row count
- byte counts
- compression ratio
- HMAC algorithm name
- `raw_data_included: false`
- safe error type

Summaries must not print raw rows, HMAC values, HMAC secrets, CSRF values, real
paths, tokens, domains, IPs, personal data, or stack traces.

## Failure Handling

| Failure | Action |
| --- | --- |
| `review-audit` fails | Do not use the audit file as validation evidence. Generate a fresh schema `1.1` audit log if legacy rows are present. |
| `audit-retention` fails | Do not write or use retained output. Fix the input audit review failure first. |
| `audit-hmac` fails | Do not create a retained JSONL manifest. Check input review status and secret availability. |
| `audit-hmac-verify` fails | Treat the retained JSONL, manifest, or secret as mismatched. |
| `audit-compress` fails | Do not use the archive. Check that input passes `review-audit` and output ends with `.jsonl.gz`. |
| `audit-compress-verify` fails | Treat the archive as invalid and regenerate it from the retained JSONL. |
| `audit-compressed-hmac` fails | Do not create a compressed archive manifest. Check archive verification status and secret availability. |
| `audit-compressed-hmac-verify` fails | Treat the archive, manifest, or secret as mismatched. |

## Local Artifact Policy

Keep these local and out of Git:

- `out/.audit/`
- `*.manifest.json`
- `*.jsonl.gz`
- local HMAC key files
- generated reports or exports derived from real engagements

When sharing status in a PR or issue, share only command names, safe error
types, row counts, and pass/fail status. Do not paste audit rows, manifests,
digest values, HMAC values, or secrets.

## Minimal Evidence Checklist

Before treating an archive as ready for local storage:

- `review-audit` passed on the retained JSONL.
- `audit-hmac-verify` passed for the retained JSONL manifest.
- `audit-compress-verify` passed for the `.jsonl.gz` archive.
- `audit-compressed-hmac-verify` passed for the archive manifest.
- Gitleaks and the repository safety check passed before committing related
  documentation or code.

The audit package is still local operational evidence, not AI prompt material.
