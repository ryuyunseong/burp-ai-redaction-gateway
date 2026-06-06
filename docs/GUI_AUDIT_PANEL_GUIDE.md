# GUI Audit Panel Guide

This guide explains the read-only audit/archive status shown in the local
dashboard. The panel is an operator aid for checking whether local audit
artifacts exist and whether archive verification can be performed. It is not a
configuration editor and it does not run archive or HMAC actions.

## Scope

The GUI audit/archive panel may appear on the dashboard home page and on the
`/settings` status page. It summarizes local metadata only:

- audit log status
- audit schema version
- retained JSONL status
- retained JSONL HMAC manifest status
- compressed archive status
- compressed archive verification status
- compressed archive HMAC manifest status

The panel is read-only. Use the CLI for creating retained logs, HMAC manifests,
gzip archives, and compressed archive HMAC manifests.

## Status Items

| Item | Meaning |
| --- | --- |
| `audit schema` | Expected audit schema version for current audit events. Current schema is `1.1`. |
| `audit log` | Whether the active local audit JSONL exists under the dashboard root audit directory. |
| `audit review` | Whether the active audit log can be reviewed with strict `review-audit` checks. |
| `retained JSONL` | Whether the retained JSONL exists and passes strict `review-audit`. |
| `HMAC manifest` | Whether the retained JSONL HMAC manifest exists and verifies with the configured local secret. |
| `compressed archive` | Whether the retained `.jsonl.gz` archive exists. |
| `compressed archive verify` | Whether the compressed archive can be decompressed and its JSONL passes `review-audit`. |
| `compressed archive HMAC manifest` | Whether the compressed archive HMAC manifest exists. |
| `compressed archive HMAC verify` | Whether the compressed archive HMAC manifest verifies with the configured local secret. |

## How To Read Status

| Status | Interpretation |
| --- | --- |
| `passed` | The relevant verification completed successfully. |
| `present` | The artifact exists, but this row is only reporting existence. Check the related verify row for validation. |
| `not found` | The artifact is not present under the expected local audit location. |
| `not configured` | A required local setting, usually the HMAC secret, is not configured. |
| `input_missing` | A manifest exists but the corresponding input artifact is missing. |
| safe `*_failed`, `*_missing`, `*_mismatch`, or `invalid_*` error type | Verification failed safely. Treat the artifact as invalid until regenerated or reviewed. |

Do not treat `present` as an integrity guarantee. For example, a compressed
archive can be present while `compressed archive verify` fails.

## Security Boundaries

The panel must not display:

- raw audit rows
- raw request or response data
- `Cookie`, `Authorization`, token, JWT, or session values
- real URLs, domains, or IP addresses
- personal data
- HMAC secrets
- CSRF token values
- environment variable values
- full local filesystem paths
- full stack traces

The panel should show aliases and safe status labels only. It must not add raw
viewing, replay, active scan, delete, edit, archive creation, HMAC creation, or
settings-write actions.

## Troubleshooting

| Symptom | Likely meaning | Next step |
| --- | --- | --- |
| `audit review` fails on old local logs | The log may contain legacy or pre-schema audit rows. | Generate a fresh audit log or review the old file with the CLI before using it operationally. |
| `retained JSONL` is `not found` | `audit-retention` has not produced a retained JSONL artifact. | Run `audit-retention` after strict `review-audit` passes. |
| `HMAC manifest` is `not found` | The retained JSONL HMAC manifest has not been created. | Run `audit-hmac` with a local secret. Do not paste the secret into chat, docs, logs, or PRs. |
| `HMAC manifest` is `not configured` or `hmac_secret_missing` | The dashboard cannot verify HMAC without a local secret. | Configure `BURP_AI_AUDIT_HMAC_KEY` or use the CLI with a local key file. |
| `compressed archive` is `not found` | `audit-compress` has not produced the `.jsonl.gz` archive. | Run `audit-compress` after the retained JSONL passes `review-audit`. |
| `compressed archive verify` fails | The gzip archive cannot be trusted as a reviewed audit package. | Regenerate the archive from the retained JSONL and verify it again. |
| `compressed archive HMAC manifest` is `not found` | The compressed archive HMAC manifest has not been created. | Run `audit-compressed-hmac` after `audit-compress-verify` passes. |
| `compressed archive HMAC verify` fails | The archive, manifest, or local secret does not match. | Treat the archive as invalid until regenerated or investigated locally. |

## CLI Relationship

The GUI summarizes state. The CLI performs operations:

```powershell
python -m burp_ai_redaction_gateway review-audit --input out\.audit
python -m burp_ai_redaction_gateway audit-retention --input out\.audit\mcp_audit.jsonl --output out\.audit\mcp_audit.retained.jsonl --retention-days 30
python -m burp_ai_redaction_gateway audit-hmac --input out\.audit\mcp_audit.retained.jsonl --manifest out\.audit\mcp_audit.retained.manifest.json
python -m burp_ai_redaction_gateway audit-compress --input out\.audit\mcp_audit.retained.jsonl --output out\.audit\mcp_audit.retained.jsonl.gz
python -m burp_ai_redaction_gateway audit-compress-verify --input out\.audit\mcp_audit.retained.jsonl.gz
python -m burp_ai_redaction_gateway audit-compressed-hmac --input out\.audit\mcp_audit.retained.jsonl.gz --manifest out\.audit\mcp_audit.retained.jsonl.gz.manifest.json
python -m burp_ai_redaction_gateway audit-compressed-hmac-verify --input out\.audit\mcp_audit.retained.jsonl.gz --manifest out\.audit\mcp_audit.retained.jsonl.gz.manifest.json
```

All generated audit, archive, and manifest artifacts are local operational
outputs. Do not commit them.
