# User Quickstart

This quickstart is for local use of Burp AI Redaction Gateway with the CLI and
the local dashboard. It is designed for a short first run after the project is
already checked out.

The goal is:

```text
Burp scoped HTTP history
-> local receiver
-> redaction and verify
-> dashboard review
-> safe AI files
```

Do not paste raw Burp data into AI tools, pull requests, issues, reports, or
documentation.

## 1. Start the Receiver

On Windows, the shortest path is to start the receiver and dashboard together:

```powershell
scripts\start_gateway.ps1
```

Default launcher settings:

| Setting | Default |
| --- | --- |
| Receiver | loopback port `8765` |
| Dashboard | loopback port `8766` |
| Output alias | `out\receiver` |
| Project alias | `receiver_alias` |
| PID and launcher logs | ignored `out\.launcher\` files |

The launcher opens the dashboard in a browser and prints only safe metadata such
as ports, output alias, project alias, process ids, and `raw_data_included=false`.
It does not print raw request or response values, cookies, authorization values,
tokens, real target domains, personal data, HMAC secrets, or CSRF values.

Stop the launcher-managed receiver and dashboard with:

```powershell
scripts\stop_gateway.ps1
```

If you prefer separate terminal windows, start the receiver manually.

Start the loopback receiver:

```powershell
python -m burp_ai_redaction_gateway serve --host 127.0.0.1 --port 8765 --output out\receiver --project receiver_alias
```

Safe expectations:

- The receiver listens only on `127.0.0.1`.
- Raw request and response values are processed locally.
- Generated output is written under `out\receiver`.
- Output still must pass `verify` before AI use.

## 2. Send Scoped Burp History

In Burp, send only scoped HTTP history items to the local receiver with the
collector context menu.

Safe expectations:

- Use scoped history only.
- Do not send unrelated browsing history.
- Do not copy raw request or response values into chat, issues, or docs.
- If the receiver is not running, handle the safe connection error and retry
  after starting the receiver.

## 3. Start the Dashboard

Run the local dashboard:

```powershell
python -m burp_ai_redaction_gateway dashboard --host 127.0.0.1 --port 8766 --root out
```

Open:

```text
http://127.0.0.1:8766/
```

The dashboard is a `127.0.0.1` local review tool. It is not a production web
application and should not be exposed to a network.

## 4. Use the Dashboard Flow

Use the dashboard actions in this order:

1. Select a verified output directory or the receiver output.
2. Run `Verify`.
3. Run `Review`.
4. Run `Report`.
5. Run `Export`.

Dashboard action boundaries:

- State-changing actions use POST with CSRF protection.
- `Refresh` is a read-only GET action.
- Export is limited to the safe file allowlist.
- Raw viewer, replay, active scan, delete, and edit actions are not provided.

## 5. Safe Files for AI

Only use the following files with ChatGPT, Codex, or another AI tool after the
selected output passes `verify`:

| File | Use |
| --- | --- |
| `analysis_packet.json` | Structured sanitized finding candidate packet. |
| `chatgpt_prompt.md` | ChatGPT-oriented safe analysis prompt. |
| `codex_task_prompt.md` | Codex-oriented safe task prompt. |
| `report_draft.md` | Candidate report draft for manual review. |

If `verify` fails, do not use these files with AI.

## 6. Files and Values Never To Send

Never send or document the following:

| Do not send | Reason |
| --- | --- |
| Raw request or response data | May contain sensitive values. |
| Real Burp XML exports | Raw traffic source. |
| `local_only/`, `raw/`, `raw_vault/` | Local-only or raw storage areas. |
| Unverified `out/` output | Safety gate has not passed. |
| `out/.audit/` logs or HMAC manifests | Operational metadata, not AI prompt material. |
| Cookie, Authorization, token, JWT, or session values | Authentication or session material. |
| Real domains, customer names, internal IPs, or personal data | Sensitive environment or identity data. |
| HMAC secrets, CSRF values, or local secret files | Security-sensitive local values. |

## 7. Interpret Results Conservatively

Finding output is not a confirmed vulnerability report.

- Findings are candidates or suspected findings.
- `confidence` is evidence confidence, not severity.
- `risk_rating_draft` is a draft based on likelihood and impact.
- Severity decisions require manual verification and manual risk review.
- Do not claim exploitation, data breach, or privilege escalation without proof.

Use the report draft as review material, not as a final customer report.

## 8. Common Troubleshooting

### Verify Fails

Do not use the output with AI. Reproduce the problem with a synthetic fixture,
then strengthen redaction or scanner rules before trying again.

### Dashboard Does Not Show an Output

Check that the output directory is under the dashboard root and contains the
expected sanitized files. Run:

```powershell
python -m burp_ai_redaction_gateway verify --input out\receiver
```

### Legacy Audit Rows Fail Review

`review-audit` is strict by design. Older local audit rows generated before
audit schema `1.1` may fail. Generate a fresh audit log before using audit
review output as validation evidence.

### HMAC Is Not Configured

The dashboard may show HMAC as not configured. This is a status indicator only.
Do not print or paste HMAC secrets into chat, docs, PRs, or logs.

## 9. Minimal CLI-Only Flow

If you do not need the dashboard, run the CLI flow directly:

```powershell
python -m burp_ai_redaction_gateway verify --input out\receiver
python -m burp_ai_redaction_gateway review --input out\receiver --export-dir exports\receiver_review
python -m burp_ai_redaction_gateway report --input out\receiver --output out\receiver\report_draft.md --profile conservative
```

Use only verified safe files from the output or export directory.
