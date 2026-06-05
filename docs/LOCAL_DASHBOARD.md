# Local Dashboard

The local dashboard is a loopback-only browser surface for verified sanitized
output. It is intended to make the existing safe workflow easier to inspect
without exposing raw Burp traffic.

## Run

```powershell
python -m burp_ai_redaction_gateway dashboard --host 127.0.0.1 --port 8766 --root out
```

Only `127.0.0.1` is accepted as the bind host. Non-loopback hosts are rejected.
Use an explicit root such as `out`; the dashboard discovers output directories
under that root that contain `analysis_packet.json`.

## Allowed Scope

The dashboard applies the same verify-first boundary as the CLI and read-only
MCP server. A selected output directory must pass `verify` before any preview or
download is allowed.

The only preview and download files are:

- `analysis_packet.json`
- `chatgpt_prompt.md`
- `codex_task_prompt.md`
- `report_draft.md`

All file content is scanned before it is rendered or returned. JSON and Markdown
are HTML-escaped in browser previews.

## Review Surface

The dashboard is designed as a review surface, not an execution console. It
highlights the safe workflow state directly in the UI:

- verify passed output only
- raw-free display mode
- candidate or suspected finding language
- manual verification required before confirmation
- confidence as evidence confidence, not severity
- severity requiring a separate risk rating step

Finding cards may show sanitized candidate metadata, rationale, confidence
basis, recommended manual tests, and `do_not_claim` guidance. They must not show
raw request or response data.

## Blocked Scope

The dashboard does not implement:

- raw request or response viewers
- replay or active scan actions
- file writes
- state-changing requests
- automatic exploit confirmation
- severity assignment

The following paths are rejected:

- `local_only/`
- `raw/`
- `raw_vault/`
- `build/`
- `.gradle/`

Path traversal and absolute output paths are rejected.

## Audit Panel

The audit panel summarizes local audit status only. It may show review status,
event counts, retained JSONL status, and HMAC manifest status. It does not print
audit rows, HMAC secrets, raw request or response values, cookies, authorization
values, tokens, real domains, internal IPs, personal data, or stack traces.

If `BURP_AI_AUDIT_HMAC_KEY` is not set, HMAC status is reported as a safe error
type rather than printing the secret configuration.

## Finding Language

Dashboard findings remain candidate or suspected findings. `confidence` is
evidence confidence, not severity. Manual verification is required before any
finding is reported as confirmed.

