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

The dashboard includes a read-only operations index:

```text
http://127.0.0.1:8766/help
http://127.0.0.1:8766/operations
```

The operations index is a guide hub, not an action surface. It links the
quickstart, GUI user flow guide, GUI AI-safe preflight guide, GUI AI handoff
index guide, GUI finding triage index guide, Windows launcher guide, audit
operations guide, GUI audit panel guide, risk rating guide, and v0.4 release
notes by repository-relative path. It also lists the four AI-safe files, blocked
raw-data categories, and the candidate/draft interpretation boundary.

For the screen-by-screen operator sequence, see
[GUI_USER_FLOW.md](C:/coding/burp-ai-redaction-gateway/docs/GUI_USER_FLOW.md).
For the AI handoff checklist, see
[GUI_AI_SAFE_PREFLIGHT.md](C:/coding/burp-ai-redaction-gateway/docs/GUI_AI_SAFE_PREFLIGHT.md).
For the AI-safe candidate file index, see
[GUI_AI_HANDOFF_INDEX.md](C:/coding/burp-ai-redaction-gateway/docs/GUI_AI_HANDOFF_INDEX.md).
For the finding candidate triage checklist, see
[GUI_FINDING_TRIAGE_INDEX.md](C:/coding/burp-ai-redaction-gateway/docs/GUI_FINDING_TRIAGE_INDEX.md).

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

The dashboard is designed as a review surface with a small set of safe workflow
actions. It highlights the safe workflow state directly in the UI:

- verify passed output only
- raw-free display mode
- candidate or suspected finding language
- manual verification required before confirmation
- confidence as evidence confidence, not severity
- draft likelihood, impact, and severity requiring a separate risk rating step
- CSRF-protected POST actions

Finding cards may show sanitized candidate metadata, rationale, confidence
basis, risk rating draft metadata, recommended manual tests, and `do_not_claim`
guidance. The risk rating draft must remain unfinalized and must not be treated
as a confirmed severity. Finding cards must not show raw request or response
data.

## AI-Safe Preflight

The dashboard provides a read-only AI-safe preflight view for a selected
verified output:

```text
/preflight?project=<alias>
```

The preflight view summarizes only safe metadata:

- whether each of the four AI-safe candidate files is present
- verify-passed status and verifier file count
- finding candidate count
- `report_draft.md` presence
- forbidden marker scan summary for the four safe files
- `raw_data_included=false`
- reminder that findings are candidates, risk is draft, and final severity is a
  manual decision

The preflight view does not add forms, POST actions, state-changing buttons, raw
viewers, HMAC secret inputs, CSRF token display, replay, active scan, delete,
edit, retention changes, or risk profile changes.

## AI Handoff Index

The dashboard provides a read-only AI handoff index for a selected verified
output:

```text
/handoff?project=<alias>
```

The handoff index summarizes only safe metadata for the four AI-safe candidate
files:

- file alias
- purpose
- recommended reading order
- exists or missing status
- file size in bytes
- modified UTC timestamp
- SHA-256 file fingerprint

The handoff index does not show full local paths or safe file body previews. It
does not add download buttons, forms, POST actions, state-changing buttons, raw
viewers, HMAC secret inputs, CSRF token display, replay, active scan, delete,
edit, retention changes, or risk profile changes.

## Finding Triage Index

The dashboard provides a read-only finding triage index for a selected verified
output:

```text
/triage?project=<alias>
```

The triage index summarizes only safe metadata for sanitized finding
candidates:

- project alias
- finding candidate count
- candidate index and stable candidate id
- category/type
- title and sanitized summary
- evidence confidence
- draft risk profile, likelihood, impact, and severity
- manual review required status
- `analysis_packet.json` and `report_draft.md` presence
- links to preflight, handoff, and the verified output detail flow

The triage index does not show raw request or response data, finding body
previews, request previews, response previews, full local paths, HMAC secrets,
CSRF token values, real domains, real URLs, real IP addresses, or personal data.
It does not add forms, POST actions, state-changing buttons, download buttons,
archive/HMAC actions, replay, active scan, delete, edit, retention changes, or
risk profile changes.

## Blocked Scope

The dashboard does not implement:

- raw request or response viewers
- replay or active scan actions
- arbitrary file writes
- delete or edit actions
- automatic exploit confirmation
- severity assignment
- archive or HMAC generation buttons on the operations index
- finding triage execution buttons
- risk profile change buttons on the operations index

## Dashboard Actions

The dashboard supports only these state-changing POST actions:

- `Verify`: re-runs fail-closed verification for the selected output.
- `Review`: renders a safe review summary without exporting raw data.
- `Report`: writes or refreshes `report_draft.md` after verify passes.
- `Export`: copies only the four safe preview files to `exports/dashboard/`.

Every POST action requires a per-server CSRF token. Missing or invalid tokens
return a safe error page without raw request, response, cookie, token, domain, or
personal data values. `Refresh` remains a read-only GET reload.

State-changing POST actions append raw-free audit events under
`<root>/.audit/mcp_audit.jsonl` using audit schema `1.1` and
`event_type: dashboard_action`. Events record only metadata such as action name,
sanitized output id, result status, blocked reason, safe report profile, and the
safe exported file allowlist. CSRF token values, raw request or response data,
cookies, authorization values, tokens, real domains, internal IPs, personal
data, and stack traces are not written to dashboard action audit events.

The following paths are rejected:

- `local_only/`
- `raw/`
- `raw_vault/`
- `build/`
- `.gradle/`

Path traversal and absolute output paths are rejected.

## Settings Page

The dashboard provides a read-only settings/status page at `/settings`. It is a
safe status surface, not a configuration editor. It may show:

- root alias, not the full local path
- localhost-only bind mode
- the safe preview/download file allowlist
- report profile names
- risk rating profile names
- draft-only risk rating mode and `confidence_is_severity: false`
- audit schema version and audit path alias
- HMAC configured/not configured status
- retained JSONL, compressed archive, and archive HMAC status
- CSRF enabled status without the CSRF value

The settings page must not print HMAC secret values, CSRF values, environment
variable values, raw request or response data, cookies, authorization values,
tokens, real domains, internal IPs, personal data, or stack traces. It does not
add raw viewing, replay, active scan, delete, edit, or settings-write actions.

## Audit Panel

The audit panel summarizes local audit and archive status only. It may show
review status, event counts, retained JSONL status, retained HMAC manifest
status, compressed archive status, archive verification status, and compressed
archive HMAC manifest status. It does not print audit rows, HMAC secrets, raw
request or response values, cookies, authorization values, tokens, real domains,
internal IPs, personal data, or stack traces.

If `BURP_AI_AUDIT_HMAC_KEY` is not set, HMAC status is reported as a safe error
type rather than printing the secret configuration.

For status interpretation and troubleshooting, see
[GUI_AUDIT_PANEL_GUIDE.md](C:/coding/burp-ai-redaction-gateway/docs/GUI_AUDIT_PANEL_GUIDE.md).

## Finding Language

Dashboard findings remain candidate or suspected findings. `confidence` is
evidence confidence, not severity. `risk_rating_draft` is a separate draft-only
workflow for likelihood, impact, and severity. Supported risk profiles are
`conservative`, `consultant`, and `strict`; the settings page lists them as
read-only status. Manual verification is required before any finding is
reported as completed or assigned as a severity decision.

