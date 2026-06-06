# v0.4 Release Notes

This release note summarizes the v0.4 dashboard baseline from
`v0.4.0-local-dashboard` through `v0.4.5-dashboard-settings`.

The v0.4 line adds a local browser dashboard for verified sanitized output,
keeps AI-facing files behind the existing `verify` gate, and preserves the
project rule that raw Burp traffic must never be displayed, exported, logged, or
sent to AI tools.

## Scope

- `v0.4.0-local-dashboard`: adds the loopback-only local dashboard for safe
  preview and download of verified output.
- `v0.4.1-dashboard-polish`: improves dashboard safety badges, finding cards,
  and candidate wording.
- `v0.4.2-risk-rating-draft`: separates evidence confidence from risk rating
  draft metadata.
- `v0.4.3-dashboard-actions`: adds CSRF-protected dashboard POST actions for
  verify, review, report draft generation, and safe export.
- `v0.4.4-dashboard-action-audit-ko`: adds raw-free dashboard action audit
  events and Korean dashboard UI text.
- `v0.4.5-dashboard-settings`: adds a read-only settings/status page.

## Major Changes

### Local Dashboard

The dashboard is a `127.0.0.1`-only browser surface for inspecting sanitized
outputs under a configured root such as `out`. It discovers generated output
directories, runs the same verification boundary as the CLI, and allows browser
preview or download only after verification passes.

The dashboard remains a local review tool, not a production web application.

### Safe Preview and Export

The dashboard preview and export allowlist is limited to:

- `analysis_packet.json`
- `chatgpt_prompt.md`
- `codex_task_prompt.md`
- `report_draft.md`

Raw request or response viewers, replay, active scan actions, arbitrary file
writes, delete actions, and edit actions are not implemented.

### Risk Rating Draft

`confidence` remains evidence confidence. It is not severity.

Risk metadata is exposed separately as `risk_rating_draft` with likelihood,
impact, and severity draft values. The rating remains unfinalized and requires
manual verification and manual risk review before use in a report.

### Dashboard Actions

The dashboard supports a small set of state-changing actions:

- Verify
- Review
- Report
- Export

These actions use POST with a CSRF token. Refresh remains a read-only GET
operation. Missing or invalid CSRF tokens are blocked with safe error output.

### Dashboard Action Audit

Dashboard actions append raw-free audit events with
`event_type: dashboard_action`. Events record only metadata such as action name,
sanitized output id, result status, blocked reason, report profile, and safe
exported file names.

CSRF token values, raw HTTP values, stack traces, real domains, internal IPs,
personal data, and HMAC secrets are not written to dashboard action audit
events.

### Korean UI

The dashboard UI is localized for Korean operators while keeping schema names,
action ids, file names, and audit metadata identifiers stable in English.

### Read-Only Settings Page

The `/settings` page is a status surface, not a configuration editor. It may
show:

- root alias
- localhost-only mode
- safe preview and export allowlist
- report profile names
- draft-only risk mode
- `confidence_is_severity: false`
- audit schema version
- HMAC configured or not configured status
- CSRF enabled status

It must not print HMAC secret values, CSRF values, environment variable values,
full local paths, raw traffic, cookies, authorization values, tokens, real
domains, internal IPs, personal data, or stack traces.

## Security Boundaries

The v0.4 dashboard follows the existing safe-output rules:

- Raw request and response values are not displayed.
- Cookie, Authorization, token, JWT, session, real domain, internal IP, and
  personal data values are not displayed.
- Preview and export are limited to the four safe files listed above.
- CSRF token values are not displayed or recorded in audit logs.
- Dashboard action audit records are raw-free metadata only.
- The settings page is read-only.
- The dashboard remains bound to `127.0.0.1`.
- Verified sanitized output is required before preview, download, review,
  report, or export actions.

## AI-Safe Files

Only these files are intended for ChatGPT, Codex, or other AI tools, and only
after the selected output directory passes `verify`:

- `analysis_packet.json`
- `chatgpt_prompt.md`
- `codex_task_prompt.md`
- `report_draft.md`

Do not send raw Burp exports, raw request or response data, unverified output,
audit logs, HMAC manifests, local-only files, cookies, authorization values,
tokens, real domains, customer names, internal IPs, or personal data to AI
tools.

## Typical Local Use

Generate or receive sanitized output, verify it, and then start the dashboard:

```powershell
python -m burp_ai_redaction_gateway verify --input out\demo
python -m burp_ai_redaction_gateway dashboard --host 127.0.0.1 --port 8766 --root out
```

Open the local dashboard:

```text
http://127.0.0.1:8766/
```

The dashboard should be used as a local review surface for sanitized outputs,
not as an internet-facing service.

## Verification Summary

The v0.4 baseline was validated with the project safety gates across the related
PRs:

- Python compile checks.
- `unittest` test runs.
- `verify --input out`.
- `review --input out\demo`.
- conservative `report` generation.
- Gitleaks directory and Git scans.
- `scripts\git_safety_check.bat`.
- Browser checks for safe preview, safe download, CSRF-protected actions,
  dashboard action audit metadata, Korean UI text, and the read-only settings
  page.

## Known Limits

- The dashboard is local-only and is not a production web application.
- Risk rating remains a draft. It is not a severity decision.
- CVSS scoring is not part of the v0.4 dashboard baseline.
- Settings are read-only. Configuration changes are not supported from the
  dashboard.
- Raw viewing, replay, active scan, delete, and edit actions are intentionally
  absent.
- HMAC protects retained audit files from undetected modification when the local
  secret is managed correctly. HMAC is tamper detection, not encryption.

## Follow-Up Candidates

- Risk rating profiles for organization-specific likelihood and impact
  calibration.
- Audit compression for long-term local storage.
- Settings actions, if needed, with explicit CSRF, audit, secret handling, and
  rollback review.
- A GitHub release entry based on the existing v0.4 tags.
