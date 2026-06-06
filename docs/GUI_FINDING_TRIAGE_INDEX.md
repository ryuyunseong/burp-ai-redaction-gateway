# GUI Finding Triage Index

This guide explains the dashboard finding triage index. The index is a
read-only triage checklist for sanitized finding candidates after a selected
output passes verification.

The index is not a confirmation screen. It does not decide severity, prove
impact, create files, change settings, or run any dashboard action.

## Open the View

From a verified output detail page, open:

```text
/triage?project=<alias>
```

The page is a read-only GET page. It does not submit data, create files,
download files, delete files, or run review, report, export, archive, HMAC,
replay, or active scan actions.

For draft report readiness metadata and manual review boundaries, see
[GUI_REPORT_READINESS_INDEX.md](C:/coding/burp-ai-redaction-gateway/docs/GUI_REPORT_READINESS_INDEX.md).

## What It Shows

The triage index displays only safe candidate metadata:

- project alias
- finding candidate count
- candidate index and stable candidate id
- category/type
- title
- sanitized summary
- evidence confidence
- draft risk profile
- severity draft, likelihood draft, and impact draft
- manual review required status
- `analysis_packet.json` presence
- `report_draft.md` presence
- links back to preflight, handoff, report readiness, and output detail flow

The sanitized summary may include a method and path template. It must not include
real domains, real URLs, real IP addresses, Cookie values, Authorization values,
tokens, sessions, or personal data.

## Interpretation Boundary

- Every item is a candidate finding until manual verification is complete.
- Evidence confidence is not severity.
- Draft risk is an operator aid and is not a severity decision.
- Final severity requires manual decision after authorized reproduction, role
  comparison, impact review, and separate risk review.
- CVSS is a separate calculation scope.

## Do Not Use In Triage

Do not paste, upload, commit, or document any of the following:

| Category | Reason |
| --- | --- |
| raw request or response data | May contain sensitive values. |
| Cookie or Authorization values | Authentication material. |
| token, JWT, or session values | Session or credential material. |
| real domain, URL, or IP values | Environment details. |
| personal data | Identity or privacy-sensitive data. |
| HMAC secret or CSRF token values | Local security controls. |
| full local path | Local environment detail. |
| `local_only/`, `raw/`, `raw_vault/`, unverified `out/`, or `out/.audit` artifacts | Not AI or triage input material. |

## Read-Only Boundary

The triage index does not provide:

- form submission
- POST action
- state-changing button
- file body preview
- finding body preview
- request preview
- response preview
- new download action
- raw viewer
- replay or active scan
- archive or HMAC execution
- HMAC secret input
- CSRF token display
- file deletion or retention changes
- risk profile changes

Use it as a read-only triage checklist only.

## Troubleshooting

| Symptom | Meaning | Next step |
| --- | --- | --- |
| Candidate count is zero | The selected output has no finding candidates. | Review `analysis_packet.json` locally after verification if needed. |
| `analysis_packet.json` is missing | The selected output is incomplete. | Regenerate or rerun the safe dashboard flow. |
| `report_draft.md` is missing | The report action has not been run for this output. | Run report from the verified output detail page if a draft is needed. |
| Triage page is blocked | The output failed verification or the alias is forbidden. | Run `verify` and use only dashboard-listed output aliases. |

