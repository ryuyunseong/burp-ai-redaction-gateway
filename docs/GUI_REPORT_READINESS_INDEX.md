# GUI Report Readiness Index

This guide explains the dashboard report readiness index. The index is a
read-only draft report checklist for a selected verified output.

Use it before manually reviewing `report_draft.md` for customer-facing report
work. It is not a report submission gate and it does not confirm severity.

For the full read-only workflow checklist, see
[GUI_WORKFLOW_STATUS_INDEX.md](C:/coding/burp-ai-redaction-gateway/docs/GUI_WORKFLOW_STATUS_INDEX.md).

Open it from a verified output:

```text
/report-readiness?project=<alias>
```

## Displayed Metadata

The index displays only safe metadata:

| Field | Meaning |
| --- | --- |
| `project alias` | The selected dashboard output alias. |
| `draft report status` | Whether `report_draft.md` exists or is missing. |
| `analysis_packet.json` | Whether the sanitized analysis packet exists or is missing. |
| `finding candidate count` | Number of finding candidates in the verified output. |
| `draft report status summary` | Short status text for manual review planning. |
| `triage link` | Link to the finding triage index. |
| `preflight link` | Link to the AI-safe preflight checklist. |
| `handoff link` | Link to the AI handoff index. |
| `export/review/report flow link` | Link back to the verified output detail page. |

The file metadata section may show only these values for `report_draft.md` and
`analysis_packet.json`:

- exists or missing
- file size in bytes
- modified UTC timestamp
- SHA-256 file fingerprint

The SHA-256 value is a file fingerprint, not HMAC. This page does not change
HMAC secret handling and does not display HMAC secrets.

## Operator Checklist

Use the checklist as manual review prompts:

- scope confirmation
- affected endpoint confirmation
- evidence quality confirmation
- false positive possibility
- impact statement review
- remediation wording review
- final severity manual decision
- customer submission sensitive-info review

## Interpretation Boundary

- Findings are finding candidates until manual verification is complete.
- Risk is draft and must not be treated as severity confirmation.
- Evidence confidence is not severity.
- `report_draft.md` is a draft report, not a submission report.
- report_draft.md is a draft report, not a submission report.
- Final severity is a manual decision after reviewer validation.
- CVSS is a separate calculation scope.

## Do Not Use In Report Readiness

Do not use or paste these values into the page, docs, PRs, or AI tools:

- raw request or response data
- raw audit row body
- Cookie or Authorization values
- token, JWT, or session values
- real domain, URL, or IP values
- personal data
- HMAC secret or CSRF token values
- full local path
- `local_only/`, `raw/`, `raw_vault/`, unverified `out/`, or `out/.audit` artifacts

## Read-Only Boundary

The report readiness index does not provide:

- form or POST action
- state-changing button
- report body preview
- request preview
- response preview
- new download action
- raw viewer
- replay or active scan
- HMAC secret input UI
- retention or delete action
- risk profile change action

## Troubleshooting

| Symptom | Meaning | Next step |
| --- | --- | --- |
| `report_draft.md` is missing | The report draft has not been generated for this output. | Run Report from the verified output detail page or use the CLI report command. |
| `analysis_packet.json` is missing | The selected output is incomplete or not a valid verified output. | Regenerate and rerun verify before report review. |
| Finding candidate count is zero | No candidates were produced for this output. | Review scope and input coverage locally. |
| SHA-256 is missing | The file itself is missing. | Regenerate the expected verified output artifact. |
