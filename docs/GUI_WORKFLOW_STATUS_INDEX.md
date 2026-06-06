# GUI Workflow Status Index

This guide explains the dashboard workflow status index. The index is a
read-only workflow checklist for a selected verified output.

Open it from a verified output:

```text
/workflow?project=<alias>
```

The page ties together the safe dashboard sequence:

```text
verify
-> review
-> report
-> preflight
-> handoff
-> triage
-> report-readiness
```

It is a status and navigation page only. It does not run the workflow.

## Displayed Metadata

The workflow status index displays only safe metadata:

| Field | Meaning |
| --- | --- |
| `project alias` | The selected dashboard output alias. |
| `verify status summary` | Whether the selected output has passed verify. |
| `review status summary` | Whether finding candidate metadata is available or missing. |
| `finding candidate count` | Number of finding candidates in the verified output. |
| `analysis_packet.json` | Whether the sanitized candidate packet is available or missing. |
| `report_draft.md` | Whether the report draft is available or missing. |
| safe file status | Present or missing status for the four AI-safe files. |
| related indexes | Links to preflight, handoff, triage, report-readiness, and the review/report/export flow. |

Possible status labels include:

- `missing`
- `needs verify`
- `candidate available`
- `draft available`
- `manual review required`

## Safe Files

The workflow status index may list only these four AI-safe files:

- `analysis_packet.json`
- `chatgpt_prompt.md`
- `codex_task_prompt.md`
- `report_draft.md`

Do not use the files until verify has passed and manual review has confirmed the
planned AI handoff.

## Interpretation Boundary

- finding is candidate until manual verification is complete.
- risk is draft and requires separate review.
- final severity is a manual decision.
- `report_draft.md` is a draft report, not a submission report.
- report_draft.md is a draft report, not a submission report.
- Evidence confidence is not severity.
- CVSS is a separate calculation scope.

## Related Pages

Use the workflow status index as a read-only navigation checklist:

| Link | Purpose |
| --- | --- |
| preflight | Check AI-safe file readiness. |
| handoff | Check safe file order, purpose, and metadata. |
| triage | Review sanitized finding candidate metadata. |
| report-readiness | Check draft report readiness boundaries. |
| review/report/export flow | Return to the verified output detail page. |

## Do Not Use In Workflow Status

Do not paste, display, record, or use these values in the workflow status index,
docs, PRs, issues, or AI tools:

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

The workflow status index does not provide:

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
| Output does not open | The selected alias is missing, unverified, or forbidden. | Run `verify` on the selected output and use the dashboard alias only. |
| Safe file status is `missing` | The related step has not generated that file. | Run the relevant safe CLI or dashboard action after verify passes. |
| Review status is `missing` | No finding candidates are available. | Check scope and input coverage locally before report work. |
| Report status is `missing` | `report_draft.md` has not been generated. | Run Report after review, then manually inspect the draft. |
| Operator needs archive/HMAC state | The workflow page does not execute audit operations. | Use the audit operations guide and the read-only audit panel. |
