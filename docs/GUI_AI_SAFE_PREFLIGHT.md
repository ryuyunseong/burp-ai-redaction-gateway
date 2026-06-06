# GUI AI-Safe Preflight

This guide explains the dashboard AI-safe preflight view. The view is a
read-only checklist for deciding whether a verified output is a candidate for
manual AI review. It does not generate files, run archive actions, change
settings, or submit data to an external service.

Use it after an output has passed `verify` and before putting any file into
ChatGPT, Codex, a PR, an issue, or a document.

For the file order, purpose, size, modified time, and SHA-256 metadata view, see
[GUI_AI_HANDOFF_INDEX.md](C:/coding/burp-ai-redaction-gateway/docs/GUI_AI_HANDOFF_INDEX.md).
For candidate triage metadata and manual review boundaries, see
[GUI_FINDING_TRIAGE_INDEX.md](C:/coding/burp-ai-redaction-gateway/docs/GUI_FINDING_TRIAGE_INDEX.md).

## Open the View

From the output detail page, open:

```text
/preflight?project=<alias>
```

The output detail page also links to the preflight detail view. The link is a
read-only GET navigation, not a POST action.

## What It Shows

The preflight view displays only aliases and status metadata:

| Status | Meaning |
| --- | --- |
| `analysis_packet.json` | Present or missing. |
| `chatgpt_prompt.md` | Present or missing. |
| `codex_task_prompt.md` | Present or missing. |
| `report_draft.md` | Present or missing. |
| `verify status` | Whether the selected output passed fail-closed verification. |
| `verify files checked` | Count of files checked by the verifier. |
| `finding candidate count` | Count of candidate findings in the safe output. |
| `forbidden marker scan` | Summary status for scanning the four safe files. |
| `raw_data_included` | Always `false`. |

The status `ready candidate` means the four safe files are present and the
preflight marker scan did not find sensitive markers in those files. It is not a
guarantee of correctness and it is not final approval to publish findings.

## Safe Files

Only these files may be considered for AI review, and only after verify passes:

```text
analysis_packet.json
chatgpt_prompt.md
codex_task_prompt.md
report_draft.md
```

Treat them as AI-safe candidate files. Verify first. Manual review is required.

## Do Not Send

Do not paste, upload, commit, or document any of the following:

| Category | Reason |
| --- | --- |
| raw request or response data | May contain sensitive values. |
| Cookie or Authorization values | Authentication material. |
| token, JWT, or session values | Session or credential material. |
| real domain, URL, or IP values | Environment details. |
| personal data | Identity or privacy-sensitive data. |
| HMAC secret or CSRF token values | Local security controls. |
| local-only raw storage or unverified output artifacts | Not AI input material. |
| audit logs, archives, or manifests | Operational evidence, not AI prompt material. |

## Interpretation Boundary

Preflight is a status check, not a vulnerability decision.

- Findings remain `candidate` until manual verification is complete.
- `risk_rating_draft` is draft-only and is not final severity.
- `confidence` is evidence confidence, not severity.
- Final severity requires authorized reproduction, role comparison, business
  impact review, and a manual risk decision.
- CVSS is a separate calculation scope.

## Read-Only Boundary

The preflight view does not provide:

- form submission
- POST action
- state-changing button
- raw viewer
- replay or active scan
- archive or HMAC execution
- HMAC secret input
- CSRF token display
- file deletion or retention changes
- risk profile changes

## Troubleshooting

| Status | Meaning | Next step |
| --- | --- | --- |
| `missing safe files` | One or more of the four AI-safe candidate files is absent. | Run the relevant verified dashboard action or CLI command. |
| `forbidden marker found` | A safe file candidate needs investigation. | Do not use the output with AI; rerun verify and inspect locally. |
| `needs manual review` | The output should not be treated as ready for AI handoff. | Complete local review before sharing any file. |
| `report_draft.md` is missing | Report generation has not run for this output. | Generate the report draft after verify passes. |

