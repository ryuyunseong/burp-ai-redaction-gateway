# GUI User Flow

This guide is the operator-facing flow for using the local dashboard after the
receiver and dashboard are running. It connects the quickstart, dashboard help
page, settings/status page, safe file export, and manual review boundaries.

The dashboard is a `127.0.0.1` local review tool. It is not a production web
application and must not be exposed to a network.

## End-to-End Flow

Use this order for a normal GUI-assisted review:

```text
start receiver and dashboard
-> send scoped Burp history to the local receiver
-> generate sanitized output
-> verify the selected output
-> review candidate findings
-> check finding triage index
-> generate report_draft.md
-> check report readiness index
-> check workflow status index
-> check AI-safe preflight
-> check AI handoff index
-> export safe files
-> send only verified safe files to AI
```

The Windows launcher can start the receiver and dashboard together:

```powershell
scripts\start_gateway.ps1
```

Manual startup is also supported:

```powershell
python -m burp_ai_redaction_gateway serve --host 127.0.0.1 --port 8765 --output out\receiver --project receiver_alias
python -m burp_ai_redaction_gateway dashboard --host 127.0.0.1 --port 8766 --root out
```

Open the dashboard:

```text
http://127.0.0.1:8766/
```

## Dashboard Pages

| Page | Purpose | Boundary |
| --- | --- | --- |
| `/` | Select verified outputs and inspect audit/archive status. | Shows verified sanitized metadata only. |
| `/output?project=<alias>` | Review safe files, finding candidates, and allowed dashboard actions for one verified output. | Requires verify to pass before display. |
| `/triage?project=<alias>` | Review sanitized finding candidate metadata before drafting report language. | Read-only; no finding body preview, form, POST action, or severity decision. |
| `/report-readiness?project=<alias>` | Check draft report metadata and operator review items before manual report review. | Read-only; no report body preview, form, POST action, or submission decision. |
| `/workflow?project=<alias>` | Check the full verify, review, report, preflight, handoff, triage, and report-readiness sequence. | Read-only workflow checklist; no form, POST action, button, or report body preview. |
| `/preflight?project=<alias>` | Check whether the selected verified output is an AI-safe handoff candidate. | Read-only; no form, POST action, or external transmission. |
| `/handoff?project=<alias>` | Review the four AI-safe candidate file aliases, purpose, order, and metadata. | Read-only; no file body preview, download, form, or POST action. |
| `/settings` | Show dashboard settings and security status. | Read-only; no configuration edits. |
| `/help` and `/operations` | Show the operations index and documentation entry points. | Read-only guide hub; no form or POST action. |
| `/preview` and `/download` | Preview or download one allowlisted safe file. | Only the four safe files are allowed. |

There are no `/review`, `/report`, or `/export` pages. Review, report, and
export are CSRF-protected POST actions on a verified output detail page.

## Action Order

Use the output detail actions in this order:

1. `Verify`: re-run fail-closed verification for the selected output.
2. `Review`: create a safe summary of candidate findings.
3. `Finding triage index`: check candidate metadata and manual review boundaries.
4. `Report`: write or refresh `report_draft.md`.
5. `Report readiness index`: check draft report metadata and manual review items.
6. `Workflow status index`: check the read-only workflow checklist.
7. `AI-safe preflight`: check the read-only handoff checklist.
8. `AI handoff index`: check the four AI-safe candidate files and their order.
9. `Export`: copy only the four safe files to the dashboard export directory.

`Refresh` is a read-only GET reload. `Verify`, `Review`, `Report`, and `Export`
are state-changing POST actions and require a CSRF token.
`Finding triage index`, `Report readiness index`, `Workflow status index`,
`AI-safe preflight`, and `AI handoff index` are read-only GET pages and do not
submit data.

## Safe Files For AI

Only use these files with AI after the selected output passes `verify`:

| File | Use |
| --- | --- |
| `analysis_packet.json` | Structured sanitized finding candidate packet. |
| `chatgpt_prompt.md` | ChatGPT-oriented safe analysis prompt. |
| `codex_task_prompt.md` | Codex-oriented safe task prompt. |
| `report_draft.md` | Candidate report draft for manual review. |

Do not use safe files from an output that fails verification.

For the preflight status fields and troubleshooting, see
[GUI_AI_SAFE_PREFLIGHT.md](C:/coding/burp-ai-redaction-gateway/docs/GUI_AI_SAFE_PREFLIGHT.md).
For the handoff file order and metadata fields, see
[GUI_AI_HANDOFF_INDEX.md](C:/coding/burp-ai-redaction-gateway/docs/GUI_AI_HANDOFF_INDEX.md).
For finding candidate triage fields and boundaries, see
[GUI_FINDING_TRIAGE_INDEX.md](C:/coding/burp-ai-redaction-gateway/docs/GUI_FINDING_TRIAGE_INDEX.md).
For draft report readiness fields and boundaries, see
[GUI_REPORT_READINESS_INDEX.md](C:/coding/burp-ai-redaction-gateway/docs/GUI_REPORT_READINESS_INDEX.md).
For the full read-only workflow checklist, see
[GUI_WORKFLOW_STATUS_INDEX.md](C:/coding/burp-ai-redaction-gateway/docs/GUI_WORKFLOW_STATUS_INDEX.md).

## Never Send Or Document

Do not paste, upload, commit, or document the following:

| Do not send | Why |
| --- | --- |
| Raw request or response data | May contain sensitive values. |
| Real Burp XML exports | Raw traffic source. |
| `local_only/`, `raw/`, or `raw_vault/` | Local-only or raw storage areas. |
| Unverified `out/` output | Safety gate has not passed. |
| `out/.audit/` logs, archives, or manifests | Operational evidence, not AI prompt material. |
| Cookie, Authorization, token, JWT, or session values | Authentication or session material. |
| Real domains, customer names, internal IPs, or personal data | Sensitive environment or identity data. |
| HMAC secrets, CSRF values, or local secret files | Security-sensitive local values. |

## Result Interpretation

Dashboard findings remain candidates until manual verification is complete.

- `confidence` is evidence confidence, not severity.
- `risk_rating_draft` is a draft likelihood and impact workflow.
- `severity_draft` is not final severity.
- Final severity requires authorized reproduction, role comparison, business
  impact review, and manual risk decision.
- CVSS is a separate calculation scope and is not implied by this dashboard.

## Operations Index

Use `/help` or `/operations` when you need to find the right guide from the
dashboard. The operations index is intentionally read-only. It does not add:

- raw viewers
- replay or active scan
- archive or HMAC execution buttons
- finding triage execution buttons
- report readiness execution buttons
- workflow status execution buttons
- AI-safe preflight execution buttons
- AI handoff execution buttons
- risk profile change buttons
- delete or edit actions
- settings-write actions

## Troubleshooting

| Symptom | Meaning | Next step |
| --- | --- | --- |
| Output is not listed | The output may not be under the dashboard root or may fail verification. | Run `verify` on the output directory before using it. |
| Safe file is missing | The selected flow has not generated that file yet. | Run the relevant CLI or dashboard action after verification. |
| Report wording looks too certain | The report may be interpreted as final. | Keep candidate wording and run manual verification before changing severity. |
| HMAC is not configured on `/settings` | The local secret is not configured for verification. | Configure it locally if needed; do not paste the secret into docs, chat, logs, or PRs. |
| Audit/archive status is missing | Local audit operation artifacts have not been created. | Use the CLI audit operations guide. Generated artifacts remain local-only. |

