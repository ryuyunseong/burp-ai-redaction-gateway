# GUI Upload Wizard

The GUI Upload Wizard is the v0.5 entry point for operators who want to process
a local Burp export from the dashboard instead of typing each CLI command.

It is still a local-only workflow. It does not send anything to ChatGPT, does
not publish files, and does not make findings final.

The Korean web operator guide is
[`WEB_OPERATOR_GUIDE_KO_v0.7.md`](WEB_OPERATOR_GUIDE_KO_v0.7.md). Use that guide
when an operator needs to distinguish current web UI behavior from unavailable
MCP listener runtime, raw preview, replay, active scan, and automatic handoff
work.

## Route

```text
GET /upload
POST /upload
```

`GET /upload` shows the upload form. `POST /upload` accepts one local Burp
export and runs the safe processing pipeline.

Allowed upload extensions:

- `.xml`
- `.json`

The dashboard rejects unsupported file types, empty uploads, oversized uploads,
and invalid project aliases before running the pipeline.

## Processing Flow

The wizard runs this sequence:

```text
upload validation
-> ignored local-only storage
-> redaction/generate
-> verify
-> review
-> report draft
-> safe file status
```

If `verify` fails, the wizard stops safely. Review and report are skipped, and
the page does not show safe file links.

The upload form now states this boundary directly:

- the workflow is local-only
- ChatGPT automatic handoff is absent
- output must pass `verify` before any AI candidate file is used
- raw preview/download, replay, and active scan are absent
- MCP listener runtime, transport/protocol handling, and tool execution are not
  part of the Upload Wizard

## Result Links

When the full flow succeeds, the result page links to:

- `/simple?project=<alias>`
- `/safe-files?project=<alias>`
- `/triage?project=<alias>`
- `/report-readiness?project=<alias>`

The safe files remain limited to:

- `analysis_packet.json`
- `chatgpt_prompt.md`
- `codex_task_prompt.md`
- `report_draft.md`

These files are AI input candidates only after manual review.

The success page should guide the operator to:

1. open Simple Dashboard for the overall status
2. check Safe Files for the four candidate files
3. use Triage for candidate finding review
4. use Report Readiness for draft report boundaries
5. copy only the manually reviewed subset

## Security Boundary

The wizard does not display or record:

- original request or response bodies
- request body or response body previews
- Cookie values
- Authorization values
- token, JWT, or session values
- real URL, domain, IP, tenant, account, or customer identifiers
- personal data
- integrity secrets
- request-forgery protection values
- full local paths
- actual local-only filenames
- raw upload previews
- report body previews
- prompt body previews

The uploaded source file is saved under an ignored local-only storage area using
an internal generated name. The generated name and full path are not shown in
the dashboard or action audit.

## Action Audit

The upload POST action writes a raw-free dashboard action audit event.

Audit metadata may include:

- action name
- project alias
- result status
- blocked reason
- `raw_data_included: false`

Audit metadata must not include the uploaded file name, generated storage path,
CSRF value, secret value, raw row body, or stack trace.

## Failure Handling

Failure pages and result pages show safe failure categories only.

Common categories:

- `csrf_token_missing`
- `csrf_token_invalid`
- `unsupported_file_type`
- `invalid_project_alias`
- `upload_validation_failed`
- `generate failed`
- `verify failed safely`
- `review skipped`
- `report skipped`
- `environment issue`

Failure output is not an AI input candidate. Do not copy failed output files,
raw uploads, local-only files, or audit artifacts into ChatGPT.

When verification or processing fails, the result page must not show review,
report, or safe file links. It should say that output before verify is not an AI
input candidate.

## Interpretation Boundary

Upload success means the local pipeline completed for the selected file. It does
not mean the output is safe for external sharing.

- finding means candidate
- risk means draft
- final severity is a manual decision
- CVSS is a separate manual calculation
- the four safe files still require human review before AI use

