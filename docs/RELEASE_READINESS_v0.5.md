# v0.5 Release Readiness

This document summarizes the current v0.5 MVP scope and the checks that must
pass before any tag or GitHub Release is considered. It is a planning and
readiness document only.

The current RC review is recorded in
[`RC_READINESS_v0.5.md`](RC_READINESS_v0.5.md).

It does not create a tag, publish a release, change runtime behavior, add a
local evidence file reader, add upload or import evidence actions, add POST
actions, change collector forwarding, change receiver ingest, change HMAC
handling, change CSRF handling, or change retention or delete policy.

## MVP Included Scope

The current v0.5 MVP candidate includes:

- Upload Wizard.
- Local dashboard.
- `/live-capture` read-only status panel.
- Receiver output alias evidence model.
- Montoya collector safe host filter.
- Receiver dry-run and skip summary helper.
- Runtime smoke checklist.
- Troubleshooting index.
- Local evidence schema planning document.
- MCP integration design document.
- Korean-first web UX planning document.
- Safe files four-file allowlist:
  - `analysis_packet.json`
  - `chatgpt_prompt.md`
  - `codex_task_prompt.md`
  - `report_draft.md`

## Excluded Scope

The current v0.5 MVP candidate excludes:

- ChatGPT automatic handoff.
- Raw preview or raw download.
- Replay.
- Active scan.
- Local evidence file reader.
- Upload or import evidence action.
- Dashboard state-changing live capture orchestration.
- New MCP runtime behavior.
- Automatic MCP-based ChatGPT handoff.
- HMAC secret UI.
- File retention or delete policy changes.
- Automatic final severity or CVSS decisions.

Excluded items must remain separate reviewed work. Do not treat this readiness
document as approval to add them.

## Readiness Checklist

Before any v0.5 tag or release decision, record the result of each check using
only raw-free metadata:

- Python compileall.
- Python unittest.
- `verify --input out`.
- Demo review and report generation.
- Montoya Gradle build.
- Browser smoke for `/upload`, `/live-capture`, `/safe-files`, and `/simple`.
- Gitleaks directory scan.
- Gitleaks git history scan.
- Git safety check.
- Git diff whitespace check.
- Actual Burp runtime smoke raw-free evidence.
- Montoya runtime smoke release evidence.
- PR body hygiene.
- Docs forbidden marker check.
- No tag until explicit approval.

## Release Risk Notes

- The local evidence reader does not exist yet.
- Dashboard live capture orchestration does not exist yet.
- Computer Use GUI automation is not a stable release gate.
- Latest Montoya runtime smoke release evidence is recorded as raw-free manual evidence.
- Candidate findings are not confirmed issues.
- Risk remains draft.
- Final severity and CVSS remain manual decisions.
- Passing smoke evidence is readiness evidence only.
- Passing smoke evidence is not sharing approval.

## Required Hygiene

Shared docs, PR bodies, release notes, and issue text must not include:

- target identifiers
- URL, domain, or IP values
- request or response bodies
- credential or session values
- personal data
- HMAC secret values
- CSRF token values
- full local paths
- actual local-only filenames
- raw audit rows
- archive content
- vulnerability confirmation claims
- automatic final severity claims
- sharing approval claims

## Related Documents

- [`ROADMAP_v0.5.md`](ROADMAP_v0.5.md)
- [`RC_READINESS_v0.5.md`](RC_READINESS_v0.5.md)
- [`GUI_UPLOAD_WIZARD.md`](GUI_UPLOAD_WIZARD.md)
- [`LIVE_CAPTURE_WIZARD_DESIGN_v0.5.md`](LIVE_CAPTURE_WIZARD_DESIGN_v0.5.md)
- [`LIVE_CAPTURE_RUNTIME_SMOKE_CHECKLIST_v0.5.md`](LIVE_CAPTURE_RUNTIME_SMOKE_CHECKLIST_v0.5.md)
- [`V05_MONTOYA_RUNTIME_SMOKE_RELEASE_EVIDENCE.md`](V05_MONTOYA_RUNTIME_SMOKE_RELEASE_EVIDENCE.md)
- [`LIVE_CAPTURE_DASHBOARD_INTEGRATION_PLAN_v0.5.md`](LIVE_CAPTURE_DASHBOARD_INTEGRATION_PLAN_v0.5.md)
- [`LIVE_CAPTURE_RUNTIME_EVIDENCE_SOURCE_v0.5.md`](LIVE_CAPTURE_RUNTIME_EVIDENCE_SOURCE_v0.5.md)
- [`LIVE_CAPTURE_LOCAL_EVIDENCE_SCHEMA_v0.5.md`](LIVE_CAPTURE_LOCAL_EVIDENCE_SCHEMA_v0.5.md)
- [`MCP_INTEGRATION_DESIGN_v0.5.md`](MCP_INTEGRATION_DESIGN_v0.5.md)
- [`WEB_UX_KO_PLAN_v0.5.md`](WEB_UX_KO_PLAN_v0.5.md)
- [`TROUBLESHOOTING_v0.5.md`](TROUBLESHOOTING_v0.5.md)

## Release Decision Boundary

A future v0.5 tag or GitHub Release needs explicit approval after the readiness
checks are reviewed. This document only defines what should be reviewed.
