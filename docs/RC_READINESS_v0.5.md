# v0.5 RC Readiness Review

This document records whether the current `main` branch can be treated as a
v0.5 release candidate candidate. It is a readiness review document only.

It does not create a tag, publish a GitHub Release, change runtime behavior,
add MCP server behavior, add a local evidence file reader, add upload or import
evidence actions, add dashboard POST actions, change collector forwarding,
change receiver ingest, change HMAC handling, change CSRF handling, or change
file retention or delete policy.

## Current Decision

RC possible with follow-up required.

The current `main` branch is a reasonable v0.5 RC candidate for review because
the implemented MVP and planning boundaries are documented, the read-only
dashboard flow is present, and the required static and smoke evidence can be
checked without exposing raw data.

A v0.5 tag or GitHub Release still needs explicit approval after this review.

## Included RC Scope

The current RC candidate scope includes:

- Upload Wizard.
- Local dashboard.
- Home Korean quickstart landing.
- `/live-capture` read-only status panel.
- Receiver output alias evidence model.
- Montoya collector safe host filter.
- Receiver dry-run and skip summary helper.
- Runtime smoke checklist.
- Troubleshooting index.
- Local evidence schema planning document.
- MCP integration design.
- Korean-first web UX plan.
- Safe files four-file allowlist:
  - `analysis_packet.json`
  - `chatgpt_prompt.md`
  - `codex_task_prompt.md`
  - `report_draft.md`

## Excluded RC Scope

The current RC candidate scope excludes:

- ChatGPT automatic handoff.
- MCP server implementation.
- Raw preview or raw download.
- Replay.
- Active scan.
- Local evidence file reader.
- Upload or import evidence action.
- Dashboard state-changing live capture orchestration.
- HMAC secret UI.
- File retention or delete policy changes.
- Automatic final severity or CVSS decisions.

Excluded items require separate review. Do not treat this RC review as approval
to implement them.

## RC Checklist

Before any v0.5 tag or GitHub Release decision, confirm these checks using
raw-free metadata only:

- compileall.
- unittest.
- verify --input out.
- review/report demo.
- Montoya gradle build.
- Browser smoke for `/`, `/upload`, `/live-capture`, `/safe-files`, `/help`.
- Montoya runtime smoke evidence.
- Montoya runtime smoke release evidence.
- Gitleaks dir.
- Gitleaks git.
- git_safety_check.
- git diff --check.
- PR body hygiene.
- docs forbidden marker check.
- no tag until explicit approval.
- no GitHub Release until explicit approval.

## Release Risk Notes

- The local evidence reader does not exist yet.
- Dashboard live capture orchestration does not exist yet.
- MCP server is not implemented yet.
- Computer Use GUI automation is not a stable release gate.
- Latest Montoya runtime smoke release evidence is recorded as raw-free manual evidence.
- Candidate findings are not confirmed issues.
- Risk remains draft.
- Final severity and CVSS remain manual decisions.
- Passing smoke evidence is readiness evidence only.
- Passing smoke evidence is not sharing approval.
- A tag or GitHub Release must not be created without explicit approval.

## Required Hygiene

Shared docs, PR bodies, release notes, issues, and handoff text must not include:

- target identifiers
- URL, domain, or IP values
- request or response bodies
- credential or browser state values
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

- [`RELEASE_READINESS_v0.5.md`](RELEASE_READINESS_v0.5.md)
- [`ROADMAP_v0.5.md`](ROADMAP_v0.5.md)
- [`LIVE_CAPTURE_RUNTIME_SMOKE_CHECKLIST_v0.5.md`](LIVE_CAPTURE_RUNTIME_SMOKE_CHECKLIST_v0.5.md)
- [`V05_MONTOYA_RUNTIME_SMOKE_RELEASE_EVIDENCE.md`](V05_MONTOYA_RUNTIME_SMOKE_RELEASE_EVIDENCE.md)
- [`LIVE_CAPTURE_RUNTIME_EVIDENCE_SOURCE_v0.5.md`](LIVE_CAPTURE_RUNTIME_EVIDENCE_SOURCE_v0.5.md)
- [`LIVE_CAPTURE_LOCAL_EVIDENCE_SCHEMA_v0.5.md`](LIVE_CAPTURE_LOCAL_EVIDENCE_SCHEMA_v0.5.md)
- [`MCP_INTEGRATION_DESIGN_v0.5.md`](MCP_INTEGRATION_DESIGN_v0.5.md)
- [`WEB_UX_KO_PLAN_v0.5.md`](WEB_UX_KO_PLAN_v0.5.md)
- [`TROUBLESHOOTING_v0.5.md`](TROUBLESHOOTING_v0.5.md)

## Next Decision

After this document is reviewed, decide whether to proceed with a v0.5 tag and
GitHub Release draft. That decision is separate from this PR.
