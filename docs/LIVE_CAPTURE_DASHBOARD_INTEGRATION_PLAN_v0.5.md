# Live Capture Dashboard Integration Plan v0.5

This document defines the dashboard integration plan for Live Capture after the
collector safe host filter runtime smoke. It is a planning document only. It
does not change runtime behavior, collector forwarding, receiver ingest,
dashboard routes, redaction rules, HMAC handling, CSRF handling, retention, or
delete policy.

The goal is to make `/live-capture` useful for operators without weakening the
raw-free boundary. The dashboard should guide an operator from local Burp
browsing evidence to verified receiver output and the same four AI input
candidate files used by the existing export and receiver flows.

## Current Boundary

- `/live-capture` remains a local dashboard route.
- Current start and stop controls are session placeholders.
- Collector filtering is validated separately from dashboard integration.
- Receiver output remains the source of verified safe files.
- Live Capture does not send content to ChatGPT.
- Live Capture does not make findings final.
- Live Capture does not decide final severity or CVSS.

## Phase 1: Read-Only Runtime Smoke Status Panel

First dashboard integration should be a read-only runtime smoke status panel.
It should help an operator record and review safe status evidence from a manual
or scripted local runtime smoke without starting capture, forwarding traffic, or
changing receiver ingest.

Allowed display fields:

- extension load status
- local receiver status
- in-scope handoff count
- out-of-scope skip count
- missing or invalid host skip count
- receiver verify status
- receiver output alias
- raw_data_included: false

The panel may support a local-only evidence import/status panel if the imported
evidence uses the raw-free smoke template. Imported evidence must contain counts,
status labels, route aliases, and output aliases only. Any operator checklist
display must remain raw-free and count-based.

Phase 1 must not add:

- dashboard state-changing action
- raw request/response preview is prohibited
- raw traffic download is prohibited
- collector forwarding changes
- receiver ingest changes
- replay is prohibited
- active scan is prohibited
- ChatGPT automatic handoff is prohibited

## Phase 2: Verified Receiver Output Navigation

After Phase 1, the dashboard can guide the operator from a verified receiver
output alias to existing read-only pages.

Allowed links after verification passes:

- simple dashboard
- safe files
- triage
- report readiness
- evidence boundary
- prompt readiness

The safe files remain limited to:

- `analysis_packet.json`
- `chatgpt_prompt.md`
- `codex_task_prompt.md`
- `report_draft.md`

The dashboard must keep the verify-first boundary. If receiver verify fails or
has not run, the UI should show status guidance only and avoid safe-file links.

## Phase 3: Future Action Review

Any future CSRF-protected dashboard action for Live Capture must be reviewed in
a separate implementation PR. That PR must define:

- action name
- server-side validation
- CSRF behavior
- raw-free action audit fields
- rollback behavior
- failure messages that avoid stack trace details
- tests for missing and invalid CSRF tokens
- tests for forbidden path and forbidden marker handling

Phase 3 is not approved by this plan. This document only records the decision
that future state-changing behavior is security-sensitive and must stay small.

## Non-Goals

This plan does not add or approve:

- raw request/response display
- raw traffic download
- replay
- active scan
- remote collection endpoints
- automatic ChatGPT handoff
- HMAC secret input UI
- retention or delete policy changes
- collector forwarding changes
- receiver ingest changes
- final severity decisions
- CVSS calculation

## Required Wording Boundaries

- Findings remain candidates.
- Risk remains draft.
- Final severity and CVSS remain manual decisions.
- Runtime smoke evidence is readiness evidence only.
- Runtime smoke evidence is not external sharing clearance.
- AI input candidate files still require manual review before use.

## Troubleshooting Categories

Use raw-free categories when dashboard integration does not line up with
operator expectations:

- `live_capture_status_missing`
- `receiver_output_alias_missing`
- `receiver_verify_not_run`
- `receiver_verify_failed_safely`
- `runtime_smoke_evidence_incomplete`
- `scope_mismatch`
- `dashboard_read_only_boundary_confusion`

Each entry should record only status labels, counts, route aliases, and output
aliases. Do not record actual target identifiers, raw traffic, credentials,
personal data, local machine details, or full local paths.

## Acceptance Criteria

- The first implementation after this plan is read-only.
- Runtime behavior remains unchanged unless a later implementation PR states
  otherwise.
- Dashboard text clearly separates status evidence from capture execution.
- Safe file navigation appears only after verify passes.
- No raw traffic, target identifiers, secrets, full local paths, or personal
  data are displayed.
- The operator can understand which follow-up is documentation, which is
  read-only dashboard status, and which is a future state-changing action.
