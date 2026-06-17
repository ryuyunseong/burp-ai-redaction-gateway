# v0.5 Roadmap

`v0.4.34` is the local-use final baseline. The v0.5 line should focus on
operational reliability, candidate quality, and first-time user experience
rather than expanding risky actions.

This roadmap is a planning document. It does not change runtime behavior,
redaction rules, dashboard actions, HMAC handling, CSRF handling, retention
policy, or release status.

The v0.5 MVP release readiness boundary is tracked in
[`RELEASE_READINESS_v0.5.md`](RELEASE_READINESS_v0.5.md).
The current RC readiness review is tracked in
[`RC_READINESS_v0.5.md`](RC_READINESS_v0.5.md).
MCP integration and Korean-first web UX planning are tracked in
[`MCP_INTEGRATION_DESIGN_v0.5.md`](MCP_INTEGRATION_DESIGN_v0.5.md) and
[`WEB_UX_KO_PLAN_v0.5.md`](WEB_UX_KO_PLAN_v0.5.md).
Post-v0.5 planning and the v0.5.x hotfix boundary are tracked in
[`ROADMAP_v0.6.md`](ROADMAP_v0.6.md) and
[`V0.5_HOTFIX_POLICY.md`](V0.5_HOTFIX_POLICY.md).

## Non-Negotiable Boundaries

- Raw request or response values must not be displayed, logged, committed, or
  copied into docs, issues, PRs, prompts, or release text.
- Real target identifiers, cookies, authorization values, token/JWT/session
  values, personal data, HMAC secrets, and CSRF tokens must not be used as
  examples.
- Findings remain candidates until manually reviewed.
- Risk ratings remain drafts until manually reviewed.
- Final severity and CVSS require separate manual decisions.
- Real export smoke success is readiness evidence only. It does not clear any
  output for AI handoff or external distribution.
- `local_only/`, `raw/`, `raw_vault/`, generated `out/`, and `out/.audit/`
  originals remain local artifacts and must not be treated as AI input.

## Priority 1: Operational Use and Friction Log

Goal: run `v0.4.34` in one or two real internal local workflows and record
operator friction without changing the data boundary.

Candidate tasks:

- Record where a first-time operator hesitates in the CLI or dashboard flow.
- Check whether the preferred first-screen path is clear:
  - `/upload`
  - `/live-capture` design boundary
  - `/simple?project=<alias>`
  - `/safe-files?project=<alias>`
  - `/triage?project=<alias>`
  - `/report-readiness?project=<alias>`
- Separate documentation friction from parser/redaction bugs.
- Convert reproducible bugs into scoped `fix/v0.4.x-*` work if they affect the
  final baseline.

Acceptance evidence:

- Friction notes contain only route aliases, command aliases, status labels, and
  raw-free metadata.
- No real export names, full paths, raw traffic, target identifiers, credentials,
  or personal data are copied into issue or PR text.

## Priority 2: Live Capture Wizard Design And Montoya Validation

Goal: design and then validate the Burp-side live capture workflow so the path
from exploration to local receiver to redaction is easier to trust.

Candidate tasks:

- Keep the design boundary in
  [`LIVE_CAPTURE_WIZARD_DESIGN_v0.5.md`](LIVE_CAPTURE_WIZARD_DESIGN_v0.5.md).
- Distinguish Upload Wizard file input from Live Capture Wizard guided Burp
  browsing.
- Keep `/live-capture` as a read-only status panel until actual
  collector/receiver capture integration lands in a separate reviewed PR.
- Define Live Capture as a local-only wizard, not an automatic ChatGPT handoff.
- Reuse the shared Live Capture scope guard for target normalization, safe
  aliasing, and exact/subdomain-only match checks around collector filtering.
- Add a receiver-side scope dry-run that evaluates safe host metadata only,
  returns raw-free accept/drop summaries, and does not change actual receiver
  ingest behavior.
- Add a receiver-side skip summary and audit event helper that converts dry-run
  decisions into raw-free metadata only. Keep actual audit file writing and
  receiver ingest behavior in separate reviewed PRs.
- Implement collector-side filtering with raw-free safe host metadata keys,
  synthetic fixture coverage, and skip status counts.
- Confirm in-scope filtering behavior with synthetic or authorized local-only
  inputs.
- Keep a synthetic scope drift matrix for collector host gating and receiver
  dry-run guard expectations:
  [`LIVE_CAPTURE_SCOPE_DRIFT_MATRIX_v0.5.md`](LIVE_CAPTURE_SCOPE_DRIFT_MATRIX_v0.5.md).
- Keep a raw-free runtime smoke checklist for extension load, receiver status,
  handoff counts, skip counts, and verify evidence:
  [`LIVE_CAPTURE_RUNTIME_SMOKE_CHECKLIST_v0.5.md`](LIVE_CAPTURE_RUNTIME_SMOKE_CHECKLIST_v0.5.md).
- Keep the latest raw-free Montoya runtime smoke release evidence connected to
  the release decision:
  [`V05_MONTOYA_RUNTIME_SMOKE_RELEASE_EVIDENCE.md`](V05_MONTOYA_RUNTIME_SMOKE_RELEASE_EVIDENCE.md).
- Keep a raw-free troubleshooting index for Upload Wizard and Live Capture
  setup, receiver, collector, dashboard, scope, and verify failures:
  [`TROUBLESHOOTING_v0.5.md`](TROUBLESHOOTING_v0.5.md).
- Keep the dashboard integration scope for `/live-capture` phase-based and
  read-only before adding any new dashboard action:
  [`LIVE_CAPTURE_DASHBOARD_INTEGRATION_PLAN_v0.5.md`](LIVE_CAPTURE_DASHBOARD_INTEGRATION_PLAN_v0.5.md).
- Define the future runtime evidence source before connecting runtime smoke
  evidence to the dashboard:
  [`LIVE_CAPTURE_RUNTIME_EVIDENCE_SOURCE_v0.5.md`](LIVE_CAPTURE_RUNTIME_EVIDENCE_SOURCE_v0.5.md).
- Use the verified receiver output alias as the first read-only evidence model
  before adding any local-only evidence file intake.
- Keep the planned local-only runtime smoke evidence schema raw-free and
  planning-only before adding any dashboard file reader:
  [`LIVE_CAPTURE_LOCAL_EVIDENCE_SCHEMA_v0.5.md`](LIVE_CAPTURE_LOCAL_EVIDENCE_SCHEMA_v0.5.md).
- Keep the v0.5 MVP included and excluded scope explicit before any tag or
  release decision:
  [`RELEASE_READINESS_v0.5.md`](RELEASE_READINESS_v0.5.md).
- Validate loopback receiver behavior and error messages.
- Check that collector logs remain raw-free.
- Document startup, stop, retry, and troubleshooting steps.
- Keep collector validation separate from new dashboard actions.

Out of scope for the first v0.5 slice:

- Active scan or replay actions.
- Remote collection endpoints.
- Credential, cookie, token, or raw traffic logging.

Acceptance evidence:

- Placeholder text does not imply actual traffic capture runtime support until
  collector/receiver integration lands.
- Collector validation can be reproduced without committing real traffic.
- Failure output uses safe aliases and status metadata only.

## Priority 3: Receiver to Redaction Flow Hardening

Goal: reduce friction in the local path from received events to verified
sanitized output.

Candidate tasks:

- Improve status messages for receiver input, generated output, and verify gate
  failures.
- Add clearer operator prompts for the next safe command.
- Keep fail-closed behavior when redaction or verification is uncertain.
- Preserve the four-file AI input candidate set.

Acceptance evidence:

- New messages do not expose raw values, full paths, stack traces, target
  identifiers, or secrets.
- Existing CLI and dashboard verification still pass.

## Priority 4: Candidate Triage Quality

Goal: reduce false positives, duplicates, and out-of-scope findings while
keeping candidate wording conservative.

Candidate tasks:

- Review a sample of generated candidates for duplicate patterns.
- Tune passive finding grouping where evidence is clearly repeated.
- Improve triage labels for likely false positive, duplicate, out-of-scope, and
  manual verification required.
- Preserve `do_not_claim` guidance and candidate language.

Acceptance evidence:

- Candidate count changes are explained as triage quality changes, not as
  validated vulnerability counts.
- Automation must not promote any issue to final severity or CVSS.

## Priority 5: Report Draft Quality

Goal: make `report_draft.md` more useful for a human reviewer while preserving
draft language.

Candidate tasks:

- Improve remediation draft wording.
- Clarify manual verification steps.
- Improve grouping and ordering of repeated candidate types.
- Add stronger reminders that final severity and CVSS are manual decisions.

Acceptance evidence:

- Report output remains a draft.
- Finding language stays candidate or suspected.
- The report does not imply external submission readiness.

## Priority 6: Windows Launcher and Setup UX

Goal: reduce first-run friction for Windows users.

Candidate tasks:

- Improve launcher troubleshooting for port conflicts and process cleanup.
- Clarify PowerShell execution policy handling.
- Add a short setup checklist for Python, GitHub CLI, Gitleaks, and optional
  Burp collector steps.
- Keep launcher output raw-free.

Acceptance evidence:

- A new operator can start and stop the local receiver and dashboard without
  touching raw export contents.
- Logs show ports, process ids, aliases, and status only.

## Priority 7: External User Documentation

Goal: make the repository understandable to another careful user without
weakening the local-only boundary.

Candidate tasks:

- Add a short troubleshooting index for install, verification, dashboard,
  Gitleaks, and release use.
- Keep v0.5 Live Capture and Upload Wizard troubleshooting categories in
  [`TROUBLESHOOTING_v0.5.md`](TROUBLESHOOTING_v0.5.md).
- Clarify internal local-use baseline versus broader distribution confidence.
- Add a GitHub Release follow-up checklist for future patch releases.

Acceptance evidence:

- Documentation remains raw-free.
- External-facing text does not claim AI handoff clearance, validated findings,
  final severity, or CVSS decisions.

## Priority 8: MCP And Korean-First Web UX Planning

Goal: define the safe MCP tool boundary and Korean-first dashboard copy before
adding any new MCP server behavior or dashboard orchestration.

Candidate tasks:

- Keep MCP integration read-only first:
  [`MCP_INTEGRATION_DESIGN_v0.5.md`](MCP_INTEGRATION_DESIGN_v0.5.md).
- Keep the Burp MCP compatibility boundary explicit:
  [`BURP_MCP_COMPATIBILITY_v0.5.md`](BURP_MCP_COMPATIBILITY_v0.5.md).
- Keep web UX improvements Korean-first and raw-free:
  [`WEB_UX_KO_PLAN_v0.5.md`](WEB_UX_KO_PLAN_v0.5.md).
- Separate design, prototype, and state-changing action PRs.
- Treat automatic ChatGPT handoff, replay, active scan, local evidence reader,
  and file deletion as deferred work.

Acceptance evidence:

- Tool and UI plans list allowed and forbidden boundaries.
- Planning text does not imply runtime support.
- New copy keeps candidate finding, draft risk, and manual severity/CVSS
  boundaries explicit.

## Branching Guidance

- v0.4 bug fixes: use `fix/v0.4.x-*` and consider a patch tag such as
  `v0.4.35` only after verification.
- v0.5 feature work: use `feat/v0.5-*` for runtime features and
  `docs/v0.5-*` for planning or documentation.
- High-risk changes stay small:
  - raw handling
  - HMAC secret handling
  - CSRF or state-changing dashboard actions
  - retention or deletion behavior
  - replay or active scan behavior

## Suggested First v0.5 Slices

Completed:

1. `feat/gui-upload-wizard-v0.5`
2. `docs/live-capture-wizard-design-v0.5`
3. `feat/live-capture-session-state-v0.5`
4. `feat/live-capture-scope-guard-v0.5`
5. `feat/live-capture-receiver-scope-dry-run-v0.5`
6. `feat/live-capture-receiver-skip-audit-v0.5`
7. `feat/live-capture-collector-filter-contract-v0.5`
8. `feat/live-capture-collector-filter-v0.5`
9. `test/live-capture-scope-drift-matrix-v0.5`
10. `test/live-capture-java-scope-matrix-v0.5`
11. `docs/live-capture-runtime-smoke-checklist-v0.5`
12. `docs/v0.5-troubleshooting-index`
13. `docs/v0.5-release-readiness`
14. `docs/mcp-and-web-ux-plan-v0.5`
15. `feat/web-ux-ko-quickstart-landing-v0.5`

Next:

1. `docs/v0.5-rc-readiness-review`
2. `docs/live-capture-dashboard-integration-plan-v0.5`
3. `feat/v0.5-live-capture-read-only-status-panel`
4. `feat/v0.5-montoya-live-validation`
5. `feat/v0.5-candidate-triage-quality`
6. `feat/v0.5-report-draft-quality`
7. `feat/v0.5-windows-launcher-ux`
