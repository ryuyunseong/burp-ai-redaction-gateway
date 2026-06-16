# v0.5 Troubleshooting Index

This index is a raw-free troubleshooting guide for the v0.5 Upload Wizard and
Live Capture work. It helps an operator classify common setup, receiver,
collector, dashboard, and verification failures without copying sensitive
traffic or environment details into notes, issues, PRs, prompts, or release
text.

This document does not change runtime behavior, collector forwarding, receiver
ingest, dashboard integration, replay behavior, active scan behavior, raw
preview behavior, HMAC handling, CSRF handling, retention policy, or AI handoff
rules.

## Evidence Boundary

Troubleshooting notes may include only raw-free metadata:

- tool version or branch alias
- feature area
- failure category
- passed or failed state
- safe route alias
- safe project alias
- count values
- file existence state
- validation status
- next action label

Troubleshooting notes must not include:

- actual target identifiers
- actual URL, domain, or IP values
- raw request or response values
- raw audit rows
- Cookie values
- Authorization values
- token, JWT, or session values
- personal data
- HMAC secrets
- CSRF token values
- full local paths
- local-only file names from a real run
- generated output contents
- validated finding claims
- final severity or CVSS decisions

Findings remain candidates. Risk remains draft. Final severity and CVSS remain manual decisions.
A successful runtime smoke, upload validation, verify step, or dashboard check
is readiness evidence only and does not clear an output for AI handoff or
external distribution.

## Raw-Free Evidence Format

Use this format in local notes or PR summaries:

```text
feature area: <upload_wizard|live_capture|receiver|dashboard|verify>
failure category: <raw_free_category>
tool version or branch: <safe_alias>
project alias: <safe_alias_or_n/a>
route alias: <safe_route_or_n/a>
observed status: <passed|failed|blocked>
safe count summary: <count_or_n/a>
raw markers recorded: 0
actual target identifiers recorded: no
raw request/response recorded: no
token/cookie/session recorded: no
personal data recorded: no
next action: <safe_action_label>
```

Keep completed notes local-only until they are reviewed and scrubbed.

## Failure Categories

| Category | Meaning | Safe checks | Next action |
| --- | --- | --- | --- |
| `extension_load_failed` | The Montoya extension did not load in Burp Suite. | Confirm the collector build status, extension type, and JAR selection using safe file aliases only. | Rebuild the collector, retry extension load, and record only pass/fail plus the safe failure label. |
| `receiver_unavailable` | The local receiver was not reachable by the collector or operator flow. | Check whether the receiver process is running and whether the configured receiver alias matches the expected local setup. | Restart the receiver with safe aliases, then repeat the handoff smoke. |
| `no_in_scope_handoff` | Expected in-scope synthetic or authorized local-only traffic produced no handoff. | Compare safe scope alias, collector status count, and receiver event count. | Recheck scope configuration and run the synthetic local-only in-scope step again. |
| `no_out_of_scope_skip` | Expected out-of-scope synthetic or authorized local-only traffic did not increase the skip count. | Check the out-of-scope skip count and confirm that the test input was intended to be out of scope. | Recheck scope boundaries and repeat the out-of-scope step without recording identifiers. |
| `verify_failed_safely` | Verification failed without exposing raw values. | Record verify status, safe error class, and whether raw markers stayed absent. | Keep the output out of AI handoff, classify the cause, and run the smallest relevant fix or follow-up. |
| `upload_validation_failed` | Upload Wizard validation rejected an input or project alias. | Record file type label, validation state, and safe error class only. | Use an allowed input type or corrected project alias, then rerun validation. |
| `invalid_project_alias` | A project alias failed validation. | Check whether the alias uses the documented safe alias format. | Replace it with a safe alias and retry. |
| `dashboard_server_not_running` | The expected local dashboard route was unavailable. | Check dashboard process state and route alias only. | Start the dashboard again and repeat the read-only route check. |
| `scope_mismatch` | Collector-side and receiver-side scope expectations did not match. | Compare safe scope aliases, handoff count, skip count, and receiver dry-run summary. | Use the scope drift matrix and open a follow-up if Java and Python expectations diverge. |

## Category Notes

### `extension_load_failed`

Start with collector build output and Burp extension load status. Do not paste
Burp extension stack traces, target names, request lines, headers, or full local
paths into shared notes. If the failure is reproducible, record the safe failure
label and whether the collector build gate passed.

### `receiver_unavailable`

Treat this as a local setup problem until proven otherwise. Record whether the
receiver was started, whether the dashboard or receiver route alias was checked,
and whether the smoke was blocked before any handoff.

### `no_in_scope_handoff`

This can mean the collector filter was too strict, the scope alias was wrong,
or the synthetic local-only in-scope step did not run as expected. Record only
the expected count class and actual count.

### `no_out_of_scope_skip`

This can mean the out-of-scope step was not actually out of scope, or that skip
count reporting did not update. Record only the skip count and the safe failure
category.

### `verify_failed_safely`

Verification failure is fail-closed behavior. Do not use generated output as an
AI input candidate until verify passes and the four candidate files are manually
reviewed.

### `upload_validation_failed`

Upload Wizard rejection should stay local and raw-free. Record validation type,
project alias status, and whether the failure happened before output generation.

### `invalid_project_alias`

Use a safe alias that does not identify a real target, customer, person,
environment, or local path. Record only the alias validation status.

### `dashboard_server_not_running`

This is an operator setup category. Record whether the dashboard was started and
which read-only route alias was intended. Do not add screenshots that include
raw traffic or local system details.

### `scope_mismatch`

Use this when Java collector validation and Python receiver scope handling appear
to disagree. Keep the follow-up focused on the matrix case and expected raw-free
decision, not on the actual host or request.

### `live_capture_status_missing`

Use this when the future Live Capture dashboard status panel cannot find
raw-free runtime smoke evidence or a receiver output alias. Record only the
status label that was expected and whether the operator intended a read-only
status check.

### `dashboard_read_only_boundary_confusion`

Use this when an operator expects `/live-capture` to run capture, replay,
active scan, raw preview, raw download, or automatic ChatGPT handoff. Route the
follow-up to the dashboard integration plan unless a separate implementation PR
has already approved a CSRF-protected dashboard action.

## Related Documents

- [`LIVE_CAPTURE_RUNTIME_SMOKE_CHECKLIST_v0.5.md`](LIVE_CAPTURE_RUNTIME_SMOKE_CHECKLIST_v0.5.md)
- [`LIVE_CAPTURE_DASHBOARD_INTEGRATION_PLAN_v0.5.md`](LIVE_CAPTURE_DASHBOARD_INTEGRATION_PLAN_v0.5.md)
- [`LIVE_CAPTURE_RUNTIME_EVIDENCE_SOURCE_v0.5.md`](LIVE_CAPTURE_RUNTIME_EVIDENCE_SOURCE_v0.5.md)
- [`LIVE_CAPTURE_LOCAL_EVIDENCE_SCHEMA_v0.5.md`](LIVE_CAPTURE_LOCAL_EVIDENCE_SCHEMA_v0.5.md)
- [`templates/LIVE_CAPTURE_RUNTIME_SMOKE_EVIDENCE_TEMPLATE.md`](templates/LIVE_CAPTURE_RUNTIME_SMOKE_EVIDENCE_TEMPLATE.md)
- [`LIVE_CAPTURE_SCOPE_DRIFT_MATRIX_v0.5.md`](LIVE_CAPTURE_SCOPE_DRIFT_MATRIX_v0.5.md)
- [`LIVE_CAPTURE_COLLECTOR_CONTRACT_v0.5.md`](LIVE_CAPTURE_COLLECTOR_CONTRACT_v0.5.md)
- [`MONTOYA_COLLECTOR.md`](MONTOYA_COLLECTOR.md)
- [`LOCALHOST_RECEIVER.md`](LOCALHOST_RECEIVER.md)
- [`GUI_UPLOAD_WIZARD.md`](GUI_UPLOAD_WIZARD.md)
- [`LOCAL_DASHBOARD.md`](LOCAL_DASHBOARD.md)
- [`ROADMAP_v0.5.md`](ROADMAP_v0.5.md)

## Follow-Up Routing

- v0.4 hotfix: use only when the issue affects the released local-use baseline.
- v0.5 documentation follow-up: use when the operator step is unclear but
  runtime behavior is unchanged.
- v0.5 runtime follow-up: use when collector, receiver, or dashboard behavior
  needs implementation or test changes.
- Security-sensitive follow-up: keep separate when the change touches raw
  handling, HMAC secrets, CSRF, file deletion, retention, replay, or active scan
  behavior.
