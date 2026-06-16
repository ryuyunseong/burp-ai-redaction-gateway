# Live Capture Runtime Evidence Source v0.5

This document defines how the `/live-capture` read-only dashboard status panel
should receive runtime smoke evidence in a future implementation. It is a
planning document only.

It does not add runtime behavior, collector forwarding, receiver ingest,
dashboard state-changing actions, evidence upload, evidence mutation, raw
preview, raw download, replay, active scan, HMAC handling, CSRF handling,
retention, delete policy, or automatic AI handoff behavior.

## Current Boundary

- `/live-capture` is a read-only status panel.
- The panel may display runtime smoke status labels and safe aliases only.
- The panel may link to verified receiver output pages only after verify passes.
- The panel must not start capture, stop capture, replay traffic, run active
  scans, preview raw traffic, download raw traffic, or mutate evidence.
- Findings remain candidates.
- Risk remains draft.
- Final severity and CVSS remain manual decisions.
- Runtime smoke evidence is readiness evidence only.
- Runtime smoke evidence is not external sharing clearance.

## Candidate Evidence Sources

Future work should choose one source, or a small combination of these sources,
before adding any new dashboard integration.

### Option 1: Existing Receiver Output Alias

Use the verified receiver output alias as the primary status source.

Allowed values:

- receiver output alias
- receiver verify status
- safe file existence status
- candidate count
- raw_data_included: false

Tradeoff:

- Lowest implementation risk.
- Does not prove extension load or collector skip counts by itself.
- Works with the existing verify-first boundary.

### Option 2: Local-Only Smoke Evidence File

Use a local-only metadata file created outside the dashboard from the manual
runtime smoke checklist.

Allowed values:

- extension load status
- local receiver status
- in-scope handoff count
- out-of-scope skip count
- missing_host_skipped count
- invalid_host_skipped count
- receiver verify status
- receiver output alias
- raw markers seen count
- raw_data_included: false

Tradeoff:

- Gives the dashboard enough status evidence to explain runtime readiness.
- Requires a strict schema and forbidden field checks.
- Must stay local-only and ignored by Git.
- Must not include target identifiers, raw traffic, credentials, personal data,
  or full local paths.

### Option 3: Manual Count And Status Summary

Let the operator manually copy only counts and pass/fail labels into a local
metadata summary outside the dashboard.

Allowed values:

- pass/fail labels
- handoff and skip counts
- safe route aliases
- receiver output alias
- raw_data_included: false

Tradeoff:

- Easy to use after manual Burp runtime smoke.
- Prone to transcription mistakes.
- Requires clear wording that the summary is not final security evidence.

## Recommended First Source

Use the existing receiver output alias first. Add a local-only smoke evidence
file only after the raw-free schema and forbidden field checks are stable.

The first dashboard integration should keep this order:

1. Show `/live-capture` as a read-only status panel.
2. If a verified receiver output alias is present, show safe navigation links.
3. If a local-only smoke evidence file is later approved, read status labels and
   counts only.
4. Keep all mutation or intake behavior in a separate reviewed PR.

## Raw-Free Schema

A future local-only smoke evidence file should use metadata-only fields like:

```json
{
  "schema_version": "live_capture_runtime_evidence_v0.5",
  "source_type": "manual_runtime_smoke",
  "extension_load_status": "passed",
  "local_receiver_status": "passed",
  "in_scope_handoff_count": 1,
  "out_of_scope_skip_count": 1,
  "missing_host_skipped": 0,
  "invalid_host_skipped": 0,
  "receiver_verify_status": "passed",
  "receiver_output_alias": "receiver_output_alias",
  "raw_markers_in_extension_output": 0,
  "raw_data_included": false
}
```

The example uses placeholders only. It must not be copied with actual target
identifiers, raw request or response values, credential values, personal data,
or full local paths.

## Forbidden Fields

The evidence source must not contain:

- actual target identifiers
- actual URL, domain, or IP values
- raw request values
- raw response values
- Cookie values
- Authorization values
- token, JWT, or session values
- personal data
- HMAC secret values
- CSRF token values
- full local paths
- stack trace bodies
- raw audit rows
- archive content
- final severity decisions
- CVSS scores
- external sharing clearance claims

## Verify-First Safe Navigation

Safe navigation links must stay hidden unless receiver output verification has
passed.

Allowed links after verify passes:

- simple dashboard
- safe files
- triage
- report readiness
- workflow

Safe file candidates remain limited to:

- `analysis_packet.json`
- `chatgpt_prompt.md`
- `codex_task_prompt.md`
- `report_draft.md`

These files are AI input candidates only. They still require manual review
before use.

## Future Action Boundary

A future POST or local summary intake action is a separate security-sensitive
PR. It must define:

- CSRF behavior
- server-side validation
- action audit fields
- failure messages
- rollback behavior
- forbidden field tests
- path traversal checks
- raw-free Browser smoke

This document does not approve such an action. It only records that any future
state-changing dashboard behavior must be reviewed separately.

## Acceptance Criteria

- `/live-capture` remains read-only until a later PR explicitly changes it.
- Evidence source fields are metadata-only.
- Receiver output aliases are used instead of local paths.
- Safe navigation appears only after verify passes.
- The dashboard does not store or display raw evidence.
- Runtime smoke evidence remains readiness evidence only.
- Findings remain candidates.
- Risk remains draft.
- Final severity and CVSS remain manual decisions.
