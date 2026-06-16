# Live Capture Local Evidence Schema v0.5

This document defines the planned metadata schema for a future local-only
runtime smoke evidence file. It is a planning document only.

The current dashboard does not read this file, upload this file, import this
file, or accept manual evidence input. Any future dashboard intake or
state-changing action must be reviewed in a separate security-sensitive PR.

## Purpose

The schema gives operators a raw-free way to summarize manual Burp Suite
runtime smoke results after Live Capture collector testing.

It is meant to record only:

- extension load status
- local receiver status
- in-scope handoff count
- out-of-scope skip count
- missing host skip count
- invalid host skip count
- receiver verify status
- receiver output alias
- raw marker count
- raw_data_included: false

It is not evidence that findings are confirmed, risk is final, or external
sharing is cleared.

## Current Boundary

- This is a schema design document only.
- It does not add runtime behavior.
- It does not change collector forwarding.
- It does not change receiver ingest.
- It does not add file read behavior.
- It does not add upload or import behavior.
- It does not add POST action behavior.
- It does not add dashboard live capture integration.
- It does not add raw preview or raw download behavior.
- It does not add replay or active scan behavior.
- It does not change HMAC secret handling.
- It does not change CSRF handling.
- It does not change retention or delete policy.

## File Placement

Future real evidence files should stay in an ignored local-only location. Shared
docs, PR bodies, and release notes should use only safe aliases.

Do not record full local paths or actual local-only filenames in shared text.

## Schema

The planned file is JSON. Field names are stable enough for future review, but
no runtime reader is approved by this document.

```json
{
  "schema_version": "live-capture-local-evidence-v1",
  "source_type": "manual_runtime_smoke",
  "evidence_source": "local_only_smoke_evidence_file",
  "extension_load_status": "passed",
  "local_receiver_status": "passed",
  "in_scope_handoff_count": 1,
  "out_of_scope_skip_count": 1,
  "missing_host_skipped": 0,
  "invalid_host_skipped": 0,
  "receiver_verify_status": "passed",
  "receiver_output_alias": "receiver_output_alias",
  "raw_markers_in_extension_output": 0,
  "target_identifiers_recorded": false,
  "raw_traffic_recorded": false,
  "credential_values_recorded": false,
  "raw_data_included": false,
  "created_at_utc": "2026-01-01T00:00:00Z"
}
```

The example is synthetic. It must not be replaced with actual target
identifiers, traffic values, credential values, personal data, or full local
paths.

## Required Fields

| Field | Meaning |
| --- | --- |
| `schema_version` | Fixed schema marker for this metadata shape. |
| `source_type` | Evidence creation mode, such as manual runtime smoke. |
| `evidence_source` | Safe source label. |
| `extension_load_status` | Pass or fail label for Burp extension loading. |
| `local_receiver_status` | Pass or fail label for loopback receiver availability. |
| `in_scope_handoff_count` | Count of in-scope items handed to the receiver. |
| `out_of_scope_skip_count` | Count of out-of-scope items skipped by collector filtering. |
| `missing_host_skipped` | Count of items skipped because safe host metadata was absent. |
| `invalid_host_skipped` | Count of items skipped because safe host metadata was invalid. |
| `receiver_verify_status` | Pass or fail label from receiver output verification. |
| `receiver_output_alias` | Safe alias for the receiver output. |
| `raw_markers_in_extension_output` | Count of disallowed raw markers seen in extension output. |
| `target_identifiers_recorded` | Must be false for shared evidence. |
| `raw_traffic_recorded` | Must be false for shared evidence. |
| `credential_values_recorded` | Must be false for shared evidence. |
| `raw_data_included` | Must be false. |
| `created_at_utc` | Synthetic or local timestamp. It is not a security decision. |

## Forbidden Content

Do not include:

- actual target identifiers
- actual URL, domain, or IP values
- request or response bodies
- Cookie values
- Authorization values
- token, JWT, or session values
- personal data
- HMAC secret values
- CSRF token values
- full local paths
- actual local-only filenames
- stack trace bodies
- raw audit rows
- archive content
- final severity decisions
- CVSS scores
- sharing approval claims

## Future Intake Requirements

A future dashboard reader for this schema must be a separate PR and must define:

- path traversal checks
- forbidden directory checks
- schema validation
- strict forbidden field checks
- raw-free error messages
- action audit behavior if any state changes are introduced
- CSRF behavior for any POST action
- Browser smoke proving no raw values, secrets, or full paths are displayed

Until that PR exists, `/live-capture` should continue using the verified
receiver output alias as its implemented read-only evidence model.

## Interpretation Rules

- Findings remain candidates.
- Risk remains draft.
- Final severity and CVSS remain manual decisions.
- Runtime smoke evidence is readiness evidence only.
- A passing smoke record is not sharing approval.
- AI input candidates remain limited to the verified safe file allowlist.
