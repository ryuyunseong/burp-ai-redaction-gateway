# v0.5 Montoya Runtime Smoke Release Evidence

This document records the latest raw-free Montoya runtime smoke evidence for
the v0.5 release decision. It is readiness evidence only.

It does not create a tag, publish a GitHub Release, change runtime behavior,
add MCP server behavior, add a local evidence file reader, add upload or import
evidence actions, add dashboard POST actions, change collector forwarding,
change receiver ingest, change HMAC handling, change CSRF handling, or change
file retention or delete policy.

## Summary

| Field | Value |
| --- | --- |
| smoke date | 2026-06-17 |
| run label | `montoya-runtime-smoke-v0.5-release-evidence` |
| tested commit alias | `2e7503b` |
| evidence type | manual Burp Suite runtime smoke |
| evidence status | passed |
| raw_data_included | false |

## Runtime Checks

| Check | Result |
| --- | --- |
| extension load status | passed |
| local receiver status | passed |
| in_scope_handoff_count | 2 |
| out_of_scope_skip_count | 47 |
| missing_host_skipped | 0 |
| invalid_host_skipped | 0 |
| receiver_verify_status | passed |
| receiver_output_alias | `montoya_runtime_smoke` |

## Boundary Checks

| Boundary | Result |
| --- | --- |
| raw_marker_count | 0 |
| raw_data_included | false |
| target_identifiers_recorded | false |
| raw_traffic_recorded | false |
| credential_values_recorded | false |
| full_local_paths_recorded | false |
| actual_local_only_filenames_recorded | false |
| HMAC secret recorded | false |
| CSRF token value recorded | false |

## Release Interpretation

- This evidence supports a v0.5 tag/release decision review.
- This evidence is not external sharing approval.
- This evidence is not sharing clearance.
- Candidate findings are not confirmed issues.
- Risk remains draft.
- Final severity and CVSS remain manual decisions.
- No tag until explicit approval.
- No GitHub Release until explicit approval.

## Excluded Evidence

The release evidence does not include:

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

## Follow-Up

Before creating a tag or GitHub Release, confirm that this evidence still
matches the intended release commit and repeat the raw-free runtime smoke if the
collector, receiver, dashboard, or release commit changes.
