# MCP Registry Adapter Fixture Plan v0.6

This document defines the fixture plan for a future read-only MCP registry
adapter. It is a planning and fixture document only.

It does not implement an MCP server, MCP transport, protocol handler, actual
tool execution, local evidence reader, upload or import action, dashboard POST
action, collector forwarding change, receiver ingest change, raw preview or
download, replay, active scan, automatic ChatGPT handoff, tag, or GitHub
Release.

It does not approve adapter implementation.

## Purpose

The purpose is to prevent drift between:

- `mcp_read_only_registry.py`
- `MCP_READ_ONLY_TOOL_CONTRACT_MATRIX_v0.6.md`
- `MCP_READ_ONLY_PROTOTYPE_PREFLIGHT_v0.6.md`
- `MCP_REGISTRY_ADAPTER_DESIGN_v0.6.md`
- `samples/synthetic_mcp_registry_adapter_expected_behavior_v0.6.json`

The fixture fixes expected read-only adapter behavior before any runtime MCP
surface exists.

## Non-goals

- No MCP server implementation.
- No MCP transport implementation.
- No protocol handler implementation.
- No actual tool execution.
- No local evidence reader.
- No upload or import action.
- No dashboard POST action.
- No collector forwarding change.
- No receiver ingest change.
- No raw preview or raw download.
- No replay or active scan.
- No automatic ChatGPT handoff.
- No tag or GitHub Release.
- No implementation approval.

## Fixture Scope

The fixture file is:

- `samples/synthetic_mcp_registry_adapter_expected_behavior_v0.6.json`

It records only safe metadata expectations:

- schema version
- planning-only and implementation flags
- allowed tool names
- forbidden tool concepts
- blocked response codes
- blocked response allowed fields
- safe file allowlist
- adapter behavior cases

The fixture must not include raw traffic, target identifiers, credential or
session values, secret values, local path details, file bodies, audit row bodies,
archive contents, or generated output internals.

## Adapter Expected Behavior Cases

The fixture contains these minimum cases:

| Case | Expected result | Required boundary |
| --- | --- | --- |
| `allowed_global_status_tool` | allowed | global safe metadata only |
| `allowed_verified_output_specific_tool` | allowed | verified output alias required |
| `unverified_output_alias_blocked` | blocked | `not_verified` |
| `unknown_tool_blocked` | blocked | `not_allowlisted` |
| `forbidden_concept_blocked` | blocked | `not_allowlisted` |
| `raw_access_request_blocked` | blocked | `raw_access_blocked` |
| `state_changing_request_blocked` | blocked | `state_change_blocked` |
| `local_path_request_blocked` | blocked | `local_path_blocked` |
| `secret_request_blocked` | blocked | `secret_access_blocked` |
| `safe_file_inventory_metadata_only` | allowed | four safe file names only |
| `no_automatic_chatgpt_handoff` | blocked | `state_change_blocked` |

Every case must keep:

- `raw_data_included: false`
- `local_path_included: false`
- `credential_values_included: false`
- `target_identifiers_included: false`
- `state_change_performed: false`

## Blocked Response Case Matrix

Blocked responses must use only:

- `ok`
- `code`
- `safe_reason`
- `output_alias`
- `remediation_hint`

The fixture requires these blocked response codes to stay aligned with the
registry helper:

- `not_verified`
- `not_allowlisted`
- `raw_access_blocked`
- `state_change_blocked`
- `local_path_blocked`
- `secret_access_blocked`

Later implementation must call the blocked response helper or prove the same
field shape and raw-free behavior. A second independent blocked response shape
is not acceptable.

## Drift Prevention

The fixture must match the registry helper constants:

- `ALLOWED_TOOL_NAMES`
- `FORBIDDEN_TOOL_CONCEPTS`
- `BLOCKED_RESPONSE_CODES`
- `BLOCKED_RESPONSE_ALLOWED_FIELDS`
- `SAFE_FILE_ALLOWLIST`

The fixture must also stay linked from the contract matrix, prototype preflight,
adapter design, roadmap, fast-track plan, and README so later implementers do
not bypass it.

If a future PR changes any registry helper constant, it must update the fixture,
document the reason, and keep the raw-free case flags false unless a separate
security review explicitly approves a boundary change.

## Acceptance Evidence For Later Implementation

A later implementation PR must show:

- The adapter consumes the registry helper.
- Allowed tools match the fixture.
- Forbidden concepts remain blocked.
- Unverified output aliases return a blocked response.
- Unknown tools return a blocked response.
- Raw access, state change, local path, secret, and external handoff requests
  stay blocked.
- Safe file inventory returns metadata for only the four candidate files.
- Candidate findings remain candidates.
- Risk remains draft.
- Severity and CVSS remain manual decisions.
- No runtime case returns raw traffic, target identifiers, credential or session
  values, secret values, or local path details.

## Deferred Runtime Decisions

The fixture does not decide:

- Whether to implement an MCP server.
- Which transport to use.
- How protocol messages are handled.
- Whether any tool execution layer is acceptable.
- Whether a local evidence reader is ever allowed.
- Whether dashboard state-changing actions are allowed.

Those decisions require separate design and review before implementation.

