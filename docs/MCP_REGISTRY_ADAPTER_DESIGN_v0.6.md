# MCP Registry Adapter Design v0.6

This document defines the planning boundary for a future read-only MCP registry
adapter. It is a design document only.

The fixture plan for expected adapter behavior is tracked in
[`MCP_REGISTRY_ADAPTER_FIXTURE_PLAN_v0.6.md`](MCP_REGISTRY_ADAPTER_FIXTURE_PLAN_v0.6.md).

It does not implement an MCP server, MCP transport, protocol handler, tool
handler, local evidence reader, upload or import action, dashboard POST action,
collector forwarding change, receiver ingest change, raw preview or download,
replay, active scan, automatic ChatGPT handoff, tag, or GitHub Release.

## Purpose

The adapter design explains how a later read-only MCP surface should consume
the internal registry skeleton without widening the gateway boundary. The goal
is to keep all tool exposure allowlisted, verify-first, blocked by default, and
limited to raw-free metadata.

The design sits between the contract matrix and any later runtime prototype:

- The contract matrix defines allowed tool names, blocked concepts, and safe
  output expectations.
- The preflight document defines checks before a prototype can exist.
- The adapter design defines how a later runtime layer should consume the
  registry helper while preserving the same deny-by-default behavior.

## Non-goals

- No MCP server implementation.
- No MCP transport implementation.
- No protocol handler implementation.
- No tool handler implementation.
- No local evidence reader.
- No upload or import action.
- No dashboard POST action.
- No collector forwarding change.
- No receiver ingest change.
- No raw preview or raw download.
- No replay or active scan.
- No automatic ChatGPT handoff.
- No tag or GitHub Release.

## Adapter Boundary

The adapter is a future planning layer that may translate registry metadata
into a runtime-facing description. It must not execute tools, read output file
bodies, read local-only evidence, or resolve local paths.

The only allowed source of tool identity is
`mcp_read_only_registry.py`. A future adapter must consume:

- `ALLOWED_TOOL_NAMES`
- `FORBIDDEN_TOOL_CONCEPTS`
- `BLOCKED_RESPONSE_CODES`
- `BLOCKED_RESPONSE_ALLOWED_FIELDS`
- `SAFE_FILE_ALLOWLIST`
- `build_read_only_tool_registry()`
- `build_blocked_response()`

The adapter must not define a second independent allowlist. If the adapter
needs derived metadata, it must derive that metadata from the registry helper
and keep fixture consistency checks in place.

## Registry Consumption Flow

A later implementation must follow this flow:

1. Build the registry with `build_read_only_tool_registry()`.
2. Expose only entries whose names are in `ALLOWED_TOOL_NAMES`.
3. Treat every name in `FORBIDDEN_TOOL_CONCEPTS` as blocked, not as a candidate.
4. For project-specific requests, require a verified output alias before
   returning metadata.
5. If verification is missing or the requested name is not allowlisted, return
   `build_blocked_response()` output.
6. Return only safe aliases, counts, booleans, timestamps, status labels, and
   the four safe file names.

This flow is adapter design only. It does not approve runtime registration,
transport, protocol handling, or execution.

## Verify-First Behavior

Project-specific tools must be verify-first. The adapter must check verified
output state before it exposes any output-specific metadata. If verification is
not present, the response must be blocked with a safe reason and
`raw_data_included: false`.

Global status metadata may omit an output alias only when it does not describe
project-specific evidence. It still must return safe metadata only.

## Blocked Response Handling

The adapter must use the blocked response helper rather than constructing
ad-hoc error bodies. Blocked responses must contain only fields allowed by
`BLOCKED_RESPONSE_ALLOWED_FIELDS`.

Required blocked-response behavior:

- Unknown tool names are blocked.
- Forbidden concepts are blocked.
- Unverified output aliases are blocked.
- Raw access requests are blocked.
- State-changing requests are blocked.
- Local path and secret requests are blocked.
- Blocked responses use safe aliases and remediation labels only.

Blocked responses must not include raw traffic, target identifiers, credential
or session values, secret values, local path details, stack trace bodies, audit
row bodies, archive contents, or generated output internals.

## Forbidden Actions

A future adapter must keep these action classes out of scope:

- Reading raw traffic.
- Reading local-only evidence.
- Showing local path details.
- Showing credential, session, token, integrity, or request-forgery protection
  values.
- Sending data to ChatGPT automatically.
- Replaying requests.
- Starting active scans.
- Deleting or retaining files.
- Mutating Burp configuration.
- Creating tags.
- Creating or publishing GitHub Releases.

The adapter may describe that these categories are blocked. It must not perform
them.

## Safe Metadata Boundary

Allowed output remains limited to safe metadata:

- Tool name.
- Output alias.
- Verification status.
- Capture status.
- Handoff and skip counts.
- Existence, size, timestamp, and fingerprint metadata for the four safe file
  candidates.
- Candidate counts that are clearly not confirmed issue counts.
- Manual review labels for risk, severity, and CVSS.

The four AI input candidate file names remain:

- `analysis_packet.json`
- `chatgpt_prompt.md`
- `codex_task_prompt.md`
- `report_draft.md`

The adapter must not return file bodies automatically.

## Fixture Consistency Requirements

A later implementation PR must keep these sources aligned:

- `mcp_read_only_registry.py`
- `samples/synthetic_mcp_read_only_tool_contract_matrix_v0.6.json`
- `samples/synthetic_mcp_read_only_prototype_preflight_v0.6.json`
- `samples/synthetic_mcp_registry_adapter_expected_behavior_v0.6.json`
- `MCP_READ_ONLY_TOOL_CONTRACT_MATRIX_v0.6.md`
- `MCP_READ_ONLY_PROTOTYPE_PREFLIGHT_v0.6.md`
- `MCP_REGISTRY_ADAPTER_FIXTURE_PLAN_v0.6.md`
- This adapter design document.

Required fixture checks:

- Allowed tool names match the registry helper.
- Forbidden concepts match the registry helper.
- Blocked response codes match the registry helper.
- Blocked response fields match the registry helper.
- Safe file allowlist matches the registry helper.
- Runtime implementation flags remain false until a dedicated implementation PR
  changes them.

## Acceptance Evidence For Later Implementation

A later implementation PR must provide:

- Adapter allowlist consumption test.
- Forbidden concept blocked test.
- Verify-first blocked response test.
- Blocked response field-shape test.
- Safe file inventory metadata test.
- Raw-free result check.
- No local path detail check.
- No credential or session value check.
- No automatic ChatGPT handoff check.
- Candidate finding only check.
- Risk draft only check.
- Final severity/CVSS manual decision check.

The acceptance evidence must prove read-only metadata behavior before any
runtime transport or tool execution is considered.

