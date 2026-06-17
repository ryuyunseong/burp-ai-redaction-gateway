# MCP Read-Only Prototype Preflight v0.6

This document defines the preflight checks required before any future
gateway-owned MCP read-only prototype implementation.

It is a planning and test-design document only.

It does not implement an MCP server, implement an MCP runtime registry, add MCP
tool handlers, change runtime behavior, add a local evidence reader, add upload
or import actions, add POST actions, change collector forwarding, change
receiver ingest, add raw preview or download, add replay, add active scan, add
automatic ChatGPT handoff, create a tag, or create a GitHub Release.

This preflight does not implement an MCP server, implement an MCP runtime
registry, or add MCP tool handlers.

The registry adapter design is tracked in
[`MCP_REGISTRY_ADAPTER_DESIGN_v0.6.md`](MCP_REGISTRY_ADAPTER_DESIGN_v0.6.md).

## Purpose

The purpose is to prevent drift between the v0.6 read-only MCP contract matrix
and any later prototype. The prototype must prove that only allowlisted tools can
be registered and that blocked requests return raw-free metadata only.

## Non-goals

- No MCP server implementation.
- No MCP runtime registry implementation.
- No MCP tool handler implementation.
- No local evidence file reader.
- No upload or import action.
- No dashboard POST action.
- No collector forwarding change.
- No receiver ingest change.
- No raw preview or raw download.
- No replay or active scan.
- No automatic ChatGPT handoff.
- No tag or GitHub Release.

## Allowed Runtime Registry Candidates

Only these eight tool names are eligible for a later read-only prototype:

- `get_gateway_status`
- `list_verified_outputs`
- `get_live_capture_status`
- `get_safe_file_inventory`
- `get_report_readiness`
- `get_prompt_readiness`
- `get_troubleshooting_categories`
- `get_release_readiness`

Each candidate must be read-only and must return only verified output alias
metadata or safe metadata. Project-specific tools must require verify-first
behavior before returning status about an output alias.

## Forbidden Runtime Registry Concepts

The following concepts must not appear in runtime registration:

- `get_raw_request`
- `get_raw_response`
- `read_local_only_file`
- `read_raw_vault`
- `replay_request`
- `active_scan`
- `send_to_chatgpt`
- `delete_files`
- `show_hmac_secret`
- `show_csrf_token`
- `modify_burp_config`
- `collaborator_payload_send`

These names remain blocked concepts only. They are not implementation
candidates.

## Registry Drift Prevention

A later prototype PR must include tests that compare runtime registry names
against the contract fixture:

- The registry must include only allowed tools.
- The registry must not include forbidden concepts.
- Tool handlers must not add state-changing behavior.
- Tool handlers must not read local-only evidence files.
- Tool handlers must not return raw traffic, local path details, target
  identifiers, credential/session values, or secret values.
- Tool handlers must keep candidate finding, risk draft, and manual
  severity/CVSS boundaries visible.

The first implementation step after this preflight may add an internal registry
consistency helper. That helper may define allowlist constants, forbidden
concept constants, safe file constants, and blocked response schema helpers, but
it is not an MCP server, transport, protocol handler, local evidence reader,
dashboard route, CLI command, POST action, or tool handler execution layer.

A later adapter must consume the registry helper instead of defining a second
independent allowlist. It must still return blocked responses through the
blocked response helper and keep verify-first behavior.

## Blocked Response Schema

Blocked responses may contain only raw-free metadata:

- `ok: false`
- `code`
- `safe_reason`
- `output_alias`, optional
- `remediation_hint`, optional

Allowed blocked response codes:

- `not_verified`
- `not_allowlisted`
- `raw_access_blocked`
- `state_change_blocked`
- `local_path_blocked`
- `secret_access_blocked`

Blocked responses must not contain:

- raw traffic
- request or response body
- target identifier
- URL, domain, or IP value
- credential/session value
- local path detail
- actual local-only filename
- HMAC secret value
- CSRF token value

## Verify-First Behavior

Project-specific tools must check the verified output state before returning
metadata. If verification has not passed, the prototype must return a blocked
response using `not_verified` and a safe reason.

Global status tools may return global gateway status without an output alias,
but they must still return safe metadata only.

## Safe File Allowlist

The only safe file names eligible for inventory metadata are:

- `analysis_packet.json`
- `chatgpt_prompt.md`
- `codex_task_prompt.md`
- `report_draft.md`

The prototype must not return file bodies automatically and must not perform
automatic ChatGPT handoff.

## Acceptance Evidence For Later Implementation PR

A later implementation PR must provide:

- Runtime registry allowlist test.
- Forbidden concept absence test.
- Blocked response schema test.
- Verify-first blocked response test.
- Safe file allowlist test.
- Raw-free result check with no raw traffic.
- No automatic ChatGPT handoff check.
- Candidate finding only check.
- Risk draft only check.
- Final severity/CVSS manual decision check.
