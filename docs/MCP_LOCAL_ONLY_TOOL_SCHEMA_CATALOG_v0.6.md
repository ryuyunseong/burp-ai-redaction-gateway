# MCP Local-Only Tool Schema Catalog v0.6

This document describes the internal schema catalog helper for the v0.6
gateway-owned MCP planning line.

The helper is:

- `burp_ai_redaction_gateway/mcp_tool_schema_catalog.py`

It is metadata validation code only. It does not implement an MCP server,
MCP transport, protocol handler, actual tool execution, local evidence reader,
upload or import action, dashboard POST action, collector forwarding change,
receiver ingest change, preview or download behavior, replay, active scan,
automatic ChatGPT handoff, tag, or GitHub Release.

## Purpose

The catalog converts the read-only registry into safe tool descriptor metadata
before any runtime MCP layer exists. This keeps the next implementation step
between the dry-run helper and a future server small and reviewable.

The runtime boundary decision that follows this catalog is tracked in
[`MCP_RUNTIME_BOUNDARY_DECISION_v0.6.md`](MCP_RUNTIME_BOUNDARY_DECISION_v0.6.md).
The follow-up server preflight and boundary consumption evidence are tracked in
[`MCP_SERVER_SKELETON_PREFLIGHT_v0.6.md`](MCP_SERVER_SKELETON_PREFLIGHT_v0.6.md)
and
[`MCP_RUNTIME_BOUNDARY_CONSUMPTION_v0.6.md`](MCP_RUNTIME_BOUNDARY_CONSUMPTION_v0.6.md).
That document must be reviewed before server, transport, protocol, tool
execution, or local evidence reader work starts.

The catalog consumes:

- `build_read_only_tool_registry()`
- `build_adapter_dry_run_plan()`
- `evaluate_adapter_dry_run_fixture()`
- `samples/synthetic_mcp_registry_adapter_expected_behavior_v0.6.json`
- `samples/synthetic_mcp_implementation_gate_v0.6.json`

The catalog must not create a second independent allowlist.

## Descriptor Fields

Each descriptor contains only:

- `name`
- `description`
- `read_only`
- `verify_first`
- `safe_input_fields`
- `safe_output_fields`
- `raw_data_included: false`
- `local_path_included: false`
- `credential_values_included: false`
- `target_identifiers_included: false`
- `state_change_performed: false`

`safe_output_fields` must match the registry entry for the same tool. Global
status metadata tools may have `verify_first: false`. Output-specific metadata
tools must have `verify_first: true`.

## Boundary

The catalog result is safe metadata only. It may describe tool names, status
labels, output aliases, counts, timestamps, fingerprints, and the four safe file
candidate names.

It must not include traffic bodies, generated file bodies, locator details,
credential values, session values, integrity secret values, request-forgery
protection values, stack trace bodies, audit row bodies, or archive contents.

The four AI input candidate file names remain:

- `analysis_packet.json`
- `chatgpt_prompt.md`
- `codex_task_prompt.md`
- `report_draft.md`

## Validation

The catalog helper must prove:

- Tool names match `ALLOWED_TOOL_NAMES`.
- Forbidden concepts are absent.
- All descriptors are read-only.
- Output-specific descriptors require verify-first behavior.
- Descriptor output fields match registry `safe_output_fields`.
- Boundary flags stay false.
- Adapter expected behavior fixture and implementation gate fixture are
  consumed before later runtime work is considered.
- No runtime MCP exposure is added.

## Deferred Work

This catalog does not decide:

- Whether to implement a gateway-owned MCP server.
- Which transport to use.
- How protocol messages are handled.
- Whether a local evidence reader is acceptable.
- Whether upload or import behavior is acceptable.
- Whether any state-changing action is acceptable.

Those decisions require separate review before implementation.
