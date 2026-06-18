# MCP Runtime Boundary Consumption v0.6

This document fixes the consumption evidence required before a future MCP
listener or server-facing PR is considered.

It is a fixture, test, source-check, and documentation boundary only. It does
not implement an MCP server listener, MCP transport, protocol handler,
executable tool registration, actual tool execution, local evidence reader,
safe file body reader, upload or import action, dashboard POST action,
collector forwarding change, receiver ingest change, raw preview or download,
replay, active scan, automatic ChatGPT handoff, tag, or GitHub Release.

It does not approve runtime implementation.

## Purpose

The purpose is to make follow-up listener or server work prove that it consumes
the runtime boundary decision and server skeleton preflight before opening any
runtime surface.

This keeps listener, transport, protocol handling, tool registration, tool
execution, and local evidence reading split into later security review PRs.

## Non-goals

- No MCP server listener implementation.
- No MCP transport implementation.
- No protocol handler implementation.
- No executable tool registration.
- No actual tool execution.
- No local evidence reader implementation.
- No safe file body reader implementation.
- No upload or import action.
- No dashboard POST action.
- No collector forwarding change.
- No receiver ingest change.
- No raw preview or raw download.
- No replay or active scan.
- No automatic ChatGPT handoff.
- No tag or GitHub Release.
- No runtime implementation approval.

## Consumption Fixture Scope

The consumption fixture is
`tests/fixtures/mcp_runtime_boundary_consumption_v0.6.json`.

It records the minimum evidence that a future listener or server-facing PR must
consume before runtime work is considered. It also defines a source-check scope
for the local-only pre-runtime helpers that must remain server-free.

## Required Consumed Artifacts

The fixture requires consumption of:

- Runtime boundary decision.
- Server skeleton preflight.
- Implementation gate.
- Adapter expected behavior fixture.
- Local-only adapter dry-run.
- Local-only tool schema catalog.
- Read-only registry helper.

The source documents are:

- [`MCP_RUNTIME_BOUNDARY_DECISION_v0.6.md`](MCP_RUNTIME_BOUNDARY_DECISION_v0.6.md)
- [`MCP_SERVER_SKELETON_PREFLIGHT_v0.6.md`](MCP_SERVER_SKELETON_PREFLIGHT_v0.6.md)
- [`MCP_IMPLEMENTATION_GATE_DESIGN_v0.6.md`](MCP_IMPLEMENTATION_GATE_DESIGN_v0.6.md)
- [`MCP_LOCAL_ONLY_TOOL_SCHEMA_CATALOG_v0.6.md`](MCP_LOCAL_ONLY_TOOL_SCHEMA_CATALOG_v0.6.md)

## Source Check Scope

The source check scope is intentionally narrow and limited to local-only
pre-runtime helpers:

- `burp_ai_redaction_gateway/mcp_adapter_dry_run.py`
- `burp_ai_redaction_gateway/mcp_tool_schema_catalog.py`
- `burp_ai_redaction_gateway/mcp_read_only_registry.py`

If a future PR adds an unrelated MCP server module for a different approved
slice, that module is not automatically in this source-check scope. This check
only proves that the existing pre-runtime helpers have not become listener,
transport, protocol, or execution code.

## Forbidden Source Markers

The source-check scope must not contain these markers:

- `http.server`
- `socketserver`
- `http.client`
- `socket`
- `subprocess`
- `requests`
- `urllib`
- `bind(`
- `serve_forever`
- `listen(`
- `accept(`
- `run_server`
- `create_server`

These markers are not a complete security scanner. They are an early drift
guard for the pre-runtime helper files.

## Boundary Flags

The fixture must keep these runtime flags false:

- `mcp_server_listener_implemented`
- `mcp_transport_implemented`
- `mcp_protocol_handler_implemented`
- `executable_tool_registration_implemented`
- `actual_tool_execution_implemented`
- `local_evidence_reader_implemented`
- `dashboard_post_action_implemented`
- `upload_import_action_implemented`
- `raw_preview_download_implemented`
- `replay_active_scan_implemented`
- `automatic_chatgpt_handoff_implemented`
- `tag_created`
- `github_release_created`
- `raw_data_included`

If any of those flags changes to true, the work is no longer this consumption
fixture slice and needs a separate runtime boundary review.

## Acceptance Evidence

This slice requires:

- The consumption fixture exists.
- The required consumed artifact flags are true.
- The runtime implementation flags are false.
- The source-check scope files exist.
- The source-check scope files do not contain forbidden source markers.
- The document and fixture remain raw-free and avoid target identifiers, local
  path detail, credential values, guarantee language, final severity claims, and
  external sharing approval.

## Deferred Runtime Work

The following work remains deferred:

- Server listener skeleton.
- Transport choice and protocol handling.
- Tool registration.
- Tool execution.
- Local evidence reader.
- Safe file body reader.
- Dashboard state-changing action.
- Upload or import action.
- Raw preview or download.
- Automatic ChatGPT handoff.
- Release or tag work.

Each deferred item needs its own tests and boundary review before
implementation.

The listener skeleton decision is tracked in
[`MCP_LISTENER_SKELETON_DECISION_v0.6.md`](MCP_LISTENER_SKELETON_DECISION_v0.6.md).
It keeps listener skeleton work at the design and acceptance criteria stage and
requires source-check scope expansion for any new runtime-facing MCP file.
The listener skeleton acceptance criteria are tracked in
[`MCP_LISTENER_SKELETON_ACCEPTANCE_v0.6.md`](MCP_LISTENER_SKELETON_ACCEPTANCE_v0.6.md).
They keep the next listener-facing work limited to fixture and source-check
policy before implementation.
