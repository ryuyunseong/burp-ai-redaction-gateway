# MCP Listener Skeleton Acceptance v0.6

This document fixes acceptance criteria, fixture shape, and source-check scope
policy for a future MCP listener skeleton slice.

It is an acceptance criteria, fixture, and source-check planning document only.
It does not implement an MCP server listener, MCP transport, protocol handler,
executable tool registration, actual tool execution, local evidence reader,
safe file body reader, upload or import action, dashboard POST action,
collector forwarding change, receiver ingest change, raw preview or download,
replay, active scan, automatic ChatGPT handoff, tag, or GitHub Release.

It is not listener implementation approval.

## Purpose

The purpose is to make a future listener skeleton PR prove that it consumes the
current v0.6 MCP boundary baseline and expands source-check scope before adding
any new runtime-facing MCP file.

This keeps listener shape, transport choice, protocol handling, executable
registration, execution, local evidence reading, and state-changing behavior
split into separate review units.

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
- No listener implementation approval.

## Acceptance Fixture Scope

The acceptance fixture is
`tests/fixtures/mcp_listener_skeleton_acceptance_v0.6.json`.

It records the minimum facts that a future listener skeleton PR must keep true
before any runtime file is considered. The fixture is planning-only and must
not describe a live listener, transport, protocol parser, executable tool
registration, execution path, evidence reader, or state-changing action.

## Required Consumed Artifacts

The fixture requires consumption of:

- Listener skeleton decision.
- Runtime boundary consumption.
- Server skeleton preflight.
- Implementation gate.
- Local-only tool schema catalog.
- Local-only adapter dry-run.
- Read-only registry helper.

The source documents are:

- [`MCP_LISTENER_SKELETON_DECISION_v0.6.md`](MCP_LISTENER_SKELETON_DECISION_v0.6.md)
- [`MCP_RUNTIME_BOUNDARY_CONSUMPTION_v0.6.md`](MCP_RUNTIME_BOUNDARY_CONSUMPTION_v0.6.md)
- [`MCP_SERVER_SKELETON_PREFLIGHT_v0.6.md`](MCP_SERVER_SKELETON_PREFLIGHT_v0.6.md)
- [`MCP_IMPLEMENTATION_GATE_DESIGN_v0.6.md`](MCP_IMPLEMENTATION_GATE_DESIGN_v0.6.md)
- [`MCP_LOCAL_ONLY_TOOL_SCHEMA_CATALOG_v0.6.md`](MCP_LOCAL_ONLY_TOOL_SCHEMA_CATALOG_v0.6.md)

## Source-check Scope Expansion

The fixture keeps the existing pre-runtime helper scope explicit:

- `burp_ai_redaction_gateway/mcp_adapter_dry_run.py`
- `burp_ai_redaction_gateway/mcp_tool_schema_catalog.py`
- `burp_ai_redaction_gateway/mcp_read_only_registry.py`

Any future PR that adds a runtime-facing MCP file must add that file to a new
source-check scope in the same PR. A listener skeleton file is allowed only
after this acceptance fixture is consumed. Existing `mcp_server.py` is excluded
from this scope because this slice only guards the pre-runtime helpers and
future listener-facing files.

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
- `tool_execute`
- `execute_tool`
- `read_local_evidence`
- `read_file_body`

These markers are a drift guard, not a complete security scanner. Future
runtime-facing files need their own source-check policy and tests.

## Listener Skeleton Boundaries

A future listener skeleton PR may describe names, module boundaries, blocked
responses, and metadata-only failure shape. It must not bind sockets, choose
transport, parse protocol messages, register executable tools, execute tools,
read evidence, read file bodies, create dashboard state changes, or initiate
external handoff.

The skeleton boundary must stay narrow enough that transport, protocol,
registration, execution, evidence reading, and dashboard state changes remain
independent PRs.

## Required Acceptance Criteria

A future listener skeleton PR must prove:

- Listener skeleton decision consumed.
- Runtime boundary consumption consumed.
- Server skeleton preflight consumed.
- Implementation gate consumed.
- Tool schema catalog consumed.
- Dry-run helper consumed.
- Registry helper consumed.
- Existing pre-runtime helpers are present.
- Existing pre-runtime helpers do not contain forbidden source markers.
- Future runtime-facing files must be added to source-check scope.
- Listener skeleton file allowed only after acceptance.
- Existing `mcp_server.py` excluded from this scope.
- No transport.
- No protocol handler.
- No executable tool registration.
- No actual tool execution.
- No local evidence reader.
- No safe file body reader.
- No raw file body.
- No state-changing action.
- No automatic ChatGPT handoff.
- Candidate finding only.
- Risk draft only.
- Severity and CVSS require manual decision.

## Required Test Evidence

This slice requires tests proving:

- The acceptance document exists.
- The acceptance fixture exists.
- The consumed flags are true.
- The listener, transport, protocol, execution, evidence, action, and release
  flags are false.
- `raw_data_included` is false.
- `source_check_scope_policy` exists.
- Existing pre-runtime helper files exist.
- Existing pre-runtime helper files do not contain forbidden source markers.
- The document and fixture avoid target identifiers, local path detail,
  credential values, raw body keys, guarantee language, final severity claims,
  and external sharing approval.

## Deferred Runtime Work

The following work remains deferred:

- MCP server listener runtime.
- Transport selection and implementation.
- Protocol message representation.
- Executable tool registration.
- Tool execution.
- Local evidence reader.
- Safe file body reader.
- Dashboard or upload state-changing action.
- Raw preview or download.
- Replay or active scan.
- Automatic ChatGPT handoff.
- Release or tag work.

Each deferred item needs a separate explicit approval, tests, and security
review before implementation.
