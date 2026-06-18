# MCP Listener Runtime Source Check v0.6

This document fixes the runtime-facing source-check guard for future MCP
listener work. It is a source-check guard, fixture, and test planning document only.

It does not implement an MCP server listener, MCP transport, protocol handler,
executable tool registration, actual tool execution, local evidence reader,
safe file body reader, upload or import action, dashboard POST action,
collector forwarding change, receiver ingest change, raw preview or download,
replay, active scan, automatic ChatGPT handoff, tag, or GitHub Release.

It is not listener implementation approval.

## Purpose

The purpose is to make future runtime-facing MCP files explicit before they can
enter the codebase. A future listener-facing file must be declared in the
source-check fixture and must pass the same forbidden marker checks as the
existing pre-runtime helpers.

This keeps listener shape, transport choice, protocol handling, executable
registration, execution, local evidence reading, file body reading, and
state-changing behavior split into separate review units.

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

## Runtime-facing Source Check Fixture

The source-check fixture is
`tests/fixtures/mcp_listener_runtime_source_check_v0.6.json`.

It records the baseline source-check policy for future listener-facing MCP
files. The fixture is planning-only and must not describe a live listener,
transport, protocol parser, executable tool registration, execution path,
evidence reader, file body reader, or state-changing action.

## Required Consumed Artifacts

The fixture requires consumption of:

- Listener skeleton acceptance.
- Listener skeleton decision.
- Runtime boundary consumption.
- Server skeleton preflight.
- Implementation gate.
- Local-only tool schema catalog.
- Local-only adapter dry-run.
- Read-only registry helper.

The source documents are:

- [`MCP_LISTENER_SKELETON_ACCEPTANCE_v0.6.md`](MCP_LISTENER_SKELETON_ACCEPTANCE_v0.6.md)
- [`MCP_LISTENER_SKELETON_DECISION_v0.6.md`](MCP_LISTENER_SKELETON_DECISION_v0.6.md)
- [`MCP_RUNTIME_BOUNDARY_CONSUMPTION_v0.6.md`](MCP_RUNTIME_BOUNDARY_CONSUMPTION_v0.6.md)
- [`MCP_SERVER_SKELETON_PREFLIGHT_v0.6.md`](MCP_SERVER_SKELETON_PREFLIGHT_v0.6.md)
- [`MCP_IMPLEMENTATION_GATE_DESIGN_v0.6.md`](MCP_IMPLEMENTATION_GATE_DESIGN_v0.6.md)
- [`MCP_LOCAL_ONLY_TOOL_SCHEMA_CATALOG_v0.6.md`](MCP_LOCAL_ONLY_TOOL_SCHEMA_CATALOG_v0.6.md)

## Existing Baseline Scope

The existing pre-runtime helper scope is:

- `burp_ai_redaction_gateway/mcp_adapter_dry_run.py`
- `burp_ai_redaction_gateway/mcp_tool_schema_catalog.py`
- `burp_ai_redaction_gateway/mcp_read_only_registry.py`

The existing baseline exclusion is:

- `burp_ai_redaction_gateway/mcp_server.py`

That exclusion is only a current baseline exception. It does not approve excluding future runtime-facing files from source-check scope.

## Runtime-facing File Detection Rule

The fixture enables runtime-facing filename detection. Any new Python file under
`burp_ai_redaction_gateway` whose path contains a runtime-facing filename
marker must be listed in `declared_runtime_facing_source_scope`.

Runtime-facing filename markers are:

- `mcp_listener`
- `listener_skeleton`
- `runtime_listener`
- `mcp_runtime`
- `mcp_transport`
- `mcp_protocol`
- `tool_registration`
- `tool_execution`
- `evidence_reader`
- `file_body_reader`

If a future file matches one of these markers and is not declared, the test must
fail. This prevents listener-facing work from landing outside source-check
scope.

## Declared Source-check Scope

The current declared runtime-facing source scope is empty.

Future PRs may add files to `declared_runtime_facing_source_scope` only when the
same PR adds the matching source-check policy and proves the declared files do
not contain forbidden source markers.

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
- `register_tool`
- `dispatch_tool`

These markers are a drift guard, not a complete security scanner. Runtime code
still needs separate design, tests, and security review before implementation.

## Required Acceptance Criteria

A future listener-facing PR must prove:

- Listener skeleton acceptance consumed.
- Listener skeleton decision consumed.
- Runtime boundary consumption consumed.
- Server skeleton preflight consumed.
- Implementation gate consumed.
- Tool schema catalog consumed.
- Dry-run helper consumed.
- Registry helper consumed.
- Existing pre-runtime helpers are present.
- Existing baseline exclusions are explicit and narrow.
- Runtime-facing file detection is enabled.
- Future runtime-facing files must be declared.
- Undeclared runtime-facing files fail tests.
- Declared runtime-facing source scope is currently empty.
- Existing pre-runtime helpers do not contain forbidden source markers.
- Declared runtime-facing files do not contain forbidden source markers.
- No listener implementation.
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

- The source-check document exists.
- The source-check fixture exists.
- The consumed flags are true.
- The listener, transport, protocol, execution, evidence, action, and release
  flags are false.
- `raw_data_included` is false.
- `source_check_policy` exists.
- Runtime-facing file detection is enabled.
- Future runtime-facing files must be declared.
- Undeclared runtime-facing files fail tests.
- Existing pre-runtime helper files exist.
- Existing excluded baseline files exist or are explicitly explained.
- Current declared runtime-facing source scope is empty.
- Existing pre-runtime helper files do not contain forbidden source markers.
- Declared runtime-facing files do not contain forbidden source markers.
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
