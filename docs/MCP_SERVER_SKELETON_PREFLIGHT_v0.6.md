# MCP Server Skeleton Preflight v0.6

This document fixes the preflight criteria for a future gateway-owned MCP
server skeleton before any listener, transport, protocol handler, tool
registration, tool execution, or local evidence reader work starts.

It is a document, fixture, and test boundary only. It does not implement an MCP
server listener, socket binding, stdio transport, HTTP transport, JSON-RPC
handler, MCP protocol message parser, executable tool registration, actual tool
execution, local evidence reader, safe file body reader, upload or import
action, dashboard POST action, collector forwarding change, receiver ingest
change, raw preview or download, replay, active scan, automatic ChatGPT
handoff, tag, or GitHub Release.

It does not approve runtime implementation.

## Purpose

The purpose is to make the next MCP runtime-facing PR consume the completed
planning and fixture baseline before any server surface exists.

This preflight keeps server listener, transport, protocol handling, tool
registration, tool execution, and evidence reading split into later PRs. The
next PR may prove that the boundary is consumed. It must not open the boundary.

## Required Input Baseline

The preflight consumes the current v0.6 MCP planning baseline:

- MCP contract matrix.
- MCP prototype preflight.
- Read-only registry skeleton.
- Registry adapter design.
- Adapter expected behavior fixture.
- Implementation gate fixture.
- Local-only adapter dry-run.
- Local-only tool schema catalog.
- Runtime boundary decision.

The runtime boundary decision is tracked in
[`MCP_RUNTIME_BOUNDARY_DECISION_v0.6.md`](MCP_RUNTIME_BOUNDARY_DECISION_v0.6.md).

## Acceptance Inputs

A future server skeleton PR must prove that it consumes these inputs before any
runtime surface is considered:

- Registry helper.
- Dry-run helper.
- Tool schema catalog.
- Implementation gate fixture.
- Adapter expected behavior fixture.
- Server skeleton preflight fixture.
- Blocked response contract.
- Verify-first behavior.
- Raw-free metadata boundary.

The server skeleton preflight fixture is
`tests/fixtures/mcp_server_skeleton_preflight_v0.6.json`.

## Allowed Preflight Work

This preflight allows:

- Documentation.
- Fixture updates.
- Source checks.
- Consistency tests.
- Future listener checklist text.
- Blocked response contract review.
- Boundary decision consumption checks.

The work must stay metadata-only and must not read evidence bodies, expose a
listener, parse runtime messages, bind a socket, or execute tools.

## Forbidden Work

The following work is explicitly out of scope:

- Server listener.
- Socket bind.
- Stdio transport.
- HTTP transport.
- JSON-RPC protocol handler.
- MCP protocol message parser.
- Executable tool registration.
- Actual tool execution.
- Local evidence reader.
- Safe file body reader.
- Upload or import action.
- Dashboard POST action.
- Collector forwarding change.
- Receiver ingest change.
- Raw preview or download.
- Replay or active scan.
- Automatic ChatGPT handoff.
- Tag or GitHub Release.

## Fixture Contract

The preflight fixture must keep these facts true:

- It consumes the registry helper.
- It consumes the dry-run helper.
- It consumes the tool schema catalog.
- It consumes the implementation gate fixture.
- It consumes the adapter expected behavior fixture.
- Server listener remains disallowed.
- Transport remains disallowed.
- Protocol handler remains disallowed.
- Tool execution remains disallowed.
- Local evidence reader remains disallowed.
- Automatic ChatGPT handoff remains disallowed.
- Raw data is not included.

If a future PR changes any of those disallowed fields to true, it is no longer
this preflight slice and requires a separate runtime boundary review.

## Required Test Evidence

Required evidence for this slice:

- The preflight document exists.
- The preflight fixture exists.
- The preflight document links to the runtime boundary decision.
- Registry, dry-run, catalog, gate, and adapter fixture consumption is listed.
- Listener, transport, protocol handler, tool execution, and local evidence
  reader remain disallowed.
- The fixture keeps all runtime surface allowed flags false.
- The document and fixture do not include target identifiers, local path detail,
  credential values, raw body keys, guarantee language, final severity claims,
  or external sharing approval.

## Later Runtime Split

After this preflight, later runtime-affecting work must remain split:

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

Each later PR needs its own tests, threat boundary review, and raw-free output
checks before it is considered ready.

## Deferred Decisions

This document does not decide:

- Whether a gateway-owned MCP server should be implemented.
- Which transport should be used.
- How protocol messages should be represented.
- Whether executable tools are acceptable.
- Whether local evidence reading is acceptable.
- Whether dashboard state-changing actions are acceptable.
- Whether upload or import behavior is acceptable.
- Whether any release action should happen.
