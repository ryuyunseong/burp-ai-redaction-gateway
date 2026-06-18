# MCP Listener Skeleton Decision v0.6

This document decides the pre-implementation boundary for a future MCP listener
skeleton. It is a design and acceptance criteria document only.

It does not implement an MCP server listener, MCP transport, protocol handler,
executable tool registration, actual tool execution, local evidence reader,
safe file body reader, upload or import action, dashboard POST action,
collector forwarding change, receiver ingest change, raw preview or download,
replay, active scan, automatic ChatGPT handoff, tag, or GitHub Release.

It is not listener implementation approval.

## Purpose

The purpose is to decide what must be true before a listener skeleton PR is
allowed to start. The listener path must stay split from transport selection,
protocol parsing, tool registration, tool execution, local evidence reading,
and state-changing actions.

This document keeps the next slice limited to a narrow listener skeleton
decision. It also records how source-check scope must expand if a later PR adds
any runtime-facing MCP file.

## Current Baseline

The listener decision consumes the current v0.6 MCP baseline:

- Runtime boundary decision.
- Server skeleton preflight.
- Runtime boundary consumption fixture.
- Implementation gate.
- Local-only tool schema catalog.
- Local-only adapter dry-run.
- Registry helper.
- Adapter expected behavior fixture.

The related source documents are:

- [`MCP_RUNTIME_BOUNDARY_DECISION_v0.6.md`](MCP_RUNTIME_BOUNDARY_DECISION_v0.6.md)
- [`MCP_SERVER_SKELETON_PREFLIGHT_v0.6.md`](MCP_SERVER_SKELETON_PREFLIGHT_v0.6.md)
- [`MCP_RUNTIME_BOUNDARY_CONSUMPTION_v0.6.md`](MCP_RUNTIME_BOUNDARY_CONSUMPTION_v0.6.md)
- [`MCP_IMPLEMENTATION_GATE_DESIGN_v0.6.md`](MCP_IMPLEMENTATION_GATE_DESIGN_v0.6.md)
- [`MCP_LOCAL_ONLY_TOOL_SCHEMA_CATALOG_v0.6.md`](MCP_LOCAL_ONLY_TOOL_SCHEMA_CATALOG_v0.6.md)

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

## Listener Skeleton Decision

A listener skeleton may only be considered after the existing boundary
documents and fixtures are consumed. Even then, the listener skeleton must be a
minimal shape decision before any runtime surface opens.

The listener skeleton decision allows a later PR to define:

- The intended module boundary for a gateway-owned listener skeleton.
- The minimal object or function names needed for review.
- The blocked response and metadata-only failure shape.
- The tests required before any runtime listener can be considered.
- The source-check scope that must cover any newly introduced runtime-facing
  MCP file.

It does not allow socket binding, request handling, protocol parsing,
executable tool registration, tool execution, local evidence reading, file body
reading, or dashboard state-changing behavior.

## Allowed Next Slice

The next allowed slice is a listener skeleton acceptance PR that remains
planning-first. It may add documentation, fixture fields, source-check scope,
and tests for names and blocked behavior.

The next slice must still avoid:

- Binding or opening a listener.
- Selecting or implementing transport.
- Parsing MCP protocol messages.
- Registering executable tools.
- Executing tools.
- Reading local evidence or safe file bodies.
- Sending data to ChatGPT automatically.

## Forbidden Work

The following work remains separate and requires a later explicit approval:

- MCP server listener runtime.
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

## Source-check Scope Expansion Rule

The current runtime boundary consumption source-check scope is intentionally
limited to the existing pre-runtime helper files. If a later PR adds any new
MCP runtime-facing file, that PR must extend source-check scope to include the
new file before it can be considered complete.

This rule applies to any new file that names listener skeletons, runtime entry
points, transport boundaries, protocol boundaries, registration boundaries,
execution boundaries, or evidence-reader boundaries.

The new source-check scope must continue to reject listener drift in pre-runtime
helpers and must separately test any newly introduced runtime-facing files.

## Required Acceptance Criteria

A future listener skeleton PR must prove:

- Runtime boundary consumption fixture consumed.
- Server skeleton preflight consumed.
- Implementation gate fixture consumed.
- Tool schema catalog consumed.
- Dry-run helper consumed.
- Registry helper consumed.
- Source-check scope expanded for any new runtime file.
- No transport.
- No protocol handler.
- No executable tool registration.
- No actual tool execution.
- No local evidence reader.
- No raw file body.
- No state-changing action.
- No automatic ChatGPT handoff.
- Candidate finding only.
- Risk draft only.
- Severity and CVSS require manual decision.

## Required Test Evidence

A future listener skeleton PR must include:

- Document hygiene tests for the listener skeleton decision.
- Source-check tests for any new runtime-facing MCP file.
- Tests that the previous boundary fixture remains consumed.
- Tests that blocked runtime surfaces remain absent.
- Tests that response shape is raw-free and metadata-only.
- Tests that no target identifiers, credential values, local path details,
  guarantee language, confirmed finding language, or severity confirmation
  language are introduced.

## Split Plan

The listener path remains split into separate review units:

1. Listener skeleton decision.
2. Listener skeleton acceptance criteria.
3. Listener source-check scope extension.
4. Listener runtime skeleton, if explicitly approved later.
5. Transport selection and implementation.
6. Protocol message representation.
7. Executable tool registration.
8. Tool execution.
9. Local evidence reader.
10. Dashboard or upload state-changing action.

Each runtime-affecting unit needs separate tests and security review.

## Deferred Decisions

This document does not decide:

- Whether a gateway-owned listener should be implemented.
- Which transport should be used.
- How protocol messages should be represented.
- Whether executable tools are acceptable.
- Whether local evidence reading is acceptable.
- Whether dashboard state-changing actions are acceptable.
- Whether upload or import behavior is acceptable.
- Whether any release action should happen.
