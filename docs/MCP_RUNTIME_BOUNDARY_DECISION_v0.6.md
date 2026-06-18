# MCP Runtime Boundary Decision v0.6

This document fixes the next v0.6 MCP boundary decision before any
gateway-owned MCP runtime work starts.

It is a design and decision document only. It does not implement an MCP server,
MCP transport, protocol handler, actual tool execution, local evidence reader,
upload or import action, dashboard POST action, collector forwarding change,
receiver ingest change, raw preview or download, replay, active scan,
automatic ChatGPT handoff, tag, or GitHub Release.

It does not approve runtime implementation.

## Purpose

The purpose is to keep the post-catalog MCP path reviewable. The project now has
enough planning and metadata validation to decide what must remain outside the
next slice and what evidence must exist before server work is considered.

This decision prevents the next PR from mixing server, transport, protocol,
tool execution, and local evidence reading into one broad security boundary
change.

## Current Completed MCP Preparation

The completed preparation baseline is:

- MCP contract matrix.
- MCP prototype preflight.
- Read-only registry skeleton.
- Registry adapter design.
- Adapter expected behavior fixture.
- Implementation gate fixture.
- Local-only adapter dry-run.
- Local-only tool schema catalog.

These artifacts are planning, fixture, helper, and metadata validation layers.
They do not expose a runtime MCP surface.

## Non-goals

- No MCP server implementation.
- No MCP transport implementation.
- No protocol handler implementation.
- No actual tool execution.
- No local evidence reader implementation.
- No upload or import action.
- No dashboard POST action.
- No collector forwarding change.
- No receiver ingest change.
- No raw preview or raw download.
- No replay or active scan.
- No automatic ChatGPT handoff.
- No tag or GitHub Release.
- No runtime implementation approval.

## Runtime Boundary Decision

The next step may define a server-free runtime boundary skeleton or a server
skeleton preflight. It must not create a listener, accept external transport,
parse protocol messages, register executable tools, read local evidence, read
file bodies, or perform state-changing actions.

The next slice must consume the existing registry, dry-run, schema catalog, and
gate fixtures as acceptance inputs. If any of those gates are missing, server
work remains blocked.

## Allowed Next Slice

The allowed next slice is one of:

- Server-free local-only runtime boundary skeleton.
- Server skeleton preflight.

The slice may add design text, fixture expectations, and tests that prove later
runtime work must consume the existing catalog and gate. It may not add the
runtime itself.

The server skeleton preflight is tracked in
[`MCP_SERVER_SKELETON_PREFLIGHT_v0.6.md`](MCP_SERVER_SKELETON_PREFLIGHT_v0.6.md).
It must consume this decision, the registry, dry-run, schema catalog,
implementation gate fixture, and adapter expected behavior fixture before
listener work is considered.

## Forbidden Work

The following work must stay out of the next slice unless separately approved:

- MCP server listener.
- External transport.
- Protocol handling.
- Tool registration that exposes runtime tools.
- Actual tool execution.
- Local evidence reader.
- File body reading.
- Upload or import behavior.
- Dashboard POST action.
- Collector forwarding change.
- Receiver ingest change.
- Raw preview or raw download.
- Replay or active scan.
- Automatic ChatGPT handoff.
- Release or tag work.

## Required Acceptance Criteria Before Server Work

Before server work starts, a PR must prove:

- Registry helper consumed.
- Dry-run helper consumed.
- Tool schema catalog consumed.
- Implementation gate fixture consumed.
- Adapter expected behavior fixture consumed.
- Allowed tools match registry.
- Forbidden concepts absent.
- Blocked response helper used.
- Verify-first behavior tested.
- Raw-free metadata only.
- Local path absent.
- Credential, session, and token values absent.
- Target identifier absent.
- No automatic ChatGPT handoff.
- No local evidence reader.
- No state-changing action.
- Candidate finding only.
- Risk draft only.
- Severity and CVSS manual decision.

## Required Test Evidence

Required evidence before server work:

- Unit tests that compare any future runtime-facing tool names with the registry.
- Unit tests that prove the schema catalog is consumed before runtime exposure.
- Fixture tests that consume the adapter expected behavior fixture.
- Fixture tests that consume the implementation gate fixture.
- Negative tests for forbidden concepts.
- Negative tests for raw access, local path detail, credential/session/token
  detail, target identifier detail, and automatic handoff.
- Source checks that prevent server, transport, protocol, execution, and local
  evidence reader imports in pre-runtime slices.
- Documentation hygiene checks for candidate finding, draft risk, and manual
  severity/CVSS language.

## Split Plan For Later Runtime Work

Later work must be split into separate PRs:

- Server skeleton preflight.
- Server listener skeleton.
- Transport and protocol handler.
- Tool registration.
- Tool execution.
- Local evidence reader.
- Dashboard POST action.
- Upload or import action.
- Raw preview or raw download.
- Automatic ChatGPT handoff.
- Release or tag work.

Each step needs its own tests and boundary review. A later PR may depend on a
previous one, but it should not combine multiple new security boundaries by
default.

## Deferred Decisions

This document does not decide:

- Whether to implement an MCP server.
- Which transport to use.
- How protocol messages are represented.
- Whether any tool execution layer is acceptable.
- Whether local evidence reading is acceptable.
- Whether dashboard state-changing actions are acceptable.
- Whether upload or import behavior is acceptable.
- Whether any release action should happen.

Those decisions require separate review before implementation.
