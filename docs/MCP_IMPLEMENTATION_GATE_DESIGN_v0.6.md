# MCP Implementation Gate Design v0.6

This document defines the gate that must be satisfied before any future
gateway-owned MCP implementation PR can add runtime behavior.

It is a design and gate document only. It does not implement an MCP server,
MCP transport, protocol handler, actual tool execution, local evidence reader,
upload or import action, dashboard POST action, raw preview or download,
replay, active scan, automatic ChatGPT handoff, tag, or GitHub Release.

It does not approve implementation.

The machine-readable planning fixture is:

- `samples/synthetic_mcp_implementation_gate_v0.6.json`

## Purpose

The purpose is to prevent the first MCP runtime implementation from bypassing
the registry, adapter fixture, verify-first behavior, and raw-free response
contracts that already exist in the v0.6 planning documents.

This gate connects these planning artifacts:

- `MCP_READ_ONLY_TOOL_CONTRACT_MATRIX_v0.6.md`
- `MCP_READ_ONLY_PROTOTYPE_PREFLIGHT_v0.6.md`
- `MCP_REGISTRY_ADAPTER_DESIGN_v0.6.md`
- `MCP_REGISTRY_ADAPTER_FIXTURE_PLAN_v0.6.md`
- `samples/synthetic_mcp_registry_adapter_expected_behavior_v0.6.json`
- `samples/synthetic_mcp_implementation_gate_v0.6.json`

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

## Required Preconditions

A future implementation PR must start from reviewed planning artifacts and must
show that the runtime surface is still read-only, allowlisted, verify-first, and
blocked by default.

Before runtime work starts, the PR must confirm:

- The registry helper is the single source of allowed tool names.
- The adapter expected behavior fixture is consumed by tests.
- Allowed tool names match the registry helper.
- Forbidden concepts are absent from runtime registration.
- Blocked responses use the registry helper field shape.
- Output-specific tools require verified output state before metadata is
  returned.
- Unknown, forbidden, raw-access, state-changing, local-path, secret, and
  external handoff requests are blocked.
- Candidate findings remain candidates.
- Risk values remain drafts.
- Severity and CVSS remain manual decisions.

## Required Implementation Gates

The future implementation PR must prove each gate in
`samples/synthetic_mcp_implementation_gate_v0.6.json`.

Required gate categories:

- Registry helper consumption.
- Adapter expected behavior fixture consumption.
- Allowed tool and forbidden concept consistency.
- Blocked response helper use.
- Blocked response field shape consistency.
- Verify-first behavior for output-specific tools.
- Blocked behavior for unverified aliases, unknown tools, forbidden concepts,
  raw access, state change, local path detail, secret access, and automatic
  ChatGPT handoff.
- No local evidence reader.
- No raw file body.
- No target identifier.
- No credential or session value.
- Candidate finding only language.
- Draft risk only language.
- Manual severity and CVSS decision language.

If any required gate is missing, runtime implementation remains blocked.

## Required Blocked Cases

A future implementation PR must include tests or equivalent review evidence for
these blocked cases:

| Case | Required result |
| --- | --- |
| unverified output alias | blocked with safe metadata only |
| unknown tool | blocked with safe metadata only |
| forbidden concept | blocked with safe metadata only |
| raw access request | blocked with safe metadata only |
| state-changing request | blocked with safe metadata only |
| local path detail request | blocked with safe metadata only |
| secret access request | blocked with safe metadata only |
| automatic ChatGPT handoff request | blocked with safe metadata only |

Blocked responses must not include raw traffic, generated file bodies, target
identifiers, credential or session values, integrity secret values,
request-forgery protection values, stack trace bodies, audit row bodies, or
archive contents.

## Required Review Evidence

A future implementation PR must include:

- Unit tests that compare allowed tools with the registry helper.
- Unit tests that prove forbidden concepts are absent.
- Tests that prove blocked responses use the helper and allowed field shape.
- Tests that prove verify-first behavior blocks unverified aliases.
- Raw-free scans for returned metadata.
- Documentation updates that keep the four AI candidate file boundary visible.
- Review notes confirming that no local evidence reader, upload/import action,
  raw preview/download, replay, active scan, or automatic ChatGPT handoff was
  added.

The four AI input candidate file names remain:

- `analysis_packet.json`
- `chatgpt_prompt.md`
- `codex_task_prompt.md`
- `report_draft.md`

## Runtime Work That Remains Forbidden

This gate does not permit:

- MCP server implementation.
- MCP transport implementation.
- Protocol handler implementation.
- Actual tool execution.
- Local evidence reader.
- Upload or import action.
- Dashboard POST action.
- Collector forwarding change.
- Receiver ingest change.
- Raw preview or raw download.
- Replay or active scan.
- Automatic ChatGPT handoff.
- Tag creation.
- GitHub Release creation.

## Approval Checklist

A future implementation PR cannot move out of Draft until the reviewer can
confirm:

- `implementation_approved` remains false until explicit implementation scope is
  requested.
- Runtime flags in the gate fixture stay false unless the PR is explicitly the
  implementation PR for that flag.
- Registry helper, adapter fixture, and blocked response helper are tested.
- Verify-first behavior is tested for output-specific tools.
- Required blocked cases are tested.
- The response surface contains raw-free metadata only.
- Finding language is candidate-only.
- Risk language is draft-only.
- Severity and CVSS are manual decisions.
- No tag or GitHub Release was created.

## Deferred Decisions

This gate does not decide:

- Whether to implement an MCP server.
- Which MCP transport to use.
- How protocol messages are handled.
- Whether a tool execution layer is acceptable.
- Whether a local evidence reader is ever acceptable.
- Whether dashboard state-changing actions are acceptable.
- Whether any release-management action should happen.

Those decisions require separate review before implementation.
