# v0.6 Roadmap

`v0.5` is the published local-use baseline. The v0.6 line should separate
future feature candidates from v0.5.x hotfixes and keep the raw-free gateway
boundary explicit before any new runtime capability is added.

This document is planning only. It does not implement an MCP server, local
evidence reader, upload or import action, dashboard POST action, collector
forwarding change, receiver ingest change, raw preview, replay, active scan,
automatic ChatGPT handoff, new tag, or GitHub Release.

The v0.5.x maintenance boundary is tracked in
[`V0.5_HOTFIX_POLICY.md`](V0.5_HOTFIX_POLICY.md).
The near-term read-only work grouping is tracked in
[`V0.6_FAST_TRACK_PLAN.md`](V0.6_FAST_TRACK_PLAN.md). That plan also tracks the
completed read-only dashboard UX bundle as the current v0.6 UX baseline before
MCP read-only design work starts.

## Planning Principles

- v0.5 remains the fixed local-use baseline unless an explicit v0.5.x hotfix is
  approved.
- v0.5.x changes should fix regressions, broken docs, launch friction, or test
  failures without adding new capability.
- v0.6 feature work should be grouped by risk and reviewed separately.
- Raw-free, read-only, deny-by-default work should come before state-changing
  actions.
- Findings remain candidates until manual review.
- Risk values remain drafts until manual review.
- Severity and CVSS values require separate manual decisions.
- Passing smoke checks is readiness evidence only, not sharing approval.
- AI input remains limited to the four candidate safe files.

## A. Low-Risk UX Improvements

These items improve operator clarity without changing capture, ingest, raw data
handling, integrity handling, or state-changing behavior.

- Korean quickstart wording polish.
- Safe files explanation cards.
- Output alias selector for verified output aliases only. It should stay
  read-only navigation and must not display local paths, actual target
  identifiers, raw traffic, credential values, or state-changing actions.
- Troubleshooting panel for setup, upload/export, verify/review/report,
  live-capture, safe-files, and MCP boundary guidance. It should link to
  existing dashboard routes and show document filenames as non-serving
  reference text only.
- Read-only release readiness status panel. It should link to v0.5 release
  readiness, v0.6 planning, and hotfix policy documents as reference text
  without creating tags or GitHub Releases.
- Demo and sample output guidance.

Expected acceptance evidence:

- UI or document copy remains raw-free.
- Safe file wording keeps the four-file allowlist explicit.
- Candidate finding, draft risk, and manual severity/CVSS boundaries remain
  visible.
- Browser or smoke checks confirm that new copy does not expose raw markers,
  target identifiers, credential/session values, or local path details.

## B. Read-Only Integration

These items can start after the contract and evidence boundary are reviewed.
They should remain read-only and should not add import, upload, replay, active
scan, or automatic handoff behavior.

- MCP read-only tool contract matrix.
- MCP read-only prototype.
- Release readiness status page.
- Report and prompt readiness read-only endpoint.

The first contract matrix slice is tracked in
[`MCP_READ_ONLY_TOOL_CONTRACT_MATRIX_v0.6.md`](MCP_READ_ONLY_TOOL_CONTRACT_MATRIX_v0.6.md).
The prototype preflight criteria are tracked in
[`MCP_READ_ONLY_PROTOTYPE_PREFLIGHT_v0.6.md`](MCP_READ_ONLY_PROTOTYPE_PREFLIGHT_v0.6.md).
The registry adapter design is tracked in
[`MCP_REGISTRY_ADAPTER_DESIGN_v0.6.md`](MCP_REGISTRY_ADAPTER_DESIGN_v0.6.md).
The registry adapter fixture plan is tracked in
[`MCP_REGISTRY_ADAPTER_FIXTURE_PLAN_v0.6.md`](MCP_REGISTRY_ADAPTER_FIXTURE_PLAN_v0.6.md).
The implementation gate design is tracked in
[`MCP_IMPLEMENTATION_GATE_DESIGN_v0.6.md`](MCP_IMPLEMENTATION_GATE_DESIGN_v0.6.md).
The first code slice is an internal registry skeleton and fixture consistency
helper only. It should not add MCP transport, protocol handling, tool execution,
local evidence reading, POST actions, raw preview, replay, active scan, or
automatic ChatGPT handoff.
The local-only adapter dry-run skeleton is
`burp_ai_redaction_gateway/mcp_adapter_dry_run.py`. It is gate and fixture
consumption code only, not an MCP server, not MCP transport, not a protocol
handler, not actual tool execution, not a local evidence reader, and not runtime
MCP exposure.
The local-only tool schema catalog is
[`MCP_LOCAL_ONLY_TOOL_SCHEMA_CATALOG_v0.6.md`](MCP_LOCAL_ONLY_TOOL_SCHEMA_CATALOG_v0.6.md)
and `burp_ai_redaction_gateway/mcp_tool_schema_catalog.py`. It derives safe
descriptor metadata from the registry and dry-run fixtures only. It is not an
MCP server, not MCP transport, not a protocol handler, not actual tool
execution, not a local evidence reader, and not runtime MCP exposure.
The runtime boundary decision is tracked in
[`MCP_RUNTIME_BOUNDARY_DECISION_v0.6.md`](MCP_RUNTIME_BOUNDARY_DECISION_v0.6.md).
It keeps server, transport, protocol handling, tool execution, and local
evidence reader work split before any runtime implementation is considered.
The server skeleton preflight is tracked in
[`MCP_SERVER_SKELETON_PREFLIGHT_v0.6.md`](MCP_SERVER_SKELETON_PREFLIGHT_v0.6.md).
It consumes the registry, dry-run, schema catalog, implementation gate, adapter
fixture, and runtime boundary decision without adding listener, transport,
protocol handling, tool execution, or local evidence reading.
The runtime boundary consumption fixture is tracked in
[`MCP_RUNTIME_BOUNDARY_CONSUMPTION_v0.6.md`](MCP_RUNTIME_BOUNDARY_CONSUMPTION_v0.6.md).
It adds fixture, test, and source-check evidence that the existing pre-runtime
helpers still do not contain listener, transport, protocol, execution, or local
evidence reader code.
The listener skeleton decision is tracked in
[`MCP_LISTENER_SKELETON_DECISION_v0.6.md`](MCP_LISTENER_SKELETON_DECISION_v0.6.md).
It is a design and acceptance criteria document only. It decides that any later
listener skeleton work must expand source-check scope for new runtime-facing
files and must keep transport, protocol handling, tool execution, and local
evidence reading separate.

Expected acceptance evidence:

- Tools read only verified output aliases.
- Tools do not read raw traffic, local-only evidence files, archives, audit row
  bodies, or ignored secrets.
- Error output uses safe aliases and status metadata only.
- Audit output stays raw-free.

## C. Security-Sensitive Deferred Work

These items change security boundaries or state. They need separate design and
review before implementation.

- Local evidence file reader.
- Upload or import evidence action.
- Dashboard live capture orchestration.
- Replay.
- Active scan.
- Automatic ChatGPT handoff.
- File retention or delete policy changes.
- HMAC secret UI.
- CSRF or state-changing action changes.

Expected acceptance evidence before any implementation:

- Threat boundary and failure modes are documented first.
- Required CSRF, action audit, path traversal, forbidden directory, and
  raw-free result checks are listed before code changes.
- State-changing behavior is isolated into a separate PR.
- Raw preview, replay, active scan, and automatic external handoff remain
  blocked until explicitly approved.

## Suggested First v0.6 Slices

1. Low-risk GUI and documentation UX polish.
2. Read-only MCP contract matrix.
3. MCP runtime boundary decision before any server work.
4. MCP server skeleton preflight before listener work.
5. MCP runtime boundary consumption fixture before listener work.
6. MCP listener skeleton decision before any listener implementation.
7. Read-only release readiness status page.
8. Security-sensitive design review for local evidence intake.

## v0.5.x Versus v0.6 Decision Rules

- If the change fixes a broken link, typo, launch script bug, packaging issue,
  or failing test without adding capability, consider v0.5.x.
- If the change adds a route, tool, POST action, file intake, replay path,
  active scan path, raw preview, automatic handoff, or policy behavior, treat it
  as v0.6 or later.
- If the change touches secrets, HMAC, CSRF, retention, deletion, raw handling,
  collector forwarding, receiver ingest, or external handoff behavior, split it
  into a dedicated security review PR.

## Explicitly Not Approved Here

- MCP server implementation.
- Local evidence reader implementation.
- Upload or import evidence action implementation.
- Dashboard POST action implementation.
- Collector forwarding behavior change.
- Receiver ingest behavior change.
- Raw preview or raw download.
- Replay or active scan.
- Automatic ChatGPT handoff.
- New tag.
- GitHub Release.
