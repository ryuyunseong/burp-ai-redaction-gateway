# Redacted Viewer Design

## Purpose

This document defines the v0.11 redacted static/local viewer design and the
prototype boundary consumed by the first implementation PR.

The viewer goal is to provide a fast GUI-like review experience for already
verified redacted artifacts without introducing a web server, listener runtime,
Burp MCP direct integration, raw forwarding, tool execution, replay, active
scan, or automatic AI handoff.

## Baseline

- v0.10 release: published and preserved.
- v0.10 tag target:
  `f078134dfecda1c9d153e46ef1d25d46ff811fa0`
- v0.11 scope planning is recorded in
  `docs/V0.11_SCOPE_PLANNING.md`.
- The first v0.11 GUI-like path starts with static/local viewer design.
- Raw Burp traffic remains outside viewer input and output.

## Design Scope

The viewer is intended to render only safe, verified, redacted artifacts. The
first implementation candidate should be static or local-file based rather than
server based.

Allowed design goals:

- display redacted artifact status
- display safe file inventory
- display copy-safe summary metadata
- display candidate finding/status tables
- display report and prompt readiness
- show blocked reason codes without raw values
- fail closed when verification is absent or failed

The first prototype implementation is a static HTML generator only. It does not
add a web server, upload or import workflow, raw preview, raw download, MCP
integration, listener runtime, transport runtime, replay, active scan, raw
forwarding, tool execution, or automatic AI handoff.

## Prototype Command

The static/local prototype consumes the redacted viewer fixture contract and
writes a self-contained HTML file:

```powershell
python -m burp_ai_redaction_gateway viewer `
  --input tests\fixtures\redacted_viewer_valid.json `
  --output out\viewer\redacted_viewer.html
```

The command prints raw-free summary metadata only. It does not echo raw artifact
values or full local paths. Negative, malformed, unsupported, oversized, or
unsafe-path artifacts fail closed before rendering.

## Input Contract

The viewer may consume only redacted JSON, Markdown, or static HTML artifacts
that have already passed the gateway verification boundary.

Allowed input classes:

- verified `analysis_packet.json`
- verified `chatgpt_prompt.md`
- verified `codex_task_prompt.md`
- verified `report_draft.md`
- future redacted viewer fixture metadata

Input requirements:

- input must be selected by output alias or safe file allowlist entry
- input must have verify status metadata
- input must not require raw Burp request or response bodies
- input must not require local-only file bodies
- input must not require external network access
- input must not rely on an MCP tool invocation

## Output Contract

The first viewer output may be a static HTML file or a local file viewer output
generated from verified redacted artifacts.

Allowed output components:

- copy-safe summary
- safe file inventory
- candidate finding/status table
- report readiness status
- prompt readiness status
- verification status
- blocked reason code
- manual review required marker
- generated timestamp

Output must keep findings as candidates, risk as draft, and final severity or
CVSS as a manual decision.

## Forbidden Scope

The viewer design does not allow:

- raw preview
- raw download
- web server implementation
- localhost web UI implementation
- POST or state-changing action endpoint
- listener or transport runtime
- MCP server implementation
- Burp extension implementation
- Burp MCP direct integration
- MCP tool execution
- local evidence body reader outside the safe file allowlist
- replay or active scan
- raw forwarding
- automatic AI handoff
- repository settings or ruleset changes
- v0.10 tag or GitHub Release mutation

## Security Boundary

The viewer boundary is raw-free and fail-closed.

The viewer must not display or store:

- raw Burp request or response bodies
- credential values
- token values
- cookie values
- Authorization header values
- API key values
- session values
- target identifiers
- full local paths
- stack trace bodies
- local-only filenames
- local evidence bodies

The viewer must treat any unverified artifact as blocked. It must not try to
repair, infer, or partially render a failed input.

## Safe File Allowlist

The viewer must use an explicit safe file allowlist. The initial allowlist is:

- `analysis_packet.json`
- `chatgpt_prompt.md`
- `codex_task_prompt.md`
- `report_draft.md`

Future viewer fixture files may be added only by a separate fixture contract PR.
They must remain redacted metadata fixtures, not raw traffic samples.

## Path Traversal Boundary

The viewer must not render arbitrary local file paths. A future implementation
must resolve files through output alias and allowlist metadata rather than
operator-supplied filesystem paths.

Blocked path classes:

- parent-directory traversal labels
- absolute local path labels
- drive-root path labels
- home-directory shortcut labels
- mixed-separator traversal labels
- symlink or shortcut escape labels

Tests may use synthetic labels for these classes, but they must not record real
local paths.

## Static HTML Boundary

If a future implementation generates static HTML, the generated file must be
self-contained and raw-free.

Static HTML requirements:

- no external network resources
- no remote script sources
- no raw artifact embed
- no local path embed
- no automatic clipboard write
- no automatic file download
- no form submission
- no POST action
- no active scan or replay control
- no MCP tool invocation control

Static HTML may include copyable text only when the source text is already a
verified redacted AI candidate.

## Error Handling

The viewer must fail closed for:

- malformed artifact
- missing schema
- missing verify status
- failed verify status
- secret-like value detected
- unsupported file type
- unsupported extension
- oversized file
- unsafe path label
- missing required safe file
- unknown artifact role

Error output must be raw-free. It may include a reason code and a short safe
message, but it must not echo the original unsafe value.

## Audit Log Event

A future implementation should emit only raw-free audit metadata.

Allowed audit fields:

- event_name
- project_alias
- output_alias
- artifact_role
- safe_file_name
- verify_status
- viewer_mode
- blocked_reason_code
- manual_review_required
- timestamp

Forbidden audit fields:

- raw request or response body
- credential value
- token value
- cookie value
- Authorization header value
- API key value
- session value
- target identifier
- full local path
- local-only filename
- local evidence body

## Test Plan

The first viewer implementation PR must add tests before broadening behavior.

Required test categories:

- valid redacted fixture renders safe summary metadata
- valid redacted fixture renders candidate finding/status table
- verify-failed fixture is blocked
- missing schema fixture is blocked
- malformed artifact fixture is blocked
- unsupported extension fixture is blocked
- oversized artifact fixture is blocked
- path traversal fixture is blocked
- secret-like value fixture is blocked
- generated HTML contains no raw token, cookie, Authorization, API key, session,
  target identifier, or local path pattern
- generated HTML has no external network resource references
- generated HTML has no form submission or POST action
- audit event contains only allowed raw-free fields

Fixtures must use synthetic labels only. They must not include raw Burp request
or response bodies, credential values, token values, cookie values,
Authorization header values, API key values, target identifiers, or full local
paths.

## Next Implementation PRs

Recommended split:

1. Viewer fixture contract PR
   - defines redacted viewer fixtures and expected safe output shape
   - no viewer implementation
   - no raw samples
2. Static viewer prototype PR
   - adds a static/local renderer for verified redacted artifacts
   - no web server
   - no listener runtime
   - no MCP integration
3. Viewer hygiene tests PR
   - expands negative cases for raw-like values, path traversal labels,
     unsupported inputs, and generated HTML safety
   - keeps static viewer output raw-free

## Deferred Work

Deferred until separately approved:

- localhost web UI implementation
- web server implementation
- POST or state-changing controls
- MCP server implementation
- Burp MCP direct integration
- Burp extension implementation
- listener or transport runtime
- replay or active scan
- raw forwarding
- tool execution
- automatic AI handoff
- v0.10 tag or GitHub Release mutation

## Final Decision

v0.11 should start with a redacted static/local viewer design. The viewer path
must provide a fast GUI-like review experience while preserving the raw-free,
fail-closed gateway boundary.
