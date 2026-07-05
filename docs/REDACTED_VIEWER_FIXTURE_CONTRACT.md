# Redacted Viewer Fixture Contract

## Purpose

This document fixes the v0.11 redacted viewer fixture contract before any
static/local viewer implementation starts.

The fixture contract defines which already-redacted artifacts the viewer may
consume and which synthetic failure classes must fail closed. It does not add a
viewer implementation, CLI command, web UI, web server, MCP server, Burp
extension, listener runtime, transport runtime, raw forwarding, replay, active
scan, tool execution, or automatic AI handoff.

## Baseline

- v0.10 release is published and preserved.
- v0.10 tag target:
  `f078134dfecda1c9d153e46ef1d25d46ff811fa0`
- v0.11 scope planning is recorded in
  `docs/V0.11_SCOPE_PLANNING.md`.
- Redacted viewer design is recorded in
  `docs/REDACTED_VIEWER_DESIGN.md`.
- The viewer fixture contract must be consumed before a later static/local
  viewer implementation PR.

## Contract Scope

Allowed in this contract:

- raw-free fixture schema
- one positive redacted viewer fixture
- fail-closed negative fixtures
- fixture hygiene tests
- safe file allowlist checks
- synthetic unsafe path labels

Not allowed in this contract:

- viewer rendering implementation
- CLI command implementation
- web UI implementation
- web server implementation
- MCP server implementation
- Burp extension implementation
- listener or transport runtime implementation
- replay, active scan, raw forwarding, or tool execution
- automatic AI handoff
- repository settings or ruleset changes
- v0.10 tag or GitHub Release mutation

## Required Fixture Files

The fixture contract is represented by these files:

- `tests/fixtures/redacted_viewer_valid.json`
- `tests/fixtures/redacted_viewer_reject_unredacted_like.json`
- `tests/fixtures/redacted_viewer_reject_credential_like.json`
- `tests/fixtures/redacted_viewer_reject_unsafe_path.json`

The positive fixture must pass contract checks. The negative fixtures must be
classified as blocked before any viewer implementation tries to render them.

## Positive Fixture Shape

The valid fixture must include:

- `artifact_id`
- `schema_version`
- `generated_at`
- `source_kind`
- `redaction_status`
- `findings`
- `display_sections`
- `audit`

The valid fixture must also keep:

- `fixture_kind` as `valid`
- `expected_decision` as `accept`
- `viewer_implementation_included` as `false`
- `raw_data_included` as `false`
- `manual_review_required` as `true`
- `safe_file_allowlist` equal to the four allowed output bundle files

The safe file allowlist is:

- `analysis_packet.json`
- `chatgpt_prompt.md`
- `codex_task_prompt.md`
- `report_draft.md`

## Finding Boundary

Findings in viewer fixtures are synthetic candidate rows only.

Allowed finding fields:

- `id`
- `title`
- `status`
- `risk`
- `severity_finalized`
- `evidence_aliases`
- `safe_summary`

Required finding constraints:

- `status` stays `candidate`
- `risk` stays `draft`
- `severity_finalized` stays `false`
- `evidence_aliases` only reference the safe file allowlist
- `safe_summary` contains redacted metadata only

Final severity, final CVSS, confirmed vulnerability, exploitability, and
external sharing approval remain manual decisions outside this fixture
contract.

## Negative Fixture Shape

Each negative fixture must include:

- `schema_version`
- `fixture_kind`
- `expected_decision`
- `rejection_reason_code`
- `raw_data_included`
- `manual_review_required`
- `viewer_implementation_included`
- `synthetic_input_label`
- `forbidden_classes`
- `safe_message`

Each negative fixture must keep:

- `fixture_kind` as `negative`
- `expected_decision` as `reject`
- `raw_data_included` as `false`
- `manual_review_required` as `true`
- `viewer_implementation_included` as `false`

The negative fixtures must not include real unsafe values. They use synthetic
labels and forbidden class names only.

## Raw-Like Rejection

The raw-like rejection fixture records that raw-shaped data must fail closed.
It must not contain a real Burp request, response, body, header block, archive
content, or traffic sample.

Expected result:

- `expected_decision`: `reject`
- `rejection_reason_code`: `raw_like_value_detected`
- blocked before rendering
- no input value echo

## Credential-Like Rejection

The credential-like rejection fixture records that protected values must fail
closed. It must not contain real cookie, authorization, token, API key,
password, session, or secret values.

Expected result:

- `expected_decision`: `reject`
- `rejection_reason_code`: `credential_like_value_detected`
- blocked before rendering
- no input value echo

## Unsafe Path Rejection

The unsafe path rejection fixture records that path-like labels outside the
safe allowlist must fail closed. It must not include actual local paths.

Blocked path classes:

- parent directory traversal
- Windows absolute path
- POSIX absolute path
- file scheme path
- URL-like external path

Expected result:

- `expected_decision`: `reject`
- `rejection_reason_code`: `unsafe_path_label_detected`
- blocked before rendering
- no input value echo

## Hygiene Requirements

Fixture and contract tests must verify:

- no raw body key names
- no real raw request or response content
- no cookie, authorization, token, API key, password, session, or secret value
- no target identifier
- no actual local path
- no stack trace body
- no local evidence body
- no generated HTML
- no network resource reference
- no POST or state-changing action

Synthetic labels are allowed only when they describe a blocked class and do not
include the original unsafe value.

## Test Requirements

The targeted fixture test must confirm:

- the positive fixture passes contract checks
- the raw-like fixture fails contract checks
- the credential-like fixture fails contract checks
- the unsafe path fixture fails contract checks
- the unsafe path detector rejects parent traversal labels
- the unsafe path detector rejects Windows absolute path labels
- the unsafe path detector rejects POSIX absolute path labels
- the unsafe path detector rejects file scheme labels
- the unsafe path detector rejects URL-like external path labels
- no viewer implementation module is imported

The full unittest suite must continue to pass after adding this fixture
contract.

## PR Split Requirements

Keep these as separate future PRs:

1. Static/local viewer prototype
   - consumes this fixture contract
   - renders only redacted metadata
   - no web server
2. Generated output hygiene tests
   - validates static HTML output remains raw-free
   - rejects external resources and state-changing controls
3. Localhost web UI threat model
   - defines CSRF, path, and state boundary before any web UI
4. Burp MCP feasibility
   - remains read-only and redacted-only
   - no tool execution

## Final Decision

The next v0.11 implementation work must consume this fixture contract before it
renders any viewer output. The contract keeps the fast GUI-like path raw-free,
fail-closed, and separate from server, MCP, Burp, listener, transport, and tool
execution surfaces.
