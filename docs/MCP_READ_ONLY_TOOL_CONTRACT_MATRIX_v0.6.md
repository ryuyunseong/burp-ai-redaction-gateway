# MCP Read-Only Tool Contract Matrix v0.6

This document defines the v0.6 planning contract for a future gateway-owned
read-only MCP interface. It is a contract matrix only.

Prototype preflight criteria are tracked in
[`MCP_READ_ONLY_PROTOTYPE_PREFLIGHT_v0.6.md`](MCP_READ_ONLY_PROTOTYPE_PREFLIGHT_v0.6.md).
The registry adapter design is tracked in
[`MCP_REGISTRY_ADAPTER_DESIGN_v0.6.md`](MCP_REGISTRY_ADAPTER_DESIGN_v0.6.md).
The internal registry skeleton is a code-level consistency helper for this
matrix. It is not MCP server registration, transport, protocol handling, local
evidence reading, POST action handling, or tool execution.

It does not implement an MCP server, register MCP tools, change runtime
behavior, add a local evidence reader, add upload or import actions, add POST
actions, change collector forwarding, change receiver ingest, add raw preview
or download, add replay, add active scan, add automatic ChatGPT handoff, create
a tag, or create a GitHub Release.

The contract is read-only first, allowlist tools only, and verify-first. Every
tool must return raw-free metadata only.

## Shared Tool Requirements

All allowed tool candidates must follow these requirements:

- Require a verified output alias when returning project-specific metadata.
- Return safe aliases, booleans, counts, timestamps, status labels, and safe file
  names only.
- Do not return raw traffic, target identifiers, credential/session values,
  personal data, integrity secrets, request-forgery protection values, local path
  details, raw audit rows, archive contents, or generated output internals.
- Keep finding language candidate-only.
- Keep risk language draft-only.
- Keep severity and CVSS as manual decisions.
- Never perform a state-changing operation.
- Never send data to ChatGPT automatically.

## Allowed Candidate Tools

These names are contract candidates only. A later implementation PR must still
define and test the actual MCP registry.

| Tool | Purpose | Required input | Allowed output fields | Forbidden output fields | Verify-first requirement | Blocked response code | Raw-free acceptance criteria |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `get_gateway_status` | Report gateway runtime and policy status | none | `tool_name`, `status`, `gateway_version`, `root_alias`, `verify_mode`, `raw_data_included` | raw traffic, target identifiers, local path details, secrets | not required for global status | `not_allowlisted` | Uses aliases and labels only |
| `list_verified_outputs` | List verified output aliases | optional root alias | `tool_name`, `output_aliases`, `verify_status`, `safe_file_status`, `raw_data_included` | raw file bodies, local path details, generated output internals | required for each listed output | `not_verified` | Lists aliases and status labels only |
| `get_live_capture_status` | Summarize Live Capture status | output alias | `tool_name`, `capture_status`, `receiver_alias`, `handoff_count`, `skip_count`, `raw_data_included` | raw traffic, target identifiers, collector payload bodies | required | `not_verified` | Counts and status labels only |
| `get_safe_file_inventory` | Report the four safe file candidates | output alias | `tool_name`, `safe_files`, `exists`, `size_bytes`, `modified_at_utc`, `fingerprint`, `raw_data_included` | raw file contents, local path details, non-allowlisted files | required | `not_verified` | Only the four safe file names appear |
| `get_report_readiness` | Report report draft readiness | output alias | `tool_name`, `report_exists`, `candidate_count`, `manual_review_required`, `risk_is_draft`, `raw_data_included` | report body, raw evidence, final severity claims | required | `not_verified` | Candidate counts are not confirmed issue counts |
| `get_prompt_readiness` | Report prompt file readiness | output alias | `tool_name`, `prompt_files`, `verify_passed`, `manual_review_required`, `raw_data_included` | prompt bodies, raw evidence, automatic handoff state | required | `not_verified` | File names and readiness labels only |
| `get_troubleshooting_categories` | List safe troubleshooting categories | optional output alias | `tool_name`, `categories`, `safe_next_steps`, `raw_data_included` | stack trace bodies, local path details, raw payloads | required when project-specific | `not_verified` | Categories do not include sensitive values |
| `get_release_readiness` | Report release readiness metadata | none or release alias | `tool_name`, `readiness_status`, `gate_summary`, `manual_approval_required`, `raw_data_included` | tag creation commands, release publish actions, sensitive evidence | not required for global release metadata | `state_change_blocked` | Readiness labels only; no release action |

## Four Safe File Boundary

The only AI input candidate file names are:

- `analysis_packet.json`
- `chatgpt_prompt.md`
- `codex_task_prompt.md`
- `report_draft.md`

The MCP contract may expose inventory metadata for these names after verify
passes. It must not auto-send file content to ChatGPT.

## Forbidden Tool Concepts

These concepts must not be registered as runtime MCP tools in this contract.

| Forbidden concept | Block reason | Required blocked response code |
| --- | --- | --- |
| `get_raw_request` | raw traffic access | `raw_access_blocked` |
| `get_raw_response` | raw traffic access | `raw_access_blocked` |
| `read_local_only_file` | local-only boundary bypass | `local_path_blocked` |
| `read_raw_vault` | raw storage access | `raw_access_blocked` |
| `replay_request` | state-changing target-affecting action | `state_change_blocked` |
| `active_scan` | state-changing target-affecting action | `state_change_blocked` |
| `send_to_chatgpt` | automatic external handoff | `state_change_blocked` |
| `delete_files` | retention or deletion behavior | `state_change_blocked` |
| `show_hmac_secret` | secret material exposure | `secret_access_blocked` |
| `show_csrf_token` | request-forgery protection value exposure | `secret_access_blocked` |
| `modify_burp_config` | Burp configuration mutation | `state_change_blocked` |
| `collaborator_payload_send` | target-affecting external interaction | `state_change_blocked` |

## Blocked Response Contract

Blocked responses must contain raw-free metadata only:

- `tool_name`
- `status`
- `error_code`
- `safe_reason`
- `raw_data_included: false`

Allowed blocked response codes:

- `not_verified`
- `not_allowlisted`
- `raw_access_blocked`
- `state_change_blocked`
- `local_path_blocked`
- `secret_access_blocked`

Blocked responses must not include raw traffic, local path details,
credential/session values, target identifiers, stack trace bodies, or secret
values.

## Implementation Gate For Later PRs

A later implementation PR must prove the following before registering tools:

- Runtime registry contains only allowlisted tools.
- Registry adapter consumes the internal registry helper instead of a second
  independent allowlist.
- Forbidden tool concepts are absent from runtime registration.
- Verify-first behavior blocks unverified outputs.
- Blocked response codes match this matrix.
- Safe file inventory is limited to the four candidate file names.
- Candidate finding, draft risk, and manual severity/CVSS boundaries are kept.
- No automatic ChatGPT handoff is implemented.
- No state-changing MCP tool is implemented.
