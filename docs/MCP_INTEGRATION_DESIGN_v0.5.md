# v0.5 MCP Integration Design

This is a planning document only. It does not implement a new MCP server,
change runtime behavior, change collector forwarding, change receiver ingest,
add POST actions, add a local evidence reader, change HMAC handling, change
CSRF handling, change retention policy, create a tag, or create a GitHub
Release.

## Goal

The v0.5 MCP integration goal is to expose the local gateway as a safe
metadata interface for an AI client. The AI client should inspect verified
gateway status, safe file readiness, and troubleshooting guidance without
reading raw Burp traffic or local-only artifacts.

The intended flow is:

```text
Burp or Montoya
-> local gateway
-> redaction and verify
-> safe files or safe metadata
-> read-only MCP tools
-> AI client reads safe metadata only
```

## Read-Only First Boundary

The first MCP slice must be read-only first.

- Allowlist tools only.
- Verify-first safe navigation.
- Safe file inventory only.
- Safe metadata only.
- No raw traffic.
- No local path exposure.
- No credential, session, or token values.
- No automatic ChatGPT handoff.
- Findings remain candidates.
- Risk remains draft.
- Final severity and CVSS remain manual decisions.

## Candidate Read-Only Tools

These names are design candidates only. They are not approved runtime behavior
until implemented in a later reviewed PR.

| Tool | Allowed output |
| --- | --- |
| `get_gateway_status` | Gateway version, configured root alias, verify mode, raw-free status labels |
| `list_verified_outputs` | Verified output aliases, verify status, safe file existence status |
| `get_live_capture_status` | Live Capture status labels, receiver output alias, handoff count summary |
| `get_safe_file_inventory` | Four safe file names, existence status, size, modified time, fingerprint |
| `get_report_readiness` | Report draft existence, candidate count, manual review reminders |
| `get_prompt_readiness` | Prompt file existence, verify-first warnings, safe handoff reminders |
| `get_troubleshooting_categories` | Failure categories and raw-free next-step guidance |
| `get_release_readiness` | Readiness checklist status and explicit non-release boundary |

The four AI input candidate files remain:

- `analysis_packet.json`
- `chatgpt_prompt.md`
- `codex_task_prompt.md`
- `report_draft.md`

## Forbidden Tool Concepts

The following tool concepts are explicitly forbidden for the v0.5 MCP design.
They are listed as blocked examples only and must not be implemented in this
planning slice.

| Forbidden concept | Why blocked |
| --- | --- |
| `get_raw_request` | Would expose raw traffic |
| `get_raw_response` | Would expose raw traffic |
| `read_local_only_file` | Would bypass the verified output boundary |
| `read_raw_vault` | Would expose raw storage |
| `replay_request` | Would introduce target-affecting behavior |
| `active_scan` | Would introduce target-affecting behavior |
| `send_to_chatgpt` | Would automate external handoff before manual review |
| `delete_files` | Would change local retention or deletion behavior |
| `show_hmac_secret` | Would expose secret material |
| `show_csrf_token` | Would expose a security token |

## Permission Model

The MCP adapter should use a narrow allowlist:

1. Resolve an output alias.
2. Require verify-passed state before exposing safe navigation metadata.
3. Return only file names from the safe file allowlist.
4. Return counts, booleans, timestamps, and fingerprints as metadata.
5. Return raw-free failure categories when a request is blocked.
6. Never return local filesystem paths.

Blocked requests should return a short failure code and a safe reason such as
`not_verified`, `not_allowlisted`, `raw_access_blocked`, or
`state_change_blocked`.

## Resources and Prompts

Future MCP resources and prompts should be derived from verified outputs only:

- Safe file inventory.
- Report readiness summary.
- Prompt readiness summary.
- Troubleshooting category list.
- Release readiness summary.

Resources must not include file bodies unless the file is one of the four safe
AI input candidate files and the output has passed verification. Even then, the
first v0.5 design should prefer metadata and explicit user-driven file review
over automatic body handoff.

## Security And Privacy Boundary

The MCP layer must not return:

- request or response bodies
- target identifiers
- URL, domain, or IP values
- credential or session values
- personal data
- HMAC secret values
- CSRF token values
- full local paths
- local-only filenames
- generated output directory internals
- raw audit rows
- archive contents
- vulnerability confirmation claims
- automatic final severity claims
- sharing approval claims

## Drift Risks

The MCP layer should reuse the same concepts already used by CLI and dashboard:

- verified output alias
- safe file allowlist
- raw-free metadata
- candidate finding wording
- draft risk wording
- manual final severity and CVSS decision

If MCP implements separate allowlist or status logic, it can drift from the CLI
and dashboard. A later implementation PR should include fixture-based tests for
allowed tools, blocked tools, safe output aliases, and forbidden marker checks.

## Acceptance Criteria For A Later Implementation PR

- MCP tool list is allowlisted.
- Forbidden tool concepts are absent from runtime registration.
- Safe output alias is required.
- Unverified output is blocked.
- Safe file inventory includes only the four AI input candidate files.
- Raw-free blocked responses are tested.
- No automatic ChatGPT handoff is implemented.
- No state-changing tool is implemented.
- No tag or release is created by the implementation PR.

