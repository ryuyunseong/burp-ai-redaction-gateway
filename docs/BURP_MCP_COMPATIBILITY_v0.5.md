# Burp MCP Compatibility v0.5

This document defines how a Burp MCP-style upstream tool should relate to this
gateway. It is a compatibility and safety boundary document only.

It does not implement an MCP server, connect to a Burp MCP tool, change runtime
behavior, change collector forwarding, change receiver ingest, add POST
actions, add a local evidence reader, create a tag, or create a GitHub Release.
The v0.6 gateway-owned read-only MCP contract matrix is tracked in
[`MCP_READ_ONLY_TOOL_CONTRACT_MATRIX_v0.6.md`](MCP_READ_ONLY_TOOL_CONTRACT_MATRIX_v0.6.md).

## Core Conclusion

Burp MCP does not replace this gateway.

Burp MCP should be treated as an upstream tool that may let an AI client inspect
or operate Burp-side capabilities. This gateway is a downstream safety gateway
that redacts and verifies Burp-derived data before any AI handoff candidate is
reviewed.

The safe relationship is:

```text
Burp or Montoya
-> optional manual Burp MCP-assisted inspection
-> local gateway
-> redaction and verify
-> safe file inventory
-> manual AI input or future read-only MCP gateway
```

The unsafe relationship is:

```text
AI client
-> direct Burp MCP access to Burp-side raw traffic or actions
-> ChatGPT handoff
```

That unsafe relationship bypasses the gateway boundary and is not approved for
v0.5.

## Role Separation

| Area | Burp MCP-style upstream tool | burp-ai-redaction-gateway |
| --- | --- | --- |
| Primary purpose | Assist with Burp-side inspection or operation | Produce verified raw-free AI handoff candidates |
| Data access | May sit close to Burp-side traffic and tools | Uses verified sanitized outputs only |
| Raw-free guarantee | Not provided by this gateway | Enforced by redaction and verify gates |
| Redaction and verify | Not the gateway boundary | Required before AI handoff candidates |
| Safe files | Not the source of truth | Produces the four-file allowlist |
| Report draft | Not the source of truth | Produces `report_draft.md` as a draft |
| Audit and release evidence | Separate review needed | Tracks raw-free evidence and release hygiene |
| Risk level | Higher if connected directly to AI | Lower when used after verify passes |
| Recommended position | Upstream helper in a controlled lab | Downstream safety layer before AI review |

## Four Safe File Boundary

The only AI input candidate files remain:

- `analysis_packet.json`
- `chatgpt_prompt.md`
- `codex_task_prompt.md`
- `report_draft.md`

These files are still candidates. They require manual review before use.

## Allowed Use

Burp MCP-style tooling may be considered only as a manual helper in an
authorized lab or explicitly approved workflow.

Allowed patterns:

- Use Burp MCP as a manual upstream helper inside the approved Burp scope.
- Route any relevant result back through the local gateway before AI use.
- Expose only verified output aliases and safe file inventory to an AI client.
- Prefer a future read-only MCP gateway with allowlisted metadata tools.
- Keep findings as candidates.
- Keep risk as draft.
- Keep final severity and CVSS as manual decisions.

## Blocked Or Deferred Use

The following patterns are blocked or deferred for v0.5:

- AI directly reading Burp-side raw traffic through Burp MCP.
- AI sending or replaying requests through Burp MCP.
- Automatic active scan execution.
- Automatic Collaborator payload generation or delivery.
- Burp project or user configuration modification.
- Automatic ChatGPT handoff.
- Local-only file reading.
- Raw preview or raw download.
- HMAC secret or CSRF token exposure.

## Security Principles

- Read-only first.
- Deny by default.
- Allowlist tools only.
- No raw traffic.
- No credential, session, or token values.
- No local path exposure.
- No automatic external handoff.
- Candidate finding only.
- Risk draft only.
- Final severity and CVSS are manual decisions.
- Tag and GitHub Release actions need separate approval.

## Future Read-Only MCP Gateway Boundary

A future gateway-owned MCP integration should expose only metadata derived from
verified outputs. It should not expose Burp MCP directly to ChatGPT.

Candidate safe tool concepts remain limited to:

- gateway status
- verified output aliases
- safe file inventory
- report readiness
- prompt readiness
- troubleshooting categories
- release readiness

Blocked tool concepts remain:

- raw traffic readers
- local-only file readers
- replay or scan actions
- external handoff actions
- file deletion actions
- secret or token display actions

## Review Checklist

Before any Burp MCP-related implementation PR:

- Confirm whether the tool is upstream Burp-side or gateway-owned.
- Confirm the tool is read-only first.
- Confirm the tool is allowlisted.
- Confirm the tool cannot return raw traffic.
- Confirm the tool cannot return credential, session, or token values.
- Confirm the tool cannot return local paths.
- Confirm state-changing actions are absent or separately reviewed.
- Confirm AI handoff remains manual.
- Confirm outputs still pass the gateway verify boundary.
- Confirm no tag or GitHub Release is created by the implementation PR.
