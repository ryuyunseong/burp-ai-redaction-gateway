# Read-Only MCP Server

The read-only MCP server exposes only verified sanitized output files over
stdio. It is a convenience layer for MCP clients and must not replace the
existing `verify`, `review`, and `report` gates.

## Run

```powershell
python -m burp_ai_redaction_gateway mcp --root out
```

Use an explicit output root. A tool call then selects a verified output
directory relative to that root, for example `demo` when the root is `out`.

## Exposed Tools

- `list_findings`
- `get_finding`
- `get_analysis_packet`
- `get_report_draft`
- `list_prompt_files`

All tools are read-only. The server does not implement file creation, file
modification, file deletion, Burp replay, active scan, or raw exchange lookup.

## Safety Rules

- Tool calls must resolve under the configured root.
- Path traversal is rejected.
- `local_only/`, `raw/`, `raw_vault/`, `build/`, and `.gradle/` paths are
  rejected.
- The selected output directory must pass `verify` before any tool response is
  returned.
- Tool responses are scanned before returning.
- MCP audit output is written to stderr for operator visibility.
- MCP tool-call audit records are appended to `.audit/mcp_audit.jsonl` under
  the configured root. Records contain only metadata such as timestamp, tool
  name, sanitized output id, optional finding id, result status, blocked reason,
  response class, `raw_data_included: false`, event id, sequence number, and
  hash chain fields.
- `readOnlyHint` is included in tool annotations, but safety is enforced in
  server code rather than relying on client interpretation.

## Audit Log

The audit log path is:

```text
<root>/.audit/mcp_audit.jsonl
```

The audit log must remain raw-free. It does not store request or response
bodies, analysis packet contents, report draft contents, cookies, authorization
headers, tokens, real domains, internal IPs, personal data, or stack traces.
Blocked events such as path traversal, forbidden directory access, and
verification failure are recorded with a safe `blocked_reason`.

Audit schema `1.1` adds event identity and chain integrity metadata:

- `event_id` as a standard UUID string
- `sequence_no`
- `chain_id`
- `prev_event_hash`
- `event_hash`
- `hash_algorithm`

`event_hash` is calculated with SHA-256 over canonical JSON with sorted keys
and without the `event_hash` field itself. The stored hash format is
`sha256:<hex>`. `prev_event_hash` is included in the canonical input, so row
insertion, deletion, reordering, and mutation are detectable by recalculation.
The first chained event has `prev_event_hash: null`; later events point to the
previous event hash in the same audit file. Retention, rotation, and
tamper-resistance controls are follow-up hardening work.

## Allowed Output Scope

The server is intended for sanitized files such as:

- `finding_candidates.json`
- `analysis_packet.json`
- `chatgpt_prompt.md`
- `codex_task_prompt.md`
- `report_draft.md`

Do not expose real Burp exports, local raw vaults, tokens, cookies, real
domains, or personal data through MCP.
