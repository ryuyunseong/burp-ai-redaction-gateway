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
- MCP audit output is written to stderr and contains only timestamp, tool name,
  and sanitized project label.
- `readOnlyHint` is included in tool annotations, but safety is enforced in
  server code rather than relying on client interpretation.

## Allowed Output Scope

The server is intended for sanitized files such as:

- `finding_candidates.json`
- `analysis_packet.json`
- `chatgpt_prompt.md`
- `codex_task_prompt.md`
- `report_draft.md`

Do not expose real Burp exports, local raw vaults, tokens, cookies, real
domains, or personal data through MCP.
