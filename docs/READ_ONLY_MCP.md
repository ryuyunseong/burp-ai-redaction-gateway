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
previous event hash across retained rotated files and the active file.

Audit log rotation is file-size based. The active file stays at
`mcp_audit.jsonl`; when the next event would exceed the configured size limit,
the active file is moved to a deterministic rotated name such as
`mcp_audit.000001.jsonl`. The numeric suffix is derived from the chain-wide
sequence number at the start of the rotated segment, so retained rotation names
do not restart at `000001` while the audit chain continues. The default limit is
10 MiB and the default retention keeps 20 rotated files. Retention deletes only
older rotated files and never deletes the active file. The first event in a new active file keeps
`prev_event_hash` pointing at the last retained event hash from the previous
file, so the chain continues across rotation. Hash chain verification is
guaranteed across retained rotated files and the active file only. When older
rotated files are removed by retention, historical verification before the
retained boundary is intentionally no longer available.

## Audit Review

Use `review-audit` to verify retained rotated files and the active audit file:

```powershell
python -m burp_ai_redaction_gateway review-audit --input out\.audit
```

The command accepts either an audit directory or one audit JSONL file. It checks
JSONL parsing, required audit schema fields, standard UUID `event_id` values,
chain-wide `sequence_no` continuity, `chain_id` consistency,
`prev_event_hash`, canonical SHA-256 `event_hash` recalculation, hash
algorithm, rotated suffix order, and raw-free scanner results. It returns exit
code 0 only when the retained audit range passes.

Use JSON output for automation:

```powershell
python -m burp_ai_redaction_gateway review-audit --input out\.audit --format json
```

The review is intentionally limited to retained rotated files and the active
file. If retention removed older rotated files, verification before that
retained boundary is reported as a warning rather than a failure. Policy
configuration, compression, external signatures, and external storage remain
follow-up hardening work.

The command is intentionally strict about audit schema `1.1`. Pre-schema audit
rows from older local runs, malformed development rows, or rows with nonstandard
event ids fail review. Use a fresh audit directory when validating the current
release baseline.

## Audit Retention

Use `audit-retention` to create a retained audit JSONL file without modifying
the input file:

```powershell
python -m burp_ai_redaction_gateway audit-retention `
  --input out\.audit\mcp_audit.jsonl `
  --output out\.audit\mcp_audit.retained.jsonl `
  --retention-days 30 `
  --dry-run

python -m burp_ai_redaction_gateway audit-retention `
  --input out\.audit\mcp_audit.jsonl `
  --output out\.audit\mcp_audit.retained.jsonl `
  --retention-days 30

python -m burp_ai_redaction_gateway review-audit --input out\.audit\mcp_audit.retained.jsonl
```

The command first runs strict audit review on the input. Pre-schema rows,
malformed rows, raw markers, broken hash chains, and nonstandard event ids fail
before any output is written. In-place modification is intentionally forbidden;
the retained rows must be written to a separate `--output` file. The summary
prints only raw-free metadata such as total rows, retained rows, expired rows,
retained timestamp range, and dry-run status.

Retention is based on each row's `timestamp_utc` value. The output file must
also pass `review-audit`. If retention removes an older prefix of the chain,
review remains limited to the retained boundary. Retention days are now
supported for explicit output files; policy configuration, compression,
external signatures, and external storage remain follow-up hardening work.

## Audit HMAC

Use `audit-hmac` to create a tamper-detection manifest for a retained audit
JSONL file:

```powershell
$env:BURP_AI_AUDIT_HMAC_KEY = "<LOCAL_ONLY_HMAC_SECRET>"

python -m burp_ai_redaction_gateway audit-hmac `
  --input out\.audit\mcp_audit.retained.jsonl `
  --manifest out\.audit\mcp_audit.retained.manifest.json

python -m burp_ai_redaction_gateway audit-hmac-verify `
  --input out\.audit\mcp_audit.retained.jsonl `
  --manifest out\.audit\mcp_audit.retained.manifest.json
```

The input must pass strict `review-audit` before any manifest is written or
verified. The manifest contains only metadata: manifest schema version, audit
schema version, safe file alias, row count, SHA-256, HMAC-SHA256, creation time,
and `raw_data_included: false`. It does not contain raw audit rows, request or
response data, cookies, tokens, domains, PII, stack traces, or the HMAC secret.

HMAC is not encryption. It detects file changes when the same local secret is
available for verification. Load the secret from `BURP_AI_AUDIT_HMAC_KEY` or an
ignored local secret file via `--key-file`; never commit the secret or print it
in logs. Manifest output under `out/.audit` is ignored by Git and should remain
local unless explicitly exported through a separate safe process.

## Allowed Output Scope

The server is intended for sanitized files such as:

- `finding_candidates.json`
- `analysis_packet.json`
- `chatgpt_prompt.md`
- `codex_task_prompt.md`
- `report_draft.md`

Do not expose real Burp exports, local raw vaults, tokens, cookies, real
domains, or personal data through MCP.
