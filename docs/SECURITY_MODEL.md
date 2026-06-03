# Security Model

## Core Rule

Raw data must not be sent to AI. Raw Burp exports, raw HTTP requests and
responses, cookies, authorization headers, JWTs, personal data, internal IPs,
and real customer domains must stay local and must not appear in prompts,
issues, commits, docs, logs, tests, or generated artifacts.

The only normal AI-facing path is:

```text
Burp export -> local generate -> local verify -> sanitized prompt/output
```

Files under `out/` may be used with ChatGPT or Codex only after
`python -m burp_ai_redaction_gateway verify --input out/...` passes.

## Data Boundaries

| Data class | AI allowed | Handling |
| --- | --- | --- |
| Raw HTTP request or response | No | Keep in `local_only/` only. Never commit. |
| Cookie values | No | Replace with `<REDACTED>` and keep only cookie names when allowed. |
| Authorization, Basic, Bearer, JWT | No | Keep scheme or structural metadata only. Remove raw values. |
| CSRF, API key, session, password fields | No | Remove values and emit schema-only metadata. |
| Email, phone, RRN, account or card number | No | Replace with redacted type markers or schema-only values. |
| Internal IP address or real host/domain | No | Use network buckets or `host_XX` aliases only. |
| `evidence_id` | Yes | Stable sanitized reference only. Must not contain raw values. |
| `raw_reference` | Limited | Local mapping identifier only, for example `LOCAL_ONLY:...`. Must not contain raw values. |
| Endpoint method, status, path template | Yes | Path identifiers must be templated. |
| Finding candidates and rationale | Yes | Only after `verify` passes. |

## Fail-Closed Behavior

The gateway is fail-closed. If the scanner finds a likely secret, cookie value,
JWT, PII, internal IP, real domain, raw marker, or high-entropy token in output,
the output must be blocked or `verify` must return a non-zero exit code.

Fail-closed takes priority over convenience. Do not bypass it for real customer
work. If a false positive is legitimate, document it in `policy.json` with an
allowlist note and keep the allowlist narrow.

## Local Mapping

`evidence_id` and `raw_reference` exist only to connect sanitized findings to
local evidence. They must never include raw request bodies, raw response bodies,
tokens, cookies, PII, customer domains, or internal host values.

The SQLite audit database is local-only support data. It must not be committed
and must not be pasted into AI tools.

## Repository Rules

- Real Burp exports must be stored under `local_only/` only.
- `local_only/`, `out/`, `raw/`, `raw_vault/`, `reports/`, and `exports/` are
  ignored by Git.
- Synthetic fixtures under `samples/` must not contain real customer data.
- Before committing, run `scripts/pre_commit_check.bat` on Windows or
  `scripts/pre_commit_check.sh` in Git Bash, WSL, or Linux.
- Gitleaks is a secondary scanner. The internal `verify` command is still the
  required gate for generated output.

