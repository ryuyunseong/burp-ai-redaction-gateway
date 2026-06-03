# Burp AI Redaction Gateway

Local CLI for turning Burp HTTP history exports into sanitized evidence packets
and prompt files. Raw HTTP values are parsed locally, sensitive values are
redacted, and generated output is blocked if the final safety scan finds likely
secrets or personal data.

This first MVP uses only the Python standard library so it can run without
installing packages. It supports synthetic JSON fixtures, HAR-style JSON, and a
basic Burp XML export shape.

## Usage

```powershell
python -m burp_ai_redaction_gateway generate `
  --input samples/synthetic_burp_history.json `
  --output out/demo `
  --project client_alias_demo `
  --policy policy.json
```

Verify generated output:

```powershell
python -m burp_ai_redaction_gateway verify --input out/demo --policy policy.json
```

Generated files:

- `endpoint_inventory.md`
- `sanitized_events.jsonl`
- `finding_candidates.json`
- `chatgpt_prompt.md`
- `codex_task_prompt.md`
- `redaction_audit.json`
- `redaction_audit.db`

Each generated text artifact includes metadata such as `sanitizer_version`,
`policy_hash`, `raw_data_included: false`, `generated_at`,
`source_event_count`, aggregate `redaction_counts`, and `scanner_result`.

## Policy

The default policy is [policy.json](C:/coding/burp-ai-redaction-gateway/policy.json).
It is fail-closed, disables raw request/response output, and disables response
snippets by default. Verification scans `.json`, `.jsonl`, `.md`, and `.txt`
files for raw tokens, cookie values, JWTs, PII, internal IPs, domains, high
entropy strings, and raw HTTP markers.

Allowed false positives must be documented in `verification.allowlist_notes`.
The built-in allowlist only permits network buckets such as `10.0.0.0/8`, not
raw internal host IP addresses.

## Fixtures

Repository fixtures are synthetic only:

- `samples/synthetic_burp_history.json`
- `samples/synthetic_burp_variants.json`
- `samples/burp_xml_base64_history.xml`

They cover JSON APIs, URL-encoded forms, multipart upload shape, GraphQL,
HTML forms with hidden input, JWT in multiple locations, Korean PII, internal
IP/host aliasing, high entropy strings, and Burp XML base64 request/response.

## Verification

The tests are written with `unittest`, so they also run under pytest when pytest
is installed.

```powershell
python -m compileall burp_ai_redaction_gateway tests
python -m unittest discover -s tests
python -m burp_ai_redaction_gateway generate --input samples\synthetic_burp_history.json --output out\demo --project client_alias_demo
python -m burp_ai_redaction_gateway verify --input out\demo
```

Before committing, run:

```powershell
scripts\pre_commit_check.bat
scripts\git_safety_check.bat
```

`git_safety_check` is safe to run before `git init`; in that case it skips the
tracked/staged file check and still runs the pre-commit verification.

## Security Notes

- Do not commit real Burp exports, raw HTTP history, tokens, cookies, customer
  domains, internal IPs, or local audit databases.
- Fixtures in this repository must remain synthetic.
- The audit database stores evidence references and redaction counters only. It
  does not store raw request or response values.
- Output generation is fail-closed. If a likely token, JWT, email, phone number,
  Korean RRN, financial identifier, or high-entropy secret remains in generated
  text, the CLI raises an error before writing output files.
- Real Burp exports must be tested only under `local_only/` and must never be
  moved into `samples/`, committed, pasted into prompts, or copied into issues.
