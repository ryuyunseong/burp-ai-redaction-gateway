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

Review verified analysis packet output and optionally export safe prompt files:

```powershell
python -m burp_ai_redaction_gateway review --input out/demo --export-dir exports/demo_review
```

The review command runs `verify` first and refuses to export files if verification
fails.

Generate a cautious report draft from verified analysis packets:

```powershell
python -m burp_ai_redaction_gateway report --input out/demo --output out/demo/report_draft.md
```

The report draft keeps every item in candidate status and includes rationale,
impact draft, additional verification steps, remediation draft, and claims that
must not be made before proof.

Generated files:

- `endpoint_inventory.md`
- `sanitized_events.jsonl`
- `finding_candidates.json`
- `analysis_packet.json`
- `chatgpt_prompt.md`
- `codex_task_prompt.md`
- `redaction_audit.json`
- `redaction_audit.db`

Each generated text artifact includes metadata such as `sanitizer_version`,
`policy_hash`, `raw_data_included: false`, `generated_at`,
`source_event_count`, aggregate `redaction_counts`, and `scanner_result`.

`finding_candidates.json` is built only from sanitized events. Each candidate
uses a `finding_id`, passive rule `type`, confidence, templated
`affected_endpoint`, `evidence_ids`, rationale, confidence rationale, manual
test guidance, and a `do_not_claim` list to prevent over-claiming before manual
verification.
`analysis_packet.json`, `chatgpt_prompt.md`, and `codex_task_prompt.md` are
derived from those candidates and must be used only after `verify` passes.

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

## Real-Like Smoke Test

When a real Burp export is not available, generate a safe real-like smoke test
sample:

```powershell
python scripts\make_safe_burp_export_sample.py
scripts\run_safe_sample_smoke_test.bat
```

This writes `local_only\real_burp_history_sample.xml` with synthetic data only
and then runs `generate`, `verify`, and the Git safety gate. The generated sample
is useful for parser and redaction smoke testing, but it is not a substitute for
compatibility testing with an export saved directly from Burp.

Real Burp exports must still be tested separately under `local_only/`. Raw real
exports must never be committed, pasted into prompts, copied into issues, or
added to documentation.

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

## Burp Montoya Collector

The Burp-side collector skeleton lives under
[extensions/montoya-collector](C:/coding/burp-ai-redaction-gateway/extensions/montoya-collector).
It is a Java/Gradle Montoya extension that collects only in-scope Proxy HTTP
history items and hands them off to a loopback-only local gateway endpoint. It
does not log raw request or response values, and any generated output must still
pass the existing Python `verify` gate before use.

See [docs/MONTOYA_COLLECTOR.md](C:/coding/burp-ai-redaction-gateway/docs/MONTOYA_COLLECTOR.md).

## Localhost Receiver

Run the loopback-only receiver for Montoya collector handoff payloads:

```powershell
python -m burp_ai_redaction_gateway serve --host 127.0.0.1 --port 8765 --output out\receiver --project montoya_receiver_alias
```

The receiver accepts `POST /ingest/burp-history`, applies redaction immediately,
and writes only verified sanitized output. See
[docs/LOCALHOST_RECEIVER.md](C:/coding/burp-ai-redaction-gateway/docs/LOCALHOST_RECEIVER.md).

## Security Notes

- Do not commit real Burp exports, raw HTTP history, tokens, cookies, customer
  domains, internal IPs, or local audit databases.
- Fixtures in this repository must remain synthetic.
- Use `review` only on output directories that should pass `verify`; it prints
  summary counts and safe prompt file names, not raw HTTP content.
- Use `report` only after verification. Report drafts must keep candidate
  wording until manual reproduction is complete.
- The audit database stores evidence references and redaction counters only. It
  does not store raw request or response values.
- Output generation is fail-closed. If a likely token, JWT, email, phone number,
  Korean RRN, financial identifier, or high-entropy secret remains in generated
  text, the CLI raises an error before writing output files.
- Real Burp exports must be tested only under `local_only/` and must never be
  moved into `samples/`, committed, pasted into prompts, or copied into issues.
