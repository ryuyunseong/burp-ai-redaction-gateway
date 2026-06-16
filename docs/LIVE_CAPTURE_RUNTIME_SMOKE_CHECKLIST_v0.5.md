# Live Capture Runtime Smoke Checklist v0.5

This checklist defines a raw-free manual smoke procedure for the Montoya Live
Capture path. It is for validating extension load, local receiver availability,
handoff counts, skip counts, and downstream verification.

This document does not change collector forwarding, receiver ingest, dashboard
live capture integration, replay, active scan, raw preview, raw download, HMAC,
retention, or ChatGPT handoff behavior.

## Scope

Use this checklist only with synthetic or authorized local-only browsing
traffic. The evidence record must contain counts, pass/fail states, safe aliases,
and status labels only.

Do not record:

- actual target identifiers
- actual URL, domain, or IP values
- raw request or response values
- Cookie values
- Authorization values
- token, JWT, or session values
- personal data
- HMAC secrets
- CSRF token values
- full local paths
- external sharing clearance guarantees
- validated issue or final CVSS claims

## Preconditions

- The repository checkout is clean.
- The Montoya collector builds successfully.
- The local receiver is started in a local-only configuration.
- The operator knows which synthetic or authorized local-only traffic is
  intended to be in scope.
- The operator knows which synthetic or authorized local-only traffic is
  intended to be out of scope.

## Smoke Steps

1. Build the Montoya collector.

   ```powershell
   cd extensions\montoya-collector
   .\gradlew.bat clean build
   ```

2. Start the local receiver from the repository root using safe aliases only.

   Record only whether the receiver started. Do not copy the full local path or
   raw receiver output.

3. Load the collector JAR in Burp Suite.

   Record only whether the extension load passed or failed. Do not copy target
   names, host values, request lines, response lines, headers, cookies, tokens,
   or screenshots that include raw traffic.

4. Generate at least one in-scope handoff candidate.

   Use only synthetic or authorized local-only traffic. Record only the
   resulting count.

5. Generate at least one out-of-scope item.

   Record only the out-of-scope skip count.

6. Check missing or invalid host counters when available.

   Record only counts or `n/a`.

7. Run receiver output verification.

   ```powershell
   python -m burp_ai_redaction_gateway verify --input <output_alias>
   python -m burp_ai_redaction_gateway review --input <project_alias>
   python -m burp_ai_redaction_gateway report --input <project_alias> --output <report_alias> --profile conservative
   ```

   Use aliases in notes. Do not paste generated file names, full paths, raw
   output excerpts, or target identifiers.

## Passing Criteria

All of these must be true:

- extension load: passed
- local receiver: passed
- in-scope handoff count: at least one
- out-of-scope skip count: at least one
- receiver verify: passed
- raw markers in extension output: zero
- actual target identifiers recorded: no
- raw request/response recorded: no
- token/cookie/session recorded: no

Passing this smoke is readiness evidence only. It is not external sharing
clearance, not a confirmed finding count, and not final severity or CVSS
evidence.

## Failure Categories

Use these raw-free labels when the smoke fails:

- `extension_load_failed`
- `receiver_unavailable`
- `no_in_scope_handoff`
- `no_out_of_scope_skip`
- `verify_failed_safely`
- `raw_marker_seen`
- `target_identifier_recorded`
- `unexpected_runtime_error`

If a failure output contains raw traffic, target identifiers, credentials, or
personal data, do not paste it into docs, issues, PRs, prompts, or release text.
Summarize only the failure category and the safe status metadata.

## Evidence Template

Use `docs/templates/LIVE_CAPTURE_RUNTIME_SMOKE_EVIDENCE_TEMPLATE.md`.

The template is intentionally metadata-only. It must not include actual target
identifiers, raw traffic, credentials, personal data, full local paths, HMAC
secrets, CSRF token values, or final severity/CVSS decisions.
