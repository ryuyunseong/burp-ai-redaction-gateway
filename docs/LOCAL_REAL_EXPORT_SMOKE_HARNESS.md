# Local Real Export Smoke Harness

This harness runs the v0.4 real Burp export validation flow without committing
or printing the export itself. It is intended for authorized local validation
only. It does not replace the synthetic fixtures, and it does not prove that a
finding is confirmed.

## When To Use It

Use this only after an operator has saved an authorized Burp export under the
ignored `local_only/` directory. The harness keeps the raw input local, writes
generated output under ignored `out/`, and prints only raw-free status metadata.

Do not use this harness for replay, active scan, deletion, retention policy
changes, or HMAC secret handling.

## Command

```powershell
scripts\run_local_real_export_smoke.ps1 -Input local_only\authorized_burp_export.xml
```

CMD users can run the wrapper:

```bat
scripts\run_local_real_export_smoke.bat -Input local_only\authorized_burp_export.xml
```

Optional aliases:

```powershell
scripts\run_local_real_export_smoke.ps1 `
  -Input local_only\authorized_burp_export.xml `
  -Project real_export_alias `
  -Output out\local_real_export_smoke
```

The input must be a file directly under the ignored `local_only/` tree. The
output alias must be a direct child of ignored `out/`.

## Flow

The harness runs:

1. `generate`
2. `verify`
3. `review`
4. `report`
5. dashboard route smoke

The dashboard smoke starts a temporary loopback dashboard, checks the main
output route and read-only operations routes, then stops the dashboard process.
Read-only routes must not expose forms, POST controls, or buttons.

## Safe Console Output

The harness prints only safe metadata:

- `input_alias=local_only_input`
- `output_alias=out/local_real_export_smoke`
- `project_alias=<alias>`
- step status
- file count or candidate count when available
- `raw_data_included=false`

It does not print the full local path, raw export filename, raw HTTP body, token,
secret, or stack trace.

## Never Include

Do not copy these values into docs, prompts, issues, PR descriptions, or release
notes:

- raw request or response content
- cookie, authorization, token, JWT, or session values
- real target URL, domain, or IP
- personal data or customer identifiers
- HMAC secret or CSRF token
- full local path
- failed output content

## Output Handling

Generated files remain under ignored `out/`. A successful run does not make the
output automatically suitable for AI input. Operators must still check the safe
file allowlist and candidate/draft wording before using:

- `analysis_packet.json`
- `chatgpt_prompt.md`
- `codex_task_prompt.md`
- `report_draft.md`

Findings remain candidates. Risk ratings remain drafts. Severity decisions and
CVSS decisions require manual review outside this harness.

## Failure Handling

If a step fails, the harness reports only a safe error type. Do not paste failed
output or dashboard HTML into AI tools. Keep the export and failed output local,
then reproduce the issue with a synthetic fixture if a code or policy change is
needed.
