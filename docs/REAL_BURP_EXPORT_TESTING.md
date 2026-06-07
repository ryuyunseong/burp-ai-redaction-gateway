# Real Burp Export Testing

Use this process only for local validation with explicit authorization. Real
customer data must not be copied into issues, commits, prompts, documentation,
or test fixtures.

## Safe Real-Like Smoke Test

If no real Burp export is available yet, generate a synthetic real-like sample:

```bat
python scripts\make_safe_burp_export_sample.py
scripts\run_safe_sample_smoke_test.bat
```

The generated file is `local_only\real_burp_history_sample.xml`. It contains
only synthetic values with `FAKE_`, `DUMMY_`, or `EXAMPLE_` style data. This
smoke test checks XML parsing, Base64 request/response handling, redaction,
verification, and Git ignore behavior.

This is not a real Burp export compatibility test. Real compatibility testing
still requires a file saved directly from Burp and kept only under `local_only/`.
Do not commit, upload, paste, or document real raw exports.

## Store Real Exports Locally

Create a local-only folder and put the real Burp export there:

```bat
mkdir local_only
copy <authorized_burp_export_file> local_only\authorized_burp_export.xml
```

`local_only/` is ignored by Git. Do not move real exports into `samples/`.
For a v0.4 release-candidate validation flow and raw-free result template, see
`REAL_BURP_EXPORT_VALIDATION.md`.

## Generate Sanitized Output

Run generation with a non-identifying project alias:

```bat
python -m burp_ai_redaction_gateway generate ^
  --input local_only\authorized_burp_export.xml ^
  --output out\real_export_validation ^
  --project real_export_alias
```

Do not use the real customer name as the project alias.

## Verify Output

Run the fail-closed verifier before opening or sharing any generated output:

```bat
python -m burp_ai_redaction_gateway verify --input out\real_export_validation
```

Only files that pass verification may be used as ChatGPT or Codex prompt input.

## Failure Response

If `verify` fails:

1. Do not paste the failed output into AI tools.
2. Keep the raw export and failed output local.
3. Inspect only the finding kind and file path shown by the verifier.
4. Improve the redaction rule or policy.
5. Delete the failed generated output.
6. Regenerate and rerun `verify`.

Never include the raw leaked value in an issue, commit message, prompt, test
name, or documentation note.

## Cleanup

After validation, remove local-only raw exports and temporary outputs:

```bat
rmdir /s /q local_only
rmdir /s /q out\real_export_validation
```

If you need to keep raw evidence, store it outside the repository in an
approved encrypted location with restricted OS file permissions.
