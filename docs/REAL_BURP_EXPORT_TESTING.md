# Real Burp Export Testing

Use this process only for local validation with explicit authorization. Real
customer data must not be copied into issues, commits, prompts, documentation,
or test fixtures.

## Store Real Exports Locally

Create a local-only folder and put the real Burp export there:

```bat
mkdir local_only
copy C:\path\to\real_export.xml local_only\real_burp_history_sample.xml
```

`local_only/` is ignored by Git. Do not move real exports into `samples/`.

## Generate Sanitized Output

Run generation with a non-identifying project alias:

```bat
python -m burp_ai_redaction_gateway generate ^
  --input local_only\real_burp_history_sample.xml ^
  --output out\real_sample_check ^
  --project real_sample_alias
```

Do not use the real customer name as the project alias.

## Verify Output

Run the fail-closed verifier before opening or sharing any generated output:

```bat
python -m burp_ai_redaction_gateway verify --input out\real_sample_check
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
rmdir /s /q out\real_sample_check
```

If you need to keep raw evidence, store it outside the repository in an
approved encrypted location with restricted OS file permissions.

