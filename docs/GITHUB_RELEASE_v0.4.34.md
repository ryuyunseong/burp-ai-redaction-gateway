# GitHub Release Draft: v0.4.34

This document is a review draft for the GitHub Release entry for `v0.4.34`.
It is not a release publication action. Publish the GitHub Release only after a
separate operator review.

## Release Title

```text
v0.4.34 - Local Burp AI Redaction Gateway
```

## Release Body Draft

```markdown
## Summary

`v0.4.34` is the v0.4 final baseline for the local Burp HTTP history
redaction gateway.

The tool converts local Burp HTTP history exports into sanitized, verified
analysis artifacts for human review and AI-assisted drafting. It keeps raw
traffic local, applies fail-closed verification, and limits AI input candidates
to the four allowed sanitized files.

This release is suitable as an internal local-use baseline. It does not make
finding candidates final, does not finalize risk, and does not create a CVSS
decision.

## Highlights

- Burp HTTP history export processing for local operator workflows.
- Redaction and fail-closed verification before AI-facing artifacts are used.
- Finding candidate generation from sanitized events.
- Conservative report draft generation with candidate wording.
- Four AI input candidate files:
  - `analysis_packet.json`
  - `chatgpt_prompt.md`
  - `codex_task_prompt.md`
  - `report_draft.md`
- Simple Dashboard for first-pass local review.
- Read-only advanced GUI indexes for operator guidance, preflight review,
  handoff readiness, finding triage, report readiness, workflow status, prompt
  readiness, evidence boundaries, operator runbook, and safe file inventory.
- Local-only real export smoke harness for authorized local validation.

## Verification Evidence

The v0.4.34 baseline was checked with:

- `python -m compileall burp_ai_redaction_gateway tests`: passed.
- `python -m unittest discover -s tests`: 87 tests OK.
- `python -m burp_ai_redaction_gateway verify --input out`: passed.
- `python -m burp_ai_redaction_gateway review --input out\demo`: passed.
- `python -m burp_ai_redaction_gateway report --input out\demo --output out\demo\report_draft.md --profile conservative`: passed.
- Gitleaks directory scan: no leaks found.
- Gitleaks Git scan: no leaks found.
- `scripts\git_safety_check.bat`: passed.
- First authorized local real export smoke: passed, recorded only as raw-free
  metadata.
- Second authorized local real export smoke: passed, recorded only as raw-free
  metadata.

The smoke evidence is readiness evidence only. It is not a statement that any
candidate finding is final, and it does not clear any output for external
distribution.

## Important Boundaries

- Findings are candidates until manually reviewed.
- Risk ratings are drafts until manually reviewed.
- Final severity and CVSS require separate manual decisions.
- Actual export smoke success does not replace safe file review.
- AI input candidates are limited to:
  - `analysis_packet.json`
  - `chatgpt_prompt.md`
  - `codex_task_prompt.md`
  - `report_draft.md`
- Do not send raw Burp exports, raw request or response data, unverified output,
  audit logs, HMAC manifests, local-only files, cookies, authorization values,
  tokens, real target identifiers, customer identifiers, or personal data to AI
  tools.

## Getting Started

Checkout the release tag:

```powershell
git checkout v0.4.34
```

Run the sample flow:

```powershell
python -m burp_ai_redaction_gateway generate --input samples\synthetic_burp_history.json --output out\demo --project client_alias_demo --risk-profile conservative
python -m burp_ai_redaction_gateway verify --input out\demo
python -m burp_ai_redaction_gateway review --input out\demo
python -m burp_ai_redaction_gateway report --input out\demo --output out\demo\report_draft.md --profile conservative
```

Start the local dashboard on the loopback host:

```powershell
python -m burp_ai_redaction_gateway dashboard --host <loopback-host> --port <local-port> --root out
```

Open the Simple Dashboard route for the `demo` project alias from the local
dashboard navigation.

Use `local_only/` for authorized real exports and keep generated output under
ignored local output directories. Do not commit local export files or generated
raw-adjacent artifacts.

## Known Limits

- The dashboard is local-only and not a production web application.
- The Simple Dashboard is a first-pass review surface, not a replacement for
  manual validation.
- Candidate triage quality still depends on operator review.
- Additional real export shapes may be useful before broader external release
  confidence is claimed.
- Montoya collector operation should be validated separately for live Burp
  workflows.

## Follow-Up Work

- Use the release in one or two internal local workflows and record friction.
- Triage a sample of finding candidates to tune false positives.
- Add troubleshooting notes if another operator hits setup or execution issues.
- Consider a separate external-distribution checklist if publishing beyond
  internal local use.
```

## Publication Checklist

Before publishing the GitHub Release:

- Confirm the target tag is `v0.4.34`.
- Confirm the release body does not include actual export filenames, full local
  paths, raw traffic, URL/domain/IP values, cookies, authorization values,
  token/JWT/session values, personal data, HMAC secrets, CSRF tokens, or raw
  output directory details.
- Confirm the release body keeps candidate findings, draft risk, and manual
  final severity/CVSS decisions separate.
- Confirm the release body describes the four AI input candidate files without
  expanding the allowed set.
