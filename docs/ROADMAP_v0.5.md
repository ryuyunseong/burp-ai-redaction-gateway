# v0.5 Roadmap

`v0.4.34` is the local-use final baseline. The v0.5 line should focus on
operational reliability, candidate quality, and first-time user experience
rather than expanding risky actions.

This roadmap is a planning document. It does not change runtime behavior,
redaction rules, dashboard actions, HMAC handling, CSRF handling, retention
policy, or release status.

## Non-Negotiable Boundaries

- Raw request or response values must not be displayed, logged, committed, or
  copied into docs, issues, PRs, prompts, or release text.
- Real target identifiers, cookies, authorization values, token/JWT/session
  values, personal data, HMAC secrets, and CSRF tokens must not be used as
  examples.
- Findings remain candidates until manually reviewed.
- Risk ratings remain drafts until manually reviewed.
- Final severity and CVSS require separate manual decisions.
- Real export smoke success is readiness evidence only. It does not clear any
  output for AI handoff or external distribution.
- `local_only/`, `raw/`, `raw_vault/`, generated `out/`, and `out/.audit/`
  originals remain local artifacts and must not be treated as AI input.

## Priority 1: Operational Use and Friction Log

Goal: run `v0.4.34` in one or two real internal local workflows and record
operator friction without changing the data boundary.

Candidate tasks:

- Record where a first-time operator hesitates in the CLI or dashboard flow.
- Check whether the preferred first-screen path is clear:
  - `/upload`
  - `/simple?project=<alias>`
  - `/safe-files?project=<alias>`
  - `/triage?project=<alias>`
  - `/report-readiness?project=<alias>`
- Separate documentation friction from parser/redaction bugs.
- Convert reproducible bugs into scoped `fix/v0.4.x-*` work if they affect the
  final baseline.

Acceptance evidence:

- Friction notes contain only route aliases, command aliases, status labels, and
  raw-free metadata.
- No real export names, full paths, raw traffic, target identifiers, credentials,
  or personal data are copied into issue or PR text.

## Priority 2: Montoya Collector Live-Operation Validation

Goal: validate the Burp-side collector in a live local workflow so the path from
exploration to local receiver to redaction is easier to trust.

Candidate tasks:

- Confirm in-scope filtering behavior with synthetic or authorized local-only
  inputs.
- Validate loopback receiver behavior and error messages.
- Check that collector logs remain raw-free.
- Document startup, stop, retry, and troubleshooting steps.
- Keep collector validation separate from new dashboard actions.

Out of scope for the first v0.5 slice:

- Active scan or replay actions.
- Remote collection endpoints.
- Credential, cookie, token, or raw traffic logging.

Acceptance evidence:

- Collector validation can be reproduced without committing real traffic.
- Failure output uses safe aliases and status metadata only.

## Priority 3: Receiver to Redaction Flow Hardening

Goal: reduce friction in the local path from received events to verified
sanitized output.

Candidate tasks:

- Improve status messages for receiver input, generated output, and verify gate
  failures.
- Add clearer operator prompts for the next safe command.
- Keep fail-closed behavior when redaction or verification is uncertain.
- Preserve the four-file AI input candidate set.

Acceptance evidence:

- New messages do not expose raw values, full paths, stack traces, target
  identifiers, or secrets.
- Existing CLI and dashboard verification still pass.

## Priority 4: Candidate Triage Quality

Goal: reduce false positives, duplicates, and out-of-scope findings while
keeping candidate wording conservative.

Candidate tasks:

- Review a sample of generated candidates for duplicate patterns.
- Tune passive finding grouping where evidence is clearly repeated.
- Improve triage labels for likely false positive, duplicate, out-of-scope, and
  manual verification required.
- Preserve `do_not_claim` guidance and candidate language.

Acceptance evidence:

- Candidate count changes are explained as triage quality changes, not as
  validated vulnerability counts.
- Automation must not promote any issue to final severity or CVSS.

## Priority 5: Report Draft Quality

Goal: make `report_draft.md` more useful for a human reviewer while preserving
draft language.

Candidate tasks:

- Improve remediation draft wording.
- Clarify manual verification steps.
- Improve grouping and ordering of repeated candidate types.
- Add stronger reminders that final severity and CVSS are manual decisions.

Acceptance evidence:

- Report output remains a draft.
- Finding language stays candidate or suspected.
- The report does not imply external submission readiness.

## Priority 6: Windows Launcher and Setup UX

Goal: reduce first-run friction for Windows users.

Candidate tasks:

- Improve launcher troubleshooting for port conflicts and process cleanup.
- Clarify PowerShell execution policy handling.
- Add a short setup checklist for Python, GitHub CLI, Gitleaks, and optional
  Burp collector steps.
- Keep launcher output raw-free.

Acceptance evidence:

- A new operator can start and stop the local receiver and dashboard without
  touching raw export contents.
- Logs show ports, process ids, aliases, and status only.

## Priority 7: External User Documentation

Goal: make the repository understandable to another careful user without
weakening the local-only boundary.

Candidate tasks:

- Add a short troubleshooting index for install, verification, dashboard,
  Gitleaks, and release use.
- Clarify internal local-use baseline versus broader distribution confidence.
- Add a GitHub Release follow-up checklist for future patch releases.

Acceptance evidence:

- Documentation remains raw-free.
- External-facing text does not claim AI handoff clearance, validated findings,
  final severity, or CVSS decisions.

## Branching Guidance

- v0.4 bug fixes: use `fix/v0.4.x-*` and consider a patch tag such as
  `v0.4.35` only after verification.
- v0.5 feature work: use `feat/v0.5-*` for runtime features and
  `docs/v0.5-*` for planning or documentation.
- High-risk changes stay small:
  - raw handling
  - HMAC secret handling
  - CSRF or state-changing dashboard actions
  - retention or deletion behavior
  - replay or active scan behavior

## Suggested First v0.5 Slices

1. `feat/gui-upload-wizard-v0.5`
2. `docs/v0.5-troubleshooting-index`
3. `feat/v0.5-montoya-live-validation`
4. `feat/v0.5-candidate-triage-quality`
5. `feat/v0.5-report-draft-quality`
6. `feat/v0.5-windows-launcher-ux`
