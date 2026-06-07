# Operation Friction Log for v0.5

This document defines the raw-free process for recording friction found while
using `v0.4.34` before selecting v0.5 work.

The goal is to capture setup issues, workflow confusion, parser or verification
friction, dashboard friction, candidate triage quality, and report draft quality
without copying sensitive data into Git, issues, PRs, prompts, or release text.

## Purpose

Use this log before starting v0.5 feature implementation. The log should help
answer:

- Which problems block internal local use?
- Which problems are documentation or setup friction?
- Which problems are v0.4 hotfix candidates?
- Which problems should become v0.5 feature work?
- Which candidate findings look duplicated, low-value, or out of scope?

This process does not confirm vulnerabilities, finalize risk, decide severity,
or produce CVSS scores.

## What to Record

Each entry should use
[`templates/OPERATION_FRICTION_ENTRY_TEMPLATE.md`](templates/OPERATION_FRICTION_ENTRY_TEMPLATE.md).

Allowed fields:

- date
- tool version or tag
- environment summary
- symptom category
- reproduction summary
- expected result
- actual result summary
- raw-free evidence summary
- impact
- follow-up candidate
- classification as v0.4 hotfix, v0.5 feature, documentation task, or no action

Use aliases, route names, status labels, counts, and safe command names. Keep
the description short enough that another operator can understand the problem
without seeing raw traffic.

## Symptom Categories

Use one primary category per entry:

| Category | Use When |
| --- | --- |
| `setup friction` | Python, GitHub CLI, Gitleaks, PowerShell, path setup, or first-run instructions are unclear. |
| `Burp export compatibility` | An authorized local export shape fails parsing, generation, or expected event handling. |
| `redaction/verify friction` | Redaction, scanner, or verify behavior blocks safe output creation or gives unclear next steps. |
| `dashboard UX friction` | Simple Dashboard, safe files, triage, report readiness, or other local GUI routes are confusing. |
| `candidate triage quality` | Candidate findings appear duplicated, low-value, out of scope, or hard to prioritize. |
| `report draft wording quality` | Report draft wording is unclear, too strong, too weak, or missing manual validation guidance. |
| `Windows launcher friction` | Start or stop scripts, port conflicts, process cleanup, or execution policy steps are confusing. |
| `documentation gap` | Existing docs do not answer a safe operational question. |

## Raw-Free Evidence Examples

Allowed evidence examples:

- route alias, such as `/simple?project=<alias>`
- command alias, such as `verify --input <output-alias>`
- status label, such as `verification_failed`
- file alias, such as `report_draft.md`
- safe count, such as candidate count or safe file count
- scanner category name
- blocked reason alias
- short operator note using synthetic or generic terms

Do not add screenshots or terminal logs unless they have been checked for the
forbidden values below.

## Forbidden Values

Do not record:

- raw request or response content
- real URL, domain, IP, host, tenant, account, or customer identifiers
- Cookie values
- Authorization values
- token, JWT, or session values
- personal data
- HMAC secrets
- CSRF tokens
- full local paths
- actual `local_only/` filenames
- raw output directory contents
- audit row bodies
- full stack traces

When a failure depends on a sensitive value, create a synthetic reproduction or
describe the failure with aliases and safe metadata only.

## Decision Rules

Use this triage model:

| Classification | Criteria |
| --- | --- |
| `v0.4 hotfix` | The issue breaks the published local-use baseline, weakens redaction/verify, or blocks the safe four-file workflow. |
| `v0.5 feature` | The issue improves future workflow quality but does not block the published baseline. |
| `documentation task` | The behavior works, but operator instructions are incomplete or confusing. |
| `no action` | The behavior is expected, safe, and already documented well enough. |

High-risk changes stay separate even if they appear in a friction entry:

- raw handling
- HMAC secret handling
- CSRF or state-changing dashboard actions
- retention or deletion behavior
- replay or active scan behavior

## Required Boundaries

Every entry must keep these statements true:

- finding equals candidate
- risk equals draft
- final severity and CVSS are manual decisions
- actual export smoke success is readiness evidence only
- friction log evidence is raw-free metadata only
- AI input candidates remain limited to:
  - `analysis_packet.json`
  - `chatgpt_prompt.md`
  - `codex_task_prompt.md`
  - `report_draft.md`

## Recommended Workflow

1. Use `v0.4.34` in a local internal workflow.
2. If friction appears, stop before copying raw output.
3. Summarize the problem with aliases and safe metadata.
4. Fill one entry from the template.
5. Classify the entry as hotfix, v0.5 feature, documentation task, or no action.
6. Only then create an issue or PR, keeping the same raw-free boundary.

## Storage Guidance

Keep friction entries in local notes or a future docs PR only after sanitization.
If an entry requires sensitive details to reproduce, keep those details outside
the repository and replace them with synthetic evidence before sharing.
