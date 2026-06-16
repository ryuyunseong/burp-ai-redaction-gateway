# v0.5 Korean-First Web UX Plan

This is a planning document only. It does not change dashboard runtime
behavior, add routes, add POST actions, change collector forwarding, change
receiver ingest, add local evidence reading, change HMAC handling, change CSRF
handling, change retention policy, create a tag, or create a GitHub Release.

## Goal

The v0.5 web UX goal is to make the local dashboard easier for a first-time
Korean-speaking operator to use without weakening the security boundary.

The preferred operator story is:

```text
start local gateway
-> choose Upload Wizard or Live Capture status
-> run redaction and verify
-> inspect safe files
-> inspect candidate findings
-> inspect report readiness
-> manually decide what can be used with AI
```

The dashboard should remain a local tool. User-facing text should explain the
safe next step in Korean first, while technical identifiers such as route names,
CLI command names, schema keys, HMAC, CSRF, and CVSS can remain in English.

## Copy Principles

- Korean-first user-facing wording.
- Short labels for first-time operators.
- Route and file names stay exact.
- Avoid guarantee language.
- Separate AI input candidates from approved final content.
- Keep findings as candidates.
- Keep risk as draft.
- State that final severity and CVSS are manual decisions.
- Prefer "next step" language over implementation details.
- Do not show raw values, local paths, or secrets.

## Route-Level UX Plan

| Route | Korean-first purpose | Notes |
| --- | --- | --- |
| `/` | "처음 시작하기" entry point | Link to Upload Wizard, Live Capture status, safe files, and help |
| `/upload` | "파일 업로드" guided flow | Step 1 file selection, step 2 project alias, step 3 redaction and verify, step 4 result review |
| `/live-capture` | "Live Capture 상태 확인" page | Make clear that this is a status screen, not a capture execution screen |
| `/safe-files` | "AI에 넣을 수 있는 후보 파일 확인" | Emphasize only four safe file candidates |
| `/help` | "무엇을 하면 되나요?" checklist | Keep read-only guidance, no execution controls |
| `/troubleshooting` | "문제가 생겼을 때" categories | Group by setup, receiver, collector, scope, verify, and dashboard |

## Safe Files Explanation Cards

The safe file inventory should explain the four AI input candidate files:

- `analysis_packet.json`: sanitized analysis metadata for manual review.
- `chatgpt_prompt.md`: prompt candidate for ChatGPT review.
- `codex_task_prompt.md`: prompt candidate for Codex follow-up.
- `report_draft.md`: report draft for human editing.

The UI should avoid saying these files are approved for sharing. The safer
wording is "AI input candidate files" and "manual review required".

## Live Capture Wording

The Live Capture page should avoid implying that the dashboard starts traffic
capture unless a future implementation PR explicitly adds that behavior.

Recommended wording:

- "Live Capture 상태 확인"
- "Burp에서 탐색한 뒤 receiver output을 검증하세요."
- "이 화면은 상태 확인용입니다."
- "자동 ChatGPT 전송은 하지 않습니다."
- "raw traffic은 표시하지 않습니다."

Avoid wording that implies:

- dashboard-driven capture execution
- raw preview
- automatic AI handoff
- final finding confirmation
- final severity or CVSS confirmation

## First-Run Wizard Candidates

These are UX candidates, not implemented behavior:

| Candidate | v0.5 classification | Reason |
| --- | --- | --- |
| First-run wizard | v0.5 candidate | Reduces setup friction without requiring raw access |
| Korean quickstart landing | v0.5 candidate | Helps first-time operators choose the right route |
| Safe files explanation cards | v0.5 candidate | Clarifies the four-file AI handoff boundary |
| Output alias selector | v0.5 candidate | Reduces manual project alias typing |
| Troubleshooting panel | v0.5 candidate | Converts existing docs into safer route guidance |
| Release readiness status page | v0.6 candidate | Useful, but release state can be confused with approval |
| Copy prompt button | v0.6 candidate | Only safe after verify-passed and explicit user action |
| MCP read-only server design | v0.5 candidate | Design can proceed before implementation |
| MCP read-only prototype | v0.6 candidate | Needs tool allowlist and blocked-output tests |
| Local evidence reader | deferred | Path traversal and forbidden-field risks are high |
| Dashboard orchestration | deferred | Needs CSRF, action audit, and state-change review |
| Replay or active scan | deferred | Target-affecting behavior needs a separate security review |
| ChatGPT auto-send | deferred | Automatic external handoff is too risky for v0.5 |

## Classification Rules

Classify a candidate as v0.5 only when:

- It is raw-free.
- It does not change state, or the state change is already covered by an
  existing reviewed route.
- It does not require a new secret handling path.
- It does not require local evidence file reading.
- It does not make target-affecting requests.
- It improves first-time operator clarity before release.

Move a candidate to v0.6 or deferred when:

- It requires CSRF and action audit design.
- It can expose sensitive data if implemented incorrectly.
- It reads local-only files.
- It can delete, mutate, replay, or transmit data.
- It can be mistaken for sharing approval or vulnerability confirmation.

## UI Text Hygiene

User-facing text must not include:

- request or response bodies
- target identifiers
- URL, domain, or IP values
- credential or session values
- personal data
- HMAC secret values
- CSRF token values
- full local paths
- local-only filenames
- generated output directory internals
- raw audit rows
- archive contents
- guarantee language
- vulnerability confirmation wording
- automatic final severity wording

## Acceptance Criteria For A Later UX PR

- New user-facing copy is Korean-first.
- Route names and file names remain exact.
- Read-only pages do not show forms or execution buttons.
- State-changing pages remain CSRF protected.
- Safe files are limited to the four AI input candidate files.
- Findings remain candidates.
- Risk remains draft.
- Final severity and CVSS remain manual decisions.
- Forbidden marker tests cover new copy.
