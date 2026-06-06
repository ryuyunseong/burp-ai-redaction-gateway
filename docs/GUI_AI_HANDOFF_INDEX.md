# GUI AI Handoff Index

This guide explains the dashboard AI handoff index. The index is a read-only
checklist for the four AI-safe candidate files that may be used after verify
passes and after manual review planning is clear.

For the candidate triage checklist, see
[GUI_FINDING_TRIAGE_INDEX.md](C:/coding/burp-ai-redaction-gateway/docs/GUI_FINDING_TRIAGE_INDEX.md).
For the draft report readiness checklist, see
[GUI_REPORT_READINESS_INDEX.md](C:/coding/burp-ai-redaction-gateway/docs/GUI_REPORT_READINESS_INDEX.md).

Use it as a read-only checklist only.

The index is not an approval screen. It does not say that a file is safe to
publish, that a finding is confirmed, or that severity is decided.

## Open the View

From a verified output detail page, open:

```text
/handoff?project=<alias>
```

The page is a read-only GET page. It does not submit data, create files, delete
files, download files, change settings, or run archive or HMAC actions.

## What It Shows

The index displays only aliases and safe metadata for the four AI-safe
candidate files:

| File | Recommended order | Purpose |
| --- | ---: | --- |
| `analysis_packet.json` | 1 | Read first for structured sanitized candidate evidence. |
| `chatgpt_prompt.md` | 2 | Use when asking ChatGPT for manual-review assistance. |
| `codex_task_prompt.md` | 3 | Use when asking Codex for implementation or review assistance. |
| `report_draft.md` | 4 | Read last as a candidate report draft for human review. |

For each file, the index may show:

- exists or missing
- file size in bytes
- modified UTC timestamp
- SHA-256 file fingerprint

The SHA-256 value is a normal file fingerprint. It is not HMAC, does not use a
secret, and does not replace audit HMAC verification.

## Required Reading Order

Use this order for AI-assisted review:

```text
verify first
-> check AI-safe preflight
-> read analysis_packet.json
-> choose chatgpt_prompt.md or codex_task_prompt.md for the target AI tool
-> check report readiness index before report review
-> review report_draft.md manually
-> decide what, if anything, can be shared
```

Manual review is required before treating any candidate finding as confirmed.

## Interpretation Boundary

- Findings are candidate finding records until manual verification is complete.
- Risk is draft risk and must not be treated as a severity decision.
- Final severity requires human decision after authorized reproduction, role
  comparison, and impact review.
- Treat `final severity requires human decision` as the operative boundary.
- CVSS is a separate calculation scope.

## Do Not Send

Do not paste, upload, commit, or document any of the following:

| Category | Reason |
| --- | --- |
| raw request or response data | May contain sensitive values. |
| Cookie or Authorization values | Authentication material. |
| token, JWT, or session values | Session or credential material. |
| real domain, URL, or IP values | Environment details. |
| personal data | Identity or privacy-sensitive data. |
| HMAC secret or CSRF token values | Local security controls. |
| local-only raw storage or unverified output artifacts | Not AI input material. |
| audit logs, archives, or manifests | Operational evidence, not AI prompt material. |

## Read-Only Boundary

The handoff index does not provide:

- form submission
- POST action
- state-changing button
- new download action
- safe file body preview
- raw viewer
- replay or active scan
- archive or HMAC execution
- HMAC secret input
- CSRF token display
- file deletion or retention changes
- risk profile changes

Use it as a read-only handoff checklist only.
