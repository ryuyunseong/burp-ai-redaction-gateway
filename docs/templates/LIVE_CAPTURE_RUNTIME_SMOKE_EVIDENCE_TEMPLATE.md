# Live Capture Runtime Smoke Evidence Template

Use this template for raw-free Montoya runtime smoke notes. Keep the completed
copy local-only unless it is reviewed and scrubbed for PR or issue use.

## Summary

| Field | Value |
| --- | --- |
| date | `<YYYY-MM-DD>` |
| tool version or branch | `<safe_version_or_branch_alias>` |
| operator environment | `<safe_os_and_tooling_summary>` |
| smoke result | `<passed_or_failed>` |
| failure category | `<raw_free_failure_category_or_n/a>` |

## Runtime Checks

| Check | Result |
| --- | --- |
| extension load | `<passed_or_failed>` |
| local receiver | `<passed_or_failed>` |
| in-scope handoff count | `<number>` |
| out-of-scope skip count | `<number>` |
| missing_host_skipped | `<number_or_n/a>` |
| invalid_host_skipped | `<number_or_n/a>` |
| receiver verify | `<passed_or_failed_safely>` |
| receiver review/report smoke | `<passed_or_failed_safely>` |

## Boundary Checks

| Boundary | Result |
| --- | --- |
| raw markers in extension output | `0` |
| actual target identifiers recorded | `no` |
| raw request/response recorded | `no` |
| Cookie values recorded | `no` |
| Authorization values recorded | `no` |
| token/JWT/session values recorded | `no` |
| personal data recorded | `no` |
| full local paths recorded | `no` |
| HMAC secret recorded | `no` |
| CSRF token value recorded | `no` |

## Notes

- Finding output remains candidate-only.
- Risk output remains draft-only.
- Final severity and CVSS remain manual decisions.
- Passing this smoke is readiness evidence only, not external sharing clearance.

## Follow-Up

| Item | Value |
| --- | --- |
| v0.4 hotfix needed | `<yes_or_no>` |
| v0.5 feature follow-up needed | `<yes_or_no>` |
| follow-up label | `<safe_label_or_n/a>` |
| raw-free evidence summary | `<safe_metadata_only>` |
