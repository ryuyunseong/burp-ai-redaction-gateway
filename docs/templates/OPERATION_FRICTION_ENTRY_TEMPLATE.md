# Operation Friction Entry Template

Use this template for one raw-free v0.5 friction entry.

Do not paste raw request or response data, real target identifiers, credentials,
personal data, full local paths, actual `local_only/` filenames, raw output
contents, audit row bodies, or full stack traces.

## Entry Metadata

| Field | Value |
| --- | --- |
| Date | `<YYYY-MM-DD>` |
| Tool version or tag | `<tag-or-commit-alias>` |
| Environment summary | `<windows/local/python-version-alias>` |
| Symptom category | `<setup friction | Burp export compatibility | redaction/verify friction | dashboard UX friction | candidate triage quality | report draft wording quality | Windows launcher friction | documentation gap>` |
| Classification | `<v0.4 hotfix | v0.5 feature | documentation task | no action>` |

## Summary

`<One or two sentences describing the friction with safe aliases only.>`

## Reproduction Summary

Use safe aliases and short steps.

```text
1. <safe command or route alias>
2. <safe action summary>
3. <observed status label or count>
```

## Expected Result

`<Expected safe outcome, status label, route behavior, or operator guidance.>`

## Actual Result Summary

`<Actual safe outcome, status label, route behavior, or operator confusion.>`

## Raw-Free Evidence Summary

Allowed examples include:

- route alias
- command alias
- status label
- file alias
- safe count
- scanner category
- blocked reason alias
- synthetic reproduction pointer

```text
<raw-free evidence only>
```

## Impact

| Area | Value |
| --- | --- |
| Local workflow impact | `<low | medium | high>` |
| AI handoff impact | `<none | blocks safe file review | requires manual recheck>` |
| Report draft impact | `<none | wording issue | candidate quality issue>` |
| Security boundary impact | `<none | needs review>` |

## Follow-Up Candidate

`<Recommended next action, issue candidate, docs task, hotfix, or v0.5 feature slice.>`

## Boundary Checklist

- [ ] No raw request or response content.
- [ ] No real URL, domain, IP, host, tenant, account, or customer identifier.
- [ ] No Cookie, Authorization, token, JWT, or session value.
- [ ] No personal data.
- [ ] No HMAC secret or CSRF token.
- [ ] No full local path.
- [ ] No actual `local_only/` filename.
- [ ] No raw output directory contents.
- [ ] No audit row body.
- [ ] No full stack trace.
- [ ] Finding language stays candidate.
- [ ] Risk language stays draft.
- [ ] Final severity and CVSS remain manual decisions.
