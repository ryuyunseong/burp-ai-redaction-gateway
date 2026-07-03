# v* Tag Ruleset Implementation Plan

## Purpose

This document defines a proposed `v*` release tag ruleset plan for
`burp-ai-redaction-gateway`. The goal is to reduce future release tag mutation
risk while keeping the completed v0.10 release line unchanged.

This is a planning document only. It does not create, edit, enable, disable, or
delete repository rulesets. It does not change tags, GitHub Releases, source
code, runtime behavior, tests, README, or issues.

## Current State

- v0.10 release line: complete
- v0.10 tag target checked with `git rev-parse "v0.10^{}"`:
  `f078134dfecda1c9d153e46ef1d25d46ff811fa0`
- GitHub Release v0.10: published
- Current main baseline when this plan was written:
  `03637007920a89e5c368ac6b196784145647b476`
- PR #163: merged
- Protection review document:
  `docs/V0.10_TAG_RELEASE_PROTECTION_REVIEW.md`
- Visible repository rulesets from `gh ruleset list`: none returned
- GitHub Issue created by this plan: no
- Repository settings changed by this plan: no
- v0.10 tag or Release changed by this plan: no

## Proposed Tag Pattern

Primary candidate:

- `v*`

Rationale:

- release tags in this project use a `v` prefix;
- one rule can cover future release tags, not only v0.10;
- a broad release pattern reduces the chance that a future tag is created
  outside the intended release flow.

Before applying this pattern, confirm that there are no non-release tags using
the same prefix that need different lifecycle rules.

## Intended Protection Goals

A future `v*` tag ruleset should aim to restrict:

- creation of matching release tags;
- updates or force-movement of matching release tags;
- deletion of matching release tags;
- rename-like workflows that effectively replace a release tag;
- bypass permissions for users, teams, or GitHub Apps.

The practical objective is to make release tag mutation an explicit, reviewed
administrative action instead of an ordinary push workflow.

## Out Of Scope

This plan does not approve or perform:

- repository settings or ruleset changes;
- v0.10 tag mutation, deletion, or recreation;
- GitHub Release v0.10 mutation;
- GitHub Issue creation;
- source, runtime, test, README, dashboard, MCP, parser, dispatcher, listener,
  transport, tool execution, local evidence reader, or release archive changes;
- authentication, authorization, CSRF, HMAC, token, or session handling changes;
- raw Burp request or response storage, preview, replay, forwarding, or export.

## Expected Effects If Applied Later

If a separate approved settings task applies the ruleset, expected effects are:

- release tag creation is limited to approved bypass actors;
- release tag updates are blocked unless an approved bypass actor performs the
  action;
- release tag deletion is blocked unless an approved bypass actor performs the
  action;
- future release audit checks can verify that a visible ruleset exists instead
  of relying only on manual process.

These effects depend on the exact ruleset configuration and bypass policy.
They are not active from this planning document.

## Operational Impact

Before enabling a `v*` ruleset, review:

- who currently creates release tags;
- whether release automation creates tags directly or through GitHub Releases;
- whether release workflows require tag deletion or recreation during rollback;
- whether a broad `v*` pattern would affect historical or non-release tags;
- how emergency fixes are handled when release tags need administrative action;
- how auditors and maintainers will verify ruleset status.

## Recommended Bypass Policy

Recommended default:

- use the smallest possible bypass set;
- avoid broad team or all-admin bypass unless explicitly accepted;
- document each bypass actor and why it is needed;
- prefer a release operator or dedicated GitHub App if the release workflow
  requires automation;
- keep emergency bypass use manual and logged.

Do not apply bypass configuration without a separate approval and a live
GitHub settings review.

## Pre-Application Verification

Run these checks before any future settings task changes rulesets:

```powershell
git switch main
git pull --ff-only
git status --short --branch --untracked-files=all
git rev-parse "v0.10^{}"
gh release view v0.10 --json tagName,name,isDraft,isPrerelease,publishedAt,url,targetCommitish
gh ruleset list --repo ryuyunseong/burp-ai-redaction-gateway
git tag --list "v*"
```

Expected pre-application state for the current baseline:

- v0.10 tag target remains
  `f078134dfecda1c9d153e46ef1d25d46ff811fa0`;
- GitHub Release v0.10 remains published;
- visible ruleset state is explicitly recorded before any change;
- working tree is clean.

## Proposed Settings Task Outline

When explicitly approved, the settings task should:

1. Reconfirm the pre-application state.
2. Create or prepare a repository tag ruleset targeting `v*`.
3. Include rules that restrict creation, update, and deletion of matching tags.
4. Configure bypass actors minimally.
5. Record the exact ruleset name, enforcement state, and bypass policy.
6. Reconfirm v0.10 tag target after the settings task.
7. Reconfirm GitHub Release v0.10 remains published and unchanged.
8. Record whether the ruleset is active or disabled.

This document intentionally does not encode a live ruleset payload because the
exact GitHub UI/API shape should be confirmed at the time of the approved
settings task.

## Post-Application Verification

If a future approved task applies the ruleset, run:

```powershell
gh ruleset list --repo ryuyunseong/burp-ai-redaction-gateway
git rev-parse "v0.10^{}"
gh release view v0.10 --json tagName,name,isDraft,isPrerelease,publishedAt,url,targetCommitish
git status --short --branch --untracked-files=all
```

Recommended evidence to record:

- ruleset name;
- target pattern;
- enforcement state;
- bypass actor summary;
- v0.10 tag target before and after;
- GitHub Release v0.10 published state before and after;
- confirmation that no source/runtime files changed.

## Rollback And Emergency Exception

Rollback for a settings-only ruleset task should mean disabling or editing the
ruleset, not mutating release tags. A rollback record should include:

- why the ruleset blocked a required workflow;
- whether a narrower `v*` pattern or bypass policy is needed;
- who approved the temporary exception;
- before and after `gh ruleset list` output;
- v0.10 tag target confirmation after the exception.

Emergency tag mutation should remain out of normal workflow. If it is ever
needed, require a separate approval that names the exact tag, target commit, and
rollback plan.

## Immutable Releases Follow-Up

Immutable releases should be reviewed as a future release policy. This plan
does not claim that immutable releases are already active or that they
retroactively protect the existing v0.10 release.

Recommended future review questions:

- whether the repository plan supports immutable releases;
- whether future releases can attach all intended assets before publication;
- whether immutable releases conflict with any post-publication asset workflow;
- whether tag rulesets and immutable releases should be used together.

## Decision

Recommended next step: keep v0.10 unchanged and create a separate approved
settings task if the project decides to apply a `v*` tag ruleset.

Until then, release tag protection remains a manual verification process:

- check `git rev-parse "v0.10^{}"` for the release target;
- check `gh release view v0.10` for release state;
- check `gh ruleset list` for visible ruleset state;
- do not mutate v0.10 tag or GitHub Release without explicit approval.

## Project Record Update

- Final goal: preserve completed v0.10 release state and evaluate future
  release tag protection separately.
- Current progress: v0.10 release 100%, PR #163 100%, ruleset implementation
  plan draft created locally.
- Completed work: v0.10 publication, governance evidence, post-release hygiene,
  protection review, and this `v*` tag ruleset plan draft.
- Next work: decide whether to commit/PR this plan, then separately approve or
  defer an actual repository ruleset settings task.
- Main risk: no visible ruleset is active from this check, so future release
  tag protection remains process-based until settings are changed.
- Decision: v0.10 remains frozen; actual ruleset application is a separate
  approval.
- Pending decision: apply `v*` tag ruleset, evaluate immutable releases for
  future releases, or defer both into v0.11 scope planning.
