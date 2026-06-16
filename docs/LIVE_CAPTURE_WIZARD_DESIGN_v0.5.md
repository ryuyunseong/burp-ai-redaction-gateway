# Live Capture Wizard Design v0.5

This document defines the v0.5 design boundary for a local-only Live Capture
Wizard. The current runtime slice provides `GET /live-capture` plus
CSRF-protected `POST /live-capture/start` and `POST /live-capture/stop`
as session state placeholders. It does not add collector behavior, receiver
behavior, raw traffic capture, or any automatic ChatGPT handoff.

Current `/live-capture` state is a session placeholder. It validates target
domains through the shared scope guard, stores safe aliases only, and keeps
actual capture integration separate.

## Goal

The Live Capture Wizard should let an operator start from a local dashboard,
define a narrow Burp browsing scope, explore in Burp, and produce the same four
verified AI input candidate files that the existing CLI, receiver, and Upload
Wizard flows produce.

Target workflow:

```text
open local dashboard
-> open /live-capture
-> enter a local capture label and target scope
-> start a capture session
-> browse with Burp
-> collector sends only allowed in-scope traffic to the loopback receiver
-> gateway runs redaction, verify, review, and report draft
-> operator opens /simple and /safe-files
-> operator manually reviews the four safe files
```

The wizard must not send content to ChatGPT, paste content into ChatGPT, run
active scans, replay traffic, or make findings final.

## Relationship To Existing Flows

| Flow | Input | Collection style | Output |
| --- | --- | --- | --- |
| Upload Wizard | Local `.xml` or `.json` export selected by the operator | One uploaded file | Verified output plus safe file links |
| Receiver | Burp collector handoff payloads | Collector sends in-scope items to loopback | Sanitized receiver output |
| Live Capture Wizard | Local capture label and target scope | Guided session using collector plus receiver | Verified output plus dashboard links |

The Live Capture Wizard should reuse the existing receiver, redaction,
verification, review, report, safe-file inventory, and Simple Dashboard
contracts. It should not create a parallel pipeline.

## Proposed Routes

The current runtime slice exposes a session placeholder route and two
CSRF-protected state-changing placeholder routes:

```text
GET  /live-capture
POST /live-capture/start
POST /live-capture/stop
GET  /live-capture/status?session=<capture_alias>  # future scope
```

The implemented POST routes manage local dashboard session state only. They
write raw-free dashboard action audit events and do not capture traffic. The
start/stop placeholder is not collector or receiver integration.

## Screen Model

`GET /live-capture` currently shows session placeholder guidance:

- target domain validation and safe target alias display
- current session state: idle, running_placeholder, stopped, or failed_validation
- ChatGPT automatic send status as false
- safe files 4 candidate list
- collector/receiver integration as separate PR boundary
- links back to `/`, `/help`, `/upload`, and this design document
Collector-side filtering now provides safe host metadata and raw-free skip
counts for loopback handoff. Future wizard integration may add:

- capture label input
- target scope input
- scope allowlist summary
- receiver health status
- collector readiness status
- current capture status
- links to `/simple`, `/safe-files`, `/triage`, and `/report-readiness` after
  successful verification

The screen should show safe aliases and status labels. It should not echo actual
target identifiers after a capture starts.

## Target Scope Handling

The operator may enter a target scope locally, but the system should avoid
showing that value outside the local form context.

Design rules:

- Require an explicit allowlist before capture starts.
- Accept only narrow host or domain-style scope entries.
- Normalize scope entries to lowercase and tolerate a trailing dot by matching
  the normalized domain form.
- Reject empty, wildcard-only, URL/path-style, path traversal, and malformed
  scope entries.
- Reject URL forms, path or query suffixes, wildcard entries, loopback names,
  IP literals, malformed labels, and whitespace/control characters.
- Emit only raw-free reason codes such as `scope_url_or_path_not_allowed` or
  `scope_ip_literal_not_allowed` when validation fails.
- Store the raw scope only in ignored local-only session state if storage is
  required.
- Display only a safe capture alias, scope count, and match status in dashboard
  result pages and action audit.
- Do not write actual target identifiers into docs, PRs, issues, release text,
  logs, or AI prompts.

## Collector And Receiver Integration

The collector remains Burp-side. The receiver remains loopback-only.

Expected integration:

```text
Burp Proxy history item
-> collector checks Burp suite scope and wizard allowlist
-> collector sends allowed item to loopback receiver
-> receiver redacts and verifies generated output
-> dashboard reads verified output metadata
```

Collector requirements:

- Send only allowed in-scope items.
- Do not log request or response values.
- Do not log credential, session, token, cookie, or personal data values.
- Use loopback receiver endpoints only.
- Report safe status labels when the receiver is unavailable.
- Use the raw-free safe host metadata contract in
  [`LIVE_CAPTURE_COLLECTOR_CONTRACT_v0.5.md`](LIVE_CAPTURE_COLLECTOR_CONTRACT_v0.5.md)
  for collector-side handoff eligibility.

Receiver requirements:

- Continue rejecting non-loopback bind hosts.
- Continue enforcing payload size limits.
- Continue using the existing redaction and fail-closed verify gate.
- Do not expose raw request or response values in errors.
- A receiver scope dry-run helper may evaluate safe host metadata against the
  shared scope guard before full collector integration. This dry-run must not
  parse raw request or response bodies, persist traffic, call the redaction
  pipeline, or change `POST /ingest/burp-history` behavior.
- A receiver scope summary helper may convert the dry-run decision into
  raw-free accept/skip metadata for a future audit writer. This contract should
  include only aliases, reason codes, decision status, and explicit
  `raw_data_included=false` metadata. It must not write audit files, store raw
  rows, or change actual receiver ingest behavior until a separate integration
  PR wires it in.

## Domain Match Rule

Current shared guard exposes a conservative match rule that collector-side
filtering and future wizard integration should reuse:

- Normalize the operator-provided scope locally.
- Match exact host equality or a dot-bound subdomain suffix only.
- Treat lookalike suffixes such as `allowed.example.evil.test` as out of scope.
- Treat unknown or unparsable targets as out of scope.
- Do not collect out-of-scope traffic.
- Do not collect broad wildcard matches in the first slice.
- Prefer fail-closed behavior when the collector cannot decide.

The rule should produce safe metadata only:

- `capture_alias`
- `scope_entry_count`
- `matched=true|false`
- `match_rule_version`
- `raw_data_included=false`

It must not emit actual target identifiers.

## Passive Suspicious Packet Selection

The first implementation should remain passive. It should not scan, replay, or
modify traffic.

Allowed passive signals:

| Signal | Allowed metadata |
| --- | --- |
| Authentication or session header presence | Presence only, no values |
| Query, form, JSON, XML, or multipart parameter presence | Count or redacted key class only |
| Error response status | Status family only |
| Redirect or login/logout pattern | Pattern label only |
| File upload endpoint shape | Endpoint template only |
| API or GraphQL endpoint shape | Endpoint template only |
| Hidden input or form presence | Presence only |
| Cache or security header gaps | Header name class only |

The selection output is a candidate queue. It is not a confirmed vulnerability
list.

Required wording:

```text
finding = candidate
risk = draft
final severity = manual decision
CVSS = separate manual calculation
```

## Pipeline

Live capture should reuse this sequence:

```text
capture session validation
-> collector allowlist check
-> loopback receiver handoff
-> redaction
-> verify
-> review
-> report draft
-> Simple Dashboard
-> safe file inventory
```

If `verify` fails:

- stop the workflow safely
- skip review and report
- hide safe file links
- show a safe failure category only
- write raw-free action audit metadata

## Safe Files

The only AI input candidate files remain:

- `analysis_packet.json`
- `chatgpt_prompt.md`
- `codex_task_prompt.md`
- `report_draft.md`

The wizard should show these files only after verification passes. The operator
must manually review them before AI use.

## ChatGPT Boundary

The Live Capture Wizard must not:

- send content to ChatGPT
- paste content into ChatGPT
- open a ChatGPT handoff automatically
- call a ChatGPT API automatically
- treat a verified output as safe for external sharing

A future copy-to-clipboard button may be considered only for verified safe
prompt files. If added, it must be a separate reviewed feature with explicit UI
wording, raw-free audit, and no automatic paste behavior.

## Raw Storage Boundary

The implementation should not store raw traffic in repository source files.

If local temporary storage is needed:

- store only under ignored local-only locations
- use generated internal names
- do not display full local paths
- do not display actual local-only filenames
- do not expose raw preview or raw download actions
- do not add deletion or retention policy changes in the first slice

## Action Audit Design

Dashboard action audit should record safe metadata only:

- action name
- capture alias
- output alias
- result status
- blocked reason
- receiver health status
- collector readiness status
- scope entry count
- selected candidate count
- safe file count
- `raw_data_included=false`

Audit must not record:

- raw request or response values
- target identifiers
- credential, cookie, token, JWT, or session values
- personal data
- HMAC secret values
- CSRF values
- full local paths
- stack traces

## Failure Handling

Safe failure categories:

- `receiver_not_running`
- `collector_not_ready`
- `scope_missing`
- `scope_invalid`
- `scope_too_broad`
- `out_of_scope_traffic_skipped`
- `capture_start_blocked`
- `capture_stop_failed`
- `handoff_failed`
- `generate_failed`
- `verify_failed`
- `review_skipped`
- `report_skipped`

Failure output must be actionable without exposing raw values.

## Out Of Scope For First Implementation

- Active scan
- Replay
- Traffic modification
- Remote receiver endpoints
- Automatic ChatGPT send
- Automatic ChatGPT paste
- HMAC secret handling changes
- Retention or deletion policy changes
- Final severity assignment
- CVSS scoring
- Raw request or response viewer
- Raw preview or raw download

## Implementation PR Split

Recommended follow-up slices:

1. `feat/live-capture-session-state-v0.5`
   - add `/live-capture` session state UI and CSRF-protected placeholder actions
   - keep collector and receiver behavior unchanged
   - write raw-free action audit
2. `feat/live-capture-scope-guard-v0.5`
   - centralize target domain normalization, validation, safe aliasing, and
     exact/subdomain match checks
   - keep collector and receiver behavior unchanged
   - expose raw-free validation reason codes only
3. `feat/live-capture-receiver-scope-dry-run-v0.5`
   - evaluate safe receiver host metadata against the shared scope guard
   - return raw-free accept/drop summaries only
   - keep actual receiver ingest, collector behavior, and redaction pipeline
     execution unchanged
4. `feat/live-capture-receiver-skip-audit-v0.5`
   - convert receiver scope dry-run results into raw-free accept/skip summaries
     and audit event metadata
   - keep audit file writing, receiver ingest, and collector behavior unchanged
5. `feat/live-capture-collector-filter-contract-v0.5`
   - document and fixture the safe host metadata contract expected by the
     receiver dry-run helper
   - keep collector forwarding, receiver ingest, and raw traffic handling
     unchanged
6. `feat/live-capture-collector-filter-v0.5`
   - harden collector in-scope filtering, safe host metadata handoff, and
     raw-free skip status output
7. `test/live-capture-smoke-v0.5`
   - add synthetic local-only smoke coverage without real traffic
8. `docs/live-capture-operations-v0.5`
   - document operator steps after the implementation is verified

## Acceptance Criteria

- No runtime behavior changes in this design PR.
- Future implementation remains local-only and loopback-only.
- The first live capture implementation cannot collect out-of-scope traffic.
- The dashboard does not display raw values, actual target identifiers, full
  paths, secrets, or personal data.
- Verification remains fail-closed.
- Safe file links appear only after verification passes.
- Findings remain candidates.
- Risk remains draft.
- Final severity and CVSS remain manual decisions.
