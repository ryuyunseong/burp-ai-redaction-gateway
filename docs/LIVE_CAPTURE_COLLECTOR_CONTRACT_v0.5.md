# Live Capture Collector Contract v0.5

This document defines the raw-free metadata contract that the Burp collector
filter uses before local loopback handoff.

The collector-side filter is implemented for Montoya handoff eligibility. This
document does not add receiver ingest changes, raw traffic storage, redaction
pipeline automation, or audit file writing.

## Purpose

The collector filter must decide whether a Burp item is eligible for local
handoff without logging or displaying raw traffic. The receiver-side dry-run
helper expects safe host metadata only. If that metadata is missing or invalid,
the receiver-side decision summary must stay raw-free and fail closed.

## Safe Metadata Keys

The receiver dry-run helper reads host metadata only from these keys:

```text
request_host
target_host
host
```

The same keys may appear at the payload root or inside one of these containers:

```text
request_metadata
metadata
scope_metadata
```

Collector handoff uses `request_metadata.host` because it groups the safe
routing metadata away from raw request and response values. This field must
contain a host name only, not a URL, path, query string, credential, cookie,
token, session value, personal data, or IP literal.

## Decision Contract

Receiver-side scope evaluation produces one of two decisions:

| Decision | Meaning |
| --- | --- |
| `would_accept` | Safe host metadata matches the configured exact host or subdomain scope. |
| `would_drop` | Safe host metadata is missing, invalid, or outside the configured scope. |

Skip and accept summaries use raw-free metadata only:

- summary kind
- decision
- reason code
- match reason
- result status
- host alias
- scope alias
- `raw_data_included=false`
- `ingest_performed=false`
- `collector_changed=false`
- `receiver_ingest_changed=false`

The summary is not a stored audit row. A future audit writer may consume this
metadata, but audit file writing is a separate PR.

Collector-side status output also stays raw-free. It may report counts such as
`items_sent`, `skipped`, `out_of_scope_skipped`, `missing_host_skipped`, and
`invalid_host_skipped`, but it must not report target host values.

## Scope Drift Matrix

`docs/LIVE_CAPTURE_SCOPE_DRIFT_MATRIX_v0.5.md` and
`samples/synthetic_live_capture_scope_drift_matrix.json` document the synthetic
host metadata cases used to compare collector gating with the Python receiver
dry-run guard. This matrix is raw-free and does not change collector
forwarding, receiver ingest, dashboard live capture integration, replay, active
scan, raw preview, retention, HMAC, or ChatGPT handoff behavior.

## Required Reason Codes

The current receiver-side contract uses these reason codes:

- `receiver_scope_in_scope`
- `receiver_scope_out_of_scope`
- `receiver_scope_missing_host`
- `receiver_scope_invalid_host`
- `receiver_scope_invalid_scope`

These codes must not include target values.

## Collector Integration Checklist

The collector filter implementation confirms:

- the collector sends only allowed in-scope items
- the collector never logs request or response values
- the collector does not include credential, cookie, token, session, personal
  data, URL, IP literal, or full local path values in status output
- the collector sends host metadata through `request_metadata.host`
- missing safe host metadata maps to a raw-free skip summary
- invalid safe host metadata maps to a raw-free skip summary
- out-of-scope safe host metadata maps to a raw-free skip summary
- accepted safe host metadata remains a candidate handoff, not a confirmed
  finding

## Explicit Non-Goals

This contract does not add:

- receiver ingest behavior changes
- raw request or response collection
- raw preview or download
- replay or active scan behavior
- file deletion or retention policy changes
- HMAC secret handling changes
- ChatGPT automatic handoff
- safe-to-share guarantees

Findings remain candidates. Risk remains draft. Final severity and CVSS remain
manual decisions.
