# Live Capture Collector Contract v0.5

This document defines the raw-free metadata contract that the future Burp
collector filter should satisfy before it is wired into receiver ingest.

It is a contract document only. It does not implement collector forwarding,
receiver ingest changes, raw traffic storage, redaction pipeline automation, or
audit file writing.

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

Future collector work should prefer `request_metadata.host` because it groups
the safe routing metadata away from raw request and response values. This field
must contain a host name only, not a URL, path, query string, credential,
cookie, token, session value, personal data, or IP literal.

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

## Required Reason Codes

The current receiver-side contract uses these reason codes:

- `receiver_scope_in_scope`
- `receiver_scope_out_of_scope`
- `receiver_scope_missing_host`
- `receiver_scope_invalid_host`
- `receiver_scope_invalid_scope`

These codes must not include target values.

## Collector Integration Checklist

Before collector forwarding is changed, the implementation PR should confirm:

- the collector sends only allowed in-scope items
- the collector never logs request or response values
- the collector does not include credential, cookie, token, session, personal
  data, URL, IP literal, or full local path values in status output
- the collector sends host metadata through one of the safe keys above
- missing safe host metadata maps to a raw-free skip summary
- invalid safe host metadata maps to a raw-free skip summary
- out-of-scope safe host metadata maps to a raw-free skip summary
- accepted safe host metadata remains a candidate handoff, not a confirmed
  finding

## Explicit Non-Goals

This contract does not add:

- collector forwarding changes
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
