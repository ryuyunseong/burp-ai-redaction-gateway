# Live Capture Scope Drift Matrix v0.5

This guide documents the synthetic matrix used to compare the Montoya
collector-side host gate with the Python receiver scope dry-run guard.

The matrix is a fixture and documentation boundary only. It does not change
collector forwarding behavior, receiver ingest behavior, dashboard live capture
integration, HMAC, retention, replay, active scan, raw preview, or ChatGPT
handoff behavior.

In short, this matrix does not change collector forwarding behavior.

## Purpose

The collector and receiver apply related safety checks in different runtimes:

- the Montoya collector checks Burp `request.isInScope()` and safe
  `HttpService.host()` metadata before local loopback handoff
- the Python receiver dry-run guard checks safe host metadata against a target
  scope and returns raw-free decision summaries

Because the checks are implemented in different languages, the matrix keeps the
expected boundary visible and grep-friendly for future reviews.

## Matrix Coverage

The synthetic fixture covers these host metadata categories:

- normal host
- uppercase host
- host with trailing dot
- URL shape
- path/query included
- wildcard
- localhost
- loopback IPv4
- IP literal
- private-looking IP
- malformed label
- lookalike suffix
- subdomain
- out-of-scope host

## Expected Boundary

Collector-side expectations:

- allowed items may proceed only to the local loopback handoff endpoint
- out-of-scope Burp items are skipped before handoff
- missing or invalid host metadata is skipped before handoff
- status output reports counts only, such as `items_sent`,
  `out_of_scope_skipped`, `missing_host_skipped`, and `invalid_host_skipped`
- status output must not include host values, raw request or response values,
  credentials, cookies, tokens, sessions, personal data, or full local paths

Receiver-side expectations:

- accepted dry-run results use only aliases and raw-free metadata
- dropped dry-run results identify reason codes without target values
- dry-run summaries do not perform ingest
- dry-run summaries do not write audit files
- findings remain candidates
- risk remains draft
- final severity and CVSS remain manual decisions

## Fixture

The matrix lives at:

```text
samples/synthetic_live_capture_scope_drift_matrix.json
```

The fixture intentionally uses synthetic host metadata only. It must not include
real target identifiers, raw request or response values, Cookie,
Authorization, token, JWT, session, personal data, HMAC secret, CSRF token, or
full local paths.

## Non-Goals

This matrix does not add:

- receiver ingest policy changes
- dashboard live capture integration
- replay or active scan behavior
- raw preview or raw download behavior
- file deletion or retention policy changes
- HMAC secret handling changes
- ChatGPT automatic handoff
- safe-to-share guarantees
