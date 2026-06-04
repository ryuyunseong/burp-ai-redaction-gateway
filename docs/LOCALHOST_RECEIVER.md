# Localhost Ingest Receiver

The receiver accepts Burp Montoya collector handoff payloads on loopback only
and immediately runs the existing redaction, output, and verification pipeline.

## Run

```powershell
python -m burp_ai_redaction_gateway serve --host 127.0.0.1 --port 8765 --output out\receiver --project montoya_receiver_alias
```

The command rejects non-`127.0.0.1` bind hosts. The receiver exposes:

- `GET /health`
- `POST /ingest/burp-history`

## Safety Rules

- Raw request and response values are accepted only in memory.
- Raw request and response values are not logged.
- Raw values are never written to repository source files.
- Generated output is written under an ignored output directory.
- Generated output must pass the existing fail-closed scanner before the HTTP
  request is accepted.
- Payloads must use the expected `montoya-handoff-v1` schema.
- Oversized payloads are rejected before parsing.

## Current Scope

This slice receives one Montoya handoff event per request and writes a sanitized
packet for that event. The generated `finding_candidates.json` uses only
sanitized event signals and emits passive suspicious finding candidates for
manual review.
