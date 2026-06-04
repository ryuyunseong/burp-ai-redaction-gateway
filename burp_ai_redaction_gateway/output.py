from __future__ import annotations

import json
from collections import Counter
from copy import deepcopy
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from . import __version__
from .inventory import render_endpoint_inventory
from .models import SanitizedEvent
from .policy import RedactionPolicy
from .scanner import assert_no_sensitive_text
from .store import write_audit_db


def write_outputs(
    project: str,
    output_dir: Path,
    events: list[SanitizedEvent],
    findings: dict[str, Any],
    policy: RedactionPolicy,
) -> dict[str, Path]:
    metadata = _metadata(project, events, policy)
    event_dicts = [{**event.to_dict(), "metadata": metadata} for event in events]
    findings_payload = deepcopy(findings)
    findings_payload["metadata"] = metadata
    audit = {
        "metadata": metadata,
        "project": project,
        "raw_data_included": False,
        "source_event_count": len(events),
        "records": [
            {
                "evidence_id": event.evidence_id,
                "raw_reference": event.raw_reference,
                "raw_values_included": event.raw_values_included,
                "redaction_counts": event.redaction["counts"],
            }
            for event in events
        ],
    }

    contents = {
        "endpoint_inventory.md": render_endpoint_inventory(project, events, metadata),
        "sanitized_events.jsonl": "\n".join(json.dumps(item, sort_keys=True) for item in event_dicts) + "\n",
        "finding_candidates.json": json.dumps(findings_payload, indent=2, sort_keys=True) + "\n",
        "chatgpt_prompt.md": _chatgpt_prompt(findings_payload),
        "codex_task_prompt.md": _codex_task_prompt(event_dicts, metadata),
        "redaction_audit.json": json.dumps(audit, indent=2, sort_keys=True) + "\n",
    }

    for content in contents.values():
        assert_no_sensitive_text(content)

    output_dir.mkdir(parents=True, exist_ok=True)
    written: dict[str, Path] = {}
    for name, content in contents.items():
        path = output_dir / name
        path.write_text(content, encoding="utf-8")
        written[name] = path

    audit_db = output_dir / "redaction_audit.db"
    write_audit_db(audit_db, events)
    written["redaction_audit.db"] = audit_db
    return written


def _metadata(project: str, events: list[SanitizedEvent], policy: RedactionPolicy) -> dict[str, Any]:
    counts: Counter[str] = Counter()
    for event in events:
        counts.update(event.redaction["counts"])
    return {
        "project": project,
        "sanitizer_version": __version__,
        "policy_hash": policy.policy_hash,
        "policy_source": policy.source_path,
        "raw_data_included": False,
        "generated_at": datetime.now(UTC).isoformat(),
        "source_event_count": len(events),
        "redaction_counts": dict(sorted(counts.items())),
        "scanner_result": {
            "status": "passed",
            "engine": "internal_fail_closed",
            "finding_count": 0,
        },
    }


def _chatgpt_prompt(findings: dict[str, Any]) -> str:
    data = json.dumps(findings, indent=2, sort_keys=True)
    return f"""# Sanitized Vulnerability Review Prompt

The following data was generated from Burp HTTP history after local redaction.

Assumptions:
- Raw cookies, tokens, personal data, customer domains, and internal IP values were removed.
- Raw request and response bodies are not included.
- Evaluate only the sanitized finding candidate data below.
- Do not over-claim impact. Separate confirmed facts from manual verification needs.

Requests:
1. Judge whether each vulnerability candidate is plausible.
2. Point out candidates that are weak or need more evidence.
3. Suggest safe manual verification steps.
4. Draft report wording for plausible findings.
5. Suggest impact and remediation language.
6. Map each candidate to likely OWASP Top 10 or CWE categories.

Data:

```json
{data}
```
"""


def _codex_task_prompt(events: list[dict[str, Any]], metadata: dict[str, Any]) -> str:
    sample = json.dumps(events[:5], indent=2, sort_keys=True)
    metadata_json = json.dumps(metadata, indent=2, sort_keys=True)
    return f"""# Codex Task Prompt

Project: burp-ai-redaction-gateway

Goal:
Improve vulnerability candidate detection using only sanitized event packets.

Requirements:
1. Do not print or store raw request or response values.
2. Do not log Cookie, Authorization, JWT, CSRF, API key, password, email, phone, RRN, or account numbers.
3. Template path parameters and query identifiers.
4. Improve only passive rules that operate on sanitized events.
5. Rule output must include finding_id, type, confidence, affected_endpoint, evidence_ids, rationale, recommended_manual_tests, and do_not_claim.
6. Add regression tests.
7. If redaction is incomplete, fail closed before output generation.
8. Supported passive rule IDs are missing_security_headers, weak_cookie_attributes, cache_control_on_authenticated_response, cors_candidate, error_exposure, idor_candidate, and sensitive_data_exposure_candidate.

Metadata:

```json
{metadata_json}
```

Sanitized sample events:

```json
{sample}
```
"""
