from __future__ import annotations

import json
from collections import Counter
from copy import deepcopy
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from . import __version__
from .analysis import build_analysis_packet, render_chatgpt_analysis_prompt, render_codex_analysis_prompt
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

    analysis_packet = build_analysis_packet(findings_payload)
    contents = {
        "endpoint_inventory.md": render_endpoint_inventory(project, events, metadata),
        "sanitized_events.jsonl": "\n".join(json.dumps(item, sort_keys=True) for item in event_dicts) + "\n",
        "finding_candidates.json": json.dumps(findings_payload, indent=2, sort_keys=True) + "\n",
        "analysis_packet.json": json.dumps(analysis_packet, indent=2, sort_keys=True) + "\n",
        "chatgpt_prompt.md": render_chatgpt_analysis_prompt(analysis_packet),
        "codex_task_prompt.md": render_codex_analysis_prompt(analysis_packet),
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
