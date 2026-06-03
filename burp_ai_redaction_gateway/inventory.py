from __future__ import annotations

from collections import defaultdict
from typing import Any

from .models import SanitizedEvent


def render_endpoint_inventory(project: str, events: list[SanitizedEvent], metadata: dict[str, Any] | None = None) -> str:
    grouped: dict[tuple[str, str, str], dict[str, object]] = defaultdict(
        lambda: {
            "status_codes": set(),
            "query_params": set(),
            "auth_required_observed": False,
            "response_mime": set(),
            "evidence_ids": [],
        }
    )
    for event in events:
        key = (event.request["method"], event.request["host"], event.request["path_template"])
        item = grouped[key]
        item["status_codes"].add(event.response["status"])
        item["query_params"].update(event.request["query_schema"].keys())
        item["auth_required_observed"] = bool(item["auth_required_observed"] or event.signals["auth_observed"])
        if event.signals["content_type"]:
            item["response_mime"].add(event.signals["content_type"])
        item["evidence_ids"].append(event.evidence_id)

    lines = [
        "# Endpoint Inventory",
        "",
        f"- Project: `{project}`",
        "- Raw data included: `false`",
    ]
    if metadata:
        lines.extend(
            [
                f"- Sanitizer version: `{metadata['sanitizer_version']}`",
                f"- Policy hash: `{metadata['policy_hash']}`",
                f"- Generated at: `{metadata['generated_at']}`",
                f"- Source event count: `{metadata['source_event_count']}`",
                f"- Scanner result: `{metadata['scanner_result']['status']}`",
            ]
        )
    lines.extend(
        [
            "",
            "| Method | Host | Path template | Status codes | Query params | Auth observed | Evidence |",
            "| --- | --- | --- | --- | --- | --- | --- |",
        ]
    )
    for (method, host, path), item in sorted(grouped.items()):
        statuses = ", ".join(str(value) for value in sorted(item["status_codes"]))
        params = ", ".join(sorted(item["query_params"])) or "-"
        evidence = ", ".join(item["evidence_ids"])
        auth = "true" if item["auth_required_observed"] else "false"
        lines.append(f"| {method} | {host} | `{path}` | {statuses} | {params} | {auth} | {evidence} |")
    lines.append("")
    return "\n".join(lines)
