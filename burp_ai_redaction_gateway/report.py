from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .policy import RedactionPolicy
from .scanner import assert_no_sensitive_text
from .verifier import verify_path


DEFAULT_REPORT_NAME = "report_draft.md"


@dataclass(frozen=True)
class ReportDraftResult:
    output_path: Path
    candidate_count: int
    raw_data_included: bool


def write_report_draft(input_dir: Path, output_path: Path | None, policy: RedactionPolicy) -> ReportDraftResult:
    verification = verify_path(input_dir, policy)
    if not verification.passed:
        raise ValueError("verification_failed")

    packet = _load_analysis_packet(input_dir)
    if packet.get("raw_data_included") is not False:
        raise ValueError("raw_data_marker_not_false")

    candidates = _candidate_list(packet)
    report = render_report_draft(candidates)
    assert_no_sensitive_text(report)

    target = output_path or (input_dir / DEFAULT_REPORT_NAME)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(report, encoding="utf-8")
    return ReportDraftResult(output_path=target, candidate_count=len(candidates), raw_data_included=False)


def render_report_draft(candidates: list[dict[str, Any]]) -> str:
    lines = [
        "# Sanitized Candidate Report Draft",
        "",
        "This draft is not a confirmed vulnerability report.",
        "Use it only as a candidate-based starting point after manual verification.",
        "",
        "Global handling rules:",
        "- Do not add raw request or response values.",
        "- Do not add Cookie, Authorization, token, real domain, IP, or personal data values.",
        "- Keep candidate wording until manual reproduction is complete.",
        "",
    ]
    if not candidates:
        lines.extend(["## No Candidates", "", "No finding candidates were present in the analysis packet.", ""])
        return "\n".join(lines)

    for candidate in candidates:
        lines.extend(_candidate_section(candidate))
    return "\n".join(lines)


def _load_analysis_packet(input_dir: Path) -> dict[str, Any]:
    path = input_dir / "analysis_packet.json"
    if not path.is_file():
        raise ValueError("missing_analysis_packet")
    text = path.read_text(encoding="utf-8")
    assert_no_sensitive_text(text)
    packet = json.loads(text)
    if not isinstance(packet, dict):
        raise ValueError("invalid_analysis_packet")
    return packet


def _candidate_list(packet: dict[str, Any]) -> list[dict[str, Any]]:
    candidates = packet.get("finding_candidates")
    if not isinstance(candidates, list):
        raise ValueError("invalid_analysis_packet")
    return [candidate for candidate in candidates if isinstance(candidate, dict)]


def _candidate_section(candidate: dict[str, Any]) -> list[str]:
    finding_id = _safe_text(candidate.get("finding_id"), "candidate")
    title = _safe_text(candidate.get("title"), _safe_text(candidate.get("type"), "Finding candidate"))
    kind = _safe_text(candidate.get("type"), "unknown_type")
    endpoint = _safe_text(candidate.get("affected_endpoint"), "unknown_endpoint")
    confidence = _safe_text(candidate.get("confidence"), "unknown")
    evidence_ids = _safe_list(candidate.get("evidence_ids"))
    rationale = _safe_list(candidate.get("rationale"))
    manual_tests = _safe_list(candidate.get("recommended_manual_tests"))
    do_not_claim = _safe_list(candidate.get("do_not_claim"))

    lines = [
        f"## Candidate {finding_id}: {title}",
        "",
        "- Candidate status: suspected, requires manual verification.",
        f"- Candidate type: {kind}",
        f"- Affected endpoint: {endpoint}",
        f"- Confidence: {confidence}",
        f"- Evidence IDs: {', '.join(evidence_ids) if evidence_ids else 'none'}",
        "",
        "### Rationale",
    ]
    lines.extend(_bullets(rationale, "No rationale was provided in the analysis packet."))
    lines.extend(["", "### Impact Draft"])
    lines.extend(_bullets(_impact_draft(kind), "Manual verification is required before impact can be stated."))
    lines.extend(["", "### Additional Verification Steps"])
    lines.extend(_bullets(manual_tests, "Reproduce safely with separate test accounts or roles before reporting impact."))
    lines.extend(["", "### Remediation Draft"])
    lines.extend(_bullets(_remediation_draft(kind), "Review the endpoint's server-side security controls."))
    lines.extend(["", "### Claims Not Allowed Before Proof"])
    lines.extend(_bullets(do_not_claim, "Do not present this candidate as a confirmed vulnerability."))
    lines.append("")
    return lines


def _impact_draft(kind: str) -> list[str]:
    impacts = {
        "missing_security_headers": [
            "If manually verified as relevant, missing security headers may reduce browser-side defense in depth."
        ],
        "weak_cookie_attributes": [
            "If the cookie is security-sensitive, weak attributes may increase session handling risk."
        ],
        "cache_control_on_authenticated_response": [
            "If the response contains user-specific data, weak cache policy may allow unintended caching."
        ],
        "cors_candidate": [
            "If credentialed cross-origin access is reproducible, the endpoint may expose data to an unintended origin."
        ],
        "error_exposure": [
            "If reproduced in production-like settings, verbose errors may disclose implementation details."
        ],
        "idor_candidate": [
            "If authorization checks can be bypassed with another user's identifier, access control impact may exist."
        ],
        "sensitive_data_exposure_candidate": [
            "If the fields are unnecessary for the user role or workflow, the endpoint may return excessive data."
        ],
    }
    return impacts.get(kind, ["Manual verification is required before impact can be stated."])


def _remediation_draft(kind: str) -> list[str]:
    remediations = {
        "missing_security_headers": [
            "Add appropriate response security headers at the application or edge layer and verify production behavior."
        ],
        "weak_cookie_attributes": [
            "Set Secure, HttpOnly, and SameSite attributes where appropriate for the cookie purpose."
        ],
        "cache_control_on_authenticated_response": [
            "Use no-store, no-cache, or private cache policy for authenticated user-specific responses."
        ],
        "cors_candidate": [
            "Restrict allowed origins and avoid credentialed cross-origin access unless explicitly required."
        ],
        "error_exposure": [
            "Return generic user-facing errors and keep detailed diagnostics in protected server-side logs only."
        ],
        "idor_candidate": [
            "Enforce server-side authorization for every object access using the authenticated principal and resource owner."
        ],
        "sensitive_data_exposure_candidate": [
            "Apply data minimization and role-based filtering to response fields."
        ],
    }
    return remediations.get(kind, ["Review the endpoint's server-side security controls."])


def _safe_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [_safe_text(item, "") for item in value if _safe_text(item, "")]


def _safe_text(value: Any, fallback: str) -> str:
    if value is None:
        return fallback
    text = str(value).replace("\r", " ").replace("\n", " ").strip()
    return text or fallback


def _bullets(values: list[str], fallback: str) -> list[str]:
    items = values or [fallback]
    return [f"- {item}" for item in items]
