from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .policy import RedactionPolicy
from .scanner import assert_no_sensitive_text
from .verifier import verify_path


DEFAULT_REPORT_NAME = "report_draft.md"
DEFAULT_REPORT_PROFILE = "conservative"


@dataclass(frozen=True)
class ReportProfile:
    name: str
    title: str
    intro_lines: list[str]
    candidate_label: str
    status_line: str
    confidence_label: str
    rationale_heading: str
    rationale_fallback: str
    confidence_fallback: str
    impact_heading: str
    impact_fallback: str
    manual_tests_heading: str
    manual_tests_fallback: str
    remediation_heading: str
    remediation_fallback: str
    claims_heading: str
    claims_fallback: str


REPORT_PROFILES: dict[str, ReportProfile] = {
    "conservative": ReportProfile(
        name="conservative",
        title="Sanitized Candidate Report Draft",
        intro_lines=[
            "This draft is not a confirmed vulnerability report.",
            "Use it only as a candidate-based starting point after manual verification.",
        ],
        candidate_label="Candidate",
        status_line="Candidate status: suspected, requires manual verification.",
        confidence_label="Evidence confidence",
        rationale_heading="Rationale",
        rationale_fallback="No rationale was provided in the analysis packet.",
        confidence_fallback="Confidence is conservative until manual verification is complete.",
        impact_heading="Impact Draft",
        impact_fallback="Manual verification is required before impact can be stated.",
        manual_tests_heading="Additional Verification Steps",
        manual_tests_fallback="Reproduce safely with separate test accounts or roles before reporting impact.",
        remediation_heading="Remediation Draft",
        remediation_fallback="Review the endpoint's server-side security controls.",
        claims_heading="Claims Not Allowed Before Proof",
        claims_fallback="Do not present this candidate as a confirmed vulnerability.",
    ),
    "consultant": ReportProfile(
        name="consultant",
        title="Sanitized Consultant Report Draft",
        intro_lines=[
            "This draft is prepared for consultant review and is not a confirmed vulnerability report.",
            "Keep each item as a suspected finding until the required manual verification is complete.",
        ],
        candidate_label="Suspected Finding",
        status_line="Suspected finding status: candidate only, manual verification required.",
        confidence_label="Evidence confidence",
        rationale_heading="Assessment Rationale",
        rationale_fallback="No assessment rationale was provided in the analysis packet.",
        confidence_fallback="Evidence confidence remains conservative until manual verification is complete.",
        impact_heading="Potential Impact If Confirmed",
        impact_fallback="Potential impact cannot be stated until the candidate is manually verified.",
        manual_tests_heading="Required Manual Verification",
        manual_tests_fallback="Verify safely with separate test accounts or roles before report submission.",
        remediation_heading="Recommended Remediation Draft",
        remediation_fallback="Review and strengthen the endpoint's server-side security controls.",
        claims_heading="Claims To Avoid Before Verification",
        claims_fallback="Do not present this suspected finding as a confirmed vulnerability.",
    ),
}
REPORT_PROFILE_NAMES = tuple(REPORT_PROFILES.keys())


@dataclass(frozen=True)
class ReportDraftResult:
    output_path: Path
    candidate_count: int
    raw_data_included: bool
    profile: str


def write_report_draft(
    input_dir: Path,
    output_path: Path | None,
    policy: RedactionPolicy,
    profile_name: str = DEFAULT_REPORT_PROFILE,
) -> ReportDraftResult:
    verification = verify_path(input_dir, policy)
    if not verification.passed:
        raise ValueError("verification_failed")

    packet = _load_analysis_packet(input_dir)
    if packet.get("raw_data_included") is not False:
        raise ValueError("raw_data_marker_not_false")

    candidates = _candidate_list(packet)
    profile = _profile(profile_name)
    report = render_report_draft(candidates, profile.name)
    assert_no_sensitive_text(report)

    target = output_path or (input_dir / DEFAULT_REPORT_NAME)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(report, encoding="utf-8")
    return ReportDraftResult(output_path=target, candidate_count=len(candidates), raw_data_included=False, profile=profile.name)


def render_report_draft(candidates: list[dict[str, Any]], profile_name: str = DEFAULT_REPORT_PROFILE) -> str:
    profile = _profile(profile_name)
    lines = [
        f"# {profile.title}",
        "",
        *profile.intro_lines,
        "",
        f"Report profile: {profile.name}",
        "",
        "Global handling rules:",
        "- Do not add raw request or response values.",
        "- Do not add Cookie, Authorization, token, real domain, IP, or personal data values.",
        "- Treat confidence as evidence confidence, not severity.",
        "- Treat risk rating values as draft-only until separate manual risk review is complete.",
        "- Keep candidate or suspected finding wording until manual reproduction is complete.",
        "",
    ]
    if not candidates:
        lines.extend(["## No Candidates", "", "No finding candidates were present in the analysis packet.", ""])
        return "\n".join(lines)

    for candidate in candidates:
        lines.extend(_candidate_section(candidate, profile))
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


def _profile(profile_name: str) -> ReportProfile:
    try:
        return REPORT_PROFILES[profile_name]
    except KeyError as error:
        raise ValueError("invalid_report_profile") from error


def _candidate_section(candidate: dict[str, Any], profile: ReportProfile) -> list[str]:
    finding_id = _safe_text(candidate.get("finding_id"), "candidate")
    title = _safe_text(candidate.get("title"), _safe_text(candidate.get("type"), "Finding candidate"))
    kind = _safe_text(candidate.get("type"), "unknown_type")
    endpoint = _safe_text(candidate.get("affected_endpoint"), "unknown_endpoint")
    confidence = _safe_text(candidate.get("confidence"), "unknown")
    confidence_rationale = _safe_list(candidate.get("confidence_rationale"))
    risk_rating_draft = _risk_rating_draft_lines(candidate.get("risk_rating_draft"))
    manual_required = bool(candidate.get("manual_verification_required", True))
    evidence_ids = _safe_list(candidate.get("evidence_ids"))
    rationale = _safe_list(candidate.get("rationale"))
    manual_tests = _safe_list(candidate.get("recommended_manual_tests"))
    do_not_claim = _safe_list(candidate.get("do_not_claim"))

    lines = [
        f"## {profile.candidate_label} {finding_id}: {title}",
        "",
        f"- {profile.status_line}",
        f"- Candidate type: {kind}",
        f"- Affected endpoint: {endpoint}",
        f"- {profile.confidence_label}: {confidence}",
        f"- Manual verification required: {str(manual_required).lower()}",
        f"- Evidence IDs: {', '.join(evidence_ids) if evidence_ids else 'none'}",
        "",
        "### Confidence Rationale",
    ]
    lines.extend(_bullets(confidence_rationale, profile.confidence_fallback))
    lines.extend([
        "",
        "### Risk Rating Draft",
    ])
    lines.extend(_bullets(risk_rating_draft, "Manual risk rating is required before assigning severity."))
    lines.extend([
        "",
        f"### {profile.rationale_heading}",
    ])
    lines.extend(_bullets(rationale, profile.rationale_fallback))
    lines.extend(["", f"### {profile.impact_heading}"])
    lines.extend(_bullets(_impact_draft(kind, profile.name), profile.impact_fallback))
    lines.extend(["", f"### {profile.manual_tests_heading}"])
    lines.extend(_bullets(manual_tests, profile.manual_tests_fallback))
    lines.extend(["", f"### {profile.remediation_heading}"])
    lines.extend(_bullets(_remediation_draft(kind, profile.name), profile.remediation_fallback))
    lines.extend(["", f"### {profile.claims_heading}"])
    lines.extend(_bullets(do_not_claim, profile.claims_fallback))
    lines.append("")
    return lines


def _impact_draft(kind: str, profile_name: str) -> list[str]:
    conservative = {
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
    consultant = {
        "missing_security_headers": [
            "If verified in the deployment path, the missing headers may reduce browser-side defense-in-depth for affected users."
        ],
        "weak_cookie_attributes": [
            "If the cookie supports a session or authentication workflow, missing attributes may increase session handling risk."
        ],
        "cache_control_on_authenticated_response": [
            "If the response is user-specific, the cache policy may allow unintended storage by browsers or intermediary caches."
        ],
        "cors_candidate": [
            "If credentialed cross-origin access is reproducible, an unintended origin may be able to read protected response data."
        ],
        "error_exposure": [
            "If reproduced in production-like settings, verbose errors may reveal implementation details useful for follow-up testing."
        ],
        "idor_candidate": [
            "If cross-user access is reproducible, the endpoint may expose an object-level authorization weakness."
        ],
        "sensitive_data_exposure_candidate": [
            "If the fields are unnecessary for the role or workflow, the endpoint may return more data than required."
        ],
    }
    impacts = consultant if profile_name == "consultant" else conservative
    return impacts.get(kind, ["Manual verification is required before impact can be stated."])


def _remediation_draft(kind: str, profile_name: str) -> list[str]:
    conservative = {
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
    consultant = {
        "missing_security_headers": [
            "Define the expected response security header policy, apply it consistently, and verify it in the deployment path."
        ],
        "weak_cookie_attributes": [
            "Confirm the cookie purpose, then apply Secure, HttpOnly, and SameSite attributes where appropriate."
        ],
        "cache_control_on_authenticated_response": [
            "Apply no-store, no-cache, or private cache policy to authenticated responses that contain user-specific data."
        ],
        "cors_candidate": [
            "Restrict allowed origins to trusted origins and disable credentialed cross-origin access unless it is required."
        ],
        "error_exposure": [
            "Return generic client-facing errors and keep detailed diagnostics in protected server-side logs."
        ],
        "idor_candidate": [
            "Enforce server-side object authorization for every object lookup using the authenticated principal."
        ],
        "sensitive_data_exposure_candidate": [
            "Review response schemas and filter fields by role, workflow need, and data minimization requirements."
        ],
    }
    remediations = consultant if profile_name == "consultant" else conservative
    return remediations.get(kind, ["Review the endpoint's server-side security controls."])


def _risk_rating_draft_lines(value: Any) -> list[str]:
    if not isinstance(value, dict):
        return ["Manual risk rating is required before assigning severity."]
    likelihood = _safe_text(value.get("likelihood_draft"), "unknown")
    impact = _safe_text(value.get("impact_draft"), "unknown")
    severity = _safe_text(value.get("severity_draft"), "unknown")
    risk_profile = _safe_text(value.get("risk_profile"), "conservative")
    profile_conservatism = _safe_text(value.get("risk_profile_conservatism"), "unknown")
    status = _safe_text(value.get("status"), "draft_requires_manual_verification")
    finalized = str(bool(value.get("risk_rating_finalized", False))).lower()
    confidence_is_severity = str(bool(value.get("confidence_is_severity", False))).lower()
    basis = _safe_list(value.get("severity_basis"))
    lines = [
        f"Status: {status}.",
        f"Risk profile: {risk_profile}.",
        f"Profile conservatism: {profile_conservatism}.",
        f"Likelihood draft: {likelihood}.",
        f"Impact draft: {impact}.",
        f"Severity draft: {severity}.",
        f"Risk rating finalized: {finalized}.",
        f"Confidence is severity: {confidence_is_severity}.",
    ]
    lines.extend(basis or ["Manual verification is required before assigning final severity."])
    return lines


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
