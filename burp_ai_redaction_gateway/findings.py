from __future__ import annotations

from typing import Any

from .models import SanitizedEvent


DO_NOT_CLAIM = [
    "Vulnerability confirmed",
    "Privilege escalation confirmed",
    "Data breach confirmed",
    "Token reuse confirmed",
]
SECURITY_HEADERS_TO_CHECK = {
    "Strict-Transport-Security",
    "X-Content-Type-Options",
    "Content-Security-Policy",
    "X-Frame-Options",
}


def build_finding_candidates(events: list[SanitizedEvent]) -> dict[str, Any]:
    candidates: list[dict[str, Any]] = []
    for event in events:
        _add_missing_security_headers(candidates, event)
        _add_weak_cookie_attributes(candidates, event)
        _add_cache_control_on_authenticated_response(candidates, event)
        _add_cors_candidate(candidates, event)
        _add_error_exposure(candidates, event)
        _add_idor_candidate(candidates, event)
        _add_sensitive_data_exposure_candidate(candidates, event)

    for index, candidate in enumerate(candidates, start=1):
        finding_id = f"FC-{index:04d}"
        candidate["finding_id"] = finding_id
        candidate["candidate_id"] = finding_id
    return {
        "raw_data_included": False,
        "finding_candidates": candidates,
    }


def _base_candidate(event: SanitizedEvent, rule_type: str, title: str, confidence: str) -> dict[str, Any]:
    endpoint = f"{event.request['method']} {event.request['path_template']}"
    return {
        "type": rule_type,
        "title": title,
        "confidence": confidence,
        "affected_endpoint": endpoint,
        "evidence_ids": [event.evidence_id],
        "rationale": [],
        "do_not_claim": DO_NOT_CLAIM,
        "recommended_manual_tests": [],
    }


def _add_missing_security_headers(candidates: list[dict[str, Any]], event: SanitizedEvent) -> None:
    if event.signals["status"] < 200 or event.signals["status"] >= 400:
        return
    missing = [
        name
        for name, present in event.signals["response_security_headers"].items()
        if name in SECURITY_HEADERS_TO_CHECK and not present
    ]
    if not missing:
        return
    candidate = _base_candidate(event, "missing_security_headers", "Missing security headers", "low")
    candidate["rationale"] = [f"Response did not include: {', '.join(sorted(missing))}."]
    candidate["recommended_manual_tests"] = [
        "Confirm whether the endpoint is served over HTTPS in the target environment.",
        "Check whether headers are added by an upstream proxy for production traffic.",
    ]
    candidates.append(candidate)


def _add_weak_cookie_attributes(candidates: list[dict[str, Any]], event: SanitizedEvent) -> None:
    for cookie in event.signals["set_cookie_security"]:
        missing = []
        if not cookie["secure"]:
            missing.append("Secure")
        if not cookie["httponly"]:
            missing.append("HttpOnly")
        if cookie["samesite"].lower() in {"none", "samesite=none", ""}:
            missing.append("SameSite")
        if not missing:
            continue
        candidate = _base_candidate(event, "weak_cookie_attributes", "Weak cookie attributes", "medium")
        candidate["rationale"] = [f"Set-Cookie for {cookie['name']} is missing: {', '.join(missing)}."]
        candidate["recommended_manual_tests"] = [
            "Confirm the cookie is used for authentication or session state.",
            "Verify Secure, HttpOnly, and SameSite behavior in a browser with HTTPS.",
        ]
        candidates.append(candidate)


def _add_cors_candidate(candidates: list[dict[str, Any]], event: SanitizedEvent) -> None:
    cors = event.signals["cors"]
    origin = cors.get("Access-Control-Allow-Origin", "")
    credentials = str(cors.get("Access-Control-Allow-Credentials", "")).lower()
    if origin != "*" and not (origin and credentials == "true"):
        return
    candidate = _base_candidate(event, "cors_candidate", "CORS misconfiguration candidate", "medium")
    candidate["rationale"] = [
        "CORS response allows a wildcard origin or credentialed cross-origin access.",
        "Manual origin and credential checks are required before confirming impact.",
    ]
    candidate["recommended_manual_tests"] = [
        "Send requests with an attacker-controlled Origin value.",
        "Check whether credentials are accepted cross-origin for authenticated endpoints.",
    ]
    candidates.append(candidate)


def _add_cache_control_on_authenticated_response(candidates: list[dict[str, Any]], event: SanitizedEvent) -> None:
    if not event.signals["auth_observed"] or not (200 <= event.signals["status"] < 300):
        return
    cache_control = event.signals["cache_control"].lower()
    if any(value in cache_control for value in ["no-store", "no-cache", "private"]):
        return
    candidate = _base_candidate(
        event,
        "cache_control_on_authenticated_response",
        "Cache-Control issue on authenticated-looking response",
        "low",
    )
    candidate["rationale"] = [
        "Request appears authenticated and response did not include no-store, no-cache, or private Cache-Control policy."
    ]
    candidate["recommended_manual_tests"] = [
        "Confirm the response contains user-specific data.",
        "Check browser, proxy, and CDN cache behavior for authenticated requests.",
    ]
    candidates.append(candidate)


def _add_error_exposure(candidates: list[dict[str, Any]], event: SanitizedEvent) -> None:
    if event.signals["status"] < 500 and not event.signals["error_snippet_present"]:
        return
    candidate = _base_candidate(event, "error_exposure", "Error message exposure candidate", "low")
    candidate["rationale"] = ["Response indicates a server error or includes a sanitized error snippet."]
    candidate["recommended_manual_tests"] = [
        "Reproduce the error with safe input and check whether stack traces or internal paths are exposed.",
        "Confirm whether production error handling differs from the test environment.",
    ]
    candidates.append(candidate)


def _add_idor_candidate(candidates: list[dict[str, Any]], event: SanitizedEvent) -> None:
    if not (
        event.signals["identifier_observed"]
        and event.signals["auth_observed"]
        and 200 <= event.signals["status"] < 300
        and event.signals["user_specific_response"]
    ):
        return
    candidate = _base_candidate(event, "idor_candidate", "Potential Broken Access Control / IDOR", "medium")
    candidate["rationale"] = [
        "Identifier parameter observed in path or query.",
        "Authenticated-looking request returned HTTP 2xx.",
        "Response body shape contains user-specific fields.",
        "Manual verification is required with different user roles.",
    ]
    candidate["recommended_manual_tests"] = [
        "Compare the response using user A and user B sessions.",
        "Check whether user A can access user B resources by changing only the identifier.",
        "Verify server-side authorization independently of UI controls.",
    ]
    candidates.append(candidate)


def _add_sensitive_data_exposure_candidate(candidates: list[dict[str, Any]], event: SanitizedEvent) -> None:
    fields = event.signals["response_sensitive_fields"]
    if not fields:
        return
    candidate = _base_candidate(
        event,
        "sensitive_data_exposure_candidate",
        "Sensitive data exposure candidate",
        "medium",
    )
    candidate["rationale"] = [
        "Response schema contains fields that required redaction.",
        f"Redacted field count: {len(fields)}.",
    ]
    candidate["recommended_manual_tests"] = [
        "Confirm whether each sensitive field is necessary for the endpoint's intended purpose.",
        "Check role-based access and data minimization requirements.",
    ]
    candidates.append(candidate)
