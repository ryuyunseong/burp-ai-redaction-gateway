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
SESSION_COOKIE_NAME_HINTS = ("session", "sid", "jsessionid", "auth", "login")


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


def _base_candidate(
    event: SanitizedEvent,
    rule_type: str,
    title: str,
    confidence: str,
    confidence_rationale: list[str],
) -> dict[str, Any]:
    endpoint = f"{event.request['method']} {event.request['path_template']}"
    return {
        "type": rule_type,
        "title": title,
        "confidence": confidence,
        "confidence_rationale": confidence_rationale,
        "manual_verification_required": True,
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
    candidate = _base_candidate(
        event,
        "missing_security_headers",
        "Missing security headers",
        "low",
        [
            "Passive single-response header observation only.",
            "Headers may be added by an upstream proxy or environment-specific edge layer.",
        ],
    )
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
        confidence = _cookie_confidence(cookie, missing)
        candidate = _base_candidate(
            event,
            "weak_cookie_attributes",
            "Weak cookie attributes",
            confidence,
            _cookie_confidence_rationale(cookie, missing, confidence),
        )
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
    confidence = "medium" if credentials == "true" else "low"
    candidate = _base_candidate(
        event,
        "cors_candidate",
        "CORS misconfiguration candidate",
        confidence,
        [
            "CORS headers were observed in sanitized response metadata.",
            "Browser enforcement and authenticated cross-origin behavior require manual reproduction.",
            f"Credentialed CORS marker observed: {credentials == 'true'}.",
        ],
    )
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
    user_specific_signal = bool(event.signals["user_specific_response"] or event.signals["response_sensitive_fields"])
    confidence = "medium" if user_specific_signal else "low"
    candidate = _base_candidate(
        event,
        "cache_control_on_authenticated_response",
        "Cache-Control issue on authenticated-looking response",
        confidence,
        [
            "Authenticated-looking request signal was observed after redaction.",
            "No no-store, no-cache, or private Cache-Control policy was observed.",
            f"User-specific response signal observed: {user_specific_signal}.",
        ],
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
    candidate = _base_candidate(
        event,
        "error_exposure",
        "Error message exposure candidate",
        "low",
        [
            "Passive error status or sanitized error snippet signal only.",
            "Production error handling may differ and must be reproduced safely.",
        ],
    )
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
    candidate = _base_candidate(
        event,
        "idor_candidate",
        "Potential Broken Access Control / IDOR",
        "medium",
        [
            "Identifier, authenticated-looking request, HTTP 2xx, and user-specific response signals were all observed.",
            "Cross-user or cross-role access was not tested and must be manually verified.",
        ],
    )
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
    contextual_signal = bool(event.signals["auth_observed"] or event.signals["user_specific_response"])
    confidence = "medium" if contextual_signal else "low"
    candidate = _base_candidate(
        event,
        "sensitive_data_exposure_candidate",
        "Sensitive data exposure candidate",
        confidence,
        [
            "Response schema contains sanitized sensitive-field markers.",
            f"Authenticated or user-specific context observed: {contextual_signal}.",
            "Business necessity and role visibility must be manually reviewed.",
        ],
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


def _cookie_confidence(cookie: dict[str, Any], missing: list[str]) -> str:
    name = str(cookie["name"]).lower()
    session_like = any(hint in name for hint in SESSION_COOKIE_NAME_HINTS)
    if session_like and ("Secure" in missing or "HttpOnly" in missing):
        return "medium"
    return "low"


def _cookie_confidence_rationale(cookie: dict[str, Any], missing: list[str], confidence: str) -> list[str]:
    name = str(cookie["name"]).lower()
    session_like = any(hint in name for hint in SESSION_COOKIE_NAME_HINTS)
    return [
        "Only Set-Cookie attribute metadata was used; cookie values were not inspected.",
        f"Session-like cookie name signal observed: {session_like}.",
        f"Missing high-impact attributes observed: {bool({'Secure', 'HttpOnly'} & set(missing))}.",
        f"Confidence remains {confidence} until cookie purpose is manually confirmed.",
    ]
