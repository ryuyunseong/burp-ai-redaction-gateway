from __future__ import annotations

from dataclasses import dataclass
from typing import Any


RISK_DRAFT_SCHEMA_VERSION = "risk-rating-draft-v1"
RISK_DRAFT_STATUS = "draft_requires_manual_verification"
RISK_DRAFT_DO_NOT_CLAIM = [
    "Final severity assigned",
    "Risk rating confirmed",
    "Exploitability confirmed",
]


@dataclass(frozen=True)
class RiskProfile:
    likelihood_draft: str
    impact_draft: str
    basis: str


RISK_PROFILES: dict[str, RiskProfile] = {
    "missing_security_headers": RiskProfile(
        likelihood_draft="low",
        impact_draft="low",
        basis="Browser defense-in-depth impact is deployment-specific and must be checked in the target path.",
    ),
    "weak_cookie_attributes": RiskProfile(
        likelihood_draft="low",
        impact_draft="medium",
        basis="Cookie purpose and session sensitivity must be confirmed before impact can be finalized.",
    ),
    "cache_control_on_authenticated_response": RiskProfile(
        likelihood_draft="low",
        impact_draft="medium",
        basis="Authenticated response caching impact depends on whether user-specific data is present and cacheable.",
    ),
    "cors_candidate": RiskProfile(
        likelihood_draft="low",
        impact_draft="medium",
        basis="Cross-origin impact requires browser reproduction with origin and credential behavior verified.",
    ),
    "error_exposure": RiskProfile(
        likelihood_draft="low",
        impact_draft="low",
        basis="Verbose error impact depends on production behavior and whether implementation details are exposed.",
    ),
    "idor_candidate": RiskProfile(
        likelihood_draft="medium",
        impact_draft="medium",
        basis="Object-level authorization impact requires cross-user or cross-role reproduction before severity is final.",
    ),
    "sensitive_data_exposure_candidate": RiskProfile(
        likelihood_draft="medium",
        impact_draft="medium",
        basis="Data exposure impact depends on business necessity, role visibility, and manual data minimization review.",
    ),
}


def build_risk_rating_draft(rule_type: str, confidence: str) -> dict[str, Any]:
    profile = RISK_PROFILES.get(
        rule_type,
        RiskProfile(
            likelihood_draft="unknown",
            impact_draft="unknown",
            basis="Manual risk rating is required because no passive rule risk profile matched this candidate type.",
        ),
    )
    severity_draft = _severity_from_likelihood_and_impact(profile.likelihood_draft, profile.impact_draft)
    return {
        "schema_version": RISK_DRAFT_SCHEMA_VERSION,
        "status": RISK_DRAFT_STATUS,
        "likelihood_draft": profile.likelihood_draft,
        "impact_draft": profile.impact_draft,
        "severity_draft": severity_draft,
        "severity_basis": [
            "Draft severity uses likelihood and impact placeholders, not evidence confidence.",
            profile.basis,
            "Manual verification and a separate risk rating review are required before assigning final severity.",
        ],
        "evidence_confidence": confidence,
        "confidence_is_severity": False,
        "manual_verification_required": True,
        "risk_rating_finalized": False,
        "do_not_claim": RISK_DRAFT_DO_NOT_CLAIM,
    }


def _severity_from_likelihood_and_impact(likelihood: str, impact: str) -> str:
    if likelihood == "unknown" or impact == "unknown":
        return "unknown"
    levels = {"low": 1, "medium": 2, "high": 3}
    score = levels.get(likelihood, 0) * levels.get(impact, 0)
    if score >= 6:
        return "high"
    if score >= 4:
        return "medium"
    if score > 0:
        return "low"
    return "unknown"
