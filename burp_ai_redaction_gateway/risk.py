from __future__ import annotations

from dataclasses import dataclass
from typing import Any


RISK_DRAFT_SCHEMA_VERSION = "risk-rating-draft-v1"
RISK_DRAFT_STATUS = "draft_requires_manual_verification"
DEFAULT_RISK_RATING_PROFILE = "conservative"
RISK_DRAFT_DO_NOT_CLAIM = [
    "Severity decision made",
    "Risk rating completed",
    "Exploitability proven",
]


@dataclass(frozen=True)
class RuleRiskBaseline:
    likelihood_draft: str
    impact_draft: str
    basis: str


@dataclass(frozen=True)
class RiskRatingProfile:
    name: str
    label: str
    conservatism: str
    likelihood_shift: int
    impact_shift: int
    basis: str


RULE_RISK_BASELINES: dict[str, RuleRiskBaseline] = {
    "missing_security_headers": RuleRiskBaseline(
        likelihood_draft="low",
        impact_draft="low",
        basis="Browser defense-in-depth impact is deployment-specific and must be checked in the target path.",
    ),
    "weak_cookie_attributes": RuleRiskBaseline(
        likelihood_draft="low",
        impact_draft="medium",
        basis="Cookie purpose and session sensitivity must be confirmed before impact can be finalized.",
    ),
    "cache_control_on_authenticated_response": RuleRiskBaseline(
        likelihood_draft="low",
        impact_draft="medium",
        basis="Authenticated response caching impact depends on whether user-specific data is present and cacheable.",
    ),
    "cors_candidate": RuleRiskBaseline(
        likelihood_draft="low",
        impact_draft="medium",
        basis="Cross-origin impact requires browser reproduction with origin and credential behavior verified.",
    ),
    "error_exposure": RuleRiskBaseline(
        likelihood_draft="low",
        impact_draft="low",
        basis="Verbose error impact depends on production behavior and whether implementation details are exposed.",
    ),
    "idor_candidate": RuleRiskBaseline(
        likelihood_draft="medium",
        impact_draft="medium",
        basis="Object-level authorization impact requires cross-user or cross-role reproduction before severity is final.",
    ),
    "sensitive_data_exposure_candidate": RuleRiskBaseline(
        likelihood_draft="medium",
        impact_draft="medium",
        basis="Data exposure impact depends on business necessity, role visibility, and manual data minimization review.",
    ),
}


RISK_RATING_PROFILES: dict[str, RiskRatingProfile] = {
    "conservative": RiskRatingProfile(
        name="conservative",
        label="Conservative draft",
        conservatism="most_cautious",
        likelihood_shift=0,
        impact_shift=0,
        basis="Conservative profile preserves the cautious passive-signal baseline.",
    ),
    "consultant": RiskRatingProfile(
        name="consultant",
        label="Consultant draft",
        conservatism="balanced_draft",
        likelihood_shift=0,
        impact_shift=0,
        basis="Consultant profile keeps draft values readable for report review without finalizing severity.",
    ),
    "strict": RiskRatingProfile(
        name="strict",
        label="Strict review draft",
        conservatism="higher_attention",
        likelihood_shift=1,
        impact_shift=0,
        basis="Strict profile increases draft likelihood sensitivity for manual triage, but still does not finalize severity.",
    ),
}
RISK_RATING_PROFILE_NAMES = tuple(RISK_RATING_PROFILES.keys())


def build_risk_rating_draft(
    rule_type: str,
    confidence: str,
    risk_profile: str = DEFAULT_RISK_RATING_PROFILE,
) -> dict[str, Any]:
    rating_profile = _risk_rating_profile(risk_profile)
    baseline = RULE_RISK_BASELINES.get(
        rule_type,
        RuleRiskBaseline(
            likelihood_draft="unknown",
            impact_draft="unknown",
            basis="Manual risk rating is required because no passive rule risk profile matched this candidate type.",
        ),
    )
    likelihood_draft = _shift_level(baseline.likelihood_draft, rating_profile.likelihood_shift)
    impact_draft = _shift_level(baseline.impact_draft, rating_profile.impact_shift)
    severity_draft = _severity_from_likelihood_and_impact(likelihood_draft, impact_draft)
    return {
        "schema_version": RISK_DRAFT_SCHEMA_VERSION,
        "status": RISK_DRAFT_STATUS,
        "risk_profile": rating_profile.name,
        "risk_profile_label": rating_profile.label,
        "risk_profile_conservatism": rating_profile.conservatism,
        "likelihood_draft": likelihood_draft,
        "impact_draft": impact_draft,
        "severity_draft": severity_draft,
        "severity_basis": [
            "Draft severity uses likelihood and impact placeholders, not evidence confidence.",
            baseline.basis,
            rating_profile.basis,
            "Manual verification and a separate risk rating review are required before using the severity draft.",
        ],
        "evidence_confidence": confidence,
        "confidence_is_severity": False,
        "manual_verification_required": True,
        "risk_rating_finalized": False,
        "do_not_claim": RISK_DRAFT_DO_NOT_CLAIM,
    }


def _risk_rating_profile(name: str) -> RiskRatingProfile:
    try:
        return RISK_RATING_PROFILES[name]
    except KeyError as error:
        raise ValueError("invalid_risk_rating_profile") from error


def _shift_level(level: str, shift: int) -> str:
    if level == "unknown":
        return "unknown"
    levels = ["low", "medium", "high"]
    try:
        index = levels.index(level)
    except ValueError:
        return "unknown"
    adjusted = min(max(index + shift, 0), len(levels) - 1)
    return levels[adjusted]


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
