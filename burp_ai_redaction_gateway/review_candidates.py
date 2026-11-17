"""Group similar passive observations for review; never send or modify a candidate."""
from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any

from .ai_review import CANDIDATE_LABELS, MAX_CANDIDATES
from .findings import SECURITY_HEADERS_TO_CHECK
from .report import _report_text


_OBSERVATIONS = {
    "idor_candidate": {"Identifier parameter observed in path or query.", "Authenticated-looking request returned HTTP 2xx.",
                       "Response body shape contains user-specific fields."},
    "sensitive_data_exposure_candidate": {"Response schema contains fields that required redaction."},
    "error_exposure": {"Response indicates a server error or includes a sanitized error snippet."},
    "cors_candidate": {"CORS response allows a wildcard origin or credentialed cross-origin access."},
    "cache_control_on_authenticated_response": {
        "Request appears authenticated and response did not include no-store, no-cache, or private Cache-Control policy."},
}
_CONFIDENCE = {"low": (1, "낮음"), "medium": (2, "중간"), "high": (3, "높음")}


def _observations(item: dict[str, Any]) -> Iterator[tuple[str, str]]:
    """Yield a stable comparison key and display text from known local rule output."""
    kind = item["type"]
    for line in item["rationale"]:
        if line in _OBSERVATIONS.get(kind, ()):
            yield line, _report_text(line)
        elif kind == "weak_cookie_attributes":
            missing = re.fullmatch(r"Set-Cookie for .+ is missing: (.+)\.", line)
            if missing and set(missing[1].split(", ")) <= {"Secure", "HttpOnly", "SameSite"}:
                yield ",".join(sorted(set(missing[1].split(", ")))), "쿠키에 없는 속성: " + missing[1]
            elif re.fullmatch(r"Set-Cookie for .+ uses SameSite=None without Secure\.", line):
                yield "none_without_secure", "SameSite=None이지만 Secure가 없습니다."
        elif kind == "missing_security_headers":
            headers = re.fullmatch(r"Response did not include: (.+)\.", line)
            if headers and set(headers[1].split(", ")) <= SECURITY_HEADERS_TO_CHECK:
                yield ",".join(sorted(set(headers[1].split(", ")))), "응답에 없는 헤더: " + headers[1]
        elif kind == "sensitive_data_exposure_candidate":
            count = re.fullmatch(r"Redacted field count: ([0-9]{1,5})\.", line)
            if count:
                yield "redacted_field_count", f"마스킹한 항목: {count[1]}개"


def candidate_metadata(item: dict[str, Any]) -> dict[str, Any]:
    kind = item["type"] if item["type"] in CANDIDATE_LABELS else "unmapped"
    return {"finding_id": item["finding_id"], "type": kind, "title": CANDIDATE_LABELS.get(kind, "미분류"),
            "confidence": item["confidence"], "rationale": [text for _, text in _observations(item)]}


@dataclass(frozen=True)
class CandidateGroup:
    members: list[dict[str, Any]]  # Representative first; every original ID remains selectable.
    reason: str
    recommended: bool


def group_candidates(candidates: list[dict[str, Any]]) -> list[CandidateGroup]:
    buckets = {}
    for item in candidates:
        signals = dict(_observations(item))
        evidence = {e for e in item["evidence_ids"] if re.fullmatch(r"EV-[0-9]{4,}", e)}
        kind = item["type"]
        scope = item["affected_endpoint"] if kind in {"idor_candidate", "sensitive_data_exposure_candidate", "error_exposure"} else ""
        if kind == "cors_candidate":
            scope = next((s for s in item["confidence_rationale"] if s in {
                "Credentialed CORS marker observed: True.", "Credentialed CORS marker observed: False."}), item["affected_endpoint"])
        eligible = bool(signals and evidence)
        key = (kind, scope, tuple(sorted(signals))) if eligible else (item["finding_id"],)
        confidence, label = _CONFIDENCE[item["confidence"]]
        rank = (-confidence, -len(signals), -len(evidence), int(item["finding_id"][3:]), item["finding_id"])
        reason = (f"{' '.join(signals.values())} (근거 신뢰도 {label}, 근거 기록 {len(evidence)}건)"
                  if eligible else "추천할 근거가 부족합니다. 직접 선택할 수 있습니다.")
        buckets.setdefault(key, []).append((rank, item, reason, eligible))

    ranked = [sorted(members, key=lambda row: row[0]) for members in buckets.values()]
    ranked.sort(key=lambda members: members[0][0])
    # At equal confidence, show one of each kind before recommending more of the same kind.
    first_of_kind = set()
    seen = set()
    for members in ranked:
        rank, item, _, eligible = members[0]
        band = (rank[0], item["type"])
        if eligible and band not in seen:
            first_of_kind.add(item["finding_id"])
            seen.add(band)

    def priority(members):
        rank, item, _, eligible = members[0]
        return not eligible, rank[0], item["finding_id"] not in first_of_kind, rank

    ordered = sorted(ranked, key=priority)
    return [CandidateGroup([row[1] for row in members], members[0][2], index < MAX_CANDIDATES and members[0][3])
            for index, members in enumerate(ordered)]
