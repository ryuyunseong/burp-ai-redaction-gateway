from __future__ import annotations

import json
import re
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
        title="보안 점검 보고서 초안",
        intro_lines=[
            "이 문서는 기록에서 찾은 검토 후보를 정리한 초안이며, 취약점 확정 보고서가 아닙니다.",
            "각 항목을 직접 확인한 뒤 실제 영향과 조치 내용을 보완하세요.",
        ],
        candidate_label="검토 후보",
        status_line="상태: 직접 확인이 필요한 검토 후보입니다.",
        confidence_label="근거 신뢰도",
        rationale_heading="발견 내용",
        rationale_fallback="분석 자료에 발견 근거가 없습니다.",
        confidence_fallback="직접 확인하기 전까지 근거 신뢰도를 보수적으로 판단합니다.",
        impact_heading="예상 영향",
        impact_fallback="실제 영향은 직접 확인해야 합니다.",
        manual_tests_heading="확인 방법",
        manual_tests_fallback="별도 테스트 계정과 권한으로 안전하게 재현한 뒤 영향을 판단하세요.",
        remediation_heading="조치 제안",
        remediation_fallback="서버의 접근 제어와 보안 설정을 확인하세요.",
        claims_heading="확인 전 단정하면 안 되는 내용",
        claims_fallback="이 검토 후보를 확정된 취약점으로 보고하지 마세요.",
    ),
    "consultant": ReportProfile(
        name="consultant",
        title="보안 점검 보고서 초안 (상세 검토용)",
        intro_lines=[
            "이 문서는 상세 검토용 초안이며, 취약점 확정 보고서가 아닙니다.",
            "직접 재현하고 영향을 확인하기 전까지 모든 항목을 검토 후보로 다루세요.",
        ],
        candidate_label="검토 후보",
        status_line="상태: 직접 확인이 필요한 검토 후보입니다.",
        confidence_label="근거 신뢰도",
        rationale_heading="발견 내용",
        rationale_fallback="분석 자료에 발견 근거가 없습니다.",
        confidence_fallback="직접 확인하기 전까지 근거 신뢰도를 보수적으로 판단합니다.",
        impact_heading="재현될 경우 예상 영향",
        impact_fallback="직접 확인하기 전에는 영향을 단정할 수 없습니다.",
        manual_tests_heading="보고 전 확인할 사항",
        manual_tests_fallback="보고 전에 별도 테스트 계정과 권한으로 안전하게 재현하세요.",
        remediation_heading="권장 조치",
        remediation_fallback="서버의 접근 제어와 보안 설정을 확인하고 보완하세요.",
        claims_heading="확인 전 단정하면 안 되는 내용",
        claims_fallback="이 검토 후보를 확정된 취약점으로 보고하지 마세요.",
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
        f"보고서 형식: {_report_text(profile.name)}",
        "",
        "공유 전 확인:",
        "- 요청·응답 원문, 쿠키·인증 정보·토큰, 실제 도메인·IP·개인정보를 추가하지 마세요.",
        "- 근거 신뢰도는 관찰한 자료의 신뢰 수준이며, 취약점의 심각도가 아닙니다.",
        "- 위험도는 초안입니다. 직접 재현하고 별도로 위험을 평가한 뒤 확정하세요.",
        "- 재현을 마치기 전까지 검토 후보라는 표현을 유지하세요.",
        "",
    ]
    if not candidates:
        lines.extend(["## 검토 후보 없음", "", "분석 자료에 검토 후보가 없습니다. 취약점이 없다는 뜻은 아닙니다.", ""])
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
    finding_id = _safe_text(candidate.get("finding_id"), "번호 없음")
    title = _report_text(_safe_text(candidate.get("title"), _safe_text(candidate.get("type"), "점검 항목")))
    kind = _safe_text(candidate.get("type"), "유형 미상")
    endpoint = _safe_text(candidate.get("affected_endpoint"), "확인 필요")
    confidence = _report_text(_safe_text(candidate.get("confidence"), "unknown"))
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
        f"- 점검 유형: {_report_text(kind)}",
        f"- 대상 요청: {endpoint}",
        f"- {profile.confidence_label}: {confidence}",
        f"- 직접 확인 필요: {'예' if manual_required else '아니요'}",
        f"- 근거 번호: {', '.join(evidence_ids) if evidence_ids else '없음'}",
        "",
        "### 근거 신뢰도 설명",
    ]
    lines.extend(_bullets(confidence_rationale, profile.confidence_fallback))
    lines.extend([
        "",
        "### 위험도 초안",
    ])
    lines.extend(_bullets(risk_rating_draft, "심각도를 정하기 전에 별도로 위험을 평가하세요."))
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
            "해당 환경에서 필요한 보안 헤더가 빠져 있다면 브라우저의 보호 기능이 줄어들 수 있습니다."
        ],
        "weak_cookie_attributes": [
            "인증이나 로그인 상태 유지에 쓰는 쿠키라면 보호 속성 누락으로 위험이 커질 수 있습니다."
        ],
        "cache_control_on_authenticated_response": [
            "사용자별 정보가 담긴 응답이라면 의도하지 않은 곳에 임시 저장될 수 있습니다."
        ],
        "cors_candidate": [
            "다른 출처에서 인증 정보를 포함한 요청이 재현된다면 허용하지 않은 출처에 정보가 노출될 수 있습니다."
        ],
        "error_exposure": [
            "운영 환경에서도 재현된다면 자세한 오류 메시지를 통해 내부 구현 정보가 드러날 수 있습니다."
        ],
        "idor_candidate": [
            "식별자만 바꿔 다른 사용자의 자료에 접근할 수 있다면 접근 권한 검사에 문제가 있을 수 있습니다."
        ],
        "sensitive_data_exposure_candidate": [
            "사용자의 권한이나 업무에 필요하지 않은 항목이라면 불필요한 정보가 응답에 포함될 수 있습니다."
        ],
    }
    consultant = {
        "missing_security_headers": [
            "실제 서비스 경로에서도 보안 헤더 누락이 확인된다면 사용자의 브라우저 보호 기능이 줄어들 수 있습니다."
        ],
        "weak_cookie_attributes": [
            "인증이나 로그인 상태 유지에 쓰는 쿠키라면 보호 속성 누락으로 위험이 커질 수 있습니다."
        ],
        "cache_control_on_authenticated_response": [
            "사용자별 응답이라면 브라우저나 중간 캐시에 정보가 의도치 않게 저장될 수 있습니다."
        ],
        "cors_candidate": [
            "다른 출처에서 인증 정보를 포함한 요청이 재현된다면 허용하지 않은 출처가 보호된 응답을 읽을 수 있습니다."
        ],
        "error_exposure": [
            "운영 환경에서도 재현된다면 자세한 오류 메시지가 추가 공격에 활용될 내부 정보를 드러낼 수 있습니다."
        ],
        "idor_candidate": [
            "다른 사용자의 자료에 접근하는 문제가 재현된다면 자료별 접근 권한 검사가 부족할 수 있습니다."
        ],
        "sensitive_data_exposure_candidate": [
            "사용자의 권한이나 업무에 필요하지 않은 항목이라면 필요한 범위보다 많은 정보가 응답에 포함될 수 있습니다."
        ],
    }
    impacts = consultant if profile_name == "consultant" else conservative
    return impacts.get(kind, ["실제 영향은 직접 확인해야 합니다."])


def _remediation_draft(kind: str, profile_name: str) -> list[str]:
    conservative = {
        "missing_security_headers": [
            "애플리케이션이나 앞단 서버에 적절한 보안 헤더를 설정하고 운영 환경에서도 적용되는지 확인하세요."
        ],
        "weak_cookie_attributes": [
            "쿠키 용도에 맞게 Secure, HttpOnly, SameSite 보호 속성을 설정하세요."
        ],
        "cache_control_on_authenticated_response": [
            "로그인한 사용자별 응답에는 용도에 맞는 no-store, no-cache, private 캐시 정책을 적용하세요."
        ],
        "cors_candidate": [
            "허용 출처를 제한하고, 꼭 필요한 경우가 아니면 다른 출처의 인증 정보 포함 요청을 허용하지 마세요."
        ],
        "error_exposure": [
            "사용자에게는 간단한 오류만 보여주고, 자세한 진단 정보는 접근이 제한된 서버 로그에만 남기세요."
        ],
        "idor_candidate": [
            "자료에 접근할 때마다 서버에서 로그인한 사용자와 자료 소유자를 기준으로 권한을 확인하세요."
        ],
        "sensitive_data_exposure_candidate": [
            "응답에는 필요한 정보만 담고, 권한에 따라 표시할 항목을 제한하세요."
        ],
    }
    consultant = {
        "missing_security_headers": [
            "필요한 보안 헤더 정책을 정해 일관되게 적용하고 실제 서비스 경로에서 확인하세요."
        ],
        "weak_cookie_attributes": [
            "쿠키 용도를 확인한 뒤 Secure, HttpOnly, SameSite 보호 속성을 알맞게 설정하세요."
        ],
        "cache_control_on_authenticated_response": [
            "로그인한 사용자별 정보가 담긴 응답에는 용도에 맞는 no-store, no-cache, private 캐시 정책을 적용하세요."
        ],
        "cors_candidate": [
            "신뢰하는 출처만 허용하고, 꼭 필요한 경우가 아니면 다른 출처의 인증 정보 포함 요청을 차단하세요."
        ],
        "error_exposure": [
            "사용자에게는 간단한 오류만 보여주고, 자세한 진단 정보는 접근이 제한된 서버 로그에 남기세요."
        ],
        "idor_candidate": [
            "자료를 조회할 때마다 서버에서 로그인한 사용자의 접근 권한을 확인하세요."
        ],
        "sensitive_data_exposure_candidate": [
            "응답 구조를 검토하고 사용자 권한과 업무에 꼭 필요한 항목만 반환하세요."
        ],
    }
    remediations = consultant if profile_name == "consultant" else conservative
    return remediations.get(kind, ["서버의 접근 제어와 보안 설정을 확인하세요."])


def _risk_rating_draft_lines(value: Any) -> list[str]:
    if not isinstance(value, dict):
        return ["심각도를 정하기 전에 별도로 위험을 평가하세요."]
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
        f"평가 상태: {_report_text(status)}",
        f"평가 기준: {_report_text(risk_profile)} / {_report_text(profile_conservatism)}",
        f"발생 가능성: {_report_text(likelihood)} / 영향: {_report_text(impact)} / 심각도: {_report_text(severity)} (모두 초안)",
        f"위험도 확정: {_report_text(finalized)}",
        f"근거 신뢰도를 심각도로 사용: {_report_text(confidence_is_severity)}",
    ]
    lines.extend(basis or ["심각도 초안을 사용하기 전에 직접 확인하세요."])
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


_REPORT_TEXT = {
    "low": "낮음",
    "medium": "보통",
    "high": "높음",
    "unknown": "확인 필요",
    "true": "예",
    "false": "아니요",
    "conservative": "보수적 검토",
    "consultant": "상세 검토",
    "strict": "집중 검토",
    "most_cautious": "신중하게 판단",
    "balanced_draft": "검토용 기준",
    "higher_attention": "우선 확인할 항목을 넓게 선정",
    "draft_requires_manual_verification": "직접 확인이 필요한 초안",
    "missing_security_headers": "보안 헤더 누락",
    "Missing security headers": "보안 헤더 누락",
    "weak_cookie_attributes": "쿠키 보호 설정 확인",
    "Weak cookie attributes": "쿠키 보호 설정 확인",
    "cache_control_on_authenticated_response": "로그인 응답의 캐시 설정 확인",
    "Cache-Control issue on authenticated-looking response": "로그인 응답의 캐시 설정 확인",
    "cors_candidate": "다른 출처의 접근 허용 설정 확인 (CORS)",
    "CORS misconfiguration candidate": "다른 출처의 접근 허용 설정 확인 (CORS)",
    "error_exposure": "오류 메시지의 내부 정보 노출 확인",
    "Error message exposure candidate": "오류 메시지의 내부 정보 노출 확인",
    "idor_candidate": "다른 사용자 자료에 대한 접근 권한 확인 (IDOR)",
    "Potential Broken Access Control / IDOR": "다른 사용자 자료에 대한 접근 권한 확인 (IDOR)",
    "sensitive_data_exposure_candidate": "응답의 민감정보 포함 여부 확인",
    "Sensitive data exposure candidate": "응답의 민감정보 포함 여부 확인",
    "Passive single-response header observation only.": "한 번의 응답에서 보안 헤더만 확인한 결과입니다.",
    "Headers may be added by an upstream proxy or environment-specific edge layer.": "앞단 프록시나 환경별 서버 설정에서 헤더를 추가할 수도 있습니다.",
    "Confirm whether the endpoint is served over HTTPS in the target environment.": "점검 환경에서 해당 요청이 HTTPS로 제공되는지 확인하세요.",
    "Check whether headers are added by an upstream proxy for production traffic.": "운영 환경의 앞단 프록시에서 헤더를 추가하는지 확인하세요.",
    "Only Set-Cookie attribute metadata was used; cookie values were not inspected.": "쿠키 값은 읽지 않고 Set-Cookie의 보호 속성만 확인했습니다.",
    "Confirm the cookie is used for authentication or session state.": "인증이나 로그인 상태 유지에 쓰는 쿠키인지 확인하세요.",
    "Verify Secure, HttpOnly, and SameSite behavior in a browser with HTTPS.": "HTTPS 브라우저에서 Secure, HttpOnly, SameSite 속성이 작동하는지 확인하세요.",
    "CORS headers were observed in sanitized response metadata.": "민감정보를 제거한 응답 자료에서 CORS 헤더를 확인했습니다.",
    "Browser enforcement and authenticated cross-origin behavior require manual reproduction.": "브라우저의 실제 차단 여부와 다른 출처의 인증 정보 포함 요청을 직접 확인해야 합니다.",
    "CORS response allows a wildcard origin or credentialed cross-origin access.": "모든 출처 또는 인증 정보를 포함한 다른 출처의 요청을 허용하는 설정이 보입니다.",
    "Manual origin and credential checks are required before confirming impact.": "영향을 판단하기 전에 허용 출처와 인증 정보 처리 방식을 직접 확인하세요.",
    "Send requests with an attacker-controlled Origin value.": "허가된 점검 환경에서 외부 출처를 가정한 Origin 헤더로 요청해 보세요.",
    "Check whether credentials are accepted cross-origin for authenticated endpoints.": "로그인이 필요한 요청에 다른 출처의 인증 정보가 허용되는지 확인하세요.",
    "Authenticated-looking request signal was observed after redaction.": "정리된 기록에 인증 정보를 사용했다는 표시가 있습니다.",
    "No no-store, no-cache, or private Cache-Control policy was observed.": "Cache-Control에서 no-store, no-cache, private 설정이 확인되지 않았습니다.",
    "Request appears authenticated and response did not include no-store, no-cache, or private Cache-Control policy.": "인증 정보를 사용한 것으로 보이는 응답에 no-store, no-cache, private 캐시 설정이 없습니다.",
    "Confirm the response contains user-specific data.": "응답에 사용자별 정보가 담겨 있는지 확인하세요.",
    "Check browser, proxy, and CDN cache behavior for authenticated requests.": "로그인한 요청이 브라우저, 프록시, CDN에 어떻게 저장되는지 확인하세요.",
    "Passive error status or sanitized error snippet signal only.": "오류 상태나 민감정보를 제거한 오류 문구만 확인한 결과입니다.",
    "Production error handling may differ and must be reproduced safely.": "운영 환경의 오류 처리는 다를 수 있으므로 안전한 조건에서 재현해야 합니다.",
    "Response indicates a server error or includes a sanitized error snippet.": "서버 오류 상태 또는 민감정보를 제거한 오류 문구가 응답에 있습니다.",
    "Reproduce the error with safe input and check whether stack traces or internal paths are exposed.": "안전한 입력으로 오류를 재현하고 호출 내역이나 내부 경로가 드러나는지 확인하세요.",
    "Confirm whether production error handling differs from the test environment.": "운영 환경과 테스트 환경의 오류 처리 방식이 다른지 확인하세요.",
    "Identifier, authenticated-looking request, HTTP 2xx, and user-specific response signals were all observed.": "식별자, 인증 정보 사용 흔적, 성공 응답(HTTP 2xx), 사용자별 응답 구조가 함께 확인됐습니다.",
    "Cross-user or cross-role access was not tested and must be manually verified.": "다른 사용자나 권한으로 접근하는 검사는 하지 않았으므로 직접 확인해야 합니다.",
    "Identifier parameter observed in path or query.": "요청 경로나 매개변수에 식별자가 있습니다.",
    "Authenticated-looking request returned HTTP 2xx.": "인증 정보를 사용한 것으로 보이는 요청이 성공 응답(HTTP 2xx)을 받았습니다.",
    "Response body shape contains user-specific fields.": "응답 구조에 사용자별 정보 항목이 있습니다.",
    "Manual verification is required with different user roles.": "서로 다른 권한의 계정으로 직접 확인해야 합니다.",
    "Compare the response using user A and user B sessions.": "서로 다른 두 테스트 계정으로 응답을 비교하세요.",
    "Check whether user A can access user B resources by changing only the identifier.": "식별자만 바꿨을 때 다른 테스트 계정의 자료에 접근할 수 있는지 확인하세요.",
    "Verify server-side authorization independently of UI controls.": "화면에서 버튼을 숨기는 것과 별개로 서버에서 접근 권한을 검사하는지 확인하세요.",
    "Response schema contains sanitized sensitive-field markers.": "응답 구조에 민감정보를 제거한 항목 표시가 있습니다.",
    "Business necessity and role visibility must be manually reviewed.": "업무상 필요한 정보인지, 해당 권한에서 보여도 되는지 직접 검토해야 합니다.",
    "Response schema contains fields that required redaction.": "응답 구조에 민감정보 제거 대상 항목이 있습니다.",
    "Confirm whether each sensitive field is necessary for the endpoint's intended purpose.": "각 민감정보 항목이 해당 기능에 꼭 필요한지 확인하세요.",
    "Check role-based access and data minimization requirements.": "권한별 접근 범위와 필요한 정보만 반환하는지 확인하세요.",
    "Vulnerability confirmed": "취약점이 확인됐다는 단정",
    "Privilege escalation confirmed": "권한 상승이 확인됐다는 단정",
    "Data breach confirmed": "정보 유출이 확인됐다는 단정",
    "Token reuse confirmed": "토큰 재사용이 확인됐다는 단정",
    "Severity decision made": "심각도 판단이 끝났다는 단정",
    "Risk rating completed": "위험도 평가가 끝났다는 단정",
    "Exploitability proven": "공격 가능성이 입증됐다는 단정",
    "Draft severity uses likelihood and impact placeholders, not evidence confidence.": "심각도 초안은 발생 가능성과 예상 영향을 기준으로 하며, 근거 신뢰도와는 다릅니다.",
    "Browser defense-in-depth impact is deployment-specific and must be checked in the target path.": "브라우저 보호에 미치는 영향은 배포 환경에 따라 다르므로 실제 서비스 경로에서 확인해야 합니다.",
    "Cookie purpose and session sensitivity must be confirmed before impact can be finalized.": "영향을 확정하기 전에 쿠키 용도와 로그인 상태에 미치는 영향을 확인해야 합니다.",
    "Authenticated response caching impact depends on whether user-specific data is present and cacheable.": "캐시의 영향은 사용자별 정보가 담겨 있는지와 실제 저장 여부에 따라 달라집니다.",
    "Cross-origin impact requires browser reproduction with origin and credential behavior verified.": "브라우저에서 출처와 인증 정보 처리 방식을 확인하며 재현해야 영향을 판단할 수 있습니다.",
    "Verbose error impact depends on production behavior and whether implementation details are exposed.": "오류 메시지의 영향은 운영 환경의 동작과 내부 구현 정보의 노출 여부에 따라 달라집니다.",
    "Object-level authorization impact requires cross-user or cross-role reproduction before severity is final.": "자료별 접근 권한 문제의 심각도는 다른 사용자나 권한으로 재현한 뒤 판단해야 합니다.",
    "Data exposure impact depends on business necessity, role visibility, and manual data minimization review.": "정보 노출의 영향은 업무상 필요성, 권한별 표시 범위, 불필요한 정보 포함 여부를 검토해 판단해야 합니다.",
    "Conservative profile preserves the cautious passive-signal baseline.": "보수적 검토는 기록에서 관찰한 단서만으로 신중하게 평가합니다.",
    "Consultant profile keeps draft values readable for report review without finalizing severity.": "상세 검토용 수치도 심각도를 확정한 값은 아닙니다.",
    "Strict profile increases draft likelihood sensitivity for manual triage, but still does not finalize severity.": "집중 검토는 우선 확인할 항목을 넓게 잡지만 심각도를 확정하지는 않습니다.",
    "Manual verification and a separate risk rating review are required before using the severity draft.": "심각도 초안을 사용하기 전에 직접 재현하고 별도로 위험을 평가해야 합니다.",
    "Manual risk rating is required because no passive rule risk profile matched this candidate type.": "이 점검 유형에는 정해진 평가 기준이 없으므로 직접 위험을 평가해야 합니다.",
}


def _report_text(text: str) -> str:
    # Translate only known generated text; keep unrecognized evidence intact.
    if text in _REPORT_TEXT:
        return _REPORT_TEXT[text]
    patterns = (
        (r"Response did not include: (.+)\.", "응답에 없는 보안 헤더: {}"),
        (r"Set-Cookie for (.+) is missing: (.+)\.", "쿠키 {}에 없는 보호 속성: {}"),
        (r"Redacted field count: ([0-9]+)\.", "민감정보 제거 대상 항목 수: {}개"),
    )
    for pattern, template in patterns:
        match = re.fullmatch(pattern, text)
        if match:
            return template.format(*match.groups())
    match = re.fullmatch(r"Confidence remains (low|medium|high) until cookie purpose is manually confirmed\.", text)
    if match:
        return f"쿠키 용도를 직접 확인하기 전의 근거 신뢰도: {_REPORT_TEXT[match.group(1)]}"
    boolean_labels = {
        "Credentialed CORS marker observed": "CORS 인증 정보 허용 표시",
        "User-specific response signal observed": "사용자별 응답 단서",
        "Authenticated or user-specific context observed": "인증 정보 사용 또는 사용자별 응답 단서",
        "Session-like cookie name signal observed": "로그인 상태 유지용으로 보이는 쿠키 이름",
        "Missing high-impact attributes observed": "Secure 또는 HttpOnly 속성 누락",
    }
    for label, translated in boolean_labels.items():
        for value, display in (("True", "있음"), ("False", "없음")):
            if text == f"{label}: {value}.":
                return f"{translated}: {display}"
    return text


def _bullets(values: list[str], fallback: str) -> list[str]:
    items = values or [fallback]
    return [f"- {_report_text(item)}" for item in items]
