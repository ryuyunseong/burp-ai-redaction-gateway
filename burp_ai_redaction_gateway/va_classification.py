from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class VaCategory:
    code: str
    title: str
    subcategories: tuple[str, ...] = ()


VA_CATALOG = (
    VaCategory("VA-01", "코드 인젝션 (Code Injection)", ("Code Injection",)),
    VaCategory("VA-02", "SQL 인젝션 (SQL Injection)", ("SQL Injection",)),
    VaCategory("VA-03", "디렉터리 인덱싱", ("디렉터리 인덱싱",)),
    VaCategory("VA-04", "에러 페이지 적용 미흡", ("에러정보 노출",)),
    VaCategory("VA-05", "정보 누출", (
        "불필요한 파일 노출", "서버정보 노출", "Front-End/API 응답 범위 설계 오류", "Config / Secret 정보 노출",
    )),
    VaCategory("VA-06", "크로스사이트 스크립트", ("저장형 XSS", "반사형 XSS", "DOM 기반 XSS", "설정 미흡 기반 XSS")),
    VaCategory("VA-07", "크로스사이트 요청 위조 (CSRF)", ("CSRF",)),
    VaCategory("VA-08", "서버사이드 요청 위조 (SSRF)", ("SSRF",)),
    VaCategory("VA-09", "약한 비밀번호 정책", (
        "패스워드 복잡도 정책 준수 미흡", "기존 패스워드 재사용", "비밀번호 사용기한 제한", "계정 초기 패스워드 설정",
    )),
    VaCategory("VA-10", "불충분한 인증 절차", (
        "사용자정보 변경 페이지 접근 시 재인증 절차 없음", "인증 프로세스 end-point 강제 호출", "부적절한 입력값 기반 인증 우회",
    )),
    VaCategory("VA-11", "불충분한 권한 검증", ("수평/수직 권한 이동", "(mobile) 애플리케이션 영역 권한설정 미흡")),
    VaCategory("VA-12", "취약한 비밀번호 복구 절차", ("취약한 비밀번호 복구 절차", "사용자정보 변경 후 재인증 절차 없음")),
    VaCategory("VA-13", "프로세스 검증 누락", ("프로세스 검증 누락",)),
    VaCategory("VA-14", "악성 파일 업로드", ("웹셸 업로드", "부적절한 파일업로드 (미실행)", "악성파일 업로드 (정상확장자)")),
    VaCategory("VA-15", "파일 다운로드", ("파일 다운로드",)),
    VaCategory("VA-16", "불충분한 세션 관리", ("부적절한 중요정보 저장", "세션 쿠키 보안 헤더 설정 미흡", "세션 유효성 관리 미흡")),
    VaCategory("VA-17", "데이터 평문 전송", ("전송구간 암호화 미적용 / 강제 적용 미흡",)),
    VaCategory("VA-18", "쿠키 변조", ("쿠키 변조",)),
    VaCategory("VA-19", "관리자 페이지 노출", ("관리자 페이지 외부 노출", "WAS / DB / OS 기본계정 사용 여부 점검")),
    VaCategory("VA-20", "자동화 공격", ("자동화 공격", "패스워드 오류 임계값 미적용")),
    VaCategory("VA-21", "불필요한 Method 악용", ("불필요한 웹 메서드 허용",)),
    VaCategory("VA-22", "불필요한 포트 오픈"),
    VaCategory("VA-23", "HTTPS 알고리즘 적용 미흡", ("HTTPS 암호화 설정 미흡",)),
    VaCategory("VA-24", "소스코드 난독화 미적용"),
    VaCategory("VA-25", "앱 무결성 검증 미흡"),
    VaCategory("VA-26", "동적 디버깅 가능"),
    VaCategory("VA-27", "루팅, 탈옥단말 실행 차단 미흡"),
    VaCategory("VA-28", "Deeplink 도용 취약점"),
    VaCategory("VA-29", "개발기 외부 노출"),
    VaCategory("VA-30", "2차 인증 우회"),
)
VA_BY_CODE = {item.code: item for item in VA_CATALOG}

# These associate passive observations with review areas, not confirmed vulnerabilities.
_RULES = {
    "idor_candidate": (
        "VA-11", "수평/수직 권한 이동", "candidate",
        "계정별 역할과 자료 소유권을 비교해야 하며, 권한 이동이 확인된 것은 아닙니다.",
    ),
    "weak_cookie_attributes": (
        "VA-16", "세션 쿠키 보안 헤더 설정 미흡", "candidate",
        "쿠키 용도와 브라우저 동작을 확인해야 합니다. 보호 속성의 누락과 설정값을 구분합니다.",
    ),
    "error_exposure": (
        "VA-04", "에러정보 노출", "candidate",
        "오류 상태만으로 정보 노출을 확정하지 말고 실제 오류 응답에 내부 정보가 있는지 확인하세요.",
    ),
    "sensitive_data_exposure_candidate": (
        "VA-05", None, "candidate",
        "업무상 필요한 반환 범위인지 확인해야 합니다. 하위 분류는 자료만으로 정하지 않습니다.",
    ),
    "cors_candidate": (
        "VA-05", None, "reference",
        "CORS 설정만으로 정보 누출을 판정하지 않습니다. 브라우저에서 허용되지 않은 응답을 읽을 수 있는지 확인하세요.",
    ),
    "cache_control_on_authenticated_response": (
        "VA-05", None, "reference",
        "캐시 설정만으로 정보 누출을 판정하지 않습니다. 다른 계정에 보호된 내용이 실제로 노출되는지 확인하세요.",
    ),
}
RELATION_LABELS = {"candidate": "검토 후보", "reference": "참고 분류", "unmapped": "분류 미정"}
SCOPE_LABELS = {"candidate": "관련 후보 있음", "reference": "참고 신호만 있음", "not_assessed": "미점검"}


def classify_candidate(kind: Any) -> dict[str, Any]:
    rule = _RULES.get(kind) if isinstance(kind, str) else None
    if rule is None:
        reason = ("헤더 누락만으로 XSS·CSRF·평문 전송을 판정하지 않습니다."
                  if isinstance(kind, str) and kind == "missing_security_headers"
                  else "현재 기록만으로 VA 항목을 정할 수 없습니다. 별도 점검 후 분류하세요.")
        return {
            "code": None, "title": None, "subcategory": None, "relation": "unmapped",
            "reason": reason,
        }
    code, subcategory, relation, reason = rule
    return {"code": code, "title": VA_BY_CODE[code].title, "subcategory": subcategory, "relation": relation, "reason": reason}


def va_label(kind: Any) -> str:
    classification = classify_candidate(kind)
    if classification["code"] is None:
        return "VA 분류 미정"
    return f"{classification['code']} {classification['title']} ({RELATION_LABELS[classification['relation']]})"


def catalog_scope(kinds: list[str]) -> dict[str, str]:
    scope = {item.code: "not_assessed" for item in VA_CATALOG}
    priority = {"not_assessed": 0, "reference": 1, "candidate": 2}
    for kind in kinds:
        classification = classify_candidate(kind)
        code, relation = classification["code"], classification["relation"]
        if code is not None and priority[relation] > priority[scope[code]]:
            scope[code] = relation
    return scope
