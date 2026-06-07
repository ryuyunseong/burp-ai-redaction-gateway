# GUI Finding Triage 인덱스

이 문서는 dashboard의 finding triage 인덱스를 설명합니다. 인덱스는
선택한 output이 검증을 통과한 뒤 sanitization 완료 finding 후보를 확인하는
조회 전용 triage 체크리스트입니다.

인덱스는 확정 화면이 아닙니다. 심각도를 결정하거나, 영향을 증명하거나,
파일을 만들거나, 설정을 바꾸거나, dashboard action을 실행하지 않습니다.

## 화면 열기

검증된 output 상세 화면에서 다음 주소를 엽니다.

```text
/triage?project=<alias>
```

이 화면은 조회 전용 GET 페이지입니다. 데이터를 제출하거나, 파일을 만들거나,
다운로드하거나, 삭제하거나, review/report/export/archive/HMAC/replay/
active scan action을 실행하지 않습니다.

보고서 초안 준비 metadata와 수동 검토 경계는
[GUI_REPORT_READINESS_INDEX.md](C:/coding/burp-ai-redaction-gateway/docs/GUI_REPORT_READINESS_INDEX.md)를
참조하세요. prompt 파일 투입 전 점검은
[GUI_PROMPT_READINESS_INDEX.md](C:/coding/burp-ai-redaction-gateway/docs/GUI_PROMPT_READINESS_INDEX.md)를
참조하세요. 정제 evidence와 raw 금지 범위 경계는
[GUI_EVIDENCE_BOUNDARY_INDEX.md](C:/coding/burp-ai-redaction-gateway/docs/GUI_EVIDENCE_BOUNDARY_INDEX.md)를
참조하세요. 전체 조회 전용 workflow 체크리스트는
[GUI_WORKFLOW_STATUS_INDEX.md](C:/coding/burp-ai-redaction-gateway/docs/GUI_WORKFLOW_STATUS_INDEX.md)를
참조하세요. 수집부터 AI 투입 전 수동 검토까지 운영 순서는
[GUI_OPERATOR_RUNBOOK_INDEX.md](C:/coding/burp-ai-redaction-gateway/docs/GUI_OPERATOR_RUNBOOK_INDEX.md)를
참조하세요. safe files 4개 inventory는
[GUI_SAFE_FILE_INVENTORY_INDEX.md](C:/coding/burp-ai-redaction-gateway/docs/GUI_SAFE_FILE_INVENTORY_INDEX.md)를
참조하세요.

## 표시 항목

triage 인덱스는 안전한 후보 metadata만 표시합니다.

- project alias
- finding candidate count
- candidate index와 stable candidate id
- category/type
- title
- sanitized summary
- evidence confidence
- draft risk profile
- severity draft, likelihood draft, impact draft
- manual review required 상태
- `analysis_packet.json` 존재 여부
- `report_draft.md` 존재 여부
- preflight, handoff, report readiness, output 상세 flow 링크

sanitized summary에는 method와 path template이 포함될 수 있습니다. 실제
domain, 실제 URL, 실제 IP 주소, Cookie 값, Authorization 값, token,
session, 개인정보를 포함하면 안 됩니다.

## 해석 경계

- 모든 항목은 수동 검증이 끝날 때까지 candidate finding입니다.
- evidence confidence는 severity가 아닙니다.
- draft risk는 운영자 보조 정보이며 severity 결정이 아닙니다.
- 심각도 결정은 권한 있는 재현, 역할별 비교, 영향 검토, 별도 risk review
  후 사람이 수행합니다.
- CVSS는 별도 산정 범위입니다.

## Triage에서 쓰지 않을 값

다음 값은 붙여넣기, 업로드, 커밋, 문서화 대상이 아닙니다.

| 분류 | 이유 |
| --- | --- |
| raw request 또는 raw response 데이터 | 민감값이 포함될 수 있음 |
| Cookie 또는 Authorization 값 | 인증 자료 |
| token, JWT, session 값 | 세션 또는 인증정보 |
| 실제 domain, URL, IP 값 | 환경 식별 정보 |
| 개인정보 | 식별 또는 프라이버시 민감 정보 |
| HMAC secret 또는 CSRF token 값 | 로컬 보안 제어값 |
| full local path | 로컬 환경 식별 정보 |
| `local_only/`, `raw/`, `raw_vault/`, 검증 전 `out/`, `out/.audit` 산출물 | AI 또는 triage 입력 자료가 아님 |

## 조회 전용 경계

triage 인덱스는 다음 기능을 제공하지 않습니다.

- form 제출
- POST action
- 상태 변경 버튼
- file body preview
- finding body preview
- request preview
- response preview
- 새 download action
- raw viewer
- replay 또는 active scan
- archive 또는 HMAC 실행
- HMAC secret 입력
- CSRF token 표시
- 파일 삭제 또는 retention 변경
- risk profile 변경

이 화면은 조회 전용 triage 체크리스트로만 사용합니다.

## 문제 해결

| 증상 | 의미 | 다음 조치 |
| --- | --- | --- |
| Candidate count가 0 | 선택한 output에 finding 후보가 없음 | 필요하면 검증 후 `analysis_packet.json`을 로컬에서 검토합니다. |
| `analysis_packet.json` 없음 | 선택한 output이 불완전함 | 다시 생성하거나 안전 dashboard flow를 다시 실행합니다. |
| `report_draft.md` 없음 | 이 output에 대해 report action이 아직 실행되지 않음 | 초안이 필요하면 검증된 output 상세 화면에서 Report를 실행합니다. |
| Triage page가 차단됨 | output 검증 실패 또는 금지 alias | `verify`를 실행하고 dashboard에 표시된 output alias만 사용합니다. |
