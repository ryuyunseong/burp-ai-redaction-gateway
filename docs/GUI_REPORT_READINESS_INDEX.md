# GUI 보고서 준비 상태 인덱스

이 문서는 dashboard의 보고서 준비 상태 인덱스를 설명합니다. 인덱스는
검증된 output 하나에 대한 보고서 초안 조회 전용 체크리스트입니다.

`report_draft.md`를 고객-facing 보고서 작업에 쓰기 전 사람이 검토할 항목을
확인하는 용도입니다. 보고서 제출 게이트가 아니며 severity를 확정하지
않습니다.

전체 조회 전용 workflow 체크리스트는
[GUI_WORKFLOW_STATUS_INDEX.md](C:/coding/burp-ai-redaction-gateway/docs/GUI_WORKFLOW_STATUS_INDEX.md)를
참조하세요. prompt 파일 투입 전 점검은
[GUI_PROMPT_READINESS_INDEX.md](C:/coding/burp-ai-redaction-gateway/docs/GUI_PROMPT_READINESS_INDEX.md)를
참조하세요.

검증된 output에서 다음 주소를 엽니다.

```text
/report-readiness?project=<alias>
```

## 표시 metadata

인덱스는 안전 metadata만 표시합니다.

| 필드 | 의미 |
| --- | --- |
| `project alias` | 선택한 dashboard output alias |
| `draft report status` | `report_draft.md` 존재 여부 |
| `analysis_packet.json` | sanitization 완료 분석 packet 존재 여부 |
| `finding candidate count` | 검증된 output 안의 finding 후보 수 |
| `draft report status summary` | 수동 검토 계획을 위한 짧은 상태 문구 |
| `triage link` | finding triage 인덱스 링크 |
| `preflight link` | AI 안전 사전 점검 체크리스트 링크 |
| `handoff link` | AI 핸드오프 인덱스 링크 |
| `prompt readiness link` | prompt 파일 점검 인덱스 링크 |
| `export/review/report flow link` | 검증된 output 상세 화면으로 돌아가는 링크 |

파일 metadata 섹션은 `report_draft.md`와 `analysis_packet.json`에 대해 다음
값만 표시할 수 있습니다.

- 존재 여부
- 크기(bytes)
- 수정 시각(UTC)
- SHA-256 파일 fingerprint

SHA-256 값은 파일 fingerprint이며 HMAC이 아닙니다. 이 화면은 HMAC secret
처리를 바꾸지 않고 HMAC secret을 표시하지 않습니다.

## 운영자 체크리스트

다음 항목은 사람이 검토할 질문입니다.

- scope 확인
- affected endpoint 확인
- evidence quality 확인
- false positive 가능성
- impact statement 검토
- remediation wording 검토
- severity 수동 결정
- 고객 제출 전 민감정보 검토

## 해석 경계

- finding은 수동 검증이 끝날 때까지 finding candidate입니다.
- Risk는 draft이며 severity 확정으로 취급하지 않습니다.
- Evidence confidence는 severity가 아닙니다.
- `report_draft.md`는 보고서 초안이며 제출용 보고서가 아닙니다.
- 심각도는 reviewer validation 뒤 사람이 수동으로 결정합니다.
- CVSS는 별도 산정 범위입니다.

## 보고서 준비 상태에서 쓰지 않을 값

다음 값은 화면, 문서, PR, AI 도구에 사용하거나 붙여넣지 않습니다.

- raw request 또는 raw response 데이터
- raw audit row 본문
- Cookie 또는 Authorization 값
- token, JWT, session 값
- 실제 domain, URL, IP 값
- 개인정보
- HMAC secret 또는 CSRF token 값
- full local path
- `local_only/`, `raw/`, `raw_vault/`, 검증 전 `out/`, `out/.audit` 산출물

## 조회 전용 경계

보고서 준비 상태 인덱스는 다음 기능을 제공하지 않습니다.

- form 또는 POST action
- 상태 변경 버튼
- report body preview
- request preview
- response preview
- 새 download action
- raw viewer
- replay 또는 active scan
- HMAC secret input UI
- retention 또는 delete action
- risk profile change action

## 문제 해결

| 증상 | 의미 | 다음 조치 |
| --- | --- | --- |
| `report_draft.md` 없음 | 이 output의 보고서 초안이 아직 생성되지 않음 | 검증된 output 상세 화면에서 Report를 실행하거나 CLI report 명령을 사용합니다. |
| `analysis_packet.json` 없음 | 선택한 output이 불완전하거나 유효한 검증 output이 아님 | 다시 생성하고 `verify`를 재실행한 뒤 검토합니다. |
| Finding candidate count가 0 | 이 output에서 후보가 생성되지 않음 | scope와 input coverage를 로컬에서 확인합니다. |
| SHA-256 없음 | 파일 자체가 없음 | 예상 검증 산출물을 다시 생성합니다. |
