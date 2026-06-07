# GUI AI 안전 사전 점검

이 문서는 dashboard의 AI 안전 사전 점검 화면을 설명합니다. 이 화면은
검증된 output이 수동 AI 검토 후보인지 확인하는 조회 전용 체크리스트입니다.
파일을 생성하거나, archive 작업을 실행하거나, 설정을 바꾸거나, 외부 서비스로
데이터를 전송하지 않습니다.

`verify`를 통과한 뒤, ChatGPT, Codex, PR, 이슈, 문서에 어떤 파일을 넣기 전
이 화면으로 상태를 확인합니다.

파일 순서, 목적, 크기, 수정 시각, SHA-256 metadata 화면은
[GUI_AI_HANDOFF_INDEX.md](C:/coding/burp-ai-redaction-gateway/docs/GUI_AI_HANDOFF_INDEX.md)를
참조하세요. finding 후보 triage metadata와 수동 검토 경계는
[GUI_FINDING_TRIAGE_INDEX.md](C:/coding/burp-ai-redaction-gateway/docs/GUI_FINDING_TRIAGE_INDEX.md)를
참조하세요. 보고서 초안 준비 상태와 수동 검토 경계는
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

## 화면 열기

output 상세 화면에서 다음 주소를 엽니다.

```text
/preflight?project=<alias>
```

output 상세 화면에도 사전 점검 화면 링크가 있습니다. 이 링크는 조회 전용
GET 이동이며 POST action이 아닙니다.

## 표시 항목

사전 점검 화면은 alias와 상태 metadata만 표시합니다.

| 상태 | 의미 |
| --- | --- |
| `analysis_packet.json` | 존재 여부 |
| `chatgpt_prompt.md` | 존재 여부 |
| `codex_task_prompt.md` | 존재 여부 |
| `report_draft.md` | 존재 여부 |
| `verify status` | 선택한 output이 fail-closed 검증을 통과했는지 여부 |
| `verify files checked` | verifier가 확인한 파일 수 |
| `finding candidate count` | 안전 output 안의 finding 후보 수 |
| `forbidden marker scan` | 안전 파일 4개에 대한 금지 마커 스캔 요약 |
| `raw_data_included` | 항상 `false` |

`ready candidate` 상태는 안전 파일 4개가 있고 해당 파일에서 금지 마커가
발견되지 않았다는 뜻입니다. 정확성 보장이나 finding 공개 판단을 의미하지
않습니다.

## AI 검토 후보 파일

다음 파일만 `verify` 통과 후 AI 검토 후보로 볼 수 있습니다.

```text
analysis_packet.json
chatgpt_prompt.md
codex_task_prompt.md
report_draft.md
```

먼저 `verify`를 통과해야 하며, 이후에도 사람이 수동으로 검토해야 합니다.

## 넣거나 기록하지 않을 값

다음 값은 붙여넣기, 업로드, 커밋, 문서화 대상이 아닙니다.

| 분류 | 이유 |
| --- | --- |
| raw request 또는 raw response 데이터 | 민감값이 포함될 수 있음 |
| Cookie 또는 Authorization 값 | 인증 자료 |
| token, JWT, session 값 | 세션 또는 인증정보 |
| 실제 domain, URL, IP 값 | 환경 식별 정보 |
| 개인정보 | 식별 또는 프라이버시 민감 정보 |
| HMAC secret 또는 CSRF token 값 | 로컬 보안 제어값 |
| local-only raw 저장소 또는 검증 전 output 산출물 | AI 입력 자료가 아님 |
| audit log, archive, manifest | 운영 증거 자료이며 AI 입력 자료가 아님 |

## 해석 경계

사전 점검은 상태 확인이며 취약점 판정이 아닙니다.

- finding은 수동 검증이 끝날 때까지 `candidate`입니다.
- `risk_rating_draft`는 초안이며 확정 심각도가 아닙니다.
- `confidence`는 증거 신뢰도이며 severity가 아닙니다.
- 심각도 결정은 권한 있는 재현, 역할별 비교, 업무 영향 검토, 별도 수동
  판단이 필요합니다.
- CVSS는 별도 산정 범위입니다.

## 조회 전용 경계

사전 점검 화면은 다음 기능을 제공하지 않습니다.

- form 제출
- POST action
- 상태 변경 버튼
- raw viewer
- replay 또는 active scan
- archive 또는 HMAC 실행
- HMAC secret 입력
- CSRF token 표시
- 파일 삭제 또는 retention 변경
- risk profile 변경

## 문제 해결

| 상태 | 의미 | 다음 조치 |
| --- | --- | --- |
| `missing safe files` | 안전 파일 4개 중 하나 이상이 없음 | 검증된 dashboard action 또는 CLI 명령으로 필요한 파일을 생성합니다. |
| `forbidden marker found` | 안전 파일 후보에 조사할 마커가 있음 | 해당 output을 AI에 사용하지 말고 `verify`를 다시 실행한 뒤 로컬에서 확인합니다. |
| `needs manual review` | AI 핸드오프 후보로 해석하기 전 수동 검토가 필요함 | 파일을 사용하기 전 로컬 검토를 완료합니다. |
| `report_draft.md` is missing | 이 output에 대해 보고서 초안 생성이 아직 실행되지 않음 | `verify` 통과 후 보고서 초안을 생성합니다. |
