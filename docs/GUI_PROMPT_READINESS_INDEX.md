# GUI Prompt Readiness 인덱스

이 문서는 dashboard의 prompt readiness 인덱스를 설명합니다. 인덱스는
검증된 output 하나에 대해 `chatgpt_prompt.md`와 `codex_task_prompt.md`를
AI에 넣기 전 상태를 확인하는 조회 전용 체크리스트입니다.

이 화면은 prompt 승인 화면, 자동 제출 화면, 안전 판정 화면이 아닙니다.
prompt 파일은 `verify`를 통과한 output에서 생성됐더라도 사람이 직접 읽고
검토해야 합니다.

검증된 output에서 다음 주소를 엽니다.

```text
/prompt-readiness?project=<alias>
```

## 표시 metadata

prompt readiness 인덱스는 안전 metadata만 표시합니다.

| 필드 | 의미 |
| --- | --- |
| `project alias` | 선택한 dashboard output alias |
| `chatgpt_prompt.md` | ChatGPT용 prompt 존재 여부 |
| `codex_task_prompt.md` | Codex용 prompt 존재 여부 |
| `analysis_packet.json` | sanitization 완료 후보 packet 존재 여부 |
| `report_draft.md` | 사람이 검토할 보고서 초안 존재 여부 |
| safe files 4개 | AI 투입 후보 allowlist |
| prompt 목적 | ChatGPT용 prompt와 Codex용 prompt의 차이 |
| 파일 크기(bytes) | 파일 본문 없이 크기만 표시 |
| 수정 시각(UTC) | 파일 본문 없이 수정 시각만 표시 |
| SHA-256 fingerprint | HMAC이 아닌 일반 파일 fingerprint |
| prompt readiness 점검 | prompt 본문을 화면에 표시하지 않는 내부 키워드 점검 요약 |

SHA-256 값은 HMAC이 아니며 secret을 사용하지 않습니다. 이 화면은 HMAC
secret 처리, audit HMAC 검증, compressed archive HMAC 검증을 바꾸지
않습니다.

## Prompt readiness 점검 항목

화면은 prompt 본문 preview를 제공하지 않습니다. 내부 점검 결과만 요약합니다.

- safe files 4개 언급 여부
- forbidden data warning 존재 여부
- verify-first warning 존재 여부
- candidate/draft/manual review boundary 존재 여부
- 최종 심각도 수동 결정 경고 존재 여부
- raw data prohibition warning 존재 여부
- Codex prompt에 작업 범위와 금지 범위가 구분되어 있는지
- ChatGPT prompt에 분석 목적과 수동 검토 경계가 구분되어 있는지

점검 결과가 `needs manual review`로 보이면 prompt 파일을 AI에 넣기 전에
사람이 해당 경계를 다시 확인해야 합니다.

## 권장 사용 순서

prompt 파일을 사용하기 전 다음 순서로 확인합니다.

```text
verify
-> AI-safe preflight
-> AI handoff index
-> workflow status index
-> prompt readiness index
-> finding triage index
-> report readiness index
-> manual review of selected safe files
```

관련 화면:

| 링크 | 목적 |
| --- | --- |
| `/preflight?project=<alias>` | safe files 4개와 금지 마커 상태 확인 |
| `/handoff?project=<alias>` | 안전 파일 목적, 순서, metadata 확인 |
| `/workflow?project=<alias>` | 전체 GUI 흐름 상태 확인 |
| `/triage?project=<alias>` | finding 후보와 수동 검토 경계 확인 |
| `/report-readiness?project=<alias>` | 보고서 초안 준비 경계 확인 |

## 해석 경계

- finding은 수동 검증이 끝날 때까지 candidate입니다.
- risk는 draft이며 severity 결정으로 취급하지 않습니다.
- evidence confidence는 severity가 아닙니다.
- 최종 심각도는 Burp 재현, 권한별 비교, 영향도 판단 후 사람이 결정합니다.
- `report_draft.md`는 초안이며 고객-facing 최종 보고서가 아닙니다.
- prompt 파일도 사람이 수동 검토한 뒤 필요한 내용만 사용해야 합니다.
- CVSS는 별도 산정 범위입니다.

## Prompt에 넣거나 기록하지 않을 값

다음 값은 prompt, 문서, PR, 이슈, AI 도구에 붙여넣거나 표시하지 않습니다.

| 분류 | 이유 |
| --- | --- |
| raw request 또는 raw response 데이터 | 민감값이 포함될 수 있음 |
| raw audit row 본문 | 운영 로그 원문 |
| Cookie 또는 Authorization 값 | 인증 자료 |
| token, JWT, session 값 | 세션 또는 인증정보 |
| 실제 domain, URL, IP 값 | 환경 식별 정보 |
| 개인정보 | 식별 또는 프라이버시 민감 정보 |
| HMAC secret 또는 CSRF token 값 | 로컬 보안 제어값 |
| full local path | 로컬 환경 식별 정보 |
| `local_only/`, `raw/`, `raw_vault/`, 검증 전 `out/`, `out/.audit` 산출물 | AI 입력 자료가 아님 |

## 조회 전용 경계

prompt readiness 인덱스는 다음 기능을 제공하지 않습니다.

- form 또는 POST action
- 상태 변경 버튼
- prompt body preview
- report body preview
- request preview
- response preview
- 새 download action
- raw viewer
- replay 또는 active scan
- HMAC secret input UI
- CSRF token 표시
- retention 또는 delete action
- risk profile change action

## 문제 해결

| 증상 | 의미 | 다음 조치 |
| --- | --- | --- |
| `chatgpt_prompt.md` 없음 | ChatGPT용 prompt가 아직 생성되지 않음 | output을 다시 생성하거나 review flow를 확인합니다. |
| `codex_task_prompt.md` 없음 | Codex용 prompt가 아직 생성되지 않음 | output을 다시 생성하거나 review flow를 확인합니다. |
| safe files 4개 점검이 `needs manual review` | prompt 본문이 안전 파일 4개를 모두 명시하지 않을 수 있음 | AI 투입 전 allowlist를 사람이 다시 확인합니다. |
| forbidden data warning이 `needs manual review` | 금지 데이터 경계 문구가 부족할 수 있음 | prompt를 사용하기 전 raw/token/domain/PII 금지 경계를 사람이 확인합니다. |
| prompt readiness page가 차단됨 | output 검증 실패 또는 금지 alias | `verify`를 실행하고 dashboard에 표시된 output alias만 사용합니다. |
