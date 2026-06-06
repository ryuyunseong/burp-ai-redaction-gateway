# GUI Operator Runbook Index

이 문서는 dashboard의 `/operator-runbook?project=<alias>` 화면을 설명합니다.
해당 화면은 Burp 수집부터 AI 투입 전 수동 검토까지 운영자가 확인할 순서를
보여주는 조회 전용 operator runbook checklist입니다.

```text
/operator-runbook?project=<alias>
```

## 목적

Operator runbook 인덱스는 실행 화면이 아니라 상태 확인 화면입니다. 검증된
output 하나에 대해 다음 운영 흐름이 끊기지 않았는지 확인합니다.

```text
Burp HTTP history 수집
-> localhost receiver 저장
-> redaction/verify
-> review candidate findings
-> report_draft.md 생성
-> preflight
-> handoff
-> triage
-> report-readiness
-> prompt-readiness
-> evidence-boundary
-> workflow status recap
```

## 표시 항목

이 화면은 안전 metadata만 표시합니다.

| 항목 | 의미 |
| --- | --- |
| project alias | 검증된 output 별칭 |
| verify gate | 선택한 output이 verify를 통과했는지 |
| review status | finding 후보 metadata가 있는지 |
| finding candidate count | 후보 finding 수 |
| safe files 4개 | AI 후보 파일 allowlist 상태 |
| workflow step status | 각 운영 단계의 조회 전용 상태 |
| related page links | 관련 조회 화면으로 이동하는 GET 링크 |

safe files 4개는 다음 파일입니다.

- `analysis_packet.json`
- `chatgpt_prompt.md`
- `codex_task_prompt.md`
- `report_draft.md`

AI 후보 입력 범위는 검증을 통과한 safe files 4개, sanitized finding
candidate metadata, candidate count, 파일 크기, 수정 시각, SHA-256
fingerprint, preflight/handoff/triage/report-readiness/prompt-readiness/
evidence-boundary 상태, workflow status recap에서 확인한 운영 순서입니다.

## 관련 화면

| 화면 | 용도 |
| --- | --- |
| `/preflight?project=<alias>` | safe files 4개와 금지 마커 상태 확인 |
| `/handoff?project=<alias>` | AI 후보 파일 목적, 순서, metadata 확인 |
| `/triage?project=<alias>` | finding 후보와 수동 검토 경계 확인 |
| `/report-readiness?project=<alias>` | 보고서 초안 준비 경계 확인 |
| `/prompt-readiness?project=<alias>` | prompt 파일 상태와 수동 검토 경계 확인 |
| `/evidence-boundary?project=<alias>` | 정제 evidence와 raw 금지 범위 확인 |
| `/workflow?project=<alias>` | 전체 GUI 흐름 상태 재확인 |

## 해석 경계

- finding은 수동 검증이 끝날 때까지 candidate입니다.
- risk rating은 draft이며 최종 심각도가 아닙니다.
- evidence confidence는 severity가 아닙니다.
- 최종 심각도는 Burp 재현, 권한별 비교, 영향도 판단 후 사람이 수동 결정합니다.
- `report_draft.md`는 최종 보고서가 아니라 초안입니다.
- report_draft.md는 최종 보고서가 아니라 초안입니다.
- prompt/evidence/report 모두 AI 투입 또는 공유 전 사람 검토가 필요합니다.

## 금지 데이터 경계

다음 값은 operator runbook 인덱스, 문서, PR, 이슈, AI 도구에 붙여넣거나
표시하지 않습니다.

| 금지 항목 | 이유 |
| --- | --- |
| raw request/response body | 민감값이 포함될 수 있음 |
| raw audit row 전문 | 운영 로그 원문은 AI 입력 자료가 아님 |
| Cookie 값 | 인증 또는 세션 자료 |
| Authorization 값 | 인증 자료 |
| token/JWT/session 값 | 인증 또는 세션 자료 |
| 실제 domain, URL, IP 값 | 고객/환경 식별 가능성 |
| 개인정보 | 개인정보 보호 필요 |
| HMAC secret 또는 CSRF token 값 | 보안 민감 로컬 값 |
| full local path | 로컬 환경 정보 |
| `local_only/`, `raw/`, `raw_vault/`, verify 전 `out/`, `out/.audit` 산출물 | AI 후보 입력 자료가 아님 |

## 제공하지 않는 기능

Operator runbook 인덱스는 다음 기능을 제공하지 않습니다.

- form 또는 POST action
- 상태 변경 버튼
- 파일 내려받기
- request/response/prompt/report/evidence body preview
- raw viewer
- HMAC secret 입력 UI
- CSRF token 표시
- retention/delete 정책 변경
- replay 또는 active scan
- risk profile 변경 action

## 문제 해결

| 증상 | 의미 | 다음 조치 |
| --- | --- | --- |
| safe file이 없음 | 해당 단계의 산출물이 아직 생성되지 않았거나 verify 대상이 다름 | verify, review, report/export 흐름을 다시 확인합니다. |
| candidate count가 0 | review 후보가 없거나 분석 packet이 비어 있음 | synthetic sample이 아닌 실제 검증 대상이면 수동으로 범위를 확인합니다. |
| report_draft.md가 없음 | 보고서 초안이 아직 생성되지 않음 | 검증된 output 상세에서 Report action을 실행합니다. |
| workflow 링크가 맞지 않음 | project alias가 다르거나 output이 이동됨 | `/output?project=<alias>`에서 alias를 다시 확인합니다. |
