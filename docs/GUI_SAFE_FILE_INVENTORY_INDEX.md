# GUI Safe File Inventory Index

이 문서는 dashboard의 `/safe-files?project=<alias>` 화면을 설명합니다.
해당 화면은 AI 투입 후보 파일 4개의 존재 여부와 안전 metadata를 보여주는
조회 전용 safe file inventory checklist입니다.

```text
/safe-files?project=<alias>
```

## 목적

Safe file inventory 인덱스는 파일 실행, 다운로드, preview 화면이 아닙니다.
검증된 output 하나에 대해 safe files 4개가 준비됐는지, 각 파일의 크기,
수정 시각, SHA-256 fingerprint가 무엇인지 확인하는 상태 화면입니다.

표시되는 safe files 4개는 다음 파일로 제한됩니다.

- `analysis_packet.json`
- `chatgpt_prompt.md`
- `codex_task_prompt.md`
- `report_draft.md`

## 표시 metadata

각 파일에는 다음 metadata만 표시합니다.

| 항목 | 의미 |
| --- | --- |
| exists / missing | 파일 존재 여부 |
| 파일 목적 | 파일을 어떤 수동 검토 흐름에서 쓰는지 |
| 권장 사용 위치 | AI 또는 보고서 작업 전 사람이 확인할 위치 |
| verify 선행 필요 | verify 통과 output에서만 사용해야 함 |
| file size | 파일 크기 |
| modified UTC | 마지막 수정 시각 |
| SHA-256 fingerprint | 파일 byte 기준 fingerprint |
| 사람 수동 검토 | AI 투입 전 사람 검토 필요 여부 |

SHA-256 fingerprint는 파일 식별을 돕는 fingerprint입니다. HMAC이 아니며,
암호화나 무결성 보증을 의미하지 않습니다.

## 관련 화면

| 화면 | 용도 |
| --- | --- |
| `/preflight?project=<alias>` | safe files 4개와 금지 마커 상태 확인 |
| `/handoff?project=<alias>` | 안전 파일 목적, 순서, metadata 확인 |
| `/prompt-readiness?project=<alias>` | prompt 파일 상태와 수동 검토 경계 확인 |
| `/evidence-boundary?project=<alias>` | 정제 evidence와 raw 금지 범위 경계 확인 |
| `/triage?project=<alias>` | finding 후보와 수동 검토 경계 확인 |
| `/report-readiness?project=<alias>` | 보고서 초안 준비 경계 확인 |
| `/workflow?project=<alias>` | 전체 GUI 흐름 상태 확인 |
| `/operator-runbook?project=<alias>` | 수집부터 AI 투입 전 수동 검토까지 운영 순서 확인 |

## 해석 경계

- finding은 수동 검증이 끝날 때까지 candidate입니다.
- risk rating은 draft이며 최종 심각도가 아닙니다.
- evidence confidence는 severity가 아닙니다.
- final severity는 Burp 재현, 권한별 비교, 영향도 판단 후 사람이 수동 결정합니다.
- `report_draft.md`는 final report가 아니라 수동 검토용 보고서 초안입니다.
- safe files가 모두 존재해도 AI 투입이나 제출이 자동 승인되는 것은 아닙니다.

## 금지 데이터 경계

다음 값은 safe file inventory 화면, 문서, PR, 이슈, AI 도구에 붙여넣거나
표시하지 않습니다.

| 금지 항목 | 이유 |
| --- | --- |
| raw request/response body | 민감값이 포함될 수 있음 |
| request body 또는 response body preview | 원문 HTTP 내용 노출 위험 |
| prompt/report/evidence body preview | 본문에 민감값이 섞일 수 있음 |
| Cookie 값 | 인증 또는 세션 자료 |
| Authorization 값 | 인증 자료 |
| token/JWT/session 값 | 인증 또는 세션 자료 |
| 실제 domain, URL, IP 값 | 고객/환경 식별 가능성 |
| 개인정보 | 개인정보 보호 필요 |
| HMAC secret 또는 CSRF token 값 | 보안 민감 로컬 값 |
| full local path | 로컬 환경 정보 |
| `local_only/`, `raw/`, `raw_vault/`, verify 전 `out/`, `out/.audit` 산출물 | AI 후보 입력 자료가 아님 |

## 제공하지 않는 기능

Safe file inventory 인덱스는 다음 기능을 제공하지 않습니다.

- form 또는 POST action
- 상태 변경 버튼
- 파일 다운로드
- 파일 본문 preview
- raw viewer
- HMAC secret 입력 UI
- CSRF token 표시
- retention/delete 정책 변경
- replay 또는 active scan
- risk profile 변경 action

## 문제 해결

| 증상 | 의미 | 다음 조치 |
| --- | --- | --- |
| safe file이 missing | 해당 파일이 아직 생성되지 않았거나 verify 대상이 다름 | generate/review/report/export 흐름과 output alias를 확인합니다. |
| SHA-256 fingerprint가 `missing` | 파일이 없어서 fingerprint를 계산하지 않음 | verify를 통과한 output에서 safe files 4개를 다시 확인합니다. |
| modified UTC가 예상과 다름 | 파일이 다시 생성됐거나 다른 output alias를 보고 있음 | `/output?project=<alias>`에서 project alias를 확인합니다. |
| candidate count가 0 | review 후보가 없거나 analysis packet이 비어 있음 | 후보가 없는 정상 케이스인지 사람이 확인합니다. |
| final report처럼 보임 | 이 화면은 초안/후보 metadata만 표시해야 함 | 문구를 확인하고 `report_draft.md`를 수동 검토용 초안으로만 사용합니다. |
