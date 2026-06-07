# GUI Evidence Boundary 인덱스

이 문서는 dashboard의 evidence boundary 인덱스를 설명합니다. 인덱스는
검증된 output 하나에 대해 보고서와 AI 검토에 사용할 정제 evidence와 절대
노출하지 않을 raw evidence 범위를 구분하는 조회 전용 체크리스트입니다.

이 화면은 승인 화면, 제출 화면, 안전 판정 화면, raw viewer가 아닙니다.
safe files가 모두 존재하더라도 사람이 직접 검토한 뒤 필요한 범위만 사용해야
합니다.

검증된 output에서 다음 주소를 엽니다.

```text
/evidence-boundary?project=<alias>
```

## 표시 metadata

evidence boundary 인덱스는 안전 metadata만 표시합니다.

| 필드 | 의미 |
| --- | --- |
| `project alias` | 선택한 dashboard output alias |
| `sanitized evidence` | 정제 evidence 후보 존재 여부 |
| `finding candidate` | finding 후보 존재 여부 |
| `candidate count` | 정제 finding 후보 수 |
| `analysis_packet.json` | 정제 finding 후보 구조 존재 여부 |
| `report_draft.md` | 보고서 초안 존재 여부 |
| `chatgpt_prompt.md` | ChatGPT용 prompt 존재 여부 |
| `codex_task_prompt.md` | Codex용 prompt 존재 여부 |
| safe files | safe files 4개 존재 수 |
| 파일 크기(bytes) | 파일 본문 없이 크기만 표시 |
| 수정 시각(UTC) | 파일 본문 없이 수정 시각만 표시 |
| SHA-256 fingerprint | HMAC이 아닌 일반 파일 fingerprint |

SHA-256 값은 HMAC이 아니며 secret을 사용하지 않습니다. 이 화면은 HMAC
secret 처리, CSRF token 처리, audit HMAC 검증, compressed archive HMAC 검증을
바꾸지 않습니다.

## 허용되는 evidence 범위

다음 범위만 보고서 초안과 AI 보조 검토 후보로 봅니다.

- `verify`를 통과한 safe files 4개
- `analysis_packet.json`의 정제 finding candidate 구조
- `report_draft.md`의 보고서 초안
- `chatgpt_prompt.md`와 `codex_task_prompt.md`의 AI 작업 안내
- candidate count, 파일 크기, 수정 시각, SHA-256 fingerprint 같은 안전 metadata

## 금지되는 raw evidence 범위

다음 값은 prompt, 문서, PR, 이슈, AI 도구에 붙여넣거나 표시하지 않습니다.

| 분류 | 이유 |
| --- | --- |
| raw request 또는 raw response body | 민감값이 포함될 수 있음 |
| raw audit row 전문 | 운영 로그 원문 |
| Cookie 또는 Authorization 값 | 인증 자료 |
| token, JWT, session 값 | 세션 또는 인증정보 |
| 실제 domain, URL, IP 값 | 환경 식별 정보 |
| 개인정보 | 식별 또는 프라이버시 민감 정보 |
| HMAC secret 또는 CSRF token 값 | 로컬 보안 제어값 |
| full local path | 로컬 환경 식별 정보 |
| `local_only/`, `raw/`, `raw_vault/`, 검증 전 `out/`, `out/.audit` 산출물 | AI 입력 자료가 아님 |

## 관련 조회 전용 화면

| 링크 | 목적 |
| --- | --- |
| `/preflight?project=<alias>` | safe files 4개와 금지 마커 상태 확인 |
| `/handoff?project=<alias>` | 안전 파일 목적, 순서, metadata 확인 |
| `/prompt-readiness?project=<alias>` | prompt 파일 상태와 수동 검토 경계 확인 |
| `/triage?project=<alias>` | finding 후보와 수동 검토 경계 확인 |
| `/report-readiness?project=<alias>` | 보고서 초안 준비 경계 확인 |
| `/workflow?project=<alias>` | 전체 GUI 흐름 상태 확인 |
| `/operator-runbook?project=<alias>` | 수집부터 AI 투입 전 수동 검토까지 운영 순서 확인 |
| `/safe-files?project=<alias>` | safe files 4개의 존재 여부와 fingerprint 확인 |

## 해석 경계

- finding은 수동 검증이 끝날 때까지 candidate입니다.
- risk는 draft이며 severity 결정으로 취급하지 않습니다.
- evidence confidence는 severity가 아닙니다.
- 최종 심각도는 Burp 재현, 권한별 비교, 영향도 판단 후 사람이 결정합니다.
- `report_draft.md`는 초안이며 고객-facing 최종 보고서가 아닙니다.
- CVSS는 별도 산정 범위입니다.

## 조회 전용 경계

evidence boundary 인덱스는 다음 기능을 제공하지 않습니다.

- form 또는 POST action
- 상태 변경 버튼
- raw body preview
- raw audit row preview
- prompt body preview
- report body preview
- request preview
- response preview
- download action
- archive 또는 HMAC 생성/검증 실행 버튼
- HMAC secret input UI
- CSRF token 표시
- retention 또는 delete action
- replay 또는 active scan

## 문제 해결

| 증상 | 의미 | 다음 조치 |
| --- | --- | --- |
| evidence boundary page가 차단됨 | output 검증 실패 또는 금지 alias | 선택한 output에 `verify`를 실행하고 dashboard alias만 사용합니다. |
| `analysis_packet.json` 없음 | 정제 finding 후보 packet이 아직 생성되지 않음 | output 생성 흐름과 `verify` 결과를 확인합니다. |
| `report_draft.md` 없음 | 보고서 초안이 아직 생성되지 않음 | Review 뒤 Report를 실행하고 사람이 초안을 검토합니다. |
| safe files가 누락됨 | AI 투입 후보 파일이 모두 준비되지 않음 | generate/review/report 흐름을 확인하고 누락 파일을 생성합니다. |
| candidate count가 0 | 현재 input에서 finding 후보가 없음 | scope와 input coverage를 로컬에서 확인합니다. |
