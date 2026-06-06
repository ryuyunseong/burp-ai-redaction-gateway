# GUI Workflow 상태 인덱스

이 문서는 dashboard의 workflow 상태 인덱스를 설명합니다. 인덱스는 검증된
output 하나에 대한 조회 전용 workflow 체크리스트입니다.

검증된 output에서 다음 주소를 엽니다.

```text
/workflow?project=<alias>
```

이 화면은 안전 dashboard 순서를 한곳에 묶어 보여줍니다.

```text
verify
-> review
-> report
-> preflight
-> handoff
-> triage
-> report-readiness
```

상태와 이동 링크만 제공하며 workflow를 실행하지 않습니다.

## 표시 metadata

workflow 상태 인덱스는 안전 metadata만 표시합니다.

| 필드 | 의미 |
| --- | --- |
| `project alias` | 선택한 dashboard output alias |
| `verify status summary` | 선택한 output이 `verify`를 통과했는지 여부 |
| `review status summary` | finding 후보 metadata가 있는지 여부 |
| `finding candidate count` | 검증된 output 안의 finding 후보 수 |
| `analysis_packet.json` | sanitization 완료 후보 packet 존재 여부 |
| `report_draft.md` | 보고서 초안 존재 여부 |
| safe file status | AI 안전 파일 4개의 존재 여부 |
| related indexes | preflight, handoff, triage, report-readiness, review/report/export flow 링크 |

표시될 수 있는 상태 label 예시는 다음과 같습니다.

- `missing`
- `needs verify`
- `candidate available`
- `draft available`
- `manual review required`

## AI 안전 파일

workflow 상태 인덱스는 다음 네 파일만 나열할 수 있습니다.

- `analysis_packet.json`
- `chatgpt_prompt.md`
- `codex_task_prompt.md`
- `report_draft.md`

`verify`를 통과하고 사람이 계획한 AI 핸드오프를 검토하기 전에는 파일을
사용하지 않습니다.

## 해석 경계

- finding은 수동 검증이 끝날 때까지 candidate입니다.
- risk는 draft이며 별도 검토가 필요합니다.
- 심각도는 사람이 수동으로 결정합니다.
- `report_draft.md`는 보고서 초안이며 제출용 보고서가 아닙니다.
- Evidence confidence는 severity가 아닙니다.
- CVSS는 별도 산정 범위입니다.

## 관련 화면

workflow 상태 인덱스는 조회 전용 이동 체크리스트로 사용합니다.

| 링크 | 목적 |
| --- | --- |
| preflight | AI 안전 파일 준비 상태 확인 |
| handoff | 안전 파일 순서, 목적, metadata 확인 |
| triage | sanitization 완료 finding 후보 metadata 검토 |
| report-readiness | 보고서 초안 준비 경계 확인 |
| review/report/export flow | 검증된 output 상세 화면으로 돌아가기 |

## Workflow 상태에서 쓰지 않을 값

다음 값은 workflow 상태 인덱스, 문서, PR, 이슈, AI 도구에 붙여넣거나
표시하거나 기록하거나 사용하지 않습니다.

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

workflow 상태 인덱스는 다음 기능을 제공하지 않습니다.

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
| Output이 열리지 않음 | 선택한 alias가 없거나, 검증되지 않았거나, 금지됨 | 선택한 output에 `verify`를 실행하고 dashboard alias만 사용합니다. |
| Safe file status가 `missing` | 관련 단계가 아직 파일을 생성하지 않음 | `verify` 통과 후 관련 안전 CLI 또는 dashboard action을 실행합니다. |
| Review status가 `missing` | finding 후보가 없음 | 보고서 작업 전 scope와 input coverage를 로컬에서 확인합니다. |
| Report status가 `missing` | `report_draft.md`가 아직 생성되지 않음 | Review 뒤 Report를 실행하고 초안을 사람이 검토합니다. |
| 운영자가 archive/HMAC 상태를 확인해야 함 | workflow 화면은 audit 작업을 실행하지 않음 | audit 운영 가이드와 조회 전용 audit panel을 사용합니다. |
