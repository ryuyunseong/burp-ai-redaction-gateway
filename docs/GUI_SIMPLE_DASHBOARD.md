# GUI Simple Dashboard

이 문서는 local dashboard의 `/simple?project=<alias>` 화면을 설명합니다.

```text
/simple?project=<alias>
/dashboard-simple?project=<alias>
```

## 목적

Simple Dashboard는 처음 보는 사용자가 복잡한 운영 인덱스를 모두 열지 않아도 현재 상태와 다음 행동을 빠르게 이해하도록 만든 read-only 간단 체크 화면입니다.

이 화면은 상태 표시만 합니다. 실행 버튼, POST form, download, preview, raw viewer는 제공하지 않습니다.

## 표시 항목

### 현재 상태

- project alias
- verify 결과
- 후보 finding count
- `report_draft.md` 존재 여부
- safe files 4개 준비 여부
- 후보 finding, 초안 risk, 최종 심각도 수동 검토 경계

### AI에 넣을 후보 파일

다음 4개 파일의 `exists` 또는 `missing` 상태만 표시합니다.

- `analysis_packet.json`
- `chatgpt_prompt.md`
- `codex_task_prompt.md`
- `report_draft.md`

파일 본문, prompt 본문, report 본문, 전체 로컬 경로는 표시하지 않습니다.

### 다음 행동

- `/safe-files`와 `/preflight`에서 AI 삽입 전 후보 파일을 확인합니다.
- `/triage`에서 후보 finding을 수동 검토합니다.
- `/report-readiness`에서 보고서 초안을 수동 검토합니다.
- `/workflow`에서 전체 고급 흐름을 확인합니다.

## 보안 경계

Simple Dashboard는 다음 값을 표시하지 않습니다.

- raw request/response
- request body, response body, prompt body, report body
- Cookie, Authorization, token/JWT/session
- 실제 domain/IP, 개인정보
- HMAC secret, CSRF token
- full local path
- `local_only`, `raw`, `raw_vault`, 검증 전 `out`, `out/.audit` 원본

다음 기능도 제공하지 않습니다.

- replay
- active scan
- 파일 삭제
- retention 정책 변경
- HMAC secret 처리 변경
- risk profile 변경

## 해석 경계

- 후보 finding은 확정 취약점이 아닙니다.
- risk 값은 초안입니다.
- 최종 심각도는 Burp 재현, 권한별 비교, 영향도 판단 후 사람이 수동 결정합니다.
- safe files 4개가 모두 있어도 AI 삽입 전 수동 검토가 필요합니다.

## 관련 고급 화면

- `/workflow?project=<alias>`
- `/safe-files?project=<alias>`
- `/triage?project=<alias>`
- `/evidence-boundary?project=<alias>`
- `/operator-runbook?project=<alias>`
