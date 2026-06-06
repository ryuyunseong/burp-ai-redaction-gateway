# Local Dashboard

local dashboard는 검증된 sanitization output을 브라우저에서 확인하기 위한
loopback 전용 화면입니다. production web application이 아니며
`127.0.0.1` 밖으로 노출하지 않습니다.

## 실행

```powershell
python -m burp_ai_redaction_gateway dashboard --host 127.0.0.1 --port 8766 --root out
```

`out`처럼 명시적인 root를 사용합니다. dashboard는 root 아래의 output
directory만 찾고, path traversal과 금지 directory 접근을 차단합니다.

dashboard에는 조회 전용 운영 인덱스가 있습니다.

```text
/help
/operations
```

운영 인덱스는 quickstart, GUI 사용자 흐름, AI 안전 사전 점검, AI 핸드오프
인덱스, finding triage, 보고서 준비 상태, workflow 상태, audit 운영, audit
panel 해석, risk rating 문서로 이동하는 진입점입니다. 또한 안전 파일 4개,
차단되는 raw-data 범위, candidate/draft 해석 경계를 요약합니다.

화면별 운영 순서는
[GUI_USER_FLOW.md](C:/coding/burp-ai-redaction-gateway/docs/GUI_USER_FLOW.md)를
참조하세요. AI 핸드오프 체크리스트는
[GUI_AI_HANDOFF_INDEX.md](C:/coding/burp-ai-redaction-gateway/docs/GUI_AI_HANDOFF_INDEX.md)를
참조하세요. AI 안전 후보 파일 인덱스는
[GUI_AI_SAFE_PREFLIGHT.md](C:/coding/burp-ai-redaction-gateway/docs/GUI_AI_SAFE_PREFLIGHT.md)를
참조하세요. finding 후보 triage 체크리스트는
[GUI_FINDING_TRIAGE_INDEX.md](C:/coding/burp-ai-redaction-gateway/docs/GUI_FINDING_TRIAGE_INDEX.md)를
참조하세요. 보고서 초안 준비 체크리스트는
[GUI_REPORT_READINESS_INDEX.md](C:/coding/burp-ai-redaction-gateway/docs/GUI_REPORT_READINESS_INDEX.md)를
참조하세요. 전체 workflow 상태 체크리스트는
[GUI_WORKFLOW_STATUS_INDEX.md](C:/coding/burp-ai-redaction-gateway/docs/GUI_WORKFLOW_STATUS_INDEX.md)를
참조하세요.

## Verify-first 경계

dashboard는 CLI와 같은 verify-first 경계를 적용합니다. 선택한 output이
`verify`를 통과한 뒤에만 preview, download, 안전 action을 허용합니다.

허용되는 안전 파일은 다음 4개뿐입니다.

- `analysis_packet.json`
- `chatgpt_prompt.md`
- `codex_task_prompt.md`
- `report_draft.md`

## Finding 표시 경계

dashboard는 검토 화면이며 확정 판정 화면이 아닙니다. 표시되는 finding은
candidate 또는 suspected finding 문구를 유지해야 합니다.

finding card에는 sanitization 완료 후보 metadata, rationale, confidence
basis, `risk_rating_draft`, 권장 수동 테스트, `do_not_claim` guidance가
표시될 수 있습니다. risk rating draft는 확정되지 않은 상태로 유지되며 별도
수동 risk review 전에 severity 결정으로 취급하지 않습니다.

## AI 안전 사전 점검

선택한 검증 output에 대해 조회 전용 AI 안전 사전 점검 화면을 제공합니다.

```text
/preflight?project=<alias>
```

사전 점검 화면은 다음 metadata만 요약합니다.

- 안전 파일 4개 존재 여부
- `verify` 통과 여부
- 검증한 파일 수
- finding candidate count
- `report_draft.md` 존재 여부
- 안전 파일 4개에 대한 금지 마커 스캔 요약
- finding은 candidate, risk는 draft, severity는 사람이 수동 결정한다는 경계

사전 점검 화면은 form, POST action, 상태 변경 버튼, raw viewer, HMAC secret
입력, CSRF token 표시, replay, active scan, delete, edit, retention control을
추가하지 않습니다.

## AI 핸드오프 인덱스

선택한 검증 output에 대해 조회 전용 AI 핸드오프 인덱스를 제공합니다.

```text
/handoff?project=<alias>
```

핸드오프 인덱스는 안전 파일 4개의 alias, 목적, 권장 순서, 존재 여부,
크기(bytes), 수정 시각(UTC), SHA-256 파일 fingerprint만 표시합니다.
파일 본문, full local path, HMAC secret, CSRF token은 표시하지 않고 새
download action이나 상태 변경 action을 추가하지 않습니다.

## Finding Triage 인덱스

선택한 검증 output에 대해 조회 전용 finding triage 인덱스를 제공합니다.

```text
/triage?project=<alias>
```

triage 인덱스는 다음 후보 metadata만 표시합니다.

- project alias
- finding candidate count
- candidate index와 stable candidate id
- category/type
- title과 sanitized summary
- evidence confidence
- draft risk profile, likelihood, impact, severity
- manual review required 상태
- `analysis_packet.json`과 `report_draft.md` 존재 여부
- preflight, handoff, report readiness, output 상세 flow 링크

이 화면은 form, POST action, 상태 변경 버튼, download button, finding body
preview, request/response preview, raw viewer, replay, active scan,
archive/HMAC 실행, HMAC secret 입력, CSRF token 표시, 파일 삭제, retention
변경, risk profile 변경을 추가하지 않습니다.

## 보고서 준비 상태 인덱스

선택한 검증 output에 대해 조회 전용 보고서 준비 상태 인덱스를 제공합니다.

```text
/report-readiness?project=<alias>
```

보고서 준비 상태 인덱스는 수동 보고서 검토를 위한 안전 metadata만 표시합니다.

- `report_draft.md` 존재 여부
- `analysis_packet.json` 존재 여부
- 안전 파일 metadata
- finding candidate count
- triage, preflight, handoff, output 상세 flow 링크
- scope, endpoint, evidence quality, false positive, impact, remediation,
  severity 수동 결정, 민감정보 검토를 위한 운영자 체크리스트
- `report_draft.md`와 `analysis_packet.json`의 SHA-256 파일 fingerprint

보고서 본문 preview, raw data, full local path, form, POST action, 새
download action, archive/HMAC action, replay, active scan, HMAC secret 입력,
CSRF token 값, 제출 control은 표시하지 않습니다.

## Workflow 상태 인덱스

선택한 검증 output에 대해 조회 전용 workflow 상태 인덱스를 제공합니다.

```text
/workflow?project=<alias>
```

workflow 상태 인덱스는 verify, review, report, preflight, handoff, triage,
report-readiness, review/report/export flow를 안전 metadata 체크리스트로
묶어 보여줍니다.

- verify status summary
- review status summary
- finding candidate count
- `analysis_packet.json`과 `report_draft.md` 존재 여부
- safe file status
- 관련 index link
- finding은 candidate, risk는 draft, severity는 수동 결정이라는 reminder

이 화면은 form, POST action, 상태 변경 버튼, report body preview, 새
download, raw viewer, 제출 판단을 추가하지 않습니다.

## 제공하지 않는 기능

dashboard는 다음 기능을 구현하지 않습니다.

- raw request/response viewer
- replay 또는 active scan
- 임의 파일 write
- delete 또는 edit operation
- archive/HMAC 실행 버튼
- finding triage 실행 버튼
- report readiness 실행 버튼
- workflow status 실행 버튼

## 허용된 상태 변경 action

dashboard가 지원하는 상태 변경 POST action은 다음으로 제한됩니다.

- `Verify`: 선택한 output에 fail-closed 검증을 다시 실행합니다.
- `Review`: raw data를 export하지 않고 안전 review summary를 만듭니다.
- `Report`: `verify` 통과 후 `report_draft.md`를 작성하거나 갱신합니다.
- `Export`: 안전 preview 파일 4개만 `exports/dashboard/`로 복사합니다.

모든 POST action은 CSRF token을 요구합니다. CSRF token 값, HMAC secret,
raw HTTP 값, cookie, authorization 값, token, 실제 domain, 내부 IP,
개인정보는 화면과 action audit event에 기록하지 않습니다. `Refresh`는 조회
전용 GET reload입니다.

## Dashboard action audit

상태 변경 dashboard action은 `event_type: dashboard_action` audit event를
추가합니다. event는 action name, sanitization output id, result status,
blocked reason, 안전 export file name 같은 metadata만 기록합니다.

CSRF token 값, raw HTTP 값, stack trace, domain, 내부 IP, 개인정보는
dashboard action audit event에 쓰지 않습니다.

## Settings/status 화면

dashboard는 `/settings`에 조회 전용 설정/상태 page를 제공합니다. 이 화면은
보안 상태 확인용이며 설정 변경 화면이 아닙니다.

표시 가능한 값:

- root alias
- localhost-only mode
- safe file allowlist
- report profile names
- draft-only risk mode와 `confidence_is_severity: false`
- audit schema version
- HMAC configured status
- CSRF enabled status
- audit/archive 상태 요약

CSRF 값, HMAC secret 값, 환경변수 값, raw HTTP data, full local path는
표시하지 않습니다.

## 결과 해석

dashboard finding은 candidate 또는 suspected finding 상태를 유지합니다.
`confidence`는 evidence confidence이며 severity가 아닙니다.
`risk_rating_draft`는 별도 draft-only workflow입니다. 수동 검증 전 finding을
확정하거나 severity를 결정하지 않습니다.
