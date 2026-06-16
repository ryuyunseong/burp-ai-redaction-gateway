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
인덱스, prompt readiness, evidence boundary, finding triage, 보고서 준비 상태,
workflow 상태, audit 운영, audit panel 해석, risk rating 문서로 이동하는 진입점입니다.
또한 안전 파일 4개, 차단되는 raw-data 범위, candidate/draft 해석 경계를
요약합니다.

v0.5 Upload Wizard는 별도 state-changing route입니다.

```text
/upload
```

이 화면은 Burp export `.xml` 또는 `.json` 파일을 받아 redaction, verify,
review, report를 순서대로 실행합니다. ChatGPT 자동 전송은 하지 않고, 성공
후 AI 입력 후보 파일 4개와 관련 dashboard 링크만 표시합니다. 자세한 경계는
[GUI_UPLOAD_WIZARD.md](GUI_UPLOAD_WIZARD.md)를
참조하세요.

v0.5 Live Capture currently provides a read-only status screen.

```text
/live-capture
/live-capture?project=<alias>
```

The screen displays runtime smoke status labels, receiver verify status, and an
optional verified receiver output alias. It has no form, POST action, action
button, capture execution, raw preview, raw download, replay, active scan, or
automatic AI handoff. Actual collector/receiver integration remains separate PR
scope.
Receiver-side scope dry-run results can be converted into raw-free accept/skip
summary metadata for future audit integration. The dashboard does not expose a
skip audit action or raw traffic view for this helper, and the helper does not
change collector behavior, receiver ingest behavior, or audit file retention.
Collector filtering follows the safe host metadata contract in
[LIVE_CAPTURE_COLLECTOR_CONTRACT_v0.5.md](LIVE_CAPTURE_COLLECTOR_CONTRACT_v0.5.md)
for loopback handoff eligibility and raw-free skip counts. This does not add
dashboard live capture, raw preview, or automatic ChatGPT handoff behavior.
Detailed design boundaries are in
[LIVE_CAPTURE_WIZARD_DESIGN_v0.5.md](LIVE_CAPTURE_WIZARD_DESIGN_v0.5.md)를
참조하세요.

Dashboard integration planning for `/live-capture` is tracked in
[LIVE_CAPTURE_DASHBOARD_INTEGRATION_PLAN_v0.5.md](LIVE_CAPTURE_DASHBOARD_INTEGRATION_PLAN_v0.5.md).
The next safe dashboard slice should start with a read-only runtime smoke status
panel and receiver output alias guidance. It should not add archive/capture
execution buttons, raw preview, raw download, replay, active scan, collector
forwarding changes, receiver ingest changes, or automatic ChatGPT handoff.
Runtime smoke evidence source planning is tracked in
[LIVE_CAPTURE_RUNTIME_EVIDENCE_SOURCE_v0.5.md](LIVE_CAPTURE_RUNTIME_EVIDENCE_SOURCE_v0.5.md).
The first read-only evidence model derives metadata from a verified receiver
output alias only. It exposes the receiver output alias, verify status, safe
file existence status, candidate count, and `raw_data_included: false`. It
should not upload, create, mutate, import local-only evidence files, or display
raw evidence.
MCP integration and Korean-first web UX planning are tracked in
[MCP_INTEGRATION_DESIGN_v0.5.md](MCP_INTEGRATION_DESIGN_v0.5.md) and
[WEB_UX_KO_PLAN_v0.5.md](WEB_UX_KO_PLAN_v0.5.md). These documents are planning
only and do not add MCP runtime behavior, dashboard orchestration, local
evidence reading, raw preview, replay, active scan, or automatic ChatGPT
handoff.

화면별 운영 순서는
[GUI_USER_FLOW.md](GUI_USER_FLOW.md)를
참조하세요. 처음 보는 사용자를 위한 간단 대시보드는
[GUI_SIMPLE_DASHBOARD.md](GUI_SIMPLE_DASHBOARD.md)를
참조하세요. AI 핸드오프 체크리스트는
[GUI_AI_HANDOFF_INDEX.md](GUI_AI_HANDOFF_INDEX.md)를
참조하세요. AI 안전 후보 파일 인덱스는
[GUI_AI_SAFE_PREFLIGHT.md](GUI_AI_SAFE_PREFLIGHT.md)를
참조하세요. Prompt readiness 체크리스트는
[GUI_PROMPT_READINESS_INDEX.md](GUI_PROMPT_READINESS_INDEX.md)를
참조하세요. Evidence boundary 체크리스트는
[GUI_EVIDENCE_BOUNDARY_INDEX.md](GUI_EVIDENCE_BOUNDARY_INDEX.md)를
참조하세요. Operator runbook 체크리스트는
[GUI_OPERATOR_RUNBOOK_INDEX.md](GUI_OPERATOR_RUNBOOK_INDEX.md)를
참조하세요. Safe file inventory 체크리스트는
[GUI_SAFE_FILE_INVENTORY_INDEX.md](GUI_SAFE_FILE_INVENTORY_INDEX.md)를
참조하세요. finding 후보 triage 체크리스트는
[GUI_FINDING_TRIAGE_INDEX.md](GUI_FINDING_TRIAGE_INDEX.md)를
참조하세요. 보고서 초안 준비 체크리스트는
[GUI_REPORT_READINESS_INDEX.md](GUI_REPORT_READINESS_INDEX.md)를
참조하세요. 전체 workflow 상태 체크리스트는
[GUI_WORKFLOW_STATUS_INDEX.md](GUI_WORKFLOW_STATUS_INDEX.md)를
참조하세요. release 전 GUI route smoke와 tag 기준은
[RELEASE_CHECKLIST_v0.4.md](RELEASE_CHECKLIST_v0.4.md)를
참조하세요.

## GUI route smoke

release 전에는 dashboard를 loopback으로 실행한 뒤 다음 route를 확인합니다.

```text
/
/upload
/live-capture
/help
/operations
/settings
/output?project=<alias>
/simple?project=<alias>
/dashboard-simple?project=<alias>
/preflight?project=<alias>
/handoff?project=<alias>
/triage?project=<alias>
/report-readiness?project=<alias>
/workflow?project=<alias>
/prompt-readiness?project=<alias>
/evidence-boundary?project=<alias>
/operator-runbook?project=<alias>
/safe-files?project=<alias>
```

조회 전용 route는 form, POST action, button, 새 download action을 표시하지
않아야 합니다. `/output?project=<alias>`의 상태 변경 action은 CSRF 보호가
적용된 verify, review, report, export로 제한됩니다. `/upload`도 CSRF 보호가
적용된 state-changing POST route이며, 원본 preview 또는 raw 다운로드 기능을
제공하지 않습니다.

`/simple?project=<alias>`와 `/dashboard-simple?project=<alias>`는 같은
read-only 간단 체크 화면입니다. release smoke에서는 `formCount=0`,
`buttonCount=0`, `downloadLinkCount=0`을 확인합니다. `/live-capture`는
read-only status panel 화면이며 form, POST action, action button을 표시하지
않습니다. release smoke에서는 download 또는 preview link가 없는지도
확인합니다.

## Verify-first 경계

dashboard는 CLI와 같은 verify-first 경계를 적용합니다. 선택한 output이
`verify`를 통과한 뒤에만 preview, download, 안전 action을 허용합니다.

허용되는 안전 파일은 다음 4개뿐입니다.

- `analysis_packet.json`
- `chatgpt_prompt.md`
- `codex_task_prompt.md`
- `report_draft.md`

## Simple Dashboard

처음 보는 사용자는 복잡한 운영 인덱스 대신 다음 화면에서 현재 상태를 먼저
확인할 수 있습니다.

```text
/simple?project=<alias>
/dashboard-simple?project=<alias>
```

Simple Dashboard는 세 영역만 넓게 표시합니다.

- 현재 상태: project alias, verify 통과 여부, 후보 finding 수,
  `report_draft.md` 존재 여부, safe files 4개 준비 여부.
- AI에 넣을 후보 파일: `analysis_packet.json`, `chatgpt_prompt.md`,
  `codex_task_prompt.md`, `report_draft.md`의 exists/missing 상태.
- 다음 행동: `/safe-files`, `/preflight`, `/triage`, `/report-readiness`,
  `/workflow`로 이동하는 조회 전용 링크.

이 화면은 파일 본문 preview, prompt/report body preview, full local path,
download, POST form, 실행 버튼, raw viewer를 제공하지 않습니다. 후보 finding은
확정 취약점이 아니며, 초안 risk와 최종 심각도는 별도 수동 검토 후 결정합니다.

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

## Prompt Readiness 인덱스

선택한 검증 output에 대해 조회 전용 prompt readiness 인덱스를 제공합니다.

```text
/prompt-readiness?project=<alias>
```

prompt readiness 인덱스는 `chatgpt_prompt.md`와 `codex_task_prompt.md`를
AI에 넣기 전에 운영자가 상태와 경계를 점검하기 위한 화면입니다.

표시 가능한 값:

- project alias
- 안전 파일 4개 존재 여부
- `chatgpt_prompt.md`와 `codex_task_prompt.md`의 목적
- 파일 크기(bytes)
- 수정 시각(UTC)
- SHA-256 파일 fingerprint
- verify 선행 필요 reminder
- preflight, handoff, workflow, triage, report-readiness 링크
- finding은 후보, risk는 초안, 최종 심각도는 수동 결정이라는 reminder
- prompt 본문을 표시하지 않는 내부 점검 결과

이 화면은 prompt 본문 preview, report 본문 preview, raw data, full local
path, form, POST action, 새 download action, archive/HMAC action, replay,
active scan, HMAC secret 입력, CSRF token 값, 제출 control을 표시하지
않습니다.

## Evidence Boundary 인덱스

선택한 검증 output에 대해 조회 전용 evidence boundary 인덱스를 제공합니다.

```text
/evidence-boundary?project=<alias>
```

이 화면은 report/AI 검토에 사용할 정제 evidence와 절대 노출하지 않을 raw
evidence 범위를 분리해 보여줍니다.

표시 가능한 값:

- project alias
- 정제 evidence 존재 여부
- finding candidate 존재 여부와 candidate count
- safe files 4개 존재 여부
- 파일 크기(bytes)
- 수정 시각(UTC)
- SHA-256 파일 fingerprint
- preflight, handoff, prompt-readiness, triage, report-readiness, workflow 링크
- finding은 후보, risk는 draft, 최종 심각도는 수동 결정이라는 reminder

이 화면은 raw row 전문, request/response body, token, secret, full local
path, form, POST action, download action, archive/HMAC 실행, replay,
active scan, delete/retention action을 제공하지 않습니다.

## Operator Runbook 인덱스

선택한 검증 output에 대해 조회 전용 operator runbook checklist를 제공합니다.

```text
/operator-runbook?project=<alias>
```

operator runbook 인덱스는 Burp HTTP history 수집, localhost receiver 저장,
redaction/verify, review candidate findings, report_draft.md 생성,
preflight, handoff, triage, report-readiness, prompt-readiness,
evidence-boundary, workflow status recap 순서를 한 화면에서 확인합니다.

표시하는 값은 project alias, finding candidate count, safe files 4개 상태,
관련 조회 화면 링크, raw_data_included=false, body preview=false 같은 안전
metadata입니다. finding은 candidate이고 risk rating은 draft이며 최종 심각도는
Burp 재현, 권한별 비교, 영향도 판단 후 사람이 수동 결정합니다.

이 화면은 form, POST action, 상태 변경 버튼, 파일 내려받기, raw row 전문,
request/response/prompt/report/evidence body preview, HMAC secret 입력,
CSRF token 표시, retention/delete 정책 변경, replay, active scan을 제공하지
않습니다.

## Safe File Inventory 인덱스

선택한 검증 output에 대해 조회 전용 safe file inventory checklist를 제공합니다.

```text
/safe-files?project=<alias>
```

safe file inventory 인덱스는 AI 후보 파일 4개의 존재 여부, 파일 목적,
권장 사용 위치, verify 선행 필요 여부, file size, modified UTC, SHA-256
fingerprint를 표시합니다.

표시하는 파일은 다음 4개로 제한합니다.

- `analysis_packet.json`
- `chatgpt_prompt.md`
- `codex_task_prompt.md`
- `report_draft.md`

파일 본문 preview, 다운로드 링크, full local path, raw request/response,
Cookie, Authorization, token/JWT/session, 실제 도메인/IP, 개인정보,
HMAC secret, CSRF token은 표시하지 않습니다. safe files가 모두 존재해도
AI 투입이나 제출이 자동 승인되는 것은 아니며 사람이 수동 검토해야 합니다.

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

workflow 상태 인덱스는 verify, review, report, preflight, handoff,
prompt-readiness, triage, report-readiness, review/report/export flow를 안전
metadata 체크리스트로 묶어 보여줍니다.

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
- prompt readiness 실행 버튼
- operator runbook 실행 버튼
- safe file inventory 실행 버튼

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
