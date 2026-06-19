# Web Operator Smoke Checklist KO v0.7

## 목적

이 문서는 운영자가 웹 화면에서 Local Dashboard와 Upload Wizard를 수동으로
점검할 때 사용할 manual smoke checklist입니다. 목표는 업로드, 검증, safe
files 확인, triage, report readiness 흐름이 local-only, verify-first,
raw-free 경계를 유지하는지 확인하는 것입니다.

이 문서는 새 기능 구현 문서가 아닙니다. 새 POST action, 업로드 처리 로직,
MCP listener runtime, raw preview, replay, active scan, automatic ChatGPT
handoff를 추가하지 않습니다.

## 전제 조건

- 저장소는 검증하려는 브랜치 또는 main 기준으로 checkout합니다.
- dashboard는 loopback host와 placeholder port로만 실행합니다.
- 실제 target, raw traffic, credential, full local path는 기록하지 않습니다.
- smoke 기록은 alias, route name, pass/fail, count, safe metadata만 남깁니다.
- `favicon.ico` 404는 현재 blocker가 아닙니다.

## 금지 범위

smoke checklist에는 다음 값을 적지 않습니다.

- 실제 target 식별자
- 실제 URL, domain, IP
- raw request/response 본문
- Cookie 값
- Authorization 값
- token, JWT, session 값
- 개인정보
- HMAC secret
- CSRF token 값
- full local path
- 실제 local-only 파일명
- raw upload preview
- prompt 또는 report body preview

이번 checklist 작업에서는 다음 구현을 하지 않습니다.

- 새 POST action
- upload processing logic 변경
- upload storage policy 변경
- file delete 또는 retention policy 변경
- raw preview/download
- prompt/report body preview
- replay/active scan
- automatic ChatGPT handoff
- MCP listener runtime
- socket/bind/listen endpoint
- transport/protocol handler
- tool registration/tool execution
- local evidence reader

## Dashboard 시작 확인

1. dashboard를 loopback host와 placeholder port로 시작합니다.
2. browser에서 dashboard home에 접근합니다.
3. home 화면이 raw-free metadata만 표시하는지 확인합니다.
4. 실제 target, full local path, raw traffic 값이 보이지 않는지 확인합니다.
5. Upload Wizard, safe files, triage, report readiness 진입 링크가 보이는지
   확인합니다.

## Upload Wizard 접근 확인

1. `/upload` route를 엽니다.
2. 화면 제목이 Upload Wizard 또는 업로드 마법사로 보이는지 확인합니다.
3. Upload Wizard가 local-only workflow라고 설명하는지 확인합니다.
4. verify 통과 전에는 AI 후보 파일을 사용하지 말라는 안내가 있는지 확인합니다.
5. automatic ChatGPT handoff가 없다고 표시되는지 확인합니다.
6. raw preview/download, replay, active scan이 없다고 표시되는지 확인합니다.
7. MCP listener runtime, socket/bind/listen, transport/protocol, tool execution은
   별도 PR 전까지 사용할 수 없다고 표시되는지 확인합니다.

## invalid upload 실패 확인

1. 파일을 선택하지 않거나 허용되지 않는 확장자를 선택합니다.
2. 잘못된 project alias를 입력하는 경우도 별도로 확인합니다.
3. 실패 화면이 safe failure category만 보여 주는지 확인합니다.
4. 실패 화면이 review/report/safe file link를 제공하지 않는지 확인합니다.
5. 실패 output은 AI 입력 후보가 아니라고 표시되는지 확인합니다.
6. raw upload body, 실제 파일명, full local path, stack trace body가 보이지
   않는지 확인합니다.

## safe sample upload 확인

1. synthetic 또는 local-only sample export를 선택합니다.
2. project alias는 식별자가 없는 placeholder alias를 사용합니다.
3. 업로드 후 generate, verify, review, report draft 단계 상태를 확인합니다.
4. 성공 화면이 raw-free metadata만 표시하는지 확인합니다.
5. 실제 파일명, full local path, target 식별자, credential 값이 보이지 않는지
   확인합니다.

## verify-first 경계 확인

- verify 실패 시 review와 report가 건너뛰어야 합니다.
- verify 실패 시 safe files link가 보이지 않아야 합니다.
- verify 통과 전 output은 AI 입력 후보가 아닙니다.
- verify 통과 후에도 외부 공유 보장이 아닙니다.
- finding은 candidate입니다.
- report는 draft입니다.
- risk는 draft입니다.
- severity와 CVSS는 수동 결정입니다.

## safe files 4개 확인

AI 입력 후보는 다음 4개로 제한합니다.

- `analysis_packet.json`
- `chatgpt_prompt.md`
- `codex_task_prompt.md`
- `report_draft.md`

확인 기준:

- 4개 파일의 존재 여부만 먼저 확인합니다.
- 필요한 경우 size, modified time, fingerprint 같은 safe metadata만 확인합니다.
- 파일 본문 preview나 download가 자동으로 열리지 않아야 합니다.
- 4개 파일도 사람이 다시 검토한 뒤 필요한 범위만 사용합니다.
- 4개 파일 존재는 외부 공유 승인이나 제출 가능 상태를 의미하지 않습니다.

## triage 화면 확인

1. `/triage?project=<alias>` route를 엽니다.
2. finding이 candidate로 표시되는지 확인합니다.
3. false positive, duplicate, out-of-scope 가능성을 사람이 검토해야 한다는
   경계가 있는지 확인합니다.
4. 실제 target, raw traffic, credential 값이 보이지 않는지 확인합니다.

## report readiness 화면 확인

1. `/report-readiness?project=<alias>` route를 엽니다.
2. report가 draft 상태임을 확인합니다.
3. risk가 draft임을 확인합니다.
4. final severity와 CVSS는 수동 결정이라고 표시되는지 확인합니다.
5. report body preview가 자동으로 표시되지 않는지 확인합니다.

## 실패 화면 확인

이 섹션은 failure screen 수동 확인 기준입니다.

실패 화면은 다음만 보여야 합니다.

- safe failure category
- 다음 조치 요약
- raw_data_included=false 같은 safe metadata
- 다시 업로드 또는 dashboard home 이동 버튼

실패 화면은 다음을 보여 주면 안 됩니다.

- raw upload body
- review/report/safe file link
- 실제 파일명
- full local path
- stack trace body
- credential 값
- target 식별자

## raw-free 확인 항목

다음 항목은 dashboard, result page, smoke 기록, PR body에 남기지 않습니다.

- 실제 target 식별자
- 실제 URL/domain/IP
- raw request/response 본문
- Cookie, Authorization, token, JWT, session 값
- 개인정보
- HMAC secret
- CSRF token 값
- full local path
- 실제 local-only 파일명
- raw audit row
- archive content

## no automatic handoff 확인 항목

- ChatGPT API 자동 전송이 없어야 합니다.
- browser 화면에서 AI로 자동 제출하는 버튼이 없어야 합니다.
- MCP listener runtime이 없어야 합니다.
- socket/bind/listen endpoint가 없어야 합니다.
- transport/protocol handler가 없어야 합니다.
- executable tool registration과 actual tool execution이 없어야 합니다.
- local evidence reader가 없어야 합니다.

## browser smoke 기록 양식

아래 형식으로 raw-free evidence만 기록합니다.

```text
Web operator smoke:
- dashboard start: passed/failed
- upload route opened: passed/failed
- local-only wording visible: yes/no
- verify-first wording visible: yes/no
- safe files limited to 4: yes/no
- invalid upload failure is raw-free: yes/no
- safe sample upload result is raw-free: yes/no
- triage route is candidate-only: yes/no
- report readiness route is draft-only: yes/no
- automatic handoff visible: no
- raw preview/download visible: no
- replay/active scan visible: no
- MCP listener runtime visible: no
- favicon 404 blocker: no
- actual target identifiers recorded: no
- raw traffic recorded: no
- credential values recorded: no
- full local path recorded: no
```

## 운영자 최종 체크리스트

1. Dashboard는 loopback에서만 열었습니다.
2. Upload Wizard가 local-only workflow임을 확인했습니다.
3. verify-first 경계를 확인했습니다.
4. 실패 화면이 review/report/safe file link를 숨기는지 확인했습니다.
5. safe files 4개만 AI 입력 후보로 표시되는지 확인했습니다.
6. safe files 4개도 사람이 다시 검토해야 함을 확인했습니다.
7. triage finding은 candidate임을 확인했습니다.
8. report와 risk는 draft임을 확인했습니다.
9. severity와 CVSS는 수동 결정임을 확인했습니다.
10. raw preview/download가 없음을 확인했습니다.
11. replay/active scan이 없음을 확인했습니다.
12. automatic ChatGPT handoff가 없음을 확인했습니다.
13. MCP listener runtime과 socket/bind/listen endpoint가 없음을 확인했습니다.
14. smoke 기록에 raw, target, credential, full local path를 남기지 않았습니다.

## 다음 단계

이 checklist가 통과하면 다음으로 가능한 안전한 작업은 browser smoke fixture
또는 Web Operator Guide 문구 정리입니다. MCP listener runtime 구현은 별도
decision, negative test, source-check, security review를 통과한 뒤 별도 PR로만
진행합니다.
