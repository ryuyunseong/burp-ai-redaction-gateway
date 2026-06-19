# Web Operator Guide KO v0.7

## Manual smoke checklist

웹 화면 수동 점검 절차는
[`WEB_OPERATOR_SMOKE_CHECKLIST_KO_v0.7.md`](WEB_OPERATOR_SMOKE_CHECKLIST_KO_v0.7.md)에
정리되어 있습니다. 이 checklist는 Upload Wizard, safe files, triage, report
readiness, failure screen을 raw-free evidence만으로 확인합니다.

## 목적

이 문서는 CLI 명령을 직접 입력하지 않고 로컬 웹 화면에서 할 수 있는
작업과 아직 할 수 없는 작업을 구분합니다. 현재 웹 흐름은 로컬
Dashboard와 Upload Wizard 중심입니다. MCP listener runtime, transport,
protocol handler, tool execution, local evidence reader는 아직 사용할 수
없습니다.

이 문서는 기능 구현 문서가 아닙니다. 새 POST action, raw preview,
automatic handoff, listener runtime을 추가하지 않습니다.

## 현재 웹에서 가능한 작업

현재 웹 화면에서 가능한 작업은 다음 범위로 제한됩니다.

| 작업 | 상태 | 설명 |
| --- | --- | --- |
| Local Dashboard 열기 | 가능 | 검증된 output alias를 기준으로 상태를 확인합니다. |
| Upload Wizard 사용 | 가능 | local Burp export 하나를 업로드해 안전한 처리 흐름을 실행합니다. |
| safe files 4개 확인 | 가능 | AI 입력 후보 파일의 존재 여부와 metadata를 확인합니다. |
| triage 화면 확인 | 가능 | candidate finding 목록과 draft risk metadata를 확인합니다. |
| report readiness 확인 | 가능 | 보고서 초안 준비 상태를 확인합니다. |
| workflow 상태 확인 | 가능 | verify, review, report, handoff 상태를 한 화면에서 봅니다. |
| Windows launcher 사용 | 가능 | receiver와 dashboard 실행을 보조합니다. |
| localhost receiver 사용 | 가능 | loopback receiver가 handoff payload를 받아 redaction output을 만듭니다. |
| read-only MCP stdio server 사용 | 가능 | 검증된 output directory의 safe metadata를 조회합니다. |

## 현재 웹에서 불가능한 작업

다음 작업은 아직 웹에서 제공하지 않습니다.

- raw preview 또는 raw download
- replay 또는 active scan
- automatic ChatGPT handoff
- v0.7 MCP listener runtime 시작 또는 중지
- socket, bind, listen 기반 endpoint
- MCP transport 또는 protocol handler
- executable tool registration
- actual tool execution
- local evidence reader
- safe file body reader
- dashboard에서 임의 파일 읽기
- dashboard에서 파일 삭제 또는 retention 정책 변경
- report, prompt, raw upload body preview

## Local Dashboard 시작 방법

Dashboard는 로컬 loopback host에만 띄워서 사용합니다. 문서나 이슈에는
실제 host, 실제 target, 전체 로컬 경로를 적지 않습니다.

```powershell
python -m burp_ai_redaction_gateway dashboard `
  --host <loopback-host> `
  --port <dashboard-port> `
  --root <verified-output-root>
```

브라우저에서는 dashboard home으로 이동한 뒤 project alias를 선택합니다.
Dashboard는 verified output alias만 보여 주며 raw traffic, full local path,
actual target identifier를 표시하지 않습니다.

## Upload Wizard 사용 흐름

Upload Wizard는 CLI 명령을 하나씩 입력하지 않고 local Burp export를 처리하기
위한 웹 진입점입니다.

```text
GET /upload
POST /upload
```

허용되는 입력 형식은 local `.xml` 또는 `.json` export입니다. 처리 흐름은
다음 순서입니다.

```text
upload validation
-> local-only storage
-> generate
-> verify
-> review
-> report draft
-> safe file status
```

`verify`가 실패하면 Wizard는 안전하게 중단합니다. 이 경우 review, report, safe file link를 제공하지 않습니다. 실패 화면도 raw-free category와
간단한 조치만 보여 주며 raw upload body나 내부 stack trace를 보여 주지
않습니다.

## safe files 4개 확인 방법

AI 입력 후보는 다음 4개로 제한됩니다.

- `analysis_packet.json`
- `chatgpt_prompt.md`
- `codex_task_prompt.md`
- `report_draft.md`

이 4개도 공유 보장 파일이 아닙니다. 사람이 내용을 확인하고 필요한 부분만
수동으로 사용합니다. Dashboard는 존재 여부, 크기, 수정 시각, fingerprint와
같은 metadata만 보여 주며 file body preview나 full local path는 표시하지
않습니다.

## triage/report readiness 화면의 의미

`/triage`는 finding 후보를 살펴보기 위한 read-only 화면입니다. 여기서
보이는 finding은 candidate입니다. 확정 취약점이 아니며 false positive,
중복, out-of-scope 가능성을 사람이 검토해야 합니다.

`/report-readiness`는 report draft 준비 상태를 확인하는 화면입니다.
`report_draft.md`는 초안입니다. risk는 draft이고 final severity와 CVSS는 사람이 별도로 결정합니다.

## Windows launcher 사용 범위

Windows launcher는 receiver와 dashboard 실행을 보조합니다.

```powershell
scripts\start_gateway.ps1
scripts\stop_gateway.ps1
```

launcher는 로컬 실행 보조 도구입니다. raw traffic, credential value,
actual target identifier, HMAC secret, request-forgery protection value를
출력하지 않아야 합니다.

## localhost receiver 사용 범위

receiver는 loopback handoff payload를 받아 redaction output을 생성합니다.
receiver output도 verify를 통과하기 전에는 AI 입력 후보가 아닙니다.

```powershell
python -m burp_ai_redaction_gateway serve `
  --host <loopback-host> `
  --port <receiver-port> `
  --output <receiver-output-alias> `
  --project <project-alias>
```

receiver는 raw traffic을 사람이 볼 수 있는 dashboard preview로 노출하지
않습니다. receiver 결과는 generate, verify, review, report 흐름을 거친
후 safe files 4개 후보로만 다룹니다.

## read-only MCP stdio server와 dashboard의 차이

read-only MCP stdio server는 검증된 output directory의 safe metadata를
조회하는 별도 실행 방식입니다.

```powershell
python -m burp_ai_redaction_gateway mcp --root <verified-output-root>
```

Dashboard는 브라우저 기반 operator 화면입니다. MCP stdio server는
브라우저 UI가 아니며 raw exchange lookup, replay, file write, external
transmission을 제공하지 않습니다.

## v0.7 MCP listener runtime 경계

v0.7 MCP listener runtime은 아직 사용할 수 없습니다. 현재 main에는
metadata-only skeleton, decision preflight, approval packet만 있습니다.

아직 없는 항목:

- listener runtime
- socket, bind, listen, accept behavior
- transport implementation
- protocol handler
- executable tool registration
- actual tool execution
- local evidence reader
- raw preview/download
- replay/active scan
- automatic ChatGPT handoff

## 보안 경계

문서, dashboard, PR, audit, failure page에는 다음 값을 표시하거나 기록하지
않습니다.

- 실제 target 식별자
- 실제 URL, domain, IP
- original request 또는 response body
- Cookie 값
- Authorization 값
- token, JWT, session 값
- HMAC secret
- request-forgery protection 값
- full local path
- actual local-only filename
- raw upload preview
- prompt 또는 report body preview

또한 외부 공유 안전 보장, 확정 취약점, 최종 심각도 확정, 최종 점수 확정처럼
읽히는 표현을 쓰지 않습니다.

## 실패 처리

실패 화면은 raw-free category와 다음 조치만 보여 줍니다. 대표 category는
다음과 같습니다.

- missing input
- unsupported file type
- invalid project alias
- upload validation failed
- generate failed
- verify failed safely
- review skipped
- report skipped
- environment issue

실패 output, local-only file, raw upload, audit artifact는 AI 입력 후보가
아닙니다.

## 운영자 체크리스트

1. 실제 export는 local-only 작업 위치에만 둡니다.
2. Upload Wizard 또는 CLI로 output alias를 만듭니다.
3. verify 통과 여부를 먼저 확인합니다.
4. safe files 4개가 모두 있는지 확인합니다.
5. triage 화면에서 finding이 candidate임을 확인합니다.
6. report readiness 화면에서 report가 draft임을 확인합니다.
7. AI에 넣기 전 4개 후보 파일을 사람이 다시 검토합니다.
8. 필요한 부분만 수동으로 복사합니다.

## 다음 단계

다음으로 가능한 안전한 작업은 Web Upload Wizard UX polish입니다. 그 작업도
raw-free, local-only, no automatic handoff 경계를 유지해야 합니다.

MCP listener runtime 구현은 별도 decision, negative test, source-check,
security review를 통과한 뒤 별도 PR로만 다룹니다.
