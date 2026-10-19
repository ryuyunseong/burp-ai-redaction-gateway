# 이전 버전 참고 자료

과거 명령·검증 결과·개발 자료를 보관한 문서입니다. 현재 설정과 실행 방법은 [구성과 추가 설정](REFERENCE.md)을 참고하세요.

<details>
<summary>이전 버전 기록 (일반 사용에는 필요하지 않습니다)</summary>

아래 내용은 당시의 명령, 검증 결과와 설계 기록입니다. 현재 사용법과 다를 수 있으므로 실행은 위 안내를 기준으로 하세요.
개발 근거를 남기기 위해 보관하며, 현재 구현이나 추가 기능의 승인을 뜻하지 않습니다.
기존 `mcp` 명령의 결과 조회 기능과 별도로, 새 MCP listener의 설계·구현 경계를 설명하는 문서도 포함되어 있습니다.

## 공개 검증 결과

아래는 `main@4001258da4fba881b3e7e9ef3936e993f05c4f81`에서 수행한
기존 단계별 명령의 검증 기록입니다. 이후 추가된 `process` 명령의 결과와는 구분합니다.

- `python -m compileall burp_ai_redaction_gateway tests`: 통과
- `python -m unittest discover -s tests`: 208개 통과
- synthetic `generate`: 산출물 8개 생성
- synthetic `verify`: 7개 파일 검사 통과
- static `viewer`: finding 1개, 화면 section 3개 생성, `raw_data_included=false`
- `scripts\pre_commit_check.bat`, `scripts\git_safety_check.bat`: 통과
- Gitleaks: 노출 항목 없음

## 처음 보는 분을 위한 안내

- [5분 한글 빠른 시작](../docs/USER_QUICKSTART_KO_v0.6.md)
- [결과 파일 4개 설명](../docs/OUTPUT_BUNDLE_GUIDE_KO_v0.6.md)
- [웹에서 가능한 작업과 제한 사항](../docs/WEB_OPERATOR_GUIDE_KO_v0.7.md)
- [웹 화면 수동 점검 체크리스트](../docs/WEB_OPERATOR_SMOKE_CHECKLIST_KO_v0.7.md)

## 빠른 실행

### 1. 가상 데이터로 결과 생성

```powershell
python -m burp_ai_redaction_gateway generate `
  --input samples\synthetic_burp_history.json `
  --output out\demo `
  --project client_alias_demo `
  --risk-profile conservative `
  --policy policy.json
```

### 2. 결과 검증

```powershell
python -m burp_ai_redaction_gateway verify --input out\demo --policy policy.json
```

`verify`가 실패하면 해당 결과를 AI, 보고서 또는 export에 사용하지 않습니다.

### 3. 검토 및 안전 파일 export

```powershell
python -m burp_ai_redaction_gateway review `
  --input out\demo `
  --export-dir exports\demo_review
```

### 4. 보고서 초안 생성

```powershell
python -m burp_ai_redaction_gateway report `
  --input out\demo `
  --output out\demo\report_draft.md `
  --profile conservative
```

finding은 수동 재현 전까지 candidate 또는 suspected 상태입니다. `confidence`는
evidence confidence이며 severity가 아닙니다. `risk_rating_draft`와 보고서 문구는
초안이므로 최종 severity와 CVSS는 별도로 검토합니다.

보고서 문구 프로필:

- `conservative`: 가장 보수적인 후보 문구를 사용합니다.
- `consultant`: 컨설팅 보고서 초안 문구를 사용하지만 수동 검증은 계속 필요합니다.

## 정적 viewer

```powershell
python -m burp_ai_redaction_gateway viewer `
  --input tests\fixtures\redacted_viewer_valid.json `
  --output out\viewer\redacted_viewer.html
```

`viewer`는 static/local HTML만 생성합니다. Web server, upload/import, raw
preview/download, MCP/Burp integration 또는 listener/transport runtime을 추가하지
않습니다. 입력이 malformed, unsupported, oversized 또는 unsafe-path 상태이면
렌더링 전에 fail-closed합니다.

## 운영 가이드

처음 사용하는 경우 다음 순서만 확인하면 됩니다.

```text
입력 준비
→ redaction/generate
→ verify
→ review 또는 report
→ 사용자가 안전 파일 4개를 직접 확인
```

- 전체 CLI·receiver 절차: [안전 운영 가이드](../docs/OPERATING_GUIDE.md)
- GUI 사용 순서: [GUI 운영 흐름](../docs/GUI_USER_FLOW.md)
- 로컬 파일 처리: [Upload Wizard](../docs/GUI_UPLOAD_WIZARD.md)
- 간단 상태 확인: [Simple Dashboard](../docs/GUI_SIMPLE_DASHBOARD.md)
- AI 전달 전 확인: [AI 안전 사전 점검](../docs/GUI_AI_SAFE_PREFLIGHT.md)
- 감사·retention·HMAC·압축: [감사 운영 상세 가이드](../docs/AUDIT_OPERATIONS_GUIDE.md)
- risk draft 해석: [Risk rating 가이드](../docs/RISK_RATING_GUIDE.md)

### AI 전달 후보 파일 4개

`verify`를 통과하고 사용자가 직접 확인한 뒤 다음 파일만 기본 AI 전달 후보로
취급합니다.

- `analysis_packet.json`
- `chatgpt_prompt.md`
- `codex_task_prompt.md`
- `report_draft.md`

검증 통과는 외부 공유 판단을 대신하지 않습니다. 실제 대상 식별자, 고객 정보,
민감정보 또는 과장된 finding 표현이 없는지 다시 확인합니다.

### GUI 조회 화면

- `/simple?project=<alias>` 또는 `/dashboard-simple?project=<alias>`: read-only 간단 체크 화면
- `/preflight?project=<alias>`: AI 안전 사전 점검
- `/handoff?project=<alias>`: AI 핸드오프 인덱스
- `/prompt-readiness?project=<alias>`: prompt 준비 상태
- `/evidence-boundary?project=<alias>`: 정제 evidence와 금지 범위
- `/operator-runbook?project=<alias>`: 운영 순서
- `/safe-files?project=<alias>`: 안전 파일 4개 상태
- `/triage?project=<alias>`: finding 후보 triage
- `/report-readiness?project=<alias>`: 보고서 초안 준비 상태
- `/workflow?project=<alias>`: 전체 workflow 상태
- `/settings`, `/help`, `/operations`: 설정 및 운영 안내

각 화면은 read-only 상태 확인을 우선하며 raw viewer, replay, active scan 또는
자동 AI 전송 기능을 제공하지 않습니다.

### Live Capture 현재 경계

`GET /live-capture`, `POST /live-capture/start`, `POST /live-capture/stop`은 현재
CSRF 보호된 session 상태 placeholder입니다. Live Capture 화면은 read-only 상태와
안전 alias만 보여 줍니다. 실제 collector/receiver capture integration과 자동 AI
handoff는 separate PR 범위입니다.

관련 문서:

- [Live Capture 설계](../docs/LIVE_CAPTURE_WIZARD_DESIGN_v0.5.md)
- [AI 핸드오프 인덱스](../docs/GUI_AI_HANDOFF_INDEX.md)
- [Prompt 준비 상태](../docs/GUI_PROMPT_READINESS_INDEX.md)
- [Evidence 경계](../docs/GUI_EVIDENCE_BOUNDARY_INDEX.md)
- [운영자 runbook](../docs/GUI_OPERATOR_RUNBOOK_INDEX.md)
- [안전 파일 inventory](../docs/GUI_SAFE_FILE_INVENTORY_INDEX.md)
- [Finding triage](../docs/GUI_FINDING_TRIAGE_INDEX.md)
- [보고서 준비 상태](../docs/GUI_REPORT_READINESS_INDEX.md)
- [Workflow 상태](../docs/GUI_WORKFLOW_STATUS_INDEX.md)
- [감사 상태 panel](../docs/GUI_AUDIT_PANEL_GUIDE.md)

## 로컬 실행 구성

### Windows 로컬 실행기

```powershell
scripts\start_gateway.ps1
```

receiver는 loopback port `8765`, Dashboard는 loopback port `8766`에서 시작합니다.
안전한 launcher metadata만 `out\.launcher` 아래에 기록하며 console에는
`raw_data_included=false`를 표시합니다.

```powershell
scripts\stop_gateway.ps1
```

자세한 내용은 [Windows 실행기 가이드](../docs/WINDOWS_LAUNCHER_GUIDE.md)를
참조하세요.

### 로컬 수신기

```powershell
python -m burp_ai_redaction_gateway serve --host 127.0.0.1 --port 8765 --output out\receiver --project montoya_receiver_alias
```

receiver는 `POST /ingest/burp-history`를 받고 즉시 redaction을 적용합니다.
외부 인터페이스에 바인딩하지 않으며 원본 요청·응답을 로그에 쓰지 않습니다.

- [로컬 수신기 설명](../docs/LOCALHOST_RECEIVER.md)
- [Burp Montoya 수집기](../docs/MONTOYA_COLLECTOR.md)

### 읽기 전용 MCP 서버

```powershell
python -m burp_ai_redaction_gateway mcp --root out
```

검증된 sanitization output에 대한 read-only tool만 제공합니다. raw exchange lookup,
replay, file write, external transmission은 구현하지 않습니다.

- [읽기 전용 MCP 설명](../docs/READ_ONLY_MCP.md)

### 로컬 Dashboard

```powershell
python -m burp_ai_redaction_gateway dashboard --host 127.0.0.1 --port 8766 --root out
```

Dashboard는 `127.0.0.1`에만 bind하고 검증된 output만 표시합니다. 안전 파일 4개와
후보 finding 상태를 확인할 수 있지만, raw request/response 조회, replay, active
scan, 임의 파일 쓰기·삭제 또는 자동 AI 전송은 제공하지 않습니다.

- [로컬 Dashboard 설명](../docs/LOCAL_DASHBOARD.md)

## 정책 설정

기본 policy는 [policy.json](../policy.json)입니다. output generation과 검증은
fail-closed 방식입니다. token, cookie value, JWT, PII, internal IP, domain,
high-entropy secret 또는 raw HTTP marker가 남아 있으면 결과 생성을 거부합니다.

허용된 false positive는 `verification.allowlist_notes`에 기록합니다. 내장 allowlist는
`10.0.0.0/8` 같은 network bucket만 허용하며 실제 내부 host IP는 허용하지
않습니다.

## 테스트용 예제

Repository fixture는 synthetic data만 포함합니다.

- `samples/synthetic_burp_history.json`
- `samples/synthetic_burp_variants.json`
- `samples/burp_xml_base64_history.xml`

## 실제와 유사한 동작 점검

실제 Burp export가 없을 때는 synthetic data만 포함한 sample로 parser와
redaction 흐름을 점검합니다.

```powershell
python scripts\make_safe_burp_export_sample.py
scripts\run_safe_sample_smoke_test.bat
```

이 sample은 실제 Burp export와의 compatibility testing을 대체하지 않습니다.
실제 export는 `local_only/` 아래에서만 사용하고 커밋·prompt·Issue·문서에 넣지
않습니다.

- [실제 export 검증 절차](../docs/REAL_BURP_EXPORT_VALIDATION.md)
- [검증 기록 template](../docs/templates/REAL_BURP_EXPORT_VALIDATION_TEMPLATE.md)
- [로컬 smoke harness](../docs/LOCAL_REAL_EXPORT_SMOKE_HARNESS.md)

v0.4 release readiness 기록은 raw-free metadata만 사용합니다. 기존 기록에는
`v0.4.30-local-real-export-smoke-harness`, `v0.4.31-rc1`,
`actual_export_smoke=passed`, `generate=passed`, `verify=passed`, `review=passed`,
`report=passed`, `dashboard_smoke=passed`, `browser_smoke=passed`,
`candidate_count=60`, `safe_files_present=4`, `forbidden_value_hits=0`이 포함됩니다.
이 값은 finding 확정이나 외부 공유 판단을 의미하지 않습니다.

v0.4 RC3 준비 상태 기록의 기준선은
`v0.4.33-rc3-redaction-metadata-hardening`이며 최종 v0.4 baseline tag는
`v0.4.34`입니다.

## 검증

```powershell
python -m compileall burp_ai_redaction_gateway tests
python -m unittest discover -s tests
python -m burp_ai_redaction_gateway generate --input samples\synthetic_burp_history.json --output out\demo --project client_alias_demo
python -m burp_ai_redaction_gateway verify --input out\demo
scripts\pre_commit_check.bat
scripts\git_safety_check.bat
```

## 감사 기록

Tool-call과 Dashboard action은 `<root>/.audit/mcp_audit.jsonl`에 raw-free metadata
형태로 기록합니다. 일반 사용자는 기본 운영 흐름까지만 수행하면 됩니다.
감사 증거 보관이 필요한 경우 다음 순서를 사용합니다.

```text
review-audit
→ audit-retention
→ audit-hmac / audit-hmac-verify
→ audit-compress / audit-compress-verify
→ audit-compressed-hmac / audit-compressed-hmac-verify
```

HMAC은 tamper detection이며 encryption이 아닙니다. 압축 archive 검증은 retained
JSONL 검증과 HMAC을 대체하지 않습니다.

## 보안 참고 사항

- 실제 Burp export와 raw HTTP history를 커밋하지 않습니다.
- 실제 데이터는 `local_only/`에만 두고 `samples/`로 이동하지 않습니다.
- `out/`, `exports/`, `reports/`, `raw/`, `raw_vault/`, 감사 로그와 manifest를
  커밋하지 않습니다.
- `review`와 `report`는 `verify`를 통과한 output에만 사용합니다.
- finding은 수동 검증 전까지 candidate이고 risk는 draft입니다.
- HMAC secret, CSRF 값, token, cookie, 실제 domain, 내부 IP와 개인정보를 출력하거나
  공유하지 않습니다.

<details>
<summary>개발·릴리스 기록 펼치기</summary>

아래 항목은 설계, 승인 경계, fixture, release readiness와 과거 구현 기록을 위한
색인입니다. 별도 문서에서 구현 완료를 명시하지 않는 한 listener/transport
runtime, socket startup, protocol handling, dispatcher/tool execution, local
evidence reader, raw preview/download, replay/active scan, Dashboard state-changing
control, upload/import, 자동 ChatGPT handoff, tag 또는 GitHub Release 생성을
승인하지 않습니다.

### v0.4~v0.5

- [v0.4 release notes](../docs/RELEASE_NOTES_v0.4.md)
- [v0.4 release checklist](../docs/RELEASE_CHECKLIST_v0.4.md)
- [v0.4.34 release draft](../docs/GITHUB_RELEASE_v0.4.34.md)
- [v0.5 roadmap](../docs/ROADMAP_v0.5.md)
- [v0.5 release readiness](../docs/RELEASE_READINESS_v0.5.md)
- [v0.5 RC readiness](../docs/RC_READINESS_v0.5.md)
- [v0.5 MCP integration design](../docs/MCP_INTEGRATION_DESIGN_v0.5.md)
- [v0.5 web UX plan](../docs/WEB_UX_KO_PLAN_v0.5.md)
- [Burp MCP compatibility boundary](../docs/BURP_MCP_COMPATIBILITY_v0.5.md)
- [Montoya runtime smoke evidence](../docs/V05_MONTOYA_RUNTIME_SMOKE_RELEASE_EVIDENCE.md)
- [v0.5 hotfix policy](../docs/V0.5_HOTFIX_POLICY.md)

### v0.6

- [v0.6 roadmap](../docs/ROADMAP_v0.6.md)
- [Read-only tool contract matrix](../docs/MCP_READ_ONLY_TOOL_CONTRACT_MATRIX_v0.6.md)
- [Prototype preflight](../docs/MCP_READ_ONLY_PROTOTYPE_PREFLIGHT_v0.6.md)
- [Registry adapter design](../docs/MCP_REGISTRY_ADAPTER_DESIGN_v0.6.md)
- [Registry adapter fixture plan](../docs/MCP_REGISTRY_ADAPTER_FIXTURE_PLAN_v0.6.md)
- [Implementation gate design](../docs/MCP_IMPLEMENTATION_GATE_DESIGN_v0.6.md)
- [`mcp_adapter_dry_run.py`](../burp_ai_redaction_gateway/mcp_adapter_dry_run.py)
- [Local-only tool schema catalog](../docs/MCP_LOCAL_ONLY_TOOL_SCHEMA_CATALOG_v0.6.md)
- [`mcp_tool_schema_catalog.py`](../burp_ai_redaction_gateway/mcp_tool_schema_catalog.py)
- [Runtime boundary decision](../docs/MCP_RUNTIME_BOUNDARY_DECISION_v0.6.md)
- [Server skeleton preflight](../docs/MCP_SERVER_SKELETON_PREFLIGHT_v0.6.md)
- [Runtime boundary consumption](../docs/MCP_RUNTIME_BOUNDARY_CONSUMPTION_v0.6.md)
- [Listener skeleton decision](../docs/MCP_LISTENER_SKELETON_DECISION_v0.6.md)
- [Listener skeleton acceptance](../docs/MCP_LISTENER_SKELETON_ACCEPTANCE_v0.6.md)
- [Listener runtime source check](../docs/MCP_LISTENER_RUNTIME_SOURCE_CHECK_v0.6.md)
- [RC readiness checklist](../docs/V0.6_RC_READINESS_CHECKLIST.md)
- [Quickstart smoke](../docs/V0.6_QUICKSTART_SMOKE.md)
- [Release notes draft](../docs/V0.6_RELEASE_NOTES_DRAFT.md)
- [RC final gate run](../docs/V0.6_RC_FINAL_GATE_RUN.md)
- [Release approval packet](../docs/V0.6_RELEASE_APPROVAL_PACKET.md)
- [v0.6.1 hotfix triage](../docs/V0.6.1_HOTFIX_TRIAGE.md)

### v0.7

- [Scope plan](../docs/V0.7_SCOPE_PLAN.md)
- [MCP listener skeleton plan](../docs/V0.7_MCP_LISTENER_SKELETON_PLAN.md)
- [Listener runtime decision preflight](../docs/V0.7_LISTENER_RUNTIME_DECISION_PREFLIGHT.md)
- [Minimal listener approval packet](../docs/V0.7_MINIMAL_LISTENER_RUNTIME_APPROVAL_PACKET.md)
- [Minimal listener design](../docs/V0.7_MINIMAL_LISTENER_RUNTIME_DESIGN.md)
- [Runtime source-check consumption](../docs/V0.7_RUNTIME_SOURCE_CHECK_CONSUMPTION.md)
- [Listener negative test harness design](../docs/V0.7_LISTENER_NEGATIVE_TEST_HARNESS_DESIGN.md)
- [Minimal listener implementation decision](../docs/V0.7_MINIMAL_LISTENER_RUNTIME_IMPLEMENTATION_DECISION.md)
- [Minimal listener implementation](../docs/V0.7_MINIMAL_LISTENER_RUNTIME_IMPLEMENTATION.md)
- [Listener local smoke evidence](../docs/V0.7_LISTENER_LOCAL_SMOKE_EVIDENCE.md)
- [RC readiness checklist](../docs/V0.7_RC_READINESS_CHECKLIST.md)
- [Release approval packet](../docs/V0.7_RELEASE_APPROVAL_PACKET.md)
- [Final gate execution](../docs/V0.7_FINAL_GATE_EXECUTION.md)
- [Release notes draft](../docs/V0.7_RELEASE_NOTES_DRAFT.md)

### v0.8

- [Backlog split](../docs/V0.8_BACKLOG_SPLIT.md)
- [Transport design](../docs/V0.8_TRANSPORT_DESIGN.md)
- [Protocol handler design](../docs/V0.8_PROTOCOL_HANDLER_DESIGN.md)
- [Protocol negative test harness](../docs/V0.8_PROTOCOL_NEGATIVE_TEST_HARNESS.md)
- [Tool registration design](../docs/V0.8_TOOL_REGISTRATION_DESIGN.md)
- [Read-only tool contract](../docs/V0.8_READ_ONLY_TOOL_CONTRACT.md)
- [Minimal skeleton planning](../docs/V0.8_MINIMAL_SKELETON_PLANNING.md)
- [Skeleton approval packet](../docs/V0.8_SKELETON_APPROVAL_PACKET.md)
- [Runtime source-check guard](../docs/V0.8_RUNTIME_SOURCE_CHECK_CONSUMPTION_GUARD.md)
- [Post-merge boundary note](../docs/V0.8_POST_MERGE_BOUNDARY_NOTE.md)
- [Scope freeze and RC readiness](../docs/V0.8_SCOPE_FREEZE_RC_READINESS.md)
- [Release approval packet](../docs/V0.8_RELEASE_APPROVAL_PACKET.md)
- [Final gate evidence](../docs/V0.8_FINAL_GATE_EVIDENCE.md)

### v0.9

- [Runtime scope decision](../docs/V0.9_RUNTIME_SCOPE_DECISION.md)
- [Protocol parser approval packet](../docs/V0.9_PROTOCOL_PARSER_APPROVAL_PACKET.md)
- [Protocol parser negative fixture](../tests/fixtures/v09_protocol_parser_negative_cases.json)
- [Protocol parser implementation decision](../docs/V0.9_PROTOCOL_PARSER_IMPLEMENTATION_DECISION.md)
- [Parser positive shape decision](../docs/V0.9_PARSER_POSITIVE_SHAPE_DECISION.md)
- [Parser positive fixture](../tests/fixtures/v09_parser_positive_shape_cases.json)
- [Read-only tool registry contract](../docs/V0.9_READ_ONLY_TOOL_REGISTRY_CONTRACT.md)
- [Registry contract fixture](../tests/fixtures/v09_read_only_tool_registry_contract.json)
- [Registry implementation guard](../tests/fixtures/v09_read_only_tool_registry_implementation_guard.json)
- [Registry/dispatcher boundary](../docs/V0.9_READ_ONLY_REGISTRY_DISPATCHER_BOUNDARY.md)
- [Registry/dispatcher boundary fixture](../tests/fixtures/v09_read_only_registry_dispatcher_boundary.json)
- [Dispatcher approval packet](../docs/V0.9_DISPATCHER_APPROVAL_PACKET.md)
- [Dispatcher approval fixture](../tests/fixtures/v09_dispatcher_approval_packet.json)
- [Dispatcher negative cases](../tests/fixtures/v09_dispatcher_negative_cases.json)
- 후속 dispatcher 구현 PR은 이 fixture를 반드시 사용해야 합니다.
- [Dispatcher implementation decision](../docs/V0.9_DISPATCHER_IMPLEMENTATION_DECISION.md)
- [Dispatcher decision fixture](../tests/fixtures/v09_dispatcher_implementation_decision.json)
- [`mcp_dispatcher.py`](../burp_ai_redaction_gateway/mcp_dispatcher.py)
- [Release readiness](../docs/V0.9_RELEASE_READINESS.md)
- [Release readiness fixture](../tests/fixtures/v09_release_readiness.json)

### v0.10

- [Scope decision](../docs/V0.10_SCOPE_DECISION.md)
- [Scope decision fixture](../tests/fixtures/v10_scope_decision.json)
- 첫 단계는 transport/listener 승인 문서이며, tool execution과 local evidence reader는 별도 검토 대상으로 유지합니다.
- [Transport/listener approval packet](../docs/V0.10_TRANSPORT_LISTENER_APPROVAL_PACKET.md)
- [Transport/listener approval fixture](../tests/fixtures/v10_transport_listener_approval_packet.json)
- 이 문서는 계획 및 승인 기준만 정의하며 listener runtime과 transport runtime을 구현하지 않습니다.
- [Listener startup negative cases](../tests/fixtures/v10_listener_startup_negative_cases.json)
- [Listener startup implementation decision](../docs/V0.10_LISTENER_STARTUP_IMPLEMENTATION_DECISION.md)
- [Listener startup decision fixture](../tests/fixtures/v10_listener_startup_implementation_decision.json)
- [`mcp_listener_startup_skeleton.py`](../burp_ai_redaction_gateway/mcp_listener_startup_skeleton.py)
- [Listener startup skeleton fixture](../tests/fixtures/v10_listener_startup_skeleton.json)
- [Listener startup implementation review](../docs/V0.10_LISTENER_STARTUP_IMPLEMENTATION_REVIEW.md)
- [Listener startup review fixture](../tests/fixtures/v10_listener_startup_implementation_review.json)
- 이 문서는 검토 전용이며 listener runtime을 구현하지 않습니다.
- [Transport runtime decision](../docs/V0.10_TRANSPORT_RUNTIME_DECISION.md)
- [Transport runtime decision fixture](../tests/fixtures/v10_transport_runtime_decision.json)
- 이 문서는 결정 전용이며 다음 단계는 release readiness입니다. 실제 runtime은 v0.11 이상에서 별도로 검토합니다.
- [Release readiness](../docs/V0.10_RELEASE_READINESS.md)
- [Release readiness fixture](../tests/fixtures/v10_release_readiness.json)
- v0.10은 메타데이터와 안전 경계 릴리스이며 실제 transport/listener runtime을 포함하지 않습니다. 후속 runtime은 v0.11 이상에서 별도로 검토합니다.

</details>

</details>
