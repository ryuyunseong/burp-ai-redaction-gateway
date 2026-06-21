# Burp AI Redaction Gateway

Burp HTTP history export를 sanitization 완료 evidence packet과 prompt file로
바꾸는 로컬 CLI/GUI 도구입니다. raw HTTP 값은 로컬에서 파싱하고 민감값은
redaction하며, 마지막 safety scan에서 token, 개인정보, raw HTTP marker가
남아 있으면 output 생성을 차단합니다.

현재 MVP는 Python 표준 라이브러리만 사용합니다. synthetic JSON fixture,
HAR-style JSON, 기본 Burp XML export 형태를 지원합니다.

## Usage

짧은 CLI와 dashboard walkthrough는
[docs/USER_QUICKSTART.md](docs/USER_QUICKSTART.md)를
참조하세요.

처음 사용하는 사용자를 위한 한글 빠른 시작 흐름은
[docs/USER_QUICKSTART_KO_v0.6.md](docs/USER_QUICKSTART_KO_v0.6.md)를
참조하세요. AI 투입 후보 4개를 기본 보기와 고급 보기로 나누어 읽는 방법은
[docs/OUTPUT_BUNDLE_GUIDE_KO_v0.6.md](docs/OUTPUT_BUNDLE_GUIDE_KO_v0.6.md)에
정리되어 있습니다.

브라우저에서 Burp export 파일을 선택해 redaction, verify, review, report를
한 번에 실행하는 v0.5 Upload Wizard는
[docs/GUI_UPLOAD_WIZARD.md](docs/GUI_UPLOAD_WIZARD.md)를
참조하세요. 이 흐름도 ChatGPT 자동 전송은 하지 않으며, AI 입력 후보 파일
4개만 표시합니다.
CLI 없이 웹에서 가능한 작업과 아직 불가능한 작업의 한글 운영자 가이드는
[docs/WEB_OPERATOR_GUIDE_KO_v0.7.md](docs/WEB_OPERATOR_GUIDE_KO_v0.7.md)를
참조하세요. 이 가이드는 Local Dashboard, Upload Wizard, safe files,
triage/report readiness, Windows launcher, localhost receiver, read-only MCP
stdio server 범위와 v0.7 MCP listener runtime 금지 경계를 분리합니다.
웹 화면 수동 점검 절차는
[docs/WEB_OPERATOR_SMOKE_CHECKLIST_KO_v0.7.md](docs/WEB_OPERATOR_SMOKE_CHECKLIST_KO_v0.7.md)를
참조하세요.
Burp browsing based live capture is now a session state placeholder.
`/live-capture` provides CSRF-protected start/stop placeholders and safe
session aliases only. collector/receiver behavior, actual traffic capture, and automatic ChatGPT handoff remain separate PR scope.

```powershell
python -m burp_ai_redaction_gateway generate `
  --input samples/synthetic_burp_history.json `
  --output out/demo `
  --project client_alias_demo `
  --risk-profile conservative `
  --policy policy.json
```

생성 output 검증:

```powershell
python -m burp_ai_redaction_gateway verify --input out/demo --policy policy.json
```

검증된 analysis packet을 review하고 필요한 경우 안전 prompt file을 export:

```powershell
python -m burp_ai_redaction_gateway review --input out/demo --export-dir exports/demo_review
```

`review` 명령은 먼저 `verify`를 실행하며, 검증 실패 시 export를 거부합니다.

검증된 analysis packet에서 보수적인 보고서 초안 생성:

```powershell
python -m burp_ai_redaction_gateway report --input out/demo --output out/demo/report_draft.md --profile conservative
```

보고서 초안은 모든 항목을 candidate 또는 suspected finding 상태로 유지합니다.
rationale, impact draft, 추가 검증 단계, remediation draft, 증명 전 주장하지
않을 항목을 포함합니다. `confidence`는 evidence confidence이며 severity가
아닙니다. risk rating은 likelihood, impact, severity draft 값을 가진 별도
초안으로만 표시되며 수동 검토가 필요합니다.

Report wording profile:

- `conservative`: 가장 보수적인 문구. 모든 finding은 후보로 유지합니다.
- `consultant`: consultant 보고서 초안 문구. 수동 검증은 계속 필요하며 확정
  취약점 주장은 차단합니다.

생성 파일:

- `endpoint_inventory.md`
- `sanitized_events.jsonl`
- `finding_candidates.json`
- `analysis_packet.json`
- `chatgpt_prompt.md`
- `codex_task_prompt.md`
- `redaction_audit.json`
- `redaction_audit.db`

각 생성 text artifact에는 `sanitizer_version`, `policy_hash`,
`raw_data_included: false`, `generated_at`, `source_event_count`, aggregate
`redaction_counts`, `scanner_result` 같은 metadata가 포함됩니다.

`finding_candidates.json`은 sanitization 완료 event만 사용해 만들어집니다.
각 후보는 `finding_id`, passive rule `type`, confidence, templated
`affected_endpoint`, `evidence_ids`, rationale, confidence rationale,
`risk_rating_draft`, manual test guidance, `do_not_claim` list를 포함해 수동
검증 전 과장된 주장을 방지합니다. `risk_rating_draft`는 draft likelihood,
impact, severity 값에 사용한 risk profile을 기록합니다. 지원 profile은
`conservative`, `consultant`, `strict`이고 기본값은 `conservative`입니다.
값은 draft-only이며 rating이 finalized가 아님을 명시합니다.
`analysis_packet.json`, `chatgpt_prompt.md`, `codex_task_prompt.md`는 이 후보
metadata에서 만들어지며 `verify` 통과 후에만 사용합니다.

## Policy

기본 policy는 [policy.json](policy.json)입니다.
fail-closed 방식이며 raw request/response output과 response snippet은 기본적으로
비활성화됩니다. 검증은 `.json`, `.jsonl`, `.md`, `.txt` 파일에서 raw token,
cookie value, JWT, PII, internal IP, domain, high entropy string, raw HTTP
marker를 스캔합니다.

허용된 false positive는 `verification.allowlist_notes`에 기록해야 합니다.
내장 allowlist는 `10.0.0.0/8` 같은 network bucket만 허용하며 raw internal
host IP address는 허용하지 않습니다.

## Fixtures

Repository fixture는 synthetic data만 포함합니다.

- `samples/synthetic_burp_history.json`
- `samples/synthetic_burp_variants.json`
- `samples/burp_xml_base64_history.xml`

fixture는 JSON API, URL-encoded form, multipart upload shape, GraphQL,
hidden input이 있는 HTML form, 여러 위치의 JWT, 한국어 PII, internal IP/host
aliasing, high entropy string, Burp XML base64 request/response를 다룹니다.

## Real-Like Smoke Test

실제 Burp export가 없을 때는 안전한 real-like smoke test sample을 생성합니다.

```powershell
python scripts\make_safe_burp_export_sample.py
scripts\run_safe_sample_smoke_test.bat
```

이 명령은 synthetic data만 포함한 `local_only\real_burp_history_sample.xml`을
만든 뒤 `generate`, `verify`, Git safety gate를 실행합니다. 생성 sample은
parser와 redaction smoke test에 유용하지만, Burp에서 직접 저장한 export와의
compatibility testing을 대체하지 않습니다.

실제 Burp export는 별도로 `local_only/` 아래에서만 테스트합니다. raw real
export는 커밋, prompt 붙여넣기, issue 복사, 문서 추가 대상이 아닙니다.
v0.4 release 후보 검증에서 실제 export를 다룰 때는
[docs/REAL_BURP_EXPORT_VALIDATION.md](docs/REAL_BURP_EXPORT_VALIDATION.md)와
[docs/templates/REAL_BURP_EXPORT_VALIDATION_TEMPLATE.md](docs/templates/REAL_BURP_EXPORT_VALIDATION_TEMPLATE.md)를
사용해 raw-free metadata만 기록합니다.
반복 가능한 로컬 smoke harness는
[docs/LOCAL_REAL_EXPORT_SMOKE_HARNESS.md](docs/LOCAL_REAL_EXPORT_SMOKE_HARNESS.md)를
참조하세요. harness는 ignored `local_only/` 입력과 ignored `out/` 출력만
허용하며, console에는 `raw_data_included=false`와 safe alias metadata만
출력합니다.

첫 authorized local real export smoke 결과는 RC1 readiness 근거로만 기록합니다.
기준선은 `v0.4.30-local-real-export-smoke-harness`이고, 기록값은
`actual_export_smoke=passed`, `generate=passed`, `verify=passed`,
`review=passed`, `report=passed`, `dashboard_smoke=passed`,
`browser_smoke=passed`, `candidate_count=60`, `safe_files_present=4`,
`forbidden_value_hits=0` 같은 raw-free metadata로 제한합니다. 제안된 RC1
tag 후보는 `v0.4.31-rc1`이지만, tag 생성은 별도 승인 후에만 진행합니다.

## v0.4 RC3 readiness metadata

Authorized local real export smoke results are recorded as release readiness
evidence only, using raw-free metadata. The current RC3 readiness baseline is
`v0.4.33-rc3-redaction-metadata-hardening`.

- First actual export smoke: `actual_export_smoke=passed`, `generate=passed`,
  `verify=passed`, `review=passed`, `report=passed`,
  `dashboard_smoke=passed`, `browser_smoke=passed`, `candidate_count=60`,
  `safe_files_present=4`, `forbidden_value_hits=0`.
- Second actual export smoke: `actual_export_smoke=passed`,
  `source_event_count=54`, `candidate_count=84`, `safe_files_present=4`,
  `local_triage_sample_count=17`, `forbidden_value_hits=0`.

These records do not make any finding final, do not make risk drafts final, and
do not clear any output for external sharing. The final v0.4 baseline tag is
`v0.4.34`.

## Verification

테스트는 `unittest` 기반이며 pytest가 설치된 환경에서도 실행할 수 있습니다.

```powershell
python -m compileall burp_ai_redaction_gateway tests
python -m unittest discover -s tests
python -m burp_ai_redaction_gateway generate --input samples\synthetic_burp_history.json --output out\demo --project client_alias_demo
python -m burp_ai_redaction_gateway verify --input out\demo
```

커밋 전에는 다음을 실행합니다.

```powershell
scripts\pre_commit_check.bat
scripts\git_safety_check.bat
```

`git_safety_check`는 `git init` 전에도 실행 가능합니다. 이 경우 tracked/staged
file check는 건너뛰지만 pre-commit verification은 실행합니다.

## Operating Guide

Burp 수집, receiver 사용, verification, AI 안전 파일, audit retention,
HMAC verification, 실패 처리까지 포함한 전체 안전 운영 흐름은
[docs/OPERATING_GUIDE.md](docs/OPERATING_GUIDE.md)를
참조하세요. 처음 실행부터 안전 AI 핸드오프까지의 GUI 운영자 흐름은
[docs/GUI_USER_FLOW.md](docs/GUI_USER_FLOW.md)를
참조하세요. dashboard에서 로컬 Burp export를 처리하는 Upload Wizard는
[docs/GUI_UPLOAD_WIZARD.md](docs/GUI_UPLOAD_WIZARD.md)를
참조하세요. Burp browsing 중 local-only capture session을 안내하는 v0.5
Live Capture Wizard 설계는
[docs/LIVE_CAPTURE_WIZARD_DESIGN_v0.5.md](docs/LIVE_CAPTURE_WIZARD_DESIGN_v0.5.md)를
Current dashboard routes provide `GET /live-capture`, `POST /live-capture/start`,
and `POST /live-capture/stop` as a session state placeholder. Dashboard-driven
capture integration is not implemented yet. The read-only AI handoff checklist is
[docs/GUI_AI_SAFE_PREFLIGHT.md](docs/GUI_AI_SAFE_PREFLIGHT.md)를
참조하세요. 조회 전용 GUI 핸드오프 파일 인덱스는
[docs/GUI_AI_HANDOFF_INDEX.md](docs/GUI_AI_HANDOFF_INDEX.md)를
참조하세요. 조회 전용 prompt readiness 체크리스트는
[docs/GUI_PROMPT_READINESS_INDEX.md](docs/GUI_PROMPT_READINESS_INDEX.md)를
참조하세요. 조회 전용 evidence boundary 체크리스트는
[docs/GUI_EVIDENCE_BOUNDARY_INDEX.md](docs/GUI_EVIDENCE_BOUNDARY_INDEX.md)를
참조하세요. 조회 전용 operator runbook 체크리스트는
[docs/GUI_OPERATOR_RUNBOOK_INDEX.md](docs/GUI_OPERATOR_RUNBOOK_INDEX.md)를
참조하세요. 조회 전용 safe file inventory 체크리스트는
[docs/GUI_SAFE_FILE_INVENTORY_INDEX.md](docs/GUI_SAFE_FILE_INVENTORY_INDEX.md)를
참조하세요. 조회 전용 GUI finding triage 체크리스트는
[docs/GUI_FINDING_TRIAGE_INDEX.md](docs/GUI_FINDING_TRIAGE_INDEX.md)를
참조하세요. 조회 전용 GUI 보고서 초안 준비 체크리스트는
[docs/GUI_REPORT_READINESS_INDEX.md](docs/GUI_REPORT_READINESS_INDEX.md)를
참조하세요. 조회 전용 GUI workflow 상태 체크리스트는
[docs/GUI_WORKFLOW_STATUS_INDEX.md](docs/GUI_WORKFLOW_STATUS_INDEX.md)를
참조하세요. audit review, retention, HMAC, compression, archive HMAC runbook은
[docs/AUDIT_OPERATIONS_GUIDE.md](docs/AUDIT_OPERATIONS_GUIDE.md)를
참조하세요. dashboard audit/archive status panel 해석은
[docs/GUI_AUDIT_PANEL_GUIDE.md](docs/GUI_AUDIT_PANEL_GUIDE.md)를
참조하세요. 처음 보는 사용자를 위한 read-only simple dashboard는
[docs/GUI_SIMPLE_DASHBOARD.md](docs/GUI_SIMPLE_DASHBOARD.md)를
참조하세요. risk rating draft 개념과 profile 해석은
[docs/RISK_RATING_GUIDE.md](docs/RISK_RATING_GUIDE.md)를
참조하세요. v0.4 dashboard release baseline은
[docs/RELEASE_NOTES_v0.4.md](docs/RELEASE_NOTES_v0.4.md)를
참조하세요. v0.4 release 전 CLI/GUI smoke와 tag 기준은
[docs/RELEASE_CHECKLIST_v0.4.md](docs/RELEASE_CHECKLIST_v0.4.md)를
참조하세요. v0.4.34 GitHub Release 발행 전 검토용 초안은
[docs/GITHUB_RELEASE_v0.4.34.md](docs/GITHUB_RELEASE_v0.4.34.md)를
참조하세요. v0.5 후보 작업과 hotfix 경계는
[docs/ROADMAP_v0.5.md](docs/ROADMAP_v0.5.md)를
참조하세요. v0.5 MVP release readiness 범위와 점검 항목은
[docs/RELEASE_READINESS_v0.5.md](docs/RELEASE_READINESS_v0.5.md)를
참조하세요. v0.5 RC 후보 판단은
[docs/RC_READINESS_v0.5.md](docs/RC_READINESS_v0.5.md)를
참조하세요. v0.5 MCP 연동 설계와 한글 웹 UX 개선 계획은
[docs/MCP_INTEGRATION_DESIGN_v0.5.md](docs/MCP_INTEGRATION_DESIGN_v0.5.md)와
[docs/WEB_UX_KO_PLAN_v0.5.md](docs/WEB_UX_KO_PLAN_v0.5.md)를 참조하세요.
For the Burp MCP upstream tool versus gateway safety boundary, see
[docs/BURP_MCP_COMPATIBILITY_v0.5.md](docs/BURP_MCP_COMPATIBILITY_v0.5.md).

See the latest raw-free Montoya runtime smoke release evidence in
[docs/V05_MONTOYA_RUNTIME_SMOKE_RELEASE_EVIDENCE.md](docs/V05_MONTOYA_RUNTIME_SMOKE_RELEASE_EVIDENCE.md).
Post-v0.5 planning and v0.5.x hotfix boundaries are tracked in
[docs/ROADMAP_v0.6.md](docs/ROADMAP_v0.6.md) and
[docs/V0.5_HOTFIX_POLICY.md](docs/V0.5_HOTFIX_POLICY.md).
The v0.6 read-only MCP tool contract matrix is tracked in
[docs/MCP_READ_ONLY_TOOL_CONTRACT_MATRIX_v0.6.md](docs/MCP_READ_ONLY_TOOL_CONTRACT_MATRIX_v0.6.md).
The v0.6 MCP prototype preflight criteria are tracked in
[docs/MCP_READ_ONLY_PROTOTYPE_PREFLIGHT_v0.6.md](docs/MCP_READ_ONLY_PROTOTYPE_PREFLIGHT_v0.6.md).
The v0.6 MCP registry adapter design is tracked in
[docs/MCP_REGISTRY_ADAPTER_DESIGN_v0.6.md](docs/MCP_REGISTRY_ADAPTER_DESIGN_v0.6.md).
The v0.6 MCP registry adapter fixture plan is tracked in
[docs/MCP_REGISTRY_ADAPTER_FIXTURE_PLAN_v0.6.md](docs/MCP_REGISTRY_ADAPTER_FIXTURE_PLAN_v0.6.md).
The v0.6 MCP implementation gate design is tracked in
[docs/MCP_IMPLEMENTATION_GATE_DESIGN_v0.6.md](docs/MCP_IMPLEMENTATION_GATE_DESIGN_v0.6.md).
The v0.6 local-only MCP adapter dry-run helper is
`burp_ai_redaction_gateway/mcp_adapter_dry_run.py`. It consumes the registry,
adapter fixture, and implementation gate fixture without adding an MCP server,
transport, protocol handler, actual tool execution, local evidence reader, or
runtime MCP exposure.
The v0.6 local-only MCP tool schema catalog is
[`docs/MCP_LOCAL_ONLY_TOOL_SCHEMA_CATALOG_v0.6.md`](docs/MCP_LOCAL_ONLY_TOOL_SCHEMA_CATALOG_v0.6.md)
and `burp_ai_redaction_gateway/mcp_tool_schema_catalog.py`. It derives
descriptor metadata from the registry and dry-run fixtures only. It is not an
MCP server, transport, protocol handler, actual tool execution, local evidence
reader, or runtime MCP exposure.
The v0.6 MCP runtime boundary decision is tracked in
[`docs/MCP_RUNTIME_BOUNDARY_DECISION_v0.6.md`](docs/MCP_RUNTIME_BOUNDARY_DECISION_v0.6.md).
It separates server, transport, protocol, tool execution, and local evidence
reader work before any runtime MCP implementation is considered.
The v0.6 MCP server skeleton preflight is tracked in
[`docs/MCP_SERVER_SKELETON_PREFLIGHT_v0.6.md`](docs/MCP_SERVER_SKELETON_PREFLIGHT_v0.6.md).
It consumes the registry, dry-run, schema catalog, implementation gate, adapter
fixture, and runtime boundary decision before any listener or transport work is
considered.
The v0.6 MCP runtime boundary consumption fixture is tracked in
[`docs/MCP_RUNTIME_BOUNDARY_CONSUMPTION_v0.6.md`](docs/MCP_RUNTIME_BOUNDARY_CONSUMPTION_v0.6.md).
It adds fixture, test, and source-check evidence only; it does not approve a
listener, transport, protocol handler, tool execution, or local evidence reader.
The v0.6 MCP listener skeleton decision is tracked in
[`docs/MCP_LISTENER_SKELETON_DECISION_v0.6.md`](docs/MCP_LISTENER_SKELETON_DECISION_v0.6.md).
It is a design and acceptance criteria document only; it does not approve a
listener implementation or expand transport, protocol, execution, or evidence
reader scope.
The v0.6 MCP listener skeleton acceptance criteria are tracked in
[`docs/MCP_LISTENER_SKELETON_ACCEPTANCE_v0.6.md`](docs/MCP_LISTENER_SKELETON_ACCEPTANCE_v0.6.md).
They add fixture and source-check policy only; they do not implement a listener,
transport, protocol handler, tool execution, or local evidence reader.
The v0.6 MCP listener runtime-facing source check guard is tracked in
[`docs/MCP_LISTENER_RUNTIME_SOURCE_CHECK_v0.6.md`](docs/MCP_LISTENER_RUNTIME_SOURCE_CHECK_v0.6.md).
It keeps future listener-facing files declared before they can enter the
source-check scope; it still does not implement a listener, transport, protocol
handler, tool execution, or local evidence reader.
The v0.6 RC readiness checklist is tracked in
[`docs/V0.6_RC_READINESS_CHECKLIST.md`](docs/V0.6_RC_READINESS_CHECKLIST.md).
It records gate, smoke, UX, output bundle, MCP boundary, blocker, tag, and
GitHub Release decision criteria without creating a tag or release.
The v0.6 quickstart smoke procedure and release notes draft are tracked in
[`docs/V0.6_QUICKSTART_SMOKE.md`](docs/V0.6_QUICKSTART_SMOKE.md) and
[`docs/V0.6_RELEASE_NOTES_DRAFT.md`](docs/V0.6_RELEASE_NOTES_DRAFT.md).
They document the generate, verify, review, report, and Simple Dashboard path
without creating a tag or GitHub Release.
The v0.6 RC final gate evidence and release approval packet draft are tracked
in [`docs/V0.6_RC_FINAL_GATE_RUN.md`](docs/V0.6_RC_FINAL_GATE_RUN.md) and
[`docs/V0.6_RELEASE_APPROVAL_PACKET.md`](docs/V0.6_RELEASE_APPROVAL_PACKET.md).
They organize release decision evidence only and still do not create a tag or
GitHub Release.
Post-release `v0.6.1` hotfix triage criteria are tracked in
[`docs/V0.6.1_HOTFIX_TRIAGE.md`](docs/V0.6.1_HOTFIX_TRIAGE.md). They define
which post-release issues may be considered hotfix candidates and keep MCP
runtime work out of patch scope.
The v0.7 scope planning boundary is tracked in
[`docs/V0.7_SCOPE_PLAN.md`](docs/V0.7_SCOPE_PLAN.md). It separates v0.7 goals,
non-goals, PR split rules, MCP listener planning, UX polish candidates, and
local evidence reader design boundaries without implementing runtime behavior.
The v0.7 MCP listener skeleton plan is tracked in
[`docs/V0.7_MCP_LISTENER_SKELETON_PLAN.md`](docs/V0.7_MCP_LISTENER_SKELETON_PLAN.md).
It fixes source-check scope and acceptance criteria before any listener,
transport, protocol, execution, or local evidence reader implementation.
The first listener-facing helper is metadata-only and does not enable listener
runtime behavior, transport, protocol handling, tool execution, raw preview, or
automatic ChatGPT handoff.
The v0.7 listener runtime decision preflight is tracked in
[`docs/V0.7_LISTENER_RUNTIME_DECISION_PREFLIGHT.md`](docs/V0.7_LISTENER_RUNTIME_DECISION_PREFLIGHT.md).
It fixes the next planning guard before any listener runtime work and still does
not implement socket bind, transport, protocol handling, tool execution, local
evidence reading, raw preview, or automatic ChatGPT handoff.
The v0.7 minimal listener runtime approval packet is tracked in
[`docs/V0.7_MINIMAL_LISTENER_RUNTIME_APPROVAL_PACKET.md`](docs/V0.7_MINIMAL_LISTENER_RUNTIME_APPROVAL_PACKET.md).
It records approval criteria and negative-test expectations only; it does not
implement listener runtime behavior, transport, protocol handling, tool
execution, local evidence reading, raw preview, or automatic ChatGPT handoff.
The v0.7 minimal listener runtime implementation design is tracked in
[`docs/V0.7_MINIMAL_LISTENER_RUNTIME_DESIGN.md`](docs/V0.7_MINIMAL_LISTENER_RUNTIME_DESIGN.md).
It fixes local-only, loopback-only, disabled-by-default, raw-free error,
source-check, negative-test, rollback, and PR split requirements before any
listener runtime implementation is added.
The v0.7 runtime source-check consumption guard is tracked in
[`docs/V0.7_RUNTIME_SOURCE_CHECK_CONSUMPTION.md`](docs/V0.7_RUNTIME_SOURCE_CHECK_CONSUMPTION.md).
It connects the design fixture to declared runtime-facing source scope and
keeps future runtime-facing files from bypassing forbidden surface checks.
The v0.7 listener negative test harness design is tracked in
[`docs/V0.7_LISTENER_NEGATIVE_TEST_HARNESS_DESIGN.md`](docs/V0.7_LISTENER_NEGATIVE_TEST_HARNESS_DESIGN.md).
It fixes blocked and disabled response expectations before any listener runtime
implementation is added.
The v0.7 minimal listener runtime implementation decision is tracked in
[`docs/V0.7_MINIMAL_LISTENER_RUNTIME_IMPLEMENTATION_DECISION.md`](docs/V0.7_MINIMAL_LISTENER_RUNTIME_IMPLEMENTATION_DECISION.md).
It records that a narrow follow-up runtime PR may be proposed, while this
decision itself still does not implement listener runtime behavior.
The v0.7 minimal listener runtime implementation is tracked in
[`docs/V0.7_MINIMAL_LISTENER_RUNTIME_IMPLEMENTATION.md`](docs/V0.7_MINIMAL_LISTENER_RUNTIME_IMPLEMENTATION.md).
It adds disabled-by-default, loopback-only startup validation and raw-free
blocked/disabled response helpers only. It does not add transport, protocol
handling, tool execution, local evidence reading, dashboard state-changing
control, upload/import behavior, or automatic ChatGPT handoff.
The v0.7 listener local smoke evidence is tracked in
[`docs/V0.7_LISTENER_LOCAL_SMOKE_EVIDENCE.md`](docs/V0.7_LISTENER_LOCAL_SMOKE_EVIDENCE.md).
It records metadata-only smoke evidence for the minimal listener runtime helper
without starting a listener, adding transport, parsing protocol messages,
executing tools, reading local evidence, or creating a tag or GitHub Release.
The v0.7 RC readiness checklist is tracked in
[`docs/V0.7_RC_READINESS_CHECKLIST.md`](docs/V0.7_RC_READINESS_CHECKLIST.md).
It ties release-readiness gates and smoke evidence together without approving
or creating any tag or GitHub Release.
The v0.7 release approval packet is tracked in
[`docs/V0.7_RELEASE_APPROVAL_PACKET.md`](docs/V0.7_RELEASE_APPROVAL_PACKET.md).
It records release approval inputs only and still does not create a tag or
GitHub Release.
The v0.7 final gate execution evidence is tracked in
[`docs/V0.7_FINAL_GATE_EXECUTION.md`](docs/V0.7_FINAL_GATE_EXECUTION.md).
It records pre-release gate results and target checks only; it still does not
create a tag or GitHub Release.
The v0.7 release notes draft is tracked in
[`docs/V0.7_RELEASE_NOTES_DRAFT.md`](docs/V0.7_RELEASE_NOTES_DRAFT.md).
It prepares a release body for review only and still does not create a tag or
GitHub Release.
The v0.8 backlog split is tracked in
[`docs/V0.8_BACKLOG_SPLIT.md`](docs/V0.8_BACKLOG_SPLIT.md). It separates MCP
transport, protocol handling, tool registration, tool execution, local evidence
reading, raw preview/download, dashboard state-changing control, upload/import,
replay/active scan, and automatic ChatGPT handoff into separate design or
approval PRs before implementation.
The first v0.8 follow-up is the transport design-only boundary in
[`docs/V0.8_TRANSPORT_DESIGN.md`](docs/V0.8_TRANSPORT_DESIGN.md). It documents
transport acceptance and negative-test requirements without implementing socket,
stdio, HTTP, protocol, tool, evidence-reader, raw preview, dashboard action,
upload/import, replay, active scan, or automatic handoff behavior.
The v0.8 protocol handler design-only boundary is tracked in
[`docs/V0.8_PROTOCOL_HANDLER_DESIGN.md`](docs/V0.8_PROTOCOL_HANDLER_DESIGN.md).
It documents malformed protocol input handling, raw-free blocked responses,
negative-test expectations, and source-check requirements without implementing
an MCP protocol handler, JSON-RPC parser, request dispatcher, tool execution,
transport runtime, local evidence reader, raw preview, or automatic handoff.
The v0.8 protocol negative test harness is tracked in
[`docs/V0.8_PROTOCOL_NEGATIVE_TEST_HARNESS.md`](docs/V0.8_PROTOCOL_NEGATIVE_TEST_HARNESS.md).
It fixes malformed input categories, echo-forbidden value classes, forbidden
source marker categories, and blocked-response requirements without
implementing a protocol parser, request dispatcher, tool registration, tool
execution, local evidence reader, raw preview, or automatic handoff.
The v0.8 tool registration design-only boundary is tracked in
[`docs/V0.8_TOOL_REGISTRATION_DESIGN.md`](docs/V0.8_TOOL_REGISTRATION_DESIGN.md).
It separates registration metadata from actual tool execution and keeps tool
registry runtime, discovery runtime, dispatcher, local evidence reader, raw
preview, replay, active scan, dashboard state-changing control, upload/import,
and automatic handoff behavior out of scope.
The v0.8 read-only tool contract is tracked in
[`docs/V0.8_READ_ONLY_TOOL_CONTRACT.md`](docs/V0.8_READ_ONLY_TOOL_CONTRACT.md).
It defines metadata-only future tool candidates and forbidden tool surfaces
without implementing tool registration runtime, discovery runtime, dispatcher,
tool execution, local evidence reader, safe file body reader, raw preview,
replay, active scan, dashboard action, upload/import, or automatic handoff.
The v0.8 minimal skeleton planning boundary is tracked in
[`docs/V0.8_MINIMAL_SKELETON_PLANNING.md`](docs/V0.8_MINIMAL_SKELETON_PLANNING.md).
It fixes disabled-by-default, contract-consumption, source-check, and rollback
requirements before any socket, stdio, HTTP, protocol parser, dispatcher, tool
runtime, local evidence reader, raw preview, dashboard action, upload/import,
replay, active scan, or automatic handoff behavior is implemented.
The v0.8 skeleton approval packet is tracked in
[`docs/V0.8_SKELETON_APPROVAL_PACKET.md`](docs/V0.8_SKELETON_APPROVAL_PACKET.md).
It fixes explicit approval, blocker, raw-free response, rollback, and
source-check requirements before any disabled-by-default skeleton runtime PR is
reviewed.

The v0.8 runtime source-check consumption guard is tracked in
[`docs/V0.8_RUNTIME_SOURCE_CHECK_CONSUMPTION_GUARD.md`](docs/V0.8_RUNTIME_SOURCE_CHECK_CONSUMPTION_GUARD.md).
It declares future runtime-facing files as fixture metadata only and keeps
runtime implementation blocked until approval packet consumption and forbidden
marker checks are in place.
The v0.8 post-merge boundary note is tracked in
[`docs/V0.8_POST_MERGE_BOUNDARY_NOTE.md`](docs/V0.8_POST_MERGE_BOUNDARY_NOTE.md).
It records the PR #130 helper-only merge baseline and keeps listener startup,
transport, protocol parsing, request dispatch, tool execution, local evidence
reading, raw preview, dashboard action, upload/import, replay, active scan,
automatic handoff, tag changes, and GitHub Release changes out of scope.
The v0.8 scope freeze and RC readiness boundary is tracked in
[`docs/V0.8_SCOPE_FREEZE_RC_READINESS.md`](docs/V0.8_SCOPE_FREEZE_RC_READINESS.md).
It recommends v0.8 as a boundary/helper release candidate and keeps listener
startup, socket behavior, transport, parser, dispatcher, tool runtime, evidence
reader, raw preview, dashboard action, upload/import, replay, active scan,
automatic handoff, tag creation, and GitHub Release creation out of scope.
The v0.8 release approval packet is tracked in
[`docs/V0.8_RELEASE_APPROVAL_PACKET.md`](docs/V0.8_RELEASE_APPROVAL_PACKET.md).
It records target commit, baseline PRs, release body hygiene, rollback
requirements, and explicit approval boundaries without creating a tag or
GitHub Release.

## Burp Montoya Collector

Burp-side collector skeleton은
[extensions/montoya-collector](extensions/montoya-collector)
아래에 있습니다. Java/Gradle Montoya extension이며 in-scope Proxy HTTP
history item만 수집해 loopback 전용 local gateway endpoint로 전달합니다.
raw request/response 값은 log에 쓰지 않으며, 생성 output은 사용 전 기존
Python `verify` gate를 계속 통과해야 합니다.

[docs/MONTOYA_COLLECTOR.md](docs/MONTOYA_COLLECTOR.md)를
참조하세요.

## Windows Local Launcher

Windows에서는 receiver와 dashboard를 함께 시작합니다.

```powershell
scripts\start_gateway.ps1
```

launcher는 receiver를 loopback port `8765`에서 시작하고, dashboard를 loopback
port `8766`에서 시작하며, 로컬 dashboard를 브라우저에서 엽니다.
ignored `out\.launcher\` file 아래에 안전 launcher metadata만 기록합니다.
console output에는 `raw_data_included=false`가 포함됩니다. launcher가 관리하는
process를 종료하려면 다음을 실행합니다.

```powershell
scripts\stop_gateway.ps1
```

launcher는 raw request/response 값, cookie, authorization 값, token, 실제
target domain, 개인정보, HMAC secret, CSRF 값을 출력하지 않습니다.
[docs/USER_QUICKSTART.md](docs/USER_QUICKSTART.md)를
참조하세요. Windows launcher troubleshooting과 execution policy note는
[docs/WINDOWS_LAUNCHER_GUIDE.md](docs/WINDOWS_LAUNCHER_GUIDE.md)를
참조하세요.

## Localhost Receiver

Montoya collector handoff payload용 loopback receiver 실행:

```powershell
python -m burp_ai_redaction_gateway serve --host 127.0.0.1 --port 8765 --output out\receiver --project montoya_receiver_alias
```

receiver는 `POST /ingest/burp-history`를 받고 즉시 redaction을 적용한 뒤 검증
가능한 sanitization output만 기록합니다.
[docs/LOCALHOST_RECEIVER.md](docs/LOCALHOST_RECEIVER.md)를
참조하세요.

## Read-Only MCP Server

검증된 sanitization output용 read-only MCP server를 stdio로 실행:

```powershell
python -m burp_ai_redaction_gateway mcp --root out
```

MCP server는 검증된 output directory에 대한 read-only tool만 제공합니다.
raw exchange lookup, replay, file write, external transmission은 구현하지
않습니다.
[docs/READ_ONLY_MCP.md](docs/READ_ONLY_MCP.md)를
참조하세요.

## Local Dashboard

검증된 output용 local read-only dashboard 실행:

```powershell
python -m burp_ai_redaction_gateway dashboard --host 127.0.0.1 --port 8766 --root out
```

dashboard home `/`에는 한글 우선 quickstart landing이 있습니다. 첫 화면에서
업로드 마법사, Live Capture 상태 확인, safe files 4개 확인, 운영 도움말로 이동할
수 있습니다. 검증 통과 산출물이 있으면 safe files 카드는 목록의 첫 번째
검증 통과 산출물로 이동하고, 없으면 운영 도움말로 이동합니다. 이 landing은 안내와
링크만 제공하며 raw preview, replay, active scan, 자동 ChatGPT 전송은
제공하지 않습니다.

home, `/safe-files`, `/triage`, `/report-readiness`, `/workflow`,
`/live-capture`에는 검증된 output 산출물 선택 영역이 있습니다. 이 selector는
verify를 통과한 output alias만 보여 주는 read-only navigation이며, local path,
actual target identifier, raw traffic, credential value를 표시하지 않습니다.
Safe files는 AI 입력 후보이며 수동 검토가 필요하고, finding은 후보, risk는
초안이며, severity와 CVSS는 사람이 수동 결정합니다.

home, `/help`, `/operations`, `/live-capture`에는 read-only troubleshooting
categories와 release readiness status 안내가 표시됩니다. 이 영역은 setup,
upload/export, verify/review/report, live-capture, safe-files, MCP boundary
기존 route로 이동하는 링크와 문서 파일명 안내만 제공합니다. Dashboard는
`docs/*.md`를 직접 serving하지 않으며, tag 생성, GitHub Release 생성, raw
preview, replay, active scan, 자동 ChatGPT 전송, POST action은 제공하지 않습니다.

dashboard는 `127.0.0.1`에만 bind합니다. 설정된 root 아래 output directory를
찾고, 선택한 output이 `verify`를 통과한 뒤에만 preview, download, 보호된
안전 action을 허용합니다. 노출되는 안전 파일은 다음 4개뿐입니다.

- `analysis_packet.json`
- `chatgpt_prompt.md`
- `codex_task_prompt.md`
- `report_draft.md`

dashboard는 raw request/response viewing, replay, active scan action, 임의
file write, delete, edit operation을 구현하지 않습니다. 상태 변경 dashboard
action은 CSRF token이 있는 POST를 사용합니다. 지원 action은 verify, review
summary, report draft generation, safe file export로 제한됩니다.
path traversal을 거부하고 `local_only/`, `raw/`, `raw_vault/`, `build/`,
`.gradle/` path를 차단합니다. Audit 상태는 audit row, cookie, authorization
값, token, domain, internal IP, 개인정보, HMAC secret을 출력하지 않고
요약합니다.

Dashboard 상태 변경 action은 `event_type: dashboard_action` raw-free audit
event도 추가합니다. event에는 action name, sanitization output id, result
status, blocked reason, 안전 exported file name 같은 metadata만 기록됩니다.
CSRF token 값, raw HTTP 값, stack trace, domain, internal IP, 개인정보는
dashboard action audit event에 쓰지 않습니다.

dashboard는 verify-passed status, raw-free display mode, candidate finding
language, manual verification requirement, evidence confidence는 severity가
아니라는 경계를 강조합니다. finding card는 별도 `risk_rating_draft`를
표시할 수 있지만, draft는 수동 risk review 전 unfinalized 상태로 유지됩니다.

dashboard에는 다음 조회 전용 화면도 포함됩니다.

- `/simple?project=<alias>` 또는 `/dashboard-simple?project=<alias>`: read-only 간단 체크 화면
- `/preflight?project=<alias>`: AI 안전 사전 점검
- `/handoff?project=<alias>`: AI 핸드오프 인덱스
- `/prompt-readiness?project=<alias>`: prompt readiness 인덱스
- `/evidence-boundary?project=<alias>`: 정제 evidence와 raw 금지 범위 경계 인덱스
- `/operator-runbook?project=<alias>`: 수집부터 AI 투입 전 수동 검토까지 운영 순서 인덱스
- `/safe-files?project=<alias>`: safe files 4개 inventory 인덱스
- `/triage?project=<alias>`: finding triage 인덱스
- `/report-readiness?project=<alias>`: 보고서 초안 준비 상태 인덱스
- `/workflow?project=<alias>`: workflow 상태 인덱스
- `/settings`: 설정/보안 상태
- `/help` and `/operations`: 운영 인덱스

Simple Dashboard는 현재 상태, AI에 넣을 후보 파일 4개, 다음 행동만 요약합니다.
이 조회 전용 화면들은 form, POST action, 상태 변경 버튼, report body preview,
새 download, raw viewer, HMAC secret input, CSRF token display, replay,
active scan, delete, edit, retention control, risk profile action을 추가하지
않습니다.

[docs/LOCAL_DASHBOARD.md](docs/LOCAL_DASHBOARD.md)를
참조하세요.

## MCP Audit Records

Tool-call과 dashboard action audit record는 `<root>/.audit/mcp_audit.jsonl`
아래에 raw-free metadata only로 기록됩니다. Audit schema `1.1`은 새 MCP
tool-call 또는 dashboard action event마다 event id, sequence number,
SHA-256 hash chain field도 기록합니다.
`event_id`는 표준 UUID string입니다. active audit file은 다음 event가 size
limit을 넘길 때 `mcp_audit.000001.jsonl` 같은 deterministic name으로
rotate됩니다. suffix는 rotated segment 시작 시점의 chain-wide sequence
number에서 오므로, audit chain이 계속되는 동안 retained rotation name은
`000001`로 다시 시작하지 않습니다. Retention은 rotated file만 유지하며
active file을 삭제하지 않습니다. Hash chain verification은 retained rotated
file과 active file에 대해서만 보장됩니다. retained boundary 이전 history는
older rotated file 제거 후 검증 범위 밖입니다.

retained audit log review:

```powershell
python -m burp_ai_redaction_gateway review-audit --input out\.audit
python -m burp_ai_redaction_gateway review-audit --input out\.audit --format json
```

`review-audit`는 JSONL parsing, required schema field, UUID event id,
sequence continuity, hash chain integrity, rotated suffix order, retained
rotated file과 active audit file의 raw-free scanner result를 확인합니다.
audit schema `1.1`에 엄격하므로 older run의 pre-schema local audit row는
review 실패로 처리됩니다.

`audit-retention`으로 명시적인 retained audit file 생성:

```powershell
python -m burp_ai_redaction_gateway audit-retention --input out\.audit\mcp_audit.jsonl --output out\.audit\mcp_audit.retained.jsonl --retention-days 30 --dry-run
python -m burp_ai_redaction_gateway audit-retention --input out\.audit\mcp_audit.jsonl --output out\.audit\mcp_audit.retained.jsonl --retention-days 30
python -m burp_ai_redaction_gateway review-audit --input out\.audit\mcp_audit.retained.jsonl
```

`audit-retention`은 먼저 strict `review-audit`로 input을 검증하고, legacy 또는
malformed row를 거부하며, in-place modification을 금지하고 raw-free summary
metadata만 출력합니다.

retained audit file용 raw-free HMAC manifest 생성/검증:

```powershell
$env:BURP_AI_AUDIT_HMAC_KEY = "<LOCAL_ONLY_HMAC_SECRET>"
python -m burp_ai_redaction_gateway audit-hmac --input out\.audit\mcp_audit.retained.jsonl --manifest out\.audit\mcp_audit.retained.manifest.json
python -m burp_ai_redaction_gateway audit-hmac-verify --input out\.audit\mcp_audit.retained.jsonl --manifest out\.audit\mcp_audit.retained.manifest.json
```

`audit-hmac`는 strict `review-audit`를 통과한 audit JSONL file만 받습니다.
manifest는 file alias, row count, SHA-256, HMAC-SHA256, creation time,
`raw_data_included: false`를 저장합니다. raw audit row나 HMAC secret은
저장하지 않습니다. HMAC은 tamper detection이며 encryption이 아닙니다.
HMAC secret은 environment variable 또는 ignored local secret file에만
저장합니다.

검토된 audit JSONL file을 gzip으로 local long-term storage용 packaging:

```powershell
python -m burp_ai_redaction_gateway audit-compress --input out\.audit\mcp_audit.retained.jsonl --output out\.audit\mcp_audit.retained.jsonl.gz
python -m burp_ai_redaction_gateway audit-compress-verify --input out\.audit\mcp_audit.retained.jsonl.gz
```

`audit-compress`는 strict `review-audit` 통과 audit JSONL file만 받으며 별도
`.jsonl.gz` file을 쓰고 source JSONL을 삭제하거나 수정하지 않습니다.
`audit-compress-verify`는 package를 temporary location에 decompress하고
decompressed JSONL이 `review-audit`를 통과해야 합니다. Compression은 archival
packaging입니다. HMAC verification은 retained JSONL file 기준으로 유지되며,
compressed archive HMAC은 별도 archive-level check입니다.

compressed archive용 raw-free HMAC manifest 생성/검증:

```powershell
$env:BURP_AI_AUDIT_HMAC_KEY = "<LOCAL_ONLY_HMAC_SECRET>"
python -m burp_ai_redaction_gateway audit-compressed-hmac --input out\.audit\mcp_audit.retained.jsonl.gz --manifest out\.audit\mcp_audit.retained.jsonl.gz.manifest.json
python -m burp_ai_redaction_gateway audit-compressed-hmac-verify --input out\.audit\mcp_audit.retained.jsonl.gz --manifest out\.audit\mcp_audit.retained.jsonl.gz.manifest.json
```

`audit-compressed-hmac`는 먼저 `audit-compress-verify`로 archive를 검증한 뒤
compressed bytes에 대해 SHA-256과 HMAC-SHA256을 계산합니다. manifest는 안전
archive alias, compressed size, SHA-256, HMAC-SHA256, creation time,
`raw_data_included: false`를 저장합니다. decompressed audit row나 HMAC secret은
저장하지 않습니다. Compressed archive HMAC은 gzip package bytes의 tamper
detection이며 encryption이 아니고 `review-audit` 또는 retained JSONL HMAC을
대체하지 않습니다.

## Security Notes

- 실제 Burp export, raw HTTP history, token, cookie, customer domain,
  internal IP, local audit database를 커밋하지 않습니다.
- 이 repository의 fixture는 synthetic 상태를 유지해야 합니다.
- `review`는 `verify`를 통과해야 하는 output directory에만 사용합니다.
  raw HTTP content가 아니라 summary count와 안전 prompt file name만 출력합니다.
- `report`는 verification 뒤에만 사용합니다. Report draft는 수동 재현 전
  candidate wording을 유지해야 합니다. 가장 보수적인 문구에는
  `--profile conservative`, consultant draft 문구에는 `--profile consultant`를
  사용하되 수동 검증은 계속 필요합니다.
- `mcp`는 명시적인 sanitization output root와 함께만 사용합니다. MCP tool은
  read-only이며 local raw data나 실제 Burp export 접근에 사용하지 않습니다.
- MCP audit log는 raw-free 상태를 유지하고 tool name, sanitization output id,
  status, blocked reason, event id, sequence number, hash chain field 같은
  metadata만 저장합니다.
- retained audit log를 raw value 출력 없이 확인하려면 `review-audit`를
  사용합니다.
- `audit-retention`은 별도 `--output` file과 함께만 사용합니다. audit log를
  in-place로 수정하지 않습니다.
- `audit-hmac`와 `audit-hmac-verify`는 `BURP_AI_AUDIT_HMAC_KEY` 또는 ignored
  secret file의 local HMAC secret으로만 사용합니다. HMAC secret이나 생성된
  manifest를 커밋하지 않습니다.
- `audit-compress`는 strict `review-audit` 성공 뒤에만 사용합니다. 원본 JSONL은
  유지합니다. compressed package는 local archival output이며 retained JSONL
  HMAC verification의 대체물이 아닙니다.
- `audit-compressed-hmac`와 `audit-compressed-hmac-verify`는 local HMAC secret과
  함께만 사용합니다. compressed archive manifest에는 raw audit row, secret
  value, real environment value를 포함하지 않습니다.
- audit database는 evidence reference와 redaction counter만 저장합니다. raw
  request/response 값은 저장하지 않습니다.
- output generation은 fail-closed입니다. likely token, JWT, email, phone
  number, Korean RRN, financial identifier, high-entropy secret이 generated
  text에 남아 있으면 CLI는 output file 쓰기 전에 error를 발생시킵니다.
- 실제 Burp export는 `local_only/` 아래에서만 테스트하고, `samples/`로
  이동하거나 커밋하거나 prompt에 붙여넣거나 issue로 복사하지 않습니다.
