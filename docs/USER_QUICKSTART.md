# 사용자 Quickstart

이 quickstart는 Burp AI Redaction Gateway를 CLI와 로컬 dashboard로 처음
사용할 때의 짧은 실행 흐름입니다. 프로젝트가 이미 checkout된 상태를
전제로 합니다.

목표 흐름은 다음과 같습니다.

```text
Burp scoped HTTP history
-> local receiver
-> redaction and verify
-> dashboard review
-> safe AI files
```

raw Burp 데이터를 AI 도구, PR, 이슈, 보고서, 문서에 붙여넣지 않습니다.

## 1. Receiver 시작

Windows에서는 receiver와 dashboard를 함께 시작하는 launcher가 가장 짧은
경로입니다.

```powershell
scripts\start_gateway.ps1
```

기본 launcher 설정은 다음과 같습니다.

| 설정 | 기본값 |
| --- | --- |
| Receiver | loopback port `8765` |
| Dashboard | loopback port `8766` |
| Output alias | `out\receiver` |
| Project alias | `receiver_alias` |
| PID와 launcher log | ignored `out\.launcher\` files |

launcher는 dashboard를 브라우저에서 열고 port, output alias, project alias,
process id, `raw_data_included=false` 같은 안전 metadata만 출력합니다.
raw request/response 값, cookie, authorization 값, token, 실제 대상 domain,
개인정보, HMAC secret, CSRF 값은 출력하지 않습니다.

launcher가 만든 receiver와 dashboard를 종료하려면 다음을 실행합니다.

```powershell
scripts\stop_gateway.ps1
```

execution policy, port 충돌, output alias, PID file 문제 해결은
[WINDOWS_LAUNCHER_GUIDE.md](C:/coding/burp-ai-redaction-gateway/docs/WINDOWS_LAUNCHER_GUIDE.md)를
참조하세요.

별도 terminal window를 선호하면 receiver를 수동으로 시작할 수 있습니다.

loopback receiver 시작:

```powershell
python -m burp_ai_redaction_gateway serve --host 127.0.0.1 --port 8765 --output out\receiver --project receiver_alias
```

안전 기대값:

- receiver는 `127.0.0.1`에서만 listen합니다.
- raw request/response 값은 로컬에서 처리됩니다.
- 생성 output은 `out\receiver` 아래에 기록됩니다.
- AI 사용 전 output은 계속 `verify`를 통과해야 합니다.

## 2. Scoped Burp History 전송

Burp에서 collector context menu를 사용해 scoped HTTP history item만 로컬
receiver로 보냅니다.

안전 기대값:

- scoped history만 사용합니다.
- 관련 없는 browsing history는 보내지 않습니다.
- raw request/response 값을 chat, issue, docs에 복사하지 않습니다.
- receiver가 실행 중이 아니면 안전한 connection error를 확인하고 receiver를
  시작한 뒤 다시 시도합니다.

## 3. Dashboard 시작

로컬 dashboard를 실행합니다.

```powershell
python -m burp_ai_redaction_gateway dashboard --host 127.0.0.1 --port 8766 --root out
```

브라우저에서 엽니다.

```text
http://127.0.0.1:8766/
```

dashboard는 `127.0.0.1` 로컬 검토 도구입니다. production web application이
아니며 네트워크에 노출하지 않습니다.

전체 GUI 화면 순서는
[GUI_USER_FLOW.md](C:/coding/burp-ai-redaction-gateway/docs/GUI_USER_FLOW.md)를
참조하세요. 조회 전용 AI 핸드오프 체크리스트는
[GUI_AI_SAFE_PREFLIGHT.md](C:/coding/burp-ai-redaction-gateway/docs/GUI_AI_SAFE_PREFLIGHT.md)를
참조하세요. 조회 전용 AI 안전 후보 파일 인덱스는
[GUI_AI_HANDOFF_INDEX.md](C:/coding/burp-ai-redaction-gateway/docs/GUI_AI_HANDOFF_INDEX.md)를
참조하세요. 조회 전용 prompt readiness 체크리스트는
[GUI_PROMPT_READINESS_INDEX.md](C:/coding/burp-ai-redaction-gateway/docs/GUI_PROMPT_READINESS_INDEX.md)를
참조하세요. 조회 전용 evidence boundary 체크리스트는
[GUI_EVIDENCE_BOUNDARY_INDEX.md](C:/coding/burp-ai-redaction-gateway/docs/GUI_EVIDENCE_BOUNDARY_INDEX.md)를
참조하세요. 조회 전용 operator runbook 체크리스트는
[GUI_OPERATOR_RUNBOOK_INDEX.md](C:/coding/burp-ai-redaction-gateway/docs/GUI_OPERATOR_RUNBOOK_INDEX.md)를
참조하세요. 조회 전용 safe file inventory 체크리스트는
[GUI_SAFE_FILE_INVENTORY_INDEX.md](C:/coding/burp-ai-redaction-gateway/docs/GUI_SAFE_FILE_INVENTORY_INDEX.md)를
참조하세요. 조회 전용 finding 후보 triage 체크리스트는
[GUI_FINDING_TRIAGE_INDEX.md](C:/coding/burp-ai-redaction-gateway/docs/GUI_FINDING_TRIAGE_INDEX.md)를
참조하세요. 조회 전용 보고서 초안 준비 체크리스트는
[GUI_REPORT_READINESS_INDEX.md](C:/coding/burp-ai-redaction-gateway/docs/GUI_REPORT_READINESS_INDEX.md)를
참조하세요. 조회 전용 workflow 상태 체크리스트는
[GUI_WORKFLOW_STATUS_INDEX.md](C:/coding/burp-ai-redaction-gateway/docs/GUI_WORKFLOW_STATUS_INDEX.md)를
참조하세요. dashboard 운영 인덱스는 다음 주소에서도 볼 수 있습니다.

```text
http://127.0.0.1:8766/help
http://127.0.0.1:8766/operations
```

## 4. Dashboard 흐름 사용

dashboard action은 다음 순서로 사용합니다.

1. 검증된 output directory 또는 receiver output을 선택합니다.
2. `Verify`를 실행합니다.
3. `Review`를 실행합니다.
4. `Finding triage index`를 엽니다.
5. `Report`를 실행합니다.
6. `Report readiness index`를 엽니다.
7. `Workflow status index`를 엽니다.
8. `AI-safe preflight`를 엽니다.
9. `AI handoff index`를 엽니다.
10. `Prompt readiness index`를 열어 prompt 파일 상태와 경계를 확인합니다.
11. `Evidence boundary index`를 열어 정제 evidence와 raw 금지 범위를 확인합니다.
12. `Operator runbook index`를 열어 수집부터 AI 투입 전 수동 검토까지 운영 순서를 확인합니다.
13. `Export`를 실행합니다.

Dashboard action 경계:

- 상태 변경 action은 CSRF 보호가 적용된 POST를 사용합니다.
- `Refresh`는 조회 전용 GET action입니다.
- `Finding triage index`는 후보 metadata용 조회 전용 GET 체크리스트입니다.
- `Report readiness index`는 수동 보고서 검토 전 조회 전용 GET 체크리스트입니다.
- `Workflow status index`는 verify, review, report, preflight, handoff,
  triage, report-readiness 순서에 대한 조회 전용 GET 체크리스트입니다.
- `AI-safe preflight`는 AI 핸드오프 전 조회 전용 GET 체크리스트입니다.
- `AI handoff index`는 안전 파일 목적과 순서에 대한 조회 전용 GET
  체크리스트입니다.
- `Prompt readiness index`는 prompt 파일 본문을 표시하지 않고
  `chatgpt_prompt.md`와 `codex_task_prompt.md`의 점검 결과만 요약하는
  조회 전용 GET 체크리스트입니다.
- `Evidence boundary index`는 정제 evidence와 raw 금지 범위를 분리해 보는
  조회 전용 GET 체크리스트입니다.
- `Operator runbook index`는 수집, verify, review, report, preflight, handoff,
  triage, report-readiness, prompt-readiness, evidence-boundary, workflow status
  recap 순서를 묶어 보는 조회 전용 GET 체크리스트입니다.
- `Safe file inventory index`는 safe files 4개의 존재 여부, 크기, 수정 시각,
  SHA-256 fingerprint를 본문 preview 없이 확인하는 조회 전용 GET 체크리스트입니다.
- Export는 안전 파일 allowlist로 제한됩니다.
- Raw viewer, replay, active scan, delete, edit action은 제공하지 않습니다.
- `/help`, `/operations`, `/settings`는 조회 전용 상태 또는 안내 page입니다.

## 5. AI에 넣을 수 있는 파일

선택한 output이 `verify`를 통과한 뒤 다음 파일만 ChatGPT, Codex 또는 다른
AI 도구의 검토 후보로 사용합니다.

| 파일 | 용도 |
| --- | --- |
| `analysis_packet.json` | 구조화된 sanitization 완료 finding 후보 packet |
| `chatgpt_prompt.md` | ChatGPT용 안전 분석 prompt |
| `codex_task_prompt.md` | Codex용 안전 task prompt |
| `report_draft.md` | 사람이 검토할 보고서 초안 |

`verify`가 실패하면 이 파일을 AI에 사용하지 않습니다.

## 6. 보내거나 문서화하지 않을 파일과 값

다음 값은 보내거나 문서화하지 않습니다.

| 보내지 않을 값 | 이유 |
| --- | --- |
| raw request 또는 raw response 데이터 | 민감값이 포함될 수 있음 |
| 실제 Burp XML export | raw traffic 원본 |
| `local_only/`, `raw/`, `raw_vault/` | 로컬 전용 또는 raw 저장 영역 |
| 검증 전 `out/` output | 안전 게이트가 통과되지 않음 |
| `out/.audit/` log 또는 HMAC manifest | 운영 metadata이며 AI prompt 자료가 아님 |
| Cookie, Authorization, token, JWT, session 값 | 인증 또는 세션 자료 |
| 실제 domain, 고객명, 내부 IP, 개인정보 | 환경 또는 식별 민감 정보 |
| HMAC secret, CSRF 값, local secret file | 보안 민감 로컬 값 |

## 7. 결과를 보수적으로 해석

finding output은 확정 취약점 보고서가 아닙니다.

- Finding은 candidate 또는 suspected finding입니다.
- `confidence`는 evidence confidence이며 severity가 아닙니다.
- `risk_rating_draft`는 likelihood와 impact 기반 초안입니다.
- Severity 결정은 수동 검증과 수동 risk review가 필요합니다.
- 증거 없이 exploitation, data breach, privilege escalation을 주장하지
  않습니다.

`report_draft.md`는 검토 자료이며 최종 고객 보고서가 아닙니다.

## 8. 일반 문제 해결

### Verify 실패

해당 output을 AI에 사용하지 않습니다. synthetic fixture로 문제를 재현하고,
redaction 또는 scanner rule을 강화한 뒤 다시 시도합니다.

### Dashboard에 output이 표시되지 않음

output directory가 dashboard root 아래에 있고 예상 sanitization 파일이 있는지
확인합니다. 다음 명령을 실행합니다.

```powershell
python -m burp_ai_redaction_gateway verify --input out\receiver
```

### Legacy Audit Row가 Review에 실패

`review-audit`는 의도적으로 엄격합니다. audit schema `1.1` 이전에 생성된
older local audit row는 실패할 수 있습니다. audit review output을 검증
증거로 쓰기 전 fresh audit log를 생성합니다.

### HMAC이 설정되지 않음

dashboard가 HMAC을 not configured로 표시할 수 있습니다. 이는 상태 표시일
뿐입니다. HMAC secret을 chat, docs, PR, log에 출력하거나 붙여넣지 않습니다.

## 9. 최소 CLI-only 흐름

dashboard가 필요 없으면 CLI 흐름을 직접 실행합니다.

```powershell
python -m burp_ai_redaction_gateway verify --input out\receiver
python -m burp_ai_redaction_gateway review --input out\receiver --export-dir exports\receiver_review
python -m burp_ai_redaction_gateway report --input out\receiver --output out\receiver\report_draft.md --profile conservative
```

검증된 output 또는 export directory의 안전 파일만 사용합니다.
