# GUI 사용자 흐름

이 문서는 receiver와 dashboard가 실행된 뒤 로컬 dashboard를 사용하는
운영자 관점의 흐름을 설명합니다. quickstart, dashboard 도움말, 설정/상태
화면, 안전 파일 export, 수동 검토 경계를 한 흐름으로 연결합니다.

dashboard는 `127.0.0.1` 로컬 검토 도구입니다. production web application이
아니며 네트워크에 노출하지 않습니다.

## 전체 흐름

일반적인 GUI 보조 검토는 다음 순서로 진행합니다.

```text
start receiver and dashboard
-> send scoped Burp history to the local receiver
-> generate sanitized output
-> verify the selected output
-> review candidate findings
-> check finding triage index
-> generate report_draft.md
-> check report readiness index
-> check workflow status index
-> check AI-safe preflight
-> check AI handoff index
-> check prompt readiness index
-> export safe files
-> send only verified safe files to AI
```

Windows launcher로 receiver와 dashboard를 함께 시작할 수 있습니다.

```powershell
scripts\start_gateway.ps1
```

수동 시작도 가능합니다.

```powershell
python -m burp_ai_redaction_gateway serve --host 127.0.0.1 --port 8765 --output out\receiver --project receiver_alias
python -m burp_ai_redaction_gateway dashboard --host 127.0.0.1 --port 8766 --root out
```

dashboard를 엽니다.

```text
http://127.0.0.1:8766/
```

## Dashboard 화면

| 화면 | 목적 | 경계 |
| --- | --- | --- |
| `/` | 검증된 output 선택과 audit/archive 상태 확인 | 검증된 sanitization metadata만 표시 |
| `/output?project=<alias>` | output 하나의 안전 파일, finding 후보, 허용된 dashboard action 확인 | 표시 전 `verify` 통과 필요 |
| `/triage?project=<alias>` | 보고서 문구 작성 전 sanitization 완료 finding 후보 metadata 확인 | 조회 전용. finding 본문 preview, form, POST action, severity 결정 없음 |
| `/report-readiness?project=<alias>` | 수동 보고서 검토 전 초안 metadata와 운영자 확인 항목 점검 | 조회 전용. 보고서 본문 preview, form, POST action, 제출 판단 없음 |
| `/workflow?project=<alias>` | verify, review, report, preflight, handoff, triage, report-readiness 순서 확인 | 조회 전용 workflow 체크리스트. form, POST action, button, 보고서 본문 preview 없음 |
| `/preflight?project=<alias>` | 선택한 검증 output이 AI 핸드오프 후보인지 확인 | 조회 전용. form, POST action, 외부 전송 없음 |
| `/handoff?project=<alias>` | 안전 파일 4개의 alias, 목적, 순서, metadata 확인 | 조회 전용. 파일 본문 preview, download, form, POST action 없음 |
| `/prompt-readiness?project=<alias>` | prompt 파일을 AI에 넣기 전 상태와 경계 확인 | 조회 전용. prompt 본문 preview, download, form, POST action 없음 |
| `/settings` | dashboard 설정과 보안 상태 확인 | 조회 전용. 설정 변경 없음 |
| `/help` and `/operations` | 운영 인덱스와 문서 진입점 확인 | 조회 전용 안내 허브. form 또는 POST action 없음 |
| `/preview` and `/download` | allowlist에 있는 안전 파일 하나를 preview 또는 download | 안전 파일 4개만 허용 |

`/review`, `/report`, `/export` page는 없습니다. Review, Report, Export는
검증된 output 상세 화면의 CSRF 보호 POST action입니다.

## Action 순서

output 상세 화면의 action은 다음 순서로 사용합니다.

1. `Verify`: 선택한 output에 fail-closed 검증을 다시 실행합니다.
2. `Review`: finding 후보의 안전 요약을 만듭니다.
3. `Finding triage index`: 후보 metadata와 수동 검토 경계를 확인합니다.
4. `Report`: `report_draft.md`를 작성하거나 갱신합니다.
5. `Report readiness index`: 보고서 초안 metadata와 수동 검토 항목을 확인합니다.
6. `Workflow status index`: 조회 전용 workflow 체크리스트를 확인합니다.
7. `AI-safe preflight`: 조회 전용 핸드오프 사전 점검을 확인합니다.
8. `AI handoff index`: 안전 파일 4개와 권장 순서를 확인합니다.
9. `Prompt readiness index`: prompt 파일 상태와 수동 검토 경계를 확인합니다.
10. `Export`: 안전 파일 4개만 dashboard export directory로 복사합니다.

`Refresh`는 조회 전용 GET reload입니다. `Verify`, `Review`, `Report`,
`Export`는 상태 변경 POST action이며 CSRF token이 필요합니다.
`Finding triage index`, `Report readiness index`, `Workflow status index`,
`AI-safe preflight`, `AI handoff index`, `Prompt readiness index`는 조회 전용
GET page이며 데이터를 제출하지 않습니다.

## AI에 넣을 수 있는 파일

선택한 output이 `verify`를 통과한 뒤, 다음 파일만 AI 검토 후보로 사용합니다.

| 파일 | 용도 |
| --- | --- |
| `analysis_packet.json` | 구조화된 sanitization 완료 finding 후보 packet |
| `chatgpt_prompt.md` | ChatGPT용 안전 분석 prompt |
| `codex_task_prompt.md` | Codex용 안전 task prompt |
| `report_draft.md` | 사람이 검토할 보고서 초안 |

검증에 실패한 output의 파일은 사용하지 않습니다.

사전 점검 상태 필드와 문제 해결은
[GUI_AI_SAFE_PREFLIGHT.md](C:/coding/burp-ai-redaction-gateway/docs/GUI_AI_SAFE_PREFLIGHT.md)를
참조하세요. 핸드오프 파일 순서와 metadata 필드는
[GUI_AI_HANDOFF_INDEX.md](C:/coding/burp-ai-redaction-gateway/docs/GUI_AI_HANDOFF_INDEX.md)를
참조하세요. finding 후보 triage 필드와 경계는
[GUI_FINDING_TRIAGE_INDEX.md](C:/coding/burp-ai-redaction-gateway/docs/GUI_FINDING_TRIAGE_INDEX.md)를
참조하세요. 보고서 초안 준비 필드와 경계는
[GUI_REPORT_READINESS_INDEX.md](C:/coding/burp-ai-redaction-gateway/docs/GUI_REPORT_READINESS_INDEX.md)를
참조하세요. 전체 조회 전용 workflow 체크리스트는
[GUI_WORKFLOW_STATUS_INDEX.md](C:/coding/burp-ai-redaction-gateway/docs/GUI_WORKFLOW_STATUS_INDEX.md)를
참조하세요. prompt 파일 투입 전 점검은
[GUI_PROMPT_READINESS_INDEX.md](C:/coding/burp-ai-redaction-gateway/docs/GUI_PROMPT_READINESS_INDEX.md)를
참조하세요.

## 보내거나 문서화하지 않을 값

다음 값은 붙여넣기, 업로드, 커밋, 문서화 대상이 아닙니다.

| 보내지 않을 값 | 이유 |
| --- | --- |
| raw request 또는 raw response 데이터 | 민감값이 포함될 수 있음 |
| 실제 Burp XML export | raw traffic 원본 |
| `local_only/`, `raw/`, `raw_vault/` | 로컬 전용 또는 raw 저장 영역 |
| 검증 전 `out/` output | 안전 게이트가 통과되지 않음 |
| `out/.audit/` log, archive, manifest | 운영 증거 자료이며 AI prompt 자료가 아님 |
| Cookie, Authorization, token, JWT, session 값 | 인증 또는 세션 자료 |
| 실제 domain, 고객명, 내부 IP, 개인정보 | 환경 또는 식별 민감 정보 |
| HMAC secret, CSRF 값, 로컬 secret file | 보안 민감 로컬 값 |

## 결과 해석

dashboard finding은 수동 검증이 끝날 때까지 후보입니다.

- `confidence`는 evidence confidence이며 severity가 아닙니다.
- `risk_rating_draft`는 likelihood와 impact 기반 초안 workflow입니다.
- `severity_draft`는 확정 severity가 아닙니다.
- severity 결정은 권한 있는 재현, 역할별 비교, 업무 영향 검토, 수동 risk
  판단이 필요합니다.
- CVSS는 별도 산정 범위이며 dashboard가 암시하지 않습니다.

## 운영 인덱스

dashboard에서 적절한 가이드를 찾을 때 `/help` 또는 `/operations`를 사용합니다.
운영 인덱스는 의도적으로 조회 전용입니다. 다음 기능을 추가하지 않습니다.

- raw viewer
- replay 또는 active scan
- archive 또는 HMAC 실행 버튼
- finding triage 실행 버튼
- report readiness 실행 버튼
- workflow status 실행 버튼
- AI-safe preflight 실행 버튼
- AI handoff 실행 버튼
- prompt readiness 실행 버튼
- risk profile 변경 버튼
- delete 또는 edit action
- settings-write action

## 문제 해결

| 증상 | 의미 | 다음 조치 |
| --- | --- | --- |
| Output이 표시되지 않음 | output이 dashboard root 아래에 없거나 검증 실패일 수 있음 | 사용 전 output directory에 `verify`를 실행합니다. |
| Safe file이 없음 | 선택한 flow에서 아직 해당 파일을 생성하지 않음 | 검증 후 관련 CLI 또는 dashboard action을 실행합니다. |
| Report wording이 너무 확정적으로 보임 | 보고서가 확정 결과처럼 읽힐 수 있음 | 후보 문구를 유지하고 severity 변경 전 수동 검증을 실행합니다. |
| `/settings`에서 HMAC이 not configured로 보임 | 검증용 local secret이 설정되지 않음 | 필요할 때 로컬에서 설정하고 secret을 문서, chat, log, PR에 붙여넣지 않습니다. |
| Audit/archive status가 없음 | 로컬 audit 운영 산출물이 아직 만들어지지 않음 | CLI audit operations guide를 사용합니다. 생성 산출물은 local-only로 유지합니다. |
