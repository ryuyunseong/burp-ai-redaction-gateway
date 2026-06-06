# GUI AI 핸드오프 인덱스

이 문서는 dashboard의 AI 핸드오프 인덱스를 설명합니다. 인덱스는
`verify`를 통과하고 수동 검토 계획이 명확할 때 확인하는 안전 파일 4개의
조회 전용 체크리스트입니다.

finding 후보 triage 체크리스트는
[GUI_FINDING_TRIAGE_INDEX.md](C:/coding/burp-ai-redaction-gateway/docs/GUI_FINDING_TRIAGE_INDEX.md)를
참조하세요. 보고서 초안 준비 체크리스트는
[GUI_REPORT_READINESS_INDEX.md](C:/coding/burp-ai-redaction-gateway/docs/GUI_REPORT_READINESS_INDEX.md)를
참조하세요. prompt 파일 투입 전 점검은
[GUI_PROMPT_READINESS_INDEX.md](C:/coding/burp-ai-redaction-gateway/docs/GUI_PROMPT_READINESS_INDEX.md)를
참조하세요. 정제 evidence와 raw 금지 범위 경계는
[GUI_EVIDENCE_BOUNDARY_INDEX.md](C:/coding/burp-ai-redaction-gateway/docs/GUI_EVIDENCE_BOUNDARY_INDEX.md)를
참조하세요. 전체 조회 전용 workflow 체크리스트는
[GUI_WORKFLOW_STATUS_INDEX.md](C:/coding/burp-ai-redaction-gateway/docs/GUI_WORKFLOW_STATUS_INDEX.md)를
참조하세요.

이 화면은 조회 전용 체크리스트로만 사용합니다.

인덱스는 승인 화면이 아닙니다. 파일 공개 판단, finding 확정, 심각도
결정을 의미하지 않습니다.

## 화면 열기

검증된 output 상세 화면에서 다음 주소를 엽니다.

```text
/handoff?project=<alias>
```

이 화면은 조회 전용 GET 페이지입니다. 데이터를 제출하거나, 파일을 만들거나,
삭제하거나, 다운로드하거나, 설정을 바꾸거나, archive/HMAC action을
실행하지 않습니다.

## 표시 항목

인덱스는 안전 파일 4개의 alias와 metadata만 표시합니다.

| 파일 | 권장 순서 | 목적 |
| --- | ---: | --- |
| `analysis_packet.json` | 1 | 구조화된 sanitization 완료 후보 증거를 먼저 확인 |
| `chatgpt_prompt.md` | 2 | ChatGPT에 수동 검토 보조를 요청할 때 사용 |
| `codex_task_prompt.md` | 3 | Codex에 구현 또는 검토 보조를 요청할 때 사용 |
| `report_draft.md` | 4 | 사람이 검토할 보고서 초안으로 마지막에 확인 |

각 파일에는 다음 정보가 표시될 수 있습니다.

- 존재 여부
- 크기(bytes)
- 수정 시각(UTC)
- SHA-256 파일 fingerprint

SHA-256 값은 일반 파일 fingerprint입니다. HMAC이 아니며 secret을 사용하지
않고, audit HMAC 검증을 대체하지 않습니다.

## 권장 확인 순서

AI 보조 검토는 다음 순서로 진행합니다.

```text
verify first
-> check AI-safe preflight
-> read analysis_packet.json
-> choose chatgpt_prompt.md or codex_task_prompt.md for the target AI tool
-> check prompt readiness index
-> check report readiness index before report review
-> review report_draft.md manually
-> decide what, if anything, can be shared
```

finding 후보를 확정된 finding으로 해석하려면 먼저 수동 검토가 필요합니다.

## 해석 경계

- finding은 수동 검증이 끝날 때까지 candidate finding record입니다.
- risk는 draft risk이며 severity 결정으로 취급하지 않습니다.
- 심각도 결정은 권한 있는 재현, 역할별 비교, 영향 검토 후 사람이 별도로
  수행합니다.
- `최종 심각도 수동 결정` 문구는 사람이 결정해야 한다는
  경계를 나타내는 고정 문구입니다.
- CVSS는 별도 산정 범위입니다.

## 넣거나 기록하지 않을 값

다음 값은 붙여넣기, 업로드, 커밋, 문서화 대상이 아닙니다.

| 분류 | 이유 |
| --- | --- |
| raw request 또는 raw response 데이터 | 민감값이 포함될 수 있음 |
| Cookie 또는 Authorization 값 | 인증 자료 |
| token, JWT, session 값 | 세션 또는 인증정보 |
| 실제 domain, URL, IP 값 | 환경 식별 정보 |
| 개인정보 | 식별 또는 프라이버시 민감 정보 |
| HMAC secret 또는 CSRF token 값 | 로컬 보안 제어값 |
| local-only raw 저장소 또는 검증 전 output 산출물 | AI 입력 자료가 아님 |
| audit log, archive, manifest | 운영 증거 자료이며 AI 입력 자료가 아님 |

## 조회 전용 경계

핸드오프 인덱스는 다음 기능을 제공하지 않습니다.

- form 제출
- POST action
- 상태 변경 버튼
- 새 download action
- 안전 파일 본문 preview
- raw viewer
- replay 또는 active scan
- archive 또는 HMAC 실행
- HMAC secret 입력
- CSRF token 표시
- 파일 삭제 또는 retention 변경
- risk profile 변경

이 화면은 조회 전용 핸드오프 체크리스트로만 사용합니다.
