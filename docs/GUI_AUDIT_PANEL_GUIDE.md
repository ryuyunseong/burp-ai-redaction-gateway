# GUI Audit Panel 가이드

이 문서는 local dashboard에 표시되는 조회 전용 audit/archive 상태를 설명합니다.
이 panel은 로컬 audit artifact 존재 여부와 archive 검증 가능 여부를 확인하기
위한 운영자 보조 화면입니다. 설정 편집기가 아니며 archive 또는 HMAC action을
실행하지 않습니다.

verify, review, report, export, 안전 AI 핸드오프까지의 넓은 dashboard 순서는
[GUI_USER_FLOW.md](C:/coding/burp-ai-redaction-gateway/docs/GUI_USER_FLOW.md)를
참조하세요.

## 범위

GUI audit/archive panel은 dashboard home page와 `/settings` 상태 page에 표시될
수 있습니다. 로컬 metadata만 요약합니다.

- audit log 상태
- audit schema version
- retained JSONL 상태
- retained JSONL HMAC manifest 상태
- compressed archive 상태
- compressed archive verification 상태
- compressed archive HMAC manifest 상태

panel은 조회 전용입니다. retained log, HMAC manifest, gzip archive,
compressed archive HMAC manifest 생성은 CLI를 사용합니다.

## 상태 항목

| 항목 | 의미 |
| --- | --- |
| `audit schema` | 현재 audit event의 예상 schema version. 현재 schema는 `1.1` |
| `audit log` | dashboard root audit directory 아래 active local audit JSONL 존재 여부 |
| `audit review` | active audit log가 strict `review-audit` check로 검토 가능한지 여부 |
| `retained JSONL` | retained JSONL 존재 여부와 strict `review-audit` 통과 여부 |
| `HMAC manifest` | retained JSONL HMAC manifest 존재 여부와 configured local secret으로 검증 가능한지 여부 |
| `compressed archive` | retained `.jsonl.gz` archive 존재 여부 |
| `compressed archive verify` | compressed archive를 decompress한 JSONL이 `review-audit`를 통과하는지 여부 |
| `compressed archive HMAC manifest` | compressed archive HMAC manifest 존재 여부 |
| `compressed archive HMAC verify` | compressed archive HMAC manifest가 configured local secret으로 검증 가능한지 여부 |

## 상태 읽는 법

| 상태 | 해석 |
| --- | --- |
| `passed` | 관련 검증이 성공적으로 완료됨 |
| `present` | artifact가 존재함. 이 row는 존재 여부만 보고하므로 관련 verify row를 별도 확인 |
| `not found` | 예상 local audit 위치에 artifact가 없음 |
| `not configured` | 보통 HMAC secret 같은 필수 local setting이 구성되지 않음 |
| `input_missing` | manifest는 있으나 대응 input artifact가 없음 |
| safe `*_failed`, `*_missing`, `*_mismatch`, `invalid_*` error type | 검증이 안전하게 실패함. 재생성 또는 로컬 검토 전까지 artifact를 유효한 것으로 보지 않음 |

`present`를 무결성 확인으로 해석하지 않습니다. 예를 들어 compressed archive가
존재해도 `compressed archive verify`가 실패할 수 있습니다.

## 보안 경계

panel은 다음 값을 표시하지 않습니다.

- raw audit row
- raw request 또는 raw response 데이터
- `Cookie`, `Authorization`, token, JWT, session 값
- 실제 URL, domain, IP 주소
- 개인정보
- HMAC secret
- CSRF token 값
- 환경변수 값
- full local filesystem path
- 전체 stack trace

panel은 alias와 안전 status label만 표시해야 합니다. raw viewing, replay,
active scan, delete, edit, archive creation, HMAC creation, settings-write
action을 추가하지 않습니다.

## 문제 해결

| 증상 | 가능한 의미 | 다음 조치 |
| --- | --- | --- |
| old local log에서 `audit review` 실패 | log에 legacy 또는 pre-schema audit row가 있을 수 있음 | fresh audit log를 생성하거나, 운영 증거로 쓰기 전 CLI로 old file을 검토합니다. |
| `retained JSONL`이 `not found` | `audit-retention`이 retained JSONL artifact를 아직 만들지 않음 | strict `review-audit` 통과 후 `audit-retention`을 실행합니다. |
| `HMAC manifest`가 `not found` | retained JSONL HMAC manifest가 아직 생성되지 않음 | local secret으로 `audit-hmac`를 실행합니다. secret을 chat, docs, log, PR에 붙여넣지 않습니다. |
| `HMAC manifest`가 `not configured` 또는 `hmac_secret_missing` | local secret 없이는 dashboard가 HMAC을 검증할 수 없음 | `BURP_AI_AUDIT_HMAC_KEY`를 구성하거나 CLI에서 local key file을 사용합니다. |
| `compressed archive`가 `not found` | `audit-compress`가 `.jsonl.gz` archive를 아직 만들지 않음 | retained JSONL이 `review-audit`를 통과한 뒤 `audit-compress`를 실행합니다. |
| `compressed archive verify` 실패 | gzip archive를 검토된 audit package로 신뢰할 수 없음 | retained JSONL에서 archive를 다시 만들고 다시 검증합니다. |
| `compressed archive HMAC manifest`가 `not found` | compressed archive HMAC manifest가 아직 생성되지 않음 | `audit-compress-verify` 통과 후 `audit-compressed-hmac`를 실행합니다. |
| `compressed archive HMAC verify` 실패 | archive, manifest, local secret 중 하나가 맞지 않음 | archive를 local에서 재생성하거나 조사하기 전까지 유효한 것으로 보지 않습니다. |

## CLI와의 관계

GUI는 상태를 요약하고, 작업 실행은 CLI가 수행합니다.

```powershell
python -m burp_ai_redaction_gateway review-audit --input out\.audit
python -m burp_ai_redaction_gateway audit-retention --input out\.audit\mcp_audit.jsonl --output out\.audit\mcp_audit.retained.jsonl --retention-days 30
python -m burp_ai_redaction_gateway audit-hmac --input out\.audit\mcp_audit.retained.jsonl --manifest out\.audit\mcp_audit.retained.manifest.json
python -m burp_ai_redaction_gateway audit-compress --input out\.audit\mcp_audit.retained.jsonl --output out\.audit\mcp_audit.retained.jsonl.gz
python -m burp_ai_redaction_gateway audit-compress-verify --input out\.audit\mcp_audit.retained.jsonl.gz
python -m burp_ai_redaction_gateway audit-compressed-hmac --input out\.audit\mcp_audit.retained.jsonl.gz --manifest out\.audit\mcp_audit.retained.jsonl.gz.manifest.json
python -m burp_ai_redaction_gateway audit-compressed-hmac-verify --input out\.audit\mcp_audit.retained.jsonl.gz --manifest out\.audit\mcp_audit.retained.jsonl.gz.manifest.json
```

생성된 audit, archive, manifest artifact는 로컬 운영 output입니다. 커밋하지
않습니다.
