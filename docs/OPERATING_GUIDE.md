# 안전 운영 가이드

이 문서는 Burp Suite 보안 점검 기록을 로컬에서 정제하고, 검증을 통과한 요약 파일만 검토·활용하는 기본 절차를 설명합니다.

> 원본 HTTP 요청·응답, 쿠키, 토큰, 실제 도메인, 내부 IP, 개인정보는 ChatGPT, Codex, GitHub Issue, PR, 보고서 또는 문서에 직접 넣지 않습니다.

## 핵심 원칙

1. 실제 Burp export는 `local_only/` 아래에만 둡니다.
2. 모든 결과는 `verify`를 통과하기 전까지 사용하지 않습니다.
3. AI에는 기본 안전 파일 4개만 전달 후보로 취급합니다.
4. finding과 risk rating은 수동 재현·검토 전까지 초안입니다.
5. 원본 데이터와 비밀값은 커밋하거나 로그에 남기지 않습니다.

## 시작 전 확인

- 저장소와 작업 디렉터리는 신뢰할 수 있는 로컬 환경에서 사용합니다.
- 실제 Burp export는 `local_only/`에만 보관합니다.
- 생성 결과는 Git에서 제외된 `out/`, `exports/`, `reports/` 아래에 둡니다.
- 테스트와 문서에는 synthetic fixture만 사용합니다.
- `raw/`, `raw_vault/`, 실제 트래픽 파일, 감사 로그, HMAC manifest와 secret file은 커밋하지 않습니다.

## 기본 사용 순서

```text
Burp export 또는 synthetic 입력
→ redaction
→ verify
→ review
→ report 또는 안전 파일 확인
→ 사용자가 직접 AI 사용 여부 결정
```

### 1. 입력 준비

처음 확인할 때는 synthetic sample을 사용합니다.

```powershell
python -m burp_ai_redaction_gateway generate `
  --input samples\synthetic_burp_history.json `
  --output out\demo `
  --project client_alias_demo `
  --risk-profile conservative `
  --policy policy.json
```

실제 Burp export를 사용할 때는 파일을 `local_only/` 밖으로 복사하지 않습니다.

### 2. 로컬 수신기 사용 선택

Burp Montoya 수집기를 사용하는 경우 수신기는 loopback에만 바인딩합니다.

```powershell
python -m burp_ai_redaction_gateway serve `
  --host 127.0.0.1 `
  --port 8765 `
  --output out\receiver `
  --project montoya_receiver_alias
```

- 외부 인터페이스에 바인딩하지 않습니다.
- receiver 또는 extension 로그에 원본 요청·응답을 출력하지 않습니다.
- 연결 실패 시 원본 데이터가 아닌 안전한 오류 유형만 공유합니다.

### 3. 결과 검증

AI 사용, 보고서 생성 또는 export 전에 반드시 `verify`를 실행합니다.

```powershell
python -m burp_ai_redaction_gateway verify --input out\demo --policy policy.json
```

`verify`가 실패하면 해당 결과를 사용하지 않습니다. 실패 패턴은 synthetic fixture로 재현한 뒤 redaction 또는 scanner 규칙을 보완합니다.

### 4. 검토 및 안전 파일 export

검증된 결과만 `review`에 전달합니다.

```powershell
python -m burp_ai_redaction_gateway review `
  --input out\demo `
  --export-dir exports\demo_review
```

`review`는 내부적으로 검증 상태를 확인하며, 실패한 결과의 export를 거부합니다.

### 5. 보고서 초안 생성

```powershell
python -m burp_ai_redaction_gateway report `
  --input out\demo `
  --output out\demo\report_draft.md `
  --profile conservative
```

- finding은 수동 재현 전까지 candidate 또는 suspected 상태로 유지합니다.
- `confidence`는 evidence confidence이며 severity가 아닙니다.
- `risk_rating_draft`는 likelihood, impact, severity의 초안이며 최종 등급이 아닙니다.
- 확정 취약점, 침해, 권한 상승 또는 CVSS를 증거 없이 주장하지 않습니다.

## 로컬 화면에서 확인

### 정적 viewer

```powershell
python -m burp_ai_redaction_gateway viewer `
  --input tests\fixtures\redacted_viewer_valid.json `
  --output out\viewer\redacted_viewer.html
```

정적 viewer는 로컬 HTML 파일만 생성합니다. Web server, raw preview, replay, active scan, Burp MCP 직접 실행 또는 자동 AI 전송 기능은 제공하지 않습니다.

### 로컬 대시보드

```powershell
python -m burp_ai_redaction_gateway dashboard `
  --host 127.0.0.1 `
  --port 8766 `
  --root out
```

대시보드는 `127.0.0.1`에만 바인딩하고, 검증된 output만 표시합니다. raw request/response 열람, replay, active scan, 임의 파일 쓰기·삭제 또는 자동 AI 전송은 제공하지 않습니다.

## AI 전달 후보 파일 4개

다음 파일은 해당 output directory가 `verify`를 통과하고 사용자가 내용을 직접 확인한 뒤에만 AI 전달 후보로 취급합니다.

- `analysis_packet.json`
- `chatgpt_prompt.md`
- `codex_task_prompt.md`
- `report_draft.md`

검증 통과는 외부 공유 승인을 의미하지 않습니다. 고객명, 실제 대상 식별자, 내부 정보 또는 과장된 finding 표현이 없는지 별도로 확인합니다.

## 절대 전달하거나 커밋하지 않을 항목

- 실제 Burp XML 또는 기타 원본 export
- raw HTTP request/response
- `local_only/`, `raw/`, `raw_vault/`
- 검증되지 않은 `out/` 결과
- 쿠키, Authorization header, bearer token, JWT, API key, password, CSRF 값, session ID
- 실제 도메인, 고객명, 내부 IP, 계정 식별자, 개인정보
- `out/.audit/` 로그, HMAC manifest, HMAC secret 또는 local secret file

## 선택 기능: 감사 기록과 보관

일반 사용자는 기본 흐름까지만 수행하면 됩니다. 감사 로그 검증, retention, HMAC, 압축 보관이 필요한 경우 다음 상세 가이드를 사용합니다.

- [감사 운영 상세 가이드](AUDIT_OPERATIONS_GUIDE.md)

권장 순서는 다음과 같습니다.

```text
review-audit
→ audit-retention
→ audit-hmac / audit-hmac-verify
→ audit-compress / audit-compress-verify
→ audit-compressed-hmac / audit-compressed-hmac-verify
```

주의사항:

- HMAC은 변조 탐지용이며 암호화가 아닙니다.
- retention은 원본 audit file을 제자리에서 수정하지 않고 별도 파일을 만듭니다.
- 압축 archive 검증은 원본 JSONL 검증을 대체하지 않습니다.
- HMAC secret과 manifest는 커밋하거나 공유하지 않습니다.

## 실패 시 처리

| 상황 | 조치 |
| --- | --- |
| `verify` 실패 | 결과 사용 중단. synthetic fixture로 재현 후 규칙 보완 |
| receiver 연결 실패 | 원본 payload는 로컬에 유지하고 오류 유형만 공유 |
| `review-audit` 실패 | 감사 증거로 사용하지 않고 현재 schema로 새 로그 생성 검토 |
| HMAC 검증 실패 | 파일·manifest·secret 불일치로 처리하고 무결성 증거로 사용 금지 |
| 압축 검증 실패 | archive 사용 중단. 검증된 retained JSONL에서 다시 생성 |
| Gitleaks 실패 | 커밋·push 중단. 실제 값을 제거하고 synthetic placeholder로 교체 |

오류 메시지에는 원본 HTTP 값, credential, 실제 대상 식별자, 전체 로컬 경로 또는 stack trace를 포함하지 않습니다.

## 고객 보고서 사용 전 확인

- [ ] source output이 `verify`를 통과했습니다.
- [ ] finding을 직접 재현하고 증거를 확인했습니다.
- [ ] `confidence`를 severity로 오해하지 않았습니다.
- [ ] `risk_rating_draft`를 별도 기준으로 재평가했습니다.
- [ ] 실제 URL, 도메인, IP, cookie, token, 계정 식별자와 개인정보를 제거했습니다.
- [ ] 확정 취약점·침해·권한 상승·CVSS 표현에 충분한 근거가 있습니다.
- [ ] 감사 로그, manifest와 secret을 보고서에 포함하지 않았습니다.

## 커밋 전 점검

```powershell
python -m compileall burp_ai_redaction_gateway tests scripts
python -m unittest discover -s tests
scripts\git_safety_check.bat
gitleaks dir -v --redact=100 --config .gitleaks.toml .
gitleaks git -v --redact=100 --config .gitleaks.toml .
git diff --check
git status --short --untracked-files=all
```

`local_only/`, `out/`, `raw/`, `raw_vault/`, 감사 manifest와 secret file이 Git status에 나타나면 커밋하지 않습니다.
