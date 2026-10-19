# 감사 기록 확인과 보관

MCP·대시보드의 처리 이력을 검사하고, 필요한 기간의 기록을 따로 보관하는 선택 기능입니다.
기본 파일 처리에는 필요하지 않습니다. 감사 기록과 검증 파일은 AI 전달 자료가 아니며 내 컴퓨터에만 보관하세요.

## 1. 기록 검사하기

README.md가 있는 폴더의 PowerShell에서 실행합니다.

```powershell
python -m burp_ai_redaction_gateway review-audit --input out/.audit
```

기록 형식(`1.1`), 이벤트 번호, 순서, 앞뒤 기록의 해시 연결과 민감정보 잔존 여부를 검사합니다.
MCP의 `--root`를 별도 폴더로 지정했다면 그 폴더 아래의 `.audit`를 사용하세요.
다음 예시는 기본 위치인 `out/.audit/mcp_audit.jsonl` 기준입니다. 다른 결과 폴더를 쓰면 경로도 바꿔 사용합니다.

검사에 실패하면 다음 단계로 넘어가지 마세요. 오래된 형식도 의도적으로 거절합니다.
실패를 숨기려고 기존 기록을 삭제하거나 고치지 말고 보존한 채 원인을 확인하세요. 새 형식의 기록이 필요하면 별도 작업 폴더에서 생성합니다.

## 2. 보관할 기간 정하기

최근 30일을 남기는 예시입니다. 먼저 `--dry-run`으로 건수만 확인합니다.

```powershell
python -m burp_ai_redaction_gateway audit-retention --input out/.audit/mcp_audit.jsonl --output out/.audit/mcp_audit.retained.jsonl --retention-days 30 --dry-run
```

맞게 선택됐다면 `--dry-run` 없이 실행하고, 만든 파일을 검사하세요. 원본은 바꾸지 않습니다.

```powershell
python -m burp_ai_redaction_gateway audit-retention --input out/.audit/mcp_audit.jsonl --output out/.audit/mcp_audit.retained.jsonl --retention-days 30
python -m burp_ai_redaction_gateway review-audit --input out/.audit/mcp_audit.retained.jsonl
```

## 3. 변경 여부 확인하기 (선택)

HMAC은 비밀키로 파일 변경을 확인하는 방식이며 암호화가 아닙니다.
로컬에서 준비한 키를 `BURP_AI_AUDIT_HMAC_KEY` 환경변수 또는 `--key-file`로 지정합니다.
아래 명령은 환경변수 사용 기준입니다. 실제 키를 명령문·로그·문서에 붙여 넣거나 저장소에 올리지 마세요.
검증할 때는 생성 때와 같은 키가 필요합니다. 키를 준비하지 않았다면 이 단계는 실행할 수 없습니다.

```powershell
python -m burp_ai_redaction_gateway audit-hmac --input out/.audit/mcp_audit.retained.jsonl --manifest out/.audit/mcp_audit.retained.manifest.json
python -m burp_ai_redaction_gateway audit-hmac-verify --input out/.audit/mcp_audit.retained.jsonl --manifest out/.audit/mcp_audit.retained.manifest.json
```

`manifest`는 검사 결과와 대조할 검증 파일입니다. HMAC 검사는 앞 단계의 기록 검사를 대신하지 않습니다.

## 4. 압축해서 보관하기 (선택)

앞 단계 검사가 통과한 기록을 압축하고, 다시 풀어 기록 검사가 통과하는지 확인합니다. 원본은 남습니다.

```powershell
python -m burp_ai_redaction_gateway audit-compress --input out/.audit/mcp_audit.retained.jsonl --output out/.audit/mcp_audit.retained.jsonl.gz
python -m burp_ai_redaction_gateway audit-compress-verify --input out/.audit/mcp_audit.retained.jsonl.gz
```

압축 자체는 암호화나 변조 검사가 아닙니다. 압축 파일의 변경 여부도 확인하려면 같은 비밀키로 검사합니다.

```powershell
python -m burp_ai_redaction_gateway audit-compressed-hmac --input out/.audit/mcp_audit.retained.jsonl.gz --manifest out/.audit/mcp_audit.retained.jsonl.gz.manifest.json
python -m burp_ai_redaction_gateway audit-compressed-hmac-verify --input out/.audit/mcp_audit.retained.jsonl.gz --manifest out/.audit/mcp_audit.retained.jsonl.gz.manifest.json
```

압축 파일의 HMAC은 원래 기록의 `review-audit`와 HMAC 검사를 대신하지 않습니다.
변경 검사까지 마친 보관본이 필요하다면 기록 검사 → 기간 선택 → 기록 HMAC 생성·검사 → 압축·검사 → 압축 HMAC 생성·검사를 모두 통과해야 합니다.

## 검사에 실패했을 때

| 실패한 단계 | 확인할 내용 |
| --- | --- |
| 기록 검사·기간 선택 | 형식, 순서, 해시 연결, 민감정보 검사 결과를 확인합니다. 실패한 파일은 검증 근거로 쓰지 않습니다. |
| HMAC 생성 | 입력 검사 통과 여부와 키 설정을 확인합니다. |
| HMAC 검사 | 원본·검증 파일·키가 서로 맞는지 확인합니다. 검증 파일을 다시 만들어 실패를 덮지 않습니다. |
| 압축·압축 검사 | 입력 검사와 `.jsonl.gz` 확장자를 확인합니다. 원본을 보존하고 원인을 확인한 뒤 다시 만듭니다. |

상태를 공유할 때는 명령 이름, 건수, 통과·실패, 오류 종류만 적으세요. `raw_data_included: false`도 공유 허가를 뜻하지 않습니다.
원본 행, 실제 경로·주소·개인정보, 쿠키·인증 헤더·토큰·세션·비밀번호·API 키·CSRF 값, HMAC 값·비밀키, 내부 오류 상세는 공유하지 않습니다.
`out/.audit/`, `*.manifest.json`, `*.jsonl.gz`, 비밀키 파일과 실제 점검에서 만든 보고서는 Git에 올리지 마세요.

[읽기 전용 MCP](READ_ONLY_MCP.md) · [구성과 추가 설정](REFERENCE.md)
