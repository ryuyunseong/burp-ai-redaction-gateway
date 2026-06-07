# Real Burp Export Validation

이 문서는 실제 Burp export를 커밋하지 않고 v0.4 실사용 후보를 검증하는
로컬 운영 절차입니다. 실제 export 검증은 synthetic fixture 검증을 대체하지
않고, parser 호환성, redaction, verify fail-closed, dashboard 미노출 경계를
보완 확인하는 단계입니다.

## 범위

이 절차는 다음을 확인합니다.

- Burp에서 저장한 export가 `generate` 입력으로 처리되는지
- `verify`가 민감값 잔존 시 fail-closed로 차단하는지
- `review`가 candidate finding 요약을 raw 없이 생성하는지
- `report`가 `report_draft.md`를 candidate/draft 표현으로 유지하는지
- dashboard가 raw/body/secret/full path를 표시하지 않는지
- AI 입력 후보가 safe files 4개로 제한되는지

이 절차는 replay, active scan, 파일 삭제, retention 정책 변경, HMAC secret
처리 변경을 포함하지 않습니다.

## 로컬 보관 위치

실제 Burp export는 ignored `local_only/` 아래에서만 테스트합니다.

```powershell
mkdir local_only
copy <authorized_burp_export_file> local_only\authorized_burp_export.xml
```

`<authorized_burp_export_file>`은 운영자가 로컬에서 직접 선택하는 파일입니다.
그 경로나 파일 내용을 문서, PR, issue, AI prompt, test fixture에 쓰지 않습니다.
실제 고객명이나 대상명을 project alias로 사용하지 않습니다.

## 검증 순서

### Optional local smoke harness

반복 실행이 필요한 경우 raw-free smoke harness를 사용할 수 있습니다.

```powershell
scripts\run_local_real_export_smoke.ps1 -Input local_only\authorized_burp_export.xml
```

harness는 generate, verify, review, report, dashboard smoke를 safe alias
기준으로 실행합니다. 입력은 ignored `local_only/` 아래 file만 허용하고,
출력은 ignored `out/` 아래 direct alias만 허용합니다. console에는 raw 값이나
full local path를 출력하지 않습니다.
자세한 사용법은 `docs/LOCAL_REAL_EXPORT_SMOKE_HARNESS.md`를 참조하세요.

### 1. Generate

```powershell
python -m burp_ai_redaction_gateway generate --input local_only\authorized_burp_export.xml --output out\real_export_validation --project real_export_alias --risk-profile conservative --policy policy.json
```

### 2. Verify

```powershell
python -m burp_ai_redaction_gateway verify --input out\real_export_validation --policy policy.json
```

`verify`가 실패하면 해당 output은 AI 입력 후보가 아닙니다. 실패한 output을
붙여넣지 말고, 실패 유형과 안전한 file alias만 기록합니다.

### 3. Review

```powershell
python -m burp_ai_redaction_gateway review --input out\real_export_validation
```

Review 결과는 candidate finding 수와 category summary 같은 raw-free metadata만
사용합니다. finding을 확정 취약점으로 표현하지 않습니다.

### 4. Report

```powershell
python -m burp_ai_redaction_gateway report --input out\real_export_validation --output out\real_export_validation\report_draft.md --profile conservative
```

`report_draft.md`는 사람이 검토할 초안입니다. 최종 심각도, CVSS 확정값,
확정 취약점 표현으로 사용하지 않습니다.

### 5. Dashboard smoke

```powershell
python -m burp_ai_redaction_gateway dashboard --host 127.0.0.1 --port 8766 --root out
```

다음 route를 확인합니다.

```text
/
/output?project=real_export_validation
/preflight?project=real_export_validation
/handoff?project=real_export_validation
/triage?project=real_export_validation
/report-readiness?project=real_export_validation
/workflow?project=real_export_validation
/prompt-readiness?project=real_export_validation
/evidence-boundary?project=real_export_validation
/operator-runbook?project=real_export_validation
/safe-files?project=real_export_validation
/settings
/help
/operations
```

Read-only route는 form, POST action, button, download control을 표시하지
않아야 합니다. `/output?project=real_export_validation`의 상태 변경 action은
CSRF 보호가 적용된 verify, review, report, export로 제한됩니다.

## 기록 템플릿

검증 결과는 raw-free 템플릿에만 기록합니다.

```text
docs/templates/REAL_BURP_EXPORT_VALIDATION_TEMPLATE.md
```

템플릿에는 다음만 기록합니다.

- validation date
- operator alias
- source type alias
- project alias
- CLI command result status
- candidate count
- safe file 4개 존재 여부
- dashboard route smoke status
- failure reason code
- `raw_data_included: false`

## RC1 readiness record

The first authorized local real export smoke run for the
`v0.4.30-local-real-export-smoke-harness` baseline is recorded only as
raw-free metadata:

- `actual_export_smoke=passed`
- `generate=passed`
- `verify=passed`
- `review=passed`
- `report=passed`
- `dashboard_smoke=passed`
- `browser_smoke=passed`
- `candidate_count=60`
- `safe_files_present=4`
- `forbidden_value_hits=0`

The candidate count is a candidate finding count, not a confirmed issue count.
Risk values remain draft values. The proposed RC1 tag candidate is
`v0.4.31-rc1`; this validation record does not create that tag.

## 금지 항목

다음은 기록하지 않습니다.

- raw request 또는 raw response 데이터
- Cookie, Authorization, token, JWT, session 값
- 실제 URL, domain, IP, 고객명, 계정 식별자, 개인정보
- HMAC secret, CSRF token, local secret file 내용
- full local path
- 실제 export 파일명 또는 원본 경로
- 검증 전 `out/`, `out/.audit/`, `local_only/`, `raw/`, `raw_vault/` 원본을
  AI 입력 대상으로 해석하는 문구

## 실패 처리

| 실패 유형 | 기록할 수 있는 값 | 기록 금지 |
| --- | --- | --- |
| `generate_failed` | parser error type, safe input alias | export 본문, 실제 file path |
| `verify_failed` | scanner category, safe file alias | 탐지된 raw 값 |
| `review_failed` | command status, safe output alias | raw finding body |
| `report_failed` | command status, profile alias | report 본문 전체 |
| `dashboard_smoke_failed` | route alias, status code, missing expected label | HTML 전체, full path |

실패가 redaction 또는 scanner rule 개선을 요구하면 실제 값을 복사하지 말고,
synthetic fixture로 재현 가능한 케이스를 별도 작업으로 만듭니다.

## AI 입력 후보 재확인

실제 export 검증에서도 AI 입력 후보는 `verify` 통과 후 아래 4개뿐입니다.

- `analysis_packet.json`
- `chatgpt_prompt.md`
- `codex_task_prompt.md`
- `report_draft.md`

safe files가 존재해도 AI 투입은 자동 승인되지 않습니다. 운영자가 수동으로
범위, 증거 품질, 민감정보 잔존 여부, candidate/draft 표현을 확인해야 합니다.
risk rating은 draft이며 최종 심각도가 아닙니다.
