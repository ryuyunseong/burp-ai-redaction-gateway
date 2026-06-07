# v0.4 Release Checklist

이 체크리스트는 v0.4 계열을 release candidate로 판단하기 전에 반복해서
확인하는 운영 절차입니다. 목적은 기능을 더 추가하는 것이 아니라, 현재
CLI/GUI 흐름이 raw-free 원칙과 verify-first 경계를 유지하는지 확인하는
것입니다.

## Release 기준

Release candidate는 다음 조건을 모두 만족해야 합니다.

- main 최신 commit 기준으로 작업트리가 clean입니다.
- 관련 PR이 병합됐고 release tag가 아직 존재하지 않습니다.
- synthetic fixture 기반 CLI 흐름이 통과합니다.
- local dashboard 주요 route smoke가 통과합니다.
- AI 입력 후보 파일은 4개 allowlist로 제한됩니다.
- 실제 Burp export 검증은 ignored `local_only/` 아래에서만 수행합니다.
- `local_only/`, `raw/`, `raw_vault/`, 검증 전 `out/`, `out/.audit/` 원본은
  AI 입력, PR 본문, issue, 문서 예시 대상이 아닙니다.

## 필수 CLI 검증

아래 명령을 release 전 최소 검증으로 실행합니다.

```powershell
python -m compileall burp_ai_redaction_gateway tests
python -m unittest discover -s tests
python -m burp_ai_redaction_gateway verify --input out
python -m burp_ai_redaction_gateway review --input out\demo
python -m burp_ai_redaction_gateway report --input out\demo --output out\demo\report_draft.md --profile conservative
gitleaks dir -v --redact=100 --config .gitleaks.toml .
gitleaks git -v --redact=100 --config .gitleaks.toml .
scripts\git_safety_check.bat
git diff --check
git status --short --untracked-files=all
```

`review-audit`, audit retention, HMAC, compression, archive HMAC 검증은 audit
운영 산출물을 release 근거로 사용할 때 함께 실행합니다.

## GUI route smoke

Dashboard는 loopback 전용으로 실행합니다.

```powershell
python -m burp_ai_redaction_gateway dashboard --host 127.0.0.1 --port 8766 --root out
```

Browser smoke는 다음 route를 확인합니다.

```text
/
/help
/operations
/settings
/output?project=<alias>
/preflight?project=<alias>
/handoff?project=<alias>
/triage?project=<alias>
/report-readiness?project=<alias>
/workflow?project=<alias>
/prompt-readiness?project=<alias>
/evidence-boundary?project=<alias>
/operator-runbook?project=<alias>
/safe-files?project=<alias>
```

조회 전용 route는 `formCount=0`, `postFormCount=0`, `buttonCount=0`이어야
합니다. `/output?project=<alias>`는 verify, review, report, export POST
action을 표시할 수 있지만 모든 POST action은 CSRF 보호를 유지해야 합니다.

공통 화면 기준:

- `lang="ko"`입니다.
- safe file 4개가 명확히 표시됩니다.
- finding은 candidate 또는 suspected finding으로 읽힙니다.
- `risk_rating_draft`는 draft이며 최종 심각도가 아닙니다.
- confidence는 evidence confidence이며 severity가 아닙니다.
- `/help`와 `/operations`는 실행 화면이 아니라 read-only 안내 허브입니다.

## AI 입력 후보 파일

`verify` 통과 후에도 AI 검토 후보는 아래 4개로 제한합니다.

| 파일 | 기준 |
| --- | --- |
| `analysis_packet.json` | 구조화된 sanitization 완료 후보 evidence |
| `chatgpt_prompt.md` | ChatGPT용 안전 prompt 후보 |
| `codex_task_prompt.md` | Codex용 안전 task prompt 후보 |
| `report_draft.md` | 사람이 검토할 보고서 초안 |

Safe file inventory가 4개 파일의 존재 여부와 SHA-256 fingerprint를 보여도
AI 투입이나 보고서 제출이 자동 확정되는 것은 아닙니다. 운영자가 수동으로
범위, 증거 품질, 민감정보 잔존 여부, severity 표현을 확인해야 합니다.

## 금지 데이터

Release 문서, PR 본문, issue, AI prompt, dashboard 도움말에는 다음 값을
넣지 않습니다.

- raw request 또는 raw response 데이터
- Cookie, Authorization, token, JWT, session 값
- 실제 URL, domain, IP, 고객명, 계정 식별자, 개인정보
- HMAC secret, CSRF token, local secret file 내용
- full local path 예시
- `local_only/`, `raw/`, `raw_vault/`, 검증 전 `out/`, `out/.audit/` 원본을
  AI 입력 대상으로 해석하는 문구
- 최종 심각도 또는 CVSS 확정값처럼 읽히는 문구

## 실제 Burp export 검증

실제 Burp export 호환성은 synthetic fixture 검증을 대체하지 않고 보완합니다.

- 실제 export는 ignored `local_only/` 아래에서만 테스트합니다.
- 실제 export 검증 절차는 `REAL_BURP_EXPORT_VALIDATION.md`를 따릅니다.
- 결과 기록은 `templates/REAL_BURP_EXPORT_VALIDATION_TEMPLATE.md`의 raw-free
  항목만 사용합니다.
- export 원본, 실패한 output, audit 원본은 Git에 추가하지 않습니다.
- 실패 내용을 공유할 때는 error type과 안전 metadata만 기록합니다.
- redaction 또는 verify 실패가 발생하면 raw 값을 복사하지 말고 synthetic
  fixture로 재현 가능한 케이스를 만듭니다.
- 실제 export 검증 결과를 release 근거로 남길 때도 고객명, 실제 endpoint,
  인증값, 개인정보를 쓰지 않습니다.
- 반복 가능한 로컬 smoke에는 `scripts\run_local_real_export_smoke.ps1`을
  사용할 수 있습니다. 사용법은 `docs/LOCAL_REAL_EXPORT_SMOKE_HARNESS.md`를
  따릅니다.
- smoke harness는 ignored `local_only/` 입력과 ignored `out/` 출력만
  허용하고, console에는 raw-free metadata만 출력해야 합니다.

## Tag 기준

Tag는 다음 조건에서만 생성합니다.

- 병합된 main 최신 commit을 기준으로 합니다.
- `git status --short --untracked-files=all`이 비어 있습니다.
- 동일 tag가 local 또는 origin에 없습니다.
- 필수 CLI 검증과 필요한 Browser smoke가 통과했습니다.
- release notes와 checklist가 현재 route와 safe file allowlist를 설명합니다.

Tag를 잘못 만들었거나 release 기준을 만족하지 못한 경우에는 즉시 공유하고
원인을 기록합니다. 이미 원격에 공개된 tag나 main history는 명시적 승인 없이
강제로 변경하지 않습니다.

## Rollback 기준

Rollback은 다음 방식으로 판단합니다.

- 문서만 잘못된 경우: 후속 PR로 문서를 정정합니다.
- 코드 회귀가 main에 병합된 경우: squash commit을 revert하는 PR을 만듭니다.
- tag 기준선이 잘못된 경우: tag 상태를 문서화하고 수정 tag 또는 후속 release
  tag로 정정합니다.
- raw 노출 가능성이 발견되면 해당 output을 AI에 사용하지 않고, scanner 또는
  redaction rule을 먼저 보강합니다.
