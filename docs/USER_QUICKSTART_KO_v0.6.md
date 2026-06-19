# 사용자 빠른 시작 가이드 v0.6

이 문서는 처음 사용하는 운영자가 Burp export 또는 Live Capture collector 결과를
로컬에서 정리하고, AI 투입 후보 파일을 사람이 확인하는 순서를 설명합니다.
자동 ChatGPT 전송은 없습니다. AI 투입 전 사람이 최종 확인합니다.

## 전체 흐름

1. Burp export 또는 collector 결과를 로컬 전용 위치에 준비합니다.
2. `generate`로 redaction output을 만듭니다.
3. `verify`로 민감정보 marker가 남지 않았는지 확인합니다.
4. `review`로 사람이 볼 수 있는 검토 묶음을 만듭니다.
5. `report`로 보고서 초안을 만듭니다.
6. 사람이 기본 보기 파일부터 확인합니다.
7. 필요한 파일만 수동으로 AI에 복사합니다.

## 1단계: Burp export 또는 collector 결과 준비

- 실제 원본 traffic은 로컬 전용 작업 위치에만 둡니다.
- 문서, PR, 채팅에는 대상 식별자, 원문 traffic, 쿠키 값, 인증 헤더 값, 토큰 값,
  세션 값, 개인정보를 옮기지 않습니다.
- Live Capture collector 결과를 사용할 때도 receiver가 만든 redaction output만
  다음 단계로 넘깁니다.

## 2단계: 로컬 redaction 실행

```powershell
python -m burp_ai_redaction_gateway generate `
  --input <input_file> `
  --output out\<output_alias> `
  --project <project_alias> `
  --risk-profile conservative `
  --policy policy.json
```

`<input_file>`, `<output_alias>`, `<project_alias>`는 사람이 알아볼 수 있는
별칭으로만 적습니다. 실제 대상 이름이나 전체 로컬 경로를 문서에 남기지 않습니다.

## 3단계: verify 실행

```powershell
python -m burp_ai_redaction_gateway verify --input out\<output_alias> --policy policy.json
```

`verify`가 통과하기 전에는 AI 후보 파일을 열람하거나 복사하지 않습니다. 실패하면
출력물을 사용하지 말고 원인을 로컬에서 확인합니다.

## 4단계: review 실행

```powershell
python -m burp_ai_redaction_gateway review `
  --input out\<output_alias> `
  --export-dir exports\<review_alias>
```

`review` 결과는 사람이 확인하기 위한 보조 자료입니다. finding은 candidate
finding이며 확정 취약점이 아닙니다.

## 5단계: report 생성

```powershell
python -m burp_ai_redaction_gateway report `
  --input out\<output_alias> `
  --output out\<output_alias>\report_draft.md `
  --profile conservative
```

`report_draft.md`는 draft report입니다. risk는 draft risk이고,
severity/CVSS는 사람이 수동 판단합니다.

## 6단계: 사람이 결과 확인

먼저 기본 보기 파일 2개를 확인합니다.

- `report_draft.md`: 보고서 초안입니다. 제출용 최종본이 아닙니다.
- `chatgpt_prompt.md`: ChatGPT용 프롬프트입니다. 자동 전송되지 않습니다.

필요할 때만 고급 산출물 2개를 추가로 확인합니다.

- `analysis_packet.json`: 구조화된 분석 packet입니다.
- `codex_task_prompt.md`: Codex 작업 프롬프트입니다.

## 7단계: 필요한 파일만 수동 복사

AI에 넣을 수 있는 후보는 아래 4개뿐입니다.

- `analysis_packet.json`
- `chatgpt_prompt.md`
- `codex_task_prompt.md`
- `report_draft.md`

이 파일들도 공유 안전 보장 파일이 아닙니다. 사람이 내용을 확인한 뒤 필요한 부분만
수동으로 복사합니다. 원문 traffic을 직접 전송하지 않습니다.

## 판단 경계

- finding은 candidate finding입니다.
- risk는 draft risk입니다.
- report는 draft report입니다.
- severity/CVSS는 사람이 수동 판단합니다.
- actual export smoke 통과는 외부 공유 승인이 아닙니다.
- 자동 ChatGPT 전송은 없습니다.

## 웹 운영자 가이드

CLI 없이 Local Dashboard와 Upload Wizard로 처리할 수 있는 작업 범위는
[`WEB_OPERATOR_GUIDE_KO_v0.7.md`](WEB_OPERATOR_GUIDE_KO_v0.7.md)에 정리되어
있습니다. 이 문서는 웹에서 가능한 작업과 아직 불가능한 작업을 분리합니다.

- 가능한 작업: Upload Wizard, safe files 4개 확인, triage/report readiness,
  Windows launcher, localhost receiver, read-only MCP stdio server 확인.
- 아직 불가능한 작업: v0.7 MCP listener runtime, socket/bind/listen endpoint,
  transport/protocol handler, tool registration/tool execution, local evidence
  reader, raw preview/download, replay/active scan, automatic ChatGPT handoff.

## RC readiness 참고

v0.6 RC 후보 판단 기준은
[`V0.6_RC_READINESS_CHECKLIST.md`](V0.6_RC_READINESS_CHECKLIST.md)에 정리되어
있습니다. 이 checklist는 tag 또는 GitHub Release를 만들지 않습니다.
quickstart smoke 절차는
[`V0.6_QUICKSTART_SMOKE.md`](V0.6_QUICKSTART_SMOKE.md)에서 확인합니다.
release notes 초안은
[`V0.6_RELEASE_NOTES_DRAFT.md`](V0.6_RELEASE_NOTES_DRAFT.md)에서 확인합니다.
두 문서도 tag 또는 GitHub Release를 만들지 않습니다.
