# Real Burp Export Validation Template

이 템플릿은 실제 Burp export 검증 결과를 raw-free metadata로만 기록하기 위한
양식입니다. 실제 export 원본, raw request/response, 인증값, 실제 대상 식별자,
개인정보, local secret 값은 기록하지 않습니다.

## Validation metadata

| 항목 | 값 |
| --- | --- |
| validation date | `<YYYY-MM-DD>` |
| operator alias | `<operator_alias>` |
| source type alias | `<burp_export_xml_or_har>` |
| project alias | `<non_identifying_project_alias>` |
| policy alias | `<policy_alias>` |
| raw_data_included | `false` |

## CLI 결과

| 단계 | 상태 | 안전 기록 |
| --- | --- | --- |
| generate | `<passed_or_failed>` | `<safe_error_type_or_none>` |
| verify | `<passed_or_failed>` | `<files_checked_or_failure_category>` |
| review | `<passed_or_failed>` | `<candidate_count_or_safe_error_type>` |
| report | `<passed_or_failed>` | `<profile_alias_or_safe_error_type>` |

## Dashboard smoke 결과

| route alias | 상태 | 비고 |
| --- | --- | --- |
| home | `<passed_or_failed>` | `<safe_note>` |
| output detail | `<passed_or_failed>` | `<safe_note>` |
| preflight | `<passed_or_failed>` | `<safe_note>` |
| handoff | `<passed_or_failed>` | `<safe_note>` |
| triage | `<passed_or_failed>` | `<safe_note>` |
| report readiness | `<passed_or_failed>` | `<safe_note>` |
| workflow | `<passed_or_failed>` | `<safe_note>` |
| prompt readiness | `<passed_or_failed>` | `<safe_note>` |
| evidence boundary | `<passed_or_failed>` | `<safe_note>` |
| operator runbook | `<passed_or_failed>` | `<safe_note>` |
| safe file inventory | `<passed_or_failed>` | `<safe_note>` |
| settings | `<passed_or_failed>` | `<safe_note>` |
| help | `<passed_or_failed>` | `<safe_note>` |
| operations | `<passed_or_failed>` | `<safe_note>` |

## Safe file inventory

| 파일 | 존재 여부 | SHA-256 fingerprint 기록 여부 |
| --- | --- | --- |
| `analysis_packet.json` | `<present_or_missing>` | `<yes_or_no>` |
| `chatgpt_prompt.md` | `<present_or_missing>` | `<yes_or_no>` |
| `codex_task_prompt.md` | `<present_or_missing>` | `<yes_or_no>` |
| `report_draft.md` | `<present_or_missing>` | `<yes_or_no>` |

## 수동 검토 메모

- finding은 candidate 또는 suspected finding으로만 기록합니다.
- risk rating은 draft이며 최종 심각도가 아닙니다.
- confidence는 evidence confidence이며 severity가 아닙니다.
- CVSS 산정은 별도 범위입니다.
- AI 입력 후보는 safe files 4개로 제한합니다.

## 금지 기록

- raw request 또는 raw response 데이터
- Cookie, Authorization, token, JWT, session 값
- 실제 URL, domain, IP, 고객명, 계정 식별자, 개인정보
- HMAC secret, CSRF token, local secret file 내용
- full local path
- 실제 export 파일명 또는 원본 경로
- 검증 전 output 또는 audit 원본을 AI 입력 대상으로 해석하는 문구

