# 읽기 전용 MCP 설정

MCP는 AI 도구가 이 프로젝트의 **검증된 결과**를 읽도록 연결하는 방식입니다.
Burp를 직접 조작하거나 원본 요청·응답을 가져오는 기능은 아닙니다.
파일 업로드와 결과 확인만 필요하다면 MCP를 설정하지 않아도 됩니다.

## 먼저 결과 만들기

저장소 폴더에서 가상 샘플로 실행해 볼 수 있습니다.

~~~powershell
python -m burp_ai_redaction_gateway process --input samples/synthetic_burp_history.json --output out/mcp_demo --project mcp_demo
~~~

이미 있는 결과 폴더는 덮어쓰지 않습니다. 같은 이름이 있으면 다른 이름을 사용하세요.

## MCP 연결

클라이언트에서 표준 입출력(stdio) 서버를 추가합니다.

| 설정 | 입력할 값 |
| --- | --- |
| 실행 프로그램 | python |
| 인수 | -m burp_ai_redaction_gateway mcp --root out |
| 작업 폴더 | 이 저장소를 내려받은 폴더 |

클라이언트마다 설정 형식은 다릅니다. 명령과 작업 폴더를 지원하는 stdio 설정에 위 값을 넣으세요.
작업 폴더를 지정할 수 없다면 저장소 폴더에서 클라이언트를 실행하거나 절대 경로를 로컬 설정에만 사용합니다.
개인 경로가 든 설정은 저장소에 올리지 마세요.

터미널에서 직접 실행하면 MCP 요청을 기다립니다. 웹 페이지를 여는 명령은 아닙니다.

~~~powershell
python -m burp_ai_redaction_gateway mcp --root out
~~~

도구 호출의 project는 허용한 폴더 아래의 상대 이름입니다.
위 예제는 out 아래에 있으므로 mcp_demo를 사용합니다.

## 사용할 수 있는 기능

| 도구 이름 | 하는 일 |
| --- | --- |
| list_findings | 점검 후보 목록 읽기 |
| get_finding | 특정 후보의 근거와 확인 항목 읽기 |
| get_analysis_packet | 분석 요약 읽기 |
| get_report_draft | 보고서 초안 읽기 |
| list_prompt_files | 프롬프트 파일 목록 읽기 |

파일 생성·수정·삭제, Burp 요청 재전송, 능동 스캔, 원본 조회는 제공하지 않습니다.
후보의 위험도는 초안입니다. 실제 취약점 여부와 최종 심각도는 직접 검토해야 합니다.

## 접근 제한

- 지정한 --root 아래의 결과만 읽습니다. 상위 폴더로 벗어나는 경로는 거절합니다.
- local_only/, raw/, raw_vault/, build/, .gradle/에는 접근하지 않습니다.
- 결과 폴더가 verify를 통과해야 응답하며, 반환할 내용도 다시 검사합니다.
- 도구의 readOnlyHint 표시뿐 아니라 서버 코드에서 읽기 전용 접근을 제한합니다.
- 이 연결은 verify, review, report 검증 단계를 대신하지 않습니다.

## 읽지 못할 때

- 작업 폴더와 Python 실행 환경을 확인하세요.
- --root와 project가 같은 결과를 가리키는지 확인하세요.
- 검증에 실패한 결과는 반환하지 않습니다. 먼저 verify 결과를 확인하세요.
- 서버를 외부에 공개하거나 원본 폴더를 읽기 대상으로 추가하지 마세요.

<details>
<summary>호출 기록 확인과 보관 설정 (선택)</summary>

## 사용 기록 확인

호출 상태는 표준 오류(stderr)와 다음 감사 파일에 기록합니다.

~~~text
<root>/.audit/mcp_audit.jsonl
~~~

기록에는 시각, 도구 이름, 결과 별칭, 상태, 차단 사유 등 필요한 정보만 남깁니다.
원본 요청·응답, 분석·보고서 본문, 인증정보, 실제 주소, 개인정보, 오류 추적 전문은 기록하지 않습니다.

~~~powershell
python -m burp_ai_redaction_gateway review-audit --input out/.audit
python -m burp_ai_redaction_gateway review-audit --input out/.audit --format json
~~~

검사한 보관 범위를 통과했을 때만 종료 코드가 0입니다.
현재 감사 형식 1.1보다 오래되거나 깨진 기록은 검사에 실패할 수 있습니다.
기록을 지워 오류를 숨기지 말고 새 실행을 별도 결과 폴더에서 확인하세요.

<details>
<summary>기록 연결과 보관 방식</summary>

각 기록은 event_id, sequence_no, chain_id, prev_event_hash, event_hash,
hash_algorithm을 가집니다. event_id는 UUID입니다.
자신의 event_hash를 제외하고 키를 정렬한 JSON에 SHA-256을 적용하며 값은 sha256:<hex>로 저장합니다.
첫 기록의 이전 해시는 null이고 이후 기록은 앞선 기록의 해시를 참조합니다.

기본 파일 크기 제한은 10 MiB이며 이전 파일 20개를 보관합니다.
활성 파일은 mcp_audit.jsonl, 이전 파일은 mcp_audit.000001.jsonl 같은 이름입니다.
이름의 번호는 해당 구간의 시작 순번을 따르며 해시 연결은 파일이 바뀌어도 이어집니다.
오래된 파일이 보관 개수를 넘어 제거되면 남은 범위만 검증할 수 있습니다.
남아 있지 않은 과거 구간은 경고로 안내하며 완전한 이력 검증을 보장하지 않습니다.

review-audit는 JSONL 형식, 필수 필드, UUID, 순번, 기록 연결,
이전 해시와 재계산한 해시, 파일 순서, 민감정보 포함 여부를 확인합니다.

</details>

<details>
<summary>날짜 기준으로 보관 사본 만들기</summary>

입력을 먼저 검사하고 별도 파일에 씁니다. 입력 파일은 수정하지 않습니다.
timestamp_utc를 기준으로 보관 기간을 적용하며 사본도 다시 검사합니다.

~~~powershell
python -m burp_ai_redaction_gateway audit-retention --input out/.audit/mcp_audit.jsonl --output out/.audit/mcp_audit.retained.jsonl --retention-days 30 --dry-run
python -m burp_ai_redaction_gateway audit-retention --input out/.audit/mcp_audit.jsonl --output out/.audit/mcp_audit.retained.jsonl --retention-days 30
python -m burp_ai_redaction_gateway review-audit --input out/.audit/mcp_audit.retained.jsonl
~~~

형식 오류, 민감정보, 해시 연결 오류가 있으면 사본을 만들지 않습니다.
앞부분이 제외된 사본은 남은 구간만 검증할 수 있습니다.

</details>

<details>
<summary>파일 위변조 검사와 압축 보관</summary>

SHA-256은 파일 내용의 요약값입니다. HMAC은 로컬 비밀키를 사용해 파일 변경을 검사합니다.
둘 다 암호화가 아닙니다. 비밀키는 BURP_AI_AUDIT_HMAC_KEY 환경변수 또는 --key-file로
로컬에서 준비하고 저장소·로그·AI 입력에 남기지 마세요.

~~~powershell
python -m burp_ai_redaction_gateway audit-hmac --input out/.audit/mcp_audit.retained.jsonl --manifest out/.audit/mcp_audit.retained.manifest.json
python -m burp_ai_redaction_gateway audit-hmac-verify --input out/.audit/mcp_audit.retained.jsonl --manifest out/.audit/mcp_audit.retained.manifest.json
python -m burp_ai_redaction_gateway audit-compress --input out/.audit/mcp_audit.retained.jsonl --output out/.audit/mcp_audit.retained.jsonl.gz
python -m burp_ai_redaction_gateway audit-compress-verify --input out/.audit/mcp_audit.retained.jsonl.gz
python -m burp_ai_redaction_gateway audit-compressed-hmac --input out/.audit/mcp_audit.retained.jsonl.gz --manifest out/.audit/mcp_audit.retained.jsonl.gz.manifest.json
python -m burp_ai_redaction_gateway audit-compressed-hmac-verify --input out/.audit/mcp_audit.retained.jsonl.gz --manifest out/.audit/mcp_audit.retained.jsonl.gz.manifest.json
~~~

검사표에는 형식, 행 수 또는 크기, 해시, 생성 시각을 저장하며 본문·비밀키·인증정보는 넣지 않습니다.
압축은 보관용이며 암호화나 위변조 검사를 대신하지 않습니다. 입력은 삭제·변경하지 않습니다.
압축 파일은 임시로 풀어 감사 기록을 검사합니다.
압축 파일의 HMAC은 압축된 바이트를 검사하며 원본 JSONL의 HMAC과 별개입니다.

</details>

</details>
