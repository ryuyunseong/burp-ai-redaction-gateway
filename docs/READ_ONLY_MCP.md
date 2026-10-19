# 읽기 전용 MCP 설정

MCP를 연결하면 Codex 대화에서 검증된 분석 결과를 읽을 수 있습니다.
Burp를 조작하거나 원본 요청·응답을 가져오지 않습니다. [파일 업로드와 결과 확인](USAGE.md)만 필요하면 설정하지 않아도 됩니다.
Python 3.12 이상과 로컬 MCP 연결을 지원하는 Codex 앱이 필요합니다. 조회할 자료를 AI에 공유해도 되는지 먼저 확인하세요.

## 1. 읽을 결과 만들기

README.md가 있는 폴더의 PowerShell에서 실행합니다. 실제 고객 기록이 아닌 가상 샘플입니다.

```powershell
python -m burp_ai_redaction_gateway process --input samples/synthetic_burp_history.json --output out/codex_mcp_sample/demo --project demo
```

완료되면 `out/codex_mcp_sample/demo/ai_candidates`의 보고서를 읽어보세요.
기존 결과가 있으면 `demo2`처럼 마지막 폴더 이름과 `--project` 값을 함께 바꾸세요. 조회할 때도 같은 이름을 씁니다.

## 2. Codex 앱에 등록하기

설정(Settings) → MCP servers → Add server에서 STDIO(표준 입출력)를 선택합니다.
이미 `burp_sample`이 등록되어 있다면 다시 추가하지 말고 3번으로 이동하세요.

같은 PowerShell에서 아래 두 줄을 실행하면 저장소 폴더와 Python 경로가 차례로 나옵니다.

```powershell
(Get-Location).Path
python -c "import sys; print(sys.executable)"
```

| 항목 | 입력할 값 |
| --- | --- |
| 이름 | `burp_sample` |
| 실행 프로그램 | 위에서 확인한 Python 경로 |
| 인수 | `-m burp_ai_redaction_gateway mcp --root "<저장소폴더>/out/codex_mcp_sample" --policy "<저장소폴더>/policy.json"` |
| 환경변수 | `PYTHONPATH=<저장소폴더>`, `PYTHONUTF8=1`을 각각 추가 |

`<저장소폴더>`는 위에서 확인한 전체 경로로 바꿉니다. `PYTHONUTF8=1`은 한글 입출력을 위한 설정입니다.
`burp_sample`은 가상 샘플 폴더만 읽습니다. 개인 경로가 든 설정은 저장소에 올리지 마세요. 기존 승인·보안 설정을 바꿀 필요는 없습니다.

## 3. 다시 시작하고 조회하기

1. 저장한 뒤 MCP servers → burp_sample → Restart(다시 시작)를 누릅니다. 서버가 활성화되어 있는지도 확인하세요.
2. 대화 입력창에 `/mcp`를 입력해 `burp_sample`이 보이는지 확인합니다. 안 보이면 앱을 다시 열고 새 대화에서 확인하세요.
3. “burp_sample에서 demo의 점검 후보 목록, FC-0010의 상세 근거와 보고서 초안을 실제 MCP 도구로 읽어줘”라고 요청합니다.

실행 전 대상과 인수를 확인하세요. 세 도구 모두 `project`에 `demo`를 지정합니다. `get_finding`의 `finding_id`는 `FC-0010`으로 지정합니다.
Codex가 서버를 실행하므로 조회할 때 CLI나 별도 서버 터미널을 열 필요는 없습니다. [Codex 공식 설정 안내](https://learn.chatgpt.com/docs/extend/mcp?surface=app)

| MCP 도구 | 가상 샘플의 실제 조회 결과 |
| --- | --- |
| `list_findings` | 검토 후보 22개 |
| `get_finding` (`FC-0010`) | 누락 속성은 Secure, HttpOnly |
| `get_report_draft` | 보안 점검 보고서 초안 |

2026-10-19 Windows의 Codex 앱 대화에서 세 도구를 직접 호출했습니다. 세 응답의 `raw_data_included`는 `false`였습니다.
FC-0010의 보고서 문구는 “쿠키 sid에 없는 보호 속성: Secure, HttpOnly.”와 “쿠키 sid는 SameSite=None이지만 Secure가 없습니다.”입니다. `SameSite` 자체를 누락으로 표시하지 않습니다.
도구 호출 기록에 세 이름이 나오는지 확인하세요. 후보와 보고서는 초안이며 확정 취약점이 아닙니다. 실제 취약점 여부와 최종 심각도는 직접 확인해야 합니다.

## 읽지 못할 때

| 상황 | 확인할 내용 |
| --- | --- |
| 등록했는데 도구가 안 보임 | 앱의 MCP servers에서 Restart를 누른 뒤 `/mcp`로 확인하세요. 등록과 대화 연결은 별개입니다. |
| 서버를 실행할 수 없음 | Python 경로와 `PYTHONPATH`를 확인하세요. 작업 폴더를 지정할 수 있다면 저장소 폴더를 사용합니다. |
| 결과를 찾을 수 없음 | `project`에는 폴더 경로가 아니라 작업 이름 `demo`를 넣으세요. 저장소를 옮겼다면 등록 경로도 수정하세요. |
| 검증 실패 | `python -m burp_ai_redaction_gateway verify --input out/codex_mcp_sample/demo`로 확인하세요. 실패한 결과는 반환하지 않습니다. |
| 모델을 지원하지 않는다는 오류 | Codex 버전·로그인·사용 가능한 모델을 확인하세요. 보안 검사를 끄지 마세요. |

## 접근과 공유 제한

- 지정한 `--root` 아래의 결과만 읽으며 상위 폴더로 벗어나는 경로는 거절합니다.
- 서버를 외부에 공개하거나 원본 폴더를 읽기 대상으로 추가하지 마세요.
- `local_only/`, `raw/`, `raw_vault/`, `build/`, `.gradle/`에는 접근하지 않습니다.
- 결과 폴더를 검증하고 반환할 내용도 다시 검사합니다. 오류가 나면 검사를 끄지 마세요.
- 결과 파일 생성·수정·삭제, 요청 재전송, 능동 스캔, 원본 조회는 제공하지 않습니다. 호출 기록은 로컬 감사 파일에 남습니다.
- 연결 도구의 공유·외부 전송 설정도 확인하세요. 이 서버의 검사만으로 공유 여부를 결정하지 말고, `verify`, `review`, `report` 결과와 파일 내용을 직접 확인하세요.

<details>
<summary>명령어로 등록하기·도구 목록·호출 기록 (선택)</summary>

앱에서 등록했다면 아래 명령은 필요 없습니다. CLI로 등록한 설정도 앱과 공유하며, 앱에서 Restart를 눌러야 대화에 반영됩니다.

```powershell
$repo = (Get-Location).Path
$python = python -c "import sys; print(sys.executable)"
codex mcp add burp_sample --env "PYTHONPATH=$repo" --env PYTHONUTF8=1 -- $python -m burp_ai_redaction_gateway mcp --root "$repo/out/codex_mcp_sample" --policy "$repo/policy.json"
codex mcp list
```

| 도구 이름 | 하는 일 |
| --- | --- |
| `list_findings` | 점검 후보 목록 읽기 |
| `get_finding` | `project`와 `finding_id`로 후보 한 건의 근거·확인 방법 읽기 |
| `get_analysis_packet` | 민감정보를 제거한 상세 분석 데이터 읽기 |
| `get_report_draft` | 보고서 초안 읽기 |
| `list_prompt_files` | 프롬프트 파일 목록 읽기 |

서버는 `readOnlyHint` 표시와 별개로 결과 파일 변경을 차단합니다. `mcp --root out/codex_mcp_sample`만 실행하면 요청을 기다리며, 웹 페이지가 열리지는 않습니다.
호출 기록은 `<root>/.audit/mcp_audit.jsonl`과 표준 오류(stderr)에 남으며 원문·보고서 본문·인증정보·실제 주소·개인정보·오류 추적 전문은 기록하지 않습니다.
호출 기록 검사: `python -m burp_ai_redaction_gateway review-audit --input out/codex_mcp_sample/.audit`
감사 기록은 형식·순번·해시 연결과 민감정보를 검사합니다. 오래되거나 깨진 기록은 실패할 수 있으며 기록을 지워 오류를 숨기지 마세요. 보관 제한으로 과거 파일이 제거되면 남은 범위만 검증할 수 있습니다.
HMAC은 비밀키로 파일 변경을 검사하며 암호화가 아닙니다. 비밀키를 저장소·로그·AI 입력에 남기지 마세요. 세부 명령은 [감사 기록 안내](AUDIT_OPERATIONS_GUIDE.md)를 참고하세요.

</details>
