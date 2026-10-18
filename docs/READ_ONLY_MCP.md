# 읽기 전용 MCP 설정

MCP는 AI 프로그램에서 이 도구의 **검증된 결과를 읽는 연결**입니다.
Burp를 직접 조작하거나 원본 요청·응답을 가져오지 않습니다. [파일 업로드와 결과 확인](USAGE.md)만 필요하면 설정하지 않아도 됩니다.

Python 3.12 이상과 **로컬 MCP 서버 연결을 지원하는 AI 프로그램**이 필요합니다.
연결하면 AI 프로그램이 결과를 읽을 수 있으므로 공유할 자료인지 먼저 확인하세요.

## 1. 읽을 결과 만들기

README.md가 있는 폴더의 PowerShell에서 실행합니다. 실제 고객 기록이 아닌 가상 샘플입니다.

```powershell
python -m burp_ai_redaction_gateway process --input samples/synthetic_burp_history.json --output out/codex_mcp_sample/demo --project demo
```

완료되면 `out/codex_mcp_sample/demo/ai_candidates`의 보고서를 직접 읽어보세요.
기존 결과가 있으면 `demo2`처럼 마지막 폴더와 작업 이름을 바꾸고 아래 조회에도 같은 이름을 사용합니다.

## 2. Codex에 연결하기

Codex CLI를 설치하고 로그인한 상태에서 같은 PowerShell에 입력합니다.

```powershell
$repo = (Get-Location).Path
$python = python -c "import sys; print(sys.executable)"
codex mcp add burp_sample --env "PYTHONPATH=$repo" --env PYTHONUTF8=1 -- $python -m burp_ai_redaction_gateway mcp --root "$repo/out/codex_mcp_sample" --policy "$repo/policy.json"
codex mcp list
```

`burp_sample`은 가상 샘플 폴더만 읽습니다. Codex가 서버를 실행하므로 별도 서버 터미널이나 웹 주소는 필요 없습니다.
설정은 이 PC의 Codex에 저장됩니다. 개인 경로가 든 설정은 저장소에 올리지 마세요. 기존 승인·보안 설정을 바꿀 필요는 없습니다.
Codex를 다시 열어 새 대화에서 확인하세요. CLI에서는 `/mcp`로 연결 상태를 볼 수 있습니다. [Codex 공식 설정 안내](https://learn.chatgpt.com/docs/extend/mcp?surface=cli)

## 3. 연결 확인하기

Codex에 **“burp_sample에서 demo의 점검 후보 목록과 보고서 초안을 읽어줘”**라고 요청합니다.
호출할 도구는 `list_findings`, `get_report_draft`이며 둘 다 `project`에 `demo`를 지정합니다. 도구 실행을 묻는 화면에서는 대상과 인수를 확인하세요.

가상 샘플을 그대로 처리했다면 검토 후보 **22개**가 나옵니다. 확정 취약점 수가 아닙니다.
Codex의 도구 호출 기록에 두 이름이 나오면 MCP로 읽은 것입니다.
2026-10-19 Windows의 Codex CLI 0.163.0-alpha.10.2에서 두 도구 호출과 한글 보고서 조회를 확인했습니다.

## 읽지 못할 때

| 상황 | 확인할 내용 |
| --- | --- |
| 서버를 실행할 수 없음 | Python과 작업 폴더를 확인하세요. 오류에 모듈을 찾을 수 없다고 나오면 README.md가 있는 폴더인지 확인합니다. |
| 결과를 찾을 수 없음 | 위 설정의 `project`는 경로가 아닌 `demo`입니다. 저장소를 옮겼다면 새 위치에서 연결 명령을 다시 실행하세요. |
| 검증 실패 | `python -m burp_ai_redaction_gateway verify --input out/codex_mcp_sample/demo`로 확인하세요. 실패한 결과는 반환하지 않습니다. |
| 모델을 지원하지 않는다는 오류 | Codex 버전과 로그인 상태, 사용 가능한 모델을 확인하세요. 서버의 보안 검사를 끄는 것으로 해결되지 않습니다. |
| 터미널에 아무 화면도 안 나옴 | `mcp --root out/codex_mcp_sample`은 요청을 기다리는 명령입니다. 직접 켰다면 `Ctrl+C`로 종료하고 Codex에서 연결하세요. |

## 접근과 공유 제한

- 지정한 `--root` 아래의 결과만 읽으며 상위 폴더로 벗어나는 경로는 거절합니다.
- 서버를 외부에 공개하거나 원본 폴더를 읽기 대상으로 추가하지 마세요.
- `local_only/`, `raw/`, `raw_vault/`, `build/`, `.gradle/`에는 접근하지 않습니다.
- 결과 폴더를 검증하고 반환할 내용도 다시 검사합니다. 오류가 나면 검사를 끄지 마세요.
- 결과 파일 생성·수정·삭제, 요청 재전송, 능동 스캔, 원본 조회는 제공하지 않습니다. 호출 기록은 로컬 감사 파일에 남습니다.
- 검토 후보와 위험도는 초안입니다. 실제 취약점 여부와 최종 심각도는 직접 확인해야 합니다.
- 연결 도구의 공유·외부 전송 설정도 확인하세요. 이 서버의 검사는 사용자의 공유 판단이나 `verify`, `review`, `report` 절차를 대신하지 않습니다.

<details>
<summary>다른 AI 프로그램, 도구 목록과 호출 기록 (선택)</summary>

다른 AI 프로그램에서는 표준 입출력(stdio) 연결을 선택하고, 위 명령에서 `--` 뒤의 실행 프로그램과 인수를 사용합니다.
`PYTHONPATH`에는 저장소 폴더, `PYTHONUTF8`에는 `1`을 지정합니다. 모듈 검색 경로와 한글 입출력을 위한 설정입니다.

| 도구 이름 | 하는 일 |
| --- | --- |
| `list_findings` | 점검 후보 목록 읽기 |
| `get_finding` | `project`와 `finding_id`로 후보 한 건의 근거·확인 방법 읽기 |
| `get_analysis_packet` | 민감정보를 제거한 상세 분석 데이터 읽기 |
| `get_report_draft` | 보고서 초안 읽기 |
| `list_prompt_files` | 프롬프트 파일 목록 읽기 |

도구의 `readOnlyHint` 표시뿐 아니라 서버 코드에서도 결과 파일 변경을 제한합니다.
호출 기록은 `<root>/.audit/mcp_audit.jsonl`과 표준 오류(stderr)에 남으며, 원문·보고서 본문·인증정보·실제 주소·개인정보·오류 추적 전문은 기록하지 않습니다.

```powershell
python -m burp_ai_redaction_gateway review-audit --input out/codex_mcp_sample/.audit
```

감사 기록은 형식, 순번, 해시 연결과 민감정보를 검사합니다. 오래되거나 깨진 기록은 실패할 수 있으며, 기록을 지워 오류를 숨기지 마세요.
보관 제한으로 과거 파일이 제거되면 남은 범위만 검증할 수 있습니다. HMAC은 비밀키로 파일 변경을 검사하는 방식이며 암호화가 아닙니다. 비밀키를 저장소·로그·AI 입력에 남기지 마세요.
보관·압축·위변조 검사의 세부 명령은 [감사 기록 안내](AUDIT_OPERATIONS_GUIDE.md)를 참고하세요.

</details>
