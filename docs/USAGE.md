# 사용 방법

파일 업로드 → 민감정보 제거 → 결과 확인 순서로 사용합니다. AI에 자동으로 보내지 않습니다.
Python 3.12 이상이 필요하며 추가 Python 패키지는 설치하지 않아도 됩니다.

## 1. 대시보드 열기

Windows에서 README.md가 있는 폴더를 열고, 탐색기 주소창에 `powershell`을 입력하세요.
아래 두 줄을 실행하고 터미널 창은 닫지 마세요. `out` 폴더가 이미 있어도 기존 결과는 지우지 않습니다.

```powershell
New-Item -ItemType Directory -Force out
python -m burp_ai_redaction_gateway dashboard --host 127.0.0.1 --port 8766 --root out
```

[대시보드](http://127.0.0.1:8766/)를 엽니다. 종료할 때는 터미널에서 `Ctrl+C`를 누르세요.

## 2. 파일 처리하기

1. 파일 업로드를 누릅니다.
2. 처음에는 `samples/synthetic_burp_history.json`을 선택합니다. 실제 고객 기록이 아닌 가상 샘플입니다.
3. 작업 이름에 `demo`를 입력하고 민감정보 제거 시작을 누릅니다.
4. 결과 파일 확인에서 보고서와 AI에 보낼 검토 요청문을 읽고, 필요한 파일만 내려받습니다.

네 파일을 한 폴더에 모으려면 파일 4개 내보내기를 누르세요. `exports/dashboard/` 아래에 복사됩니다.
파일 용도는 [결과 파일 안내](OUTPUT_BUNDLE_GUIDE_KO_v0.6.md)를 참고하세요.

다시 처리할 때는 `demo2`처럼 새 작업 이름을 쓰세요. 이름은 영문이나 숫자로 시작해야 합니다.
영문·숫자·밑줄·하이픈으로 최대 64자까지 쓸 수 있습니다. 실제 고객명이나 주소는 넣지 마세요.

## 3. 내 Burp 기록 사용하기

Burp의 Proxy → HTTP history에서 필요한 요청을 선택하고, 우클릭한 뒤 Save items로 XML 파일을 저장하세요.
원본은 `local_only/`에 보관하고 Git에 올리지 마세요. 저장한 파일을 2단계에서 선택하면 됩니다.

| 실행 방법 | 입력 파일 | 최대 크기 |
| --- | --- | --- |
| 웹 업로드 | Burp XML, JSON | 10 MiB(약 10.5 MB) |
| 명령어 실행 | Burp XML, JSON, HAR | 16 MiB(약 16.8 MB) |

JSON은 `samples/` 예제나 HAR 구조를 사용합니다. 웹에 올린 원본도 `local_only/`에 보관됩니다.

## 명령어로 처리하기

웹 화면 없이 처리하려면 같은 폴더에서 실행하세요.

```powershell
python -m burp_ai_redaction_gateway process --input samples/synthetic_burp_history.json --output out/demo --project demo
```

내 XML은 `--input local_only/history.xml`처럼 입력 위치만 바꾸면 됩니다.
`--project`는 작업 이름, `--output`은 새 결과 폴더입니다. 기존 폴더는 덮어쓰지 않습니다. 다시 실행할 때는 `--output out/demo2 --project demo2`처럼 둘 다 바꾸세요.

민감정보 제거와 검증, 보고서 작성을 마치면 결과 폴더의 `ai_candidates/`에 파일 4개가 모입니다. 입력 원본은 수정하지 않습니다.
검사에 실패하면 전달 후보 폴더를 만들지 않습니다. 중간 파일이 남을 수 있으니 공유하지 마세요.

## 문제가 생겼을 때

| 상황 또는 표시 | 해결 방법 |
| --- | --- |
| `python`을 찾을 수 없음 | Python 설치 후 터미널을 다시 여세요. `py --version`이 3.12 이상이면 명령의 `python`을 `py`로 바꿔도 됩니다. |
| `No module named burp_ai_redaction_gateway` | README.md가 있는 폴더에서 실행했는지 확인하세요. |
| 주소가 사용 중임 | `--port 8767`로 바꾸고 브라우저도 `http://127.0.0.1:8767/`로 여세요. |
| `output_already_exists` | 새 작업 이름과 새 결과 폴더를 사용하세요. |
| `invalid_project_alias` | 작업 이름의 문자와 길이를 확인하세요. |
| `unsupported_input_format`, `input_not_readable_or_invalid`, `no_http_events` | 입력 형식과 파일 위치를 확인하고, Burp에서 요청을 선택해 다시 저장하세요. |
| `input_too_large` | 입력 크기 제한을 넘었습니다. Burp에서 요청을 나눠 저장하세요. |
| `verification_failed`, `export_verification_failed`, `processing_failed` | 처리가 중단됐습니다. 실패한 결과는 공유하지 말고 입력 형식과 정책을 확인하세요. |

## 공유 전 확인

- 검증에 실패한 결과는 사용하지 마세요. 검사를 끄거나 정책을 느슨하게 바꿔 통과시키지 않습니다.
- 자동 검사가 모든 민감정보를 찾는 것은 아닙니다. 원본 요청·응답, 인증정보, 개인정보가 남지 않았는지 직접 읽어보세요.
- 검토 후보는 확정 취약점이 아니며 위험도도 초안입니다. 재현과 영향 확인 후 판단하세요.
- 원본이나 결과 폴더 전체를 AI에 올리지 말고, 확인한 파일만 사용하세요.

## 필요한 경우에만 설정

- [Burp 수집기](MONTOYA_COLLECTOR.md): 허가된 점검 범위의 기록을 로컬 수신기로 보냅니다. Burp 수집 상태 화면만 열어서는 수집이 시작되지 않습니다.
- [읽기 전용 MCP](READ_ONLY_MCP.md): AI 프로그램에서 검증된 결과를 읽습니다. Burp를 직접 조작하지 않습니다.

<details>
<summary>개발·고급 사용 참고</summary>

결과 화면의 공유 전 추가 점검에서는 파일과 검사 상태만 확인합니다. 파일을 수정하거나 처리를 실행하지 않습니다.
단계별 명령은 [구성과 추가 설정](REFERENCE.md)을 참고하세요.
기존 `review --export-dir`은 분석 파일과 프롬프트 3개만 복사합니다. 보고서를 포함한 4개 파일에는 `process` 또는 대시보드 내보내기를 사용하세요.

</details>
