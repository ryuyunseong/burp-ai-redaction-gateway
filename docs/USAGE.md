# 사용 방법

Python 3.12 이상에서 실행합니다. 추가 패키지 설치는 필요 없습니다.

## 웹에서 처리하기

Windows PowerShell에서 README.md가 있는 폴더를 열고 실행하세요.
`out` 폴더가 없으면 먼저 만듭니다. 이미 있어도 기존 결과는 지우지 않습니다.

```powershell
New-Item -ItemType Directory -Force out
python -m burp_ai_redaction_gateway dashboard --host 127.0.0.1 --port 8766 --root out
```

1. [대시보드](http://127.0.0.1:8766/)에서 **파일 업로드**를 엽니다.
2. XML 또는 JSON 파일과 `check01` 같은 새 작업 이름을 입력합니다.
3. **민감정보 제거 시작**을 누릅니다.
4. **결과 파일 확인**에서 내용을 읽고 필요한 파일을 내려받습니다.

처음에는 `samples/synthetic_burp_history.json`으로 시험해 보세요.
파일은 최대 10 MiB이며 원본은 `local_only/`에 보관됩니다.
작업 이름은 영문·숫자·밑줄·하이픈으로 입력하고 영문이나 숫자로 시작하세요. 최대 64자이며 실제 고객명이나 주소는 넣지 않습니다.
이미 쓴 작업 이름은 다시 사용할 수 없습니다.

네 파일을 로컬 폴더에 따로 모으려면 **파일 4개 내보내기**를 누릅니다. `exports/dashboard/` 아래에 복사됩니다.
공유 전에 [파일 내용](OUTPUT_BUNDLE_GUIDE_KO_v0.6.md)을 확인하세요. 검증에 실패한 결과나 원본·결과 폴더 전체를 AI에 올리지 마세요.

포트가 사용 중이면 `--port 8767`처럼 번호를 바꾸고 브라우저 주소도 맞춥니다.
종료할 때는 터미널에서 `Ctrl+C`를 누릅니다.

## 내 Burp 기록 준비하기

Burp의 HTTP history에서 필요한 요청을 골라 XML로 저장하세요.
원본은 `local_only/`에 두고 Git에 추가하지 않습니다. 저장한 XML을 웹에서 업로드하면 됩니다.

| 실행 방법 | 입력 형식 | 최대 크기 |
| --- | --- | --- |
| 웹 업로드 | Burp XML, JSON | 10 MiB |
| `process` 명령 | Burp XML, JSON, HAR | 16 MiB |

JSON은 `samples/`의 예제 형식이나 HAR 구조를 사용합니다.

## 명령어로 처리하기

웹 대신 명령어 한 번으로 처리할 수도 있습니다.

```powershell
python -m burp_ai_redaction_gateway process --input samples/synthetic_burp_history.json --output out/demo --project demo
```

Burp에서 저장한 XML을 사용하려면 입력 위치를 바꿉니다.

```powershell
python -m burp_ai_redaction_gateway process --input local_only/history.xml --output out/check01 --project check01
```

`--project`는 작업 이름, `--output`은 새 결과 폴더입니다.
이미 있는 폴더는 덮어쓰지 않으므로 다시 실행할 때는 `out/demo2`처럼 다른 이름을 지정하세요.

`process`는 민감정보 제거, 검증, 보고서 작성을 마친 뒤 `ai_candidates/`에 네 파일을 복사합니다.
입력 원본은 수정하지 않습니다. 실패한 중간 결과는 로컬에 남을 수 있지만 전달 후보 폴더는 최종 검사를 통과해야 생성됩니다.

## 문제가 생겼을 때

| 표시 | 해결 방법 |
| --- | --- |
| `output_already_exists` | 새 결과 폴더나 작업 이름을 사용하세요. |
| `invalid_project_alias` | 작업 이름의 문자와 길이를 확인하세요. |
| `unsupported_input_format` | XML, JSON, HAR 확장자인지 확인하세요. |
| `input_not_readable_or_invalid` | 파일 위치와 내용 형식을 확인하세요. |
| `input_too_large` | CLI 입력이 16 MiB를 넘었습니다. Burp에서 요청을 나눠 저장하세요. |
| `no_http_events` | 읽을 수 있는 HTTP 항목이 없습니다. 요청을 선택해 저장했는지 확인하세요. |
| `verification_failed`, `export_verification_failed`, `processing_failed` | 처리가 중단됐습니다. 실패한 결과를 AI에 보내지 말고 입력 형식과 정책을 확인하세요. |

## 선택 기능

기본 사용에는 아래 설정이 필요하지 않습니다.

- [Burp 수집기](MONTOYA_COLLECTOR.md): 탐색 중 선택한 기록을 로컬 수신기로 전달합니다. **Burp 수집 상태** 화면만 열어서는 수집이 시작되지 않습니다.
- [읽기 전용 MCP](READ_ONLY_MCP.md): AI 도구에서 검증된 결과를 읽습니다. Burp를 직접 조작하거나 원본을 전달하지 않습니다.
- **공유 전 추가 점검**: 결과 화면 아래에서 펼칩니다. 파일 생성 여부와 검사 결과를 보여주며 파일을 수정하거나 처리를 실행하지 않습니다.

<details>
<summary>단계를 나눠 실행하거나 테스트하기</summary>

```powershell
python -m burp_ai_redaction_gateway generate --input samples/synthetic_burp_history.json --output out/manual --project manual
python -m burp_ai_redaction_gateway verify --input out/manual
python -m burp_ai_redaction_gateway report --input out/manual
python -m burp_ai_redaction_gateway review --input out/manual
```

기존 `review --export-dir`은 분석 파일과 프롬프트 3개만 복사합니다.
보고서를 포함한 4개 파일이 필요하면 `process` 또는 대시보드 내보내기를 사용하세요.

```powershell
python -m unittest discover -s tests
python -m compileall burp_ai_redaction_gateway tests
```

테스트에는 가상 데이터를 사용합니다. 세부 명령과 버전별 설계는 [기술 참고](REFERENCE.md)에 있습니다.

</details>
