# 사용 방법

## CLI로 처리

저장소 폴더에서 Python 3.12 이상으로 실행합니다. 추가 패키지 설치는 필요 없습니다.

```powershell
python -m burp_ai_redaction_gateway process --input samples/synthetic_burp_history.json --output out/demo --project demo
```

`process`는 생성, 검증, 보고서 작성, 전달 후보 복사를 한 번에 실행합니다.
완료되면 `out/demo/ai_candidates/`를 열어 4개 파일을 확인하세요.
원본 입력은 수정하지 않습니다. 결과 폴더에는 감사·중간 결과도 있지만 전달 후보 폴더에는 복사하지 않습니다.

새 결과 폴더만 사용할 수 있습니다. 같은 기록을 다시 처리하려면 `--output out/demo2`처럼 다른 경로를 지정합니다.
실패한 결과 폴더는 로컬에 남을 수 있지만 `ai_candidates/`는 최종 검사를 통과해야 생성됩니다.

## 웹으로 처리

```powershell
python -m burp_ai_redaction_gateway dashboard --host 127.0.0.1 --port 8766 --root out
```

1. [대시보드](http://127.0.0.1:8766/)의 **업로드 마법사**를 엽니다.
2. XML 또는 JSON 파일을 선택하고 `check01` 같은 새 별칭을 입력합니다.
3. **로컬 마스킹 및 검증 시작**을 누릅니다.
4. 성공 후 결과 요약, 후보 항목, 파일 4개 상태를 확인합니다.
5. 산출물 상세 화면에서 **안전 파일 내보내기**를 실행하면 `exports/dashboard/` 아래에 파일을 복사합니다.

웹 업로드는 원본을 `local_only/`에 보관합니다.
프로젝트 별칭이 이미 사용 중이면 다른 별칭을 선택하세요.
웹 업로드는 XML·JSON, CLI `process`는 XML·JSON·HAR를 지원합니다.
CLI와 웹의 입력 크기 제한은 각각 16 MiB와 10 MiB입니다.

포트가 사용 중이면 `--port 8767`처럼 다른 번호를 지정하고 브라우저 주소도 바꿉니다.
터미널의 `Ctrl+C`로 서버를 종료합니다.

## Burp에서 입력 준비

HTTP history에서 처리할 요청을 골라 XML 파일로 저장하세요.
원본은 `local_only/`에만 두고 Git에 추가하지 않습니다.
HAR 파일도 CLI로 처리할 수 있으며, JSON은 `samples/`의 예제 형식이나 HAR 구조를 사용합니다.

```powershell
python -m burp_ai_redaction_gateway process --input local_only/history.xml --output out/check01 --project check01
```

실제 고객명, 도메인, 토큰을 프로젝트 별칭에 넣지 마세요.

## 자주 만나는 오류

| 표시 | 확인할 내용 |
| --- | --- |
| `output_already_exists` | 이미 존재하는 폴더입니다. 새 결과 경로를 사용하세요. |
| `invalid_project_alias` | 영문·숫자·밑줄·하이픈을 사용하고 영문이나 숫자로 시작하세요. 최대 64자입니다. |
| `unsupported_input_format` | XML, JSON, HAR 확장자인지 확인하세요. |
| `input_not_readable_or_invalid` | 파일 위치와 내용 형식을 확인하세요. |
| `input_too_large` | CLI 입력이 16 MiB를 넘었습니다. Burp에서 더 적은 요청을 선택해 저장하세요. |
| `no_http_events` | 읽을 수 있는 HTTP 항목이 없습니다. 저장할 때 요청을 선택했는지 확인하세요. |
| `verification_failed`, `export_verification_failed`, `processing_failed` | 처리가 중단됐습니다. 실패한 결과를 AI에 보내지 말고 입력 형식과 정책을 확인하세요. |

## 단계별 명령

처리를 나눠 실행할 때는 기존 명령도 사용할 수 있습니다.

```powershell
python -m burp_ai_redaction_gateway generate --input samples/synthetic_burp_history.json --output out/manual --project manual
python -m burp_ai_redaction_gateway verify --input out/manual
python -m burp_ai_redaction_gateway report --input out/manual
python -m burp_ai_redaction_gateway review --input out/manual
```

기존 `review --export-dir`은 분석 파일과 프롬프트 3개만 복사합니다.
보고서를 포함한 4개 파일이 필요하면 `process` 또는 대시보드 내보내기를 사용하세요.

## MCP와 수집기

`mcp --root out`은 로컬에서 검증된 결과를 읽는 stdio 명령입니다.
설정은 [읽기 전용 MCP](READ_ONLY_MCP.md)를 참고하세요.
이 연결은 Burp를 직접 조작하거나 raw traffic을 AI에 전달하는 기능이 아닙니다.

Burp 탐색 중 수집은 별도 [Montoya 수집기](MONTOYA_COLLECTOR.md)와 수신기가 필요합니다.
대시보드의 Live Capture 화면만 열어서는 수집이 시작되지 않습니다.
