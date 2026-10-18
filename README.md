# Burp AI Redaction Gateway

Burp Suite로 수집한 HTTP 기록에서 쿠키, 로그인 토큰, 개인정보를 가리고,
AI 검토에 쓸 요약과 보고서 초안을 만드는 로컬 도구입니다.

보안 점검 기록을 AI에 붙여 넣기 전에 민감정보를 정리하려고 만들었습니다.
기록 처리와 검증은 내 컴퓨터에서 진행하며, AI로 보내는 단계는 사용자가 직접 결정합니다.

## 먼저 실행해 보기

Python 3.12 이상이 필요합니다. 실행에 필요한 추가 Python 패키지는 없습니다.
저장소를 내려받은 뒤 저장소 폴더에서 실행하세요.

```powershell
python -m burp_ai_redaction_gateway process --input samples/synthetic_burp_history.json --output out/demo --project demo
```

예제의 요청 10개를 처리하고, 검증과 보고서 생성을 마친 다음
`out/demo/ai_candidates/`에 아래 4개 파일을 만듭니다.

| 파일 | 내용 |
| --- | --- |
| `analysis_packet.json` | 요청 요약과 점검 후보를 모은 데이터 |
| `chatgpt_prompt.md` | ChatGPT에서 검토할 때 사용할 프롬프트 |
| `codex_task_prompt.md` | Codex에서 검토할 때 사용할 프롬프트 |
| `report_draft.md` | 사람이 확인하고 수정할 보고서 초안 |

검사에 실패하면 `ai_candidates/`를 만들지 않습니다.
이미 있는 결과 폴더는 덮어쓰지 않으므로 다시 실행할 때는 `out/demo2`처럼 새 폴더를 지정하세요.
나머지 감사 기록과 중간 결과는 로컬 확인용입니다. 결과 폴더 전체를 AI에 올리지 마세요.

## 웹 화면으로 사용하기

```powershell
python -m burp_ai_redaction_gateway dashboard --host 127.0.0.1 --port 8766 --root out
```

브라우저에서 [로컬 대시보드](http://127.0.0.1:8766/)를 엽니다.
처음 화면의 **파일 업로드**에서 Burp XML 또는 JSON 파일과 작업 이름을 입력하면
민감정보 제거, 검증, 보고서 생성을 순서대로 실행합니다.
완료된 결과에서 후보 항목과 AI 전달 후보 파일 4개의 상태를 확인할 수 있습니다.

웹으로 올린 원본은 로컬 `local_only/` 아래에 보관됩니다.
종료하려면 서버를 실행한 터미널에서 `Ctrl+C`를 누르세요.

## 내 Burp 기록 처리하기

Burp의 HTTP history에서 필요한 항목을 선택해 XML로 저장합니다.
원본은 Git에서 제외된 `local_only/` 폴더에 두고 실행하세요.

```powershell
python -m burp_ai_redaction_gateway process --input local_only/history.xml --output out/check01 --project check01
```

`process`는 Burp XML, HAR, 프로젝트 JSON 형식을 받으며 입력 크기는 최대 16 MiB입니다.
`--project`에는 실제 고객명이나 서비스명 대신 영문·숫자·밑줄·하이픈으로 된 별칭을 사용합니다.

```text
Burp 기록 → 민감정보 제거 → 잔존 여부 검사 → 보고서 초안 → 파일 4개 재검증 → 수동 확인
```

검사에서 문제가 발견되면 이후 처리를 중단합니다.
자동 검증이 모든 민감정보를 찾아낸다는 보장은 없으므로 전달 전에 파일 내용을 읽어보세요.
점검 결과도 취약점 확정이 아닌 후보입니다. 실제 재현과 최종 위험도 판단은 별도로 해야 합니다.

## 실제 실행 화면

파일을 선택하고 작업 이름을 입력한 뒤 **민감정보 제거 시작**을 누릅니다.

![대시보드에서 샘플 파일을 선택한 화면](docs/images/dashboard-upload.png)

처리가 끝나면 **결과 파일 확인**에서 파일 내용을 읽고 필요한 파일만 내려받습니다.

![샘플 처리 후 전달 후보 파일 4개가 만들어진 화면](docs/images/dashboard-result.png)

두 사진은 로컬 대시보드에서 공개 샘플 `samples/synthetic_burp_history.json`을
직접 업로드하고 처리한 화면입니다. 실제 고객 기록은 사용하지 않았습니다.
요청 10개에서 검토 후보 22개가 나왔으며, 후보 수가 확정 취약점 수를 뜻하지는 않습니다.

## 지원 범위

- **파일 처리:** Burp XML·HAR·JSON 읽기, 민감정보 제거, 검증, 보고서 초안, 파일 4개 분리
- **로컬 웹:** 파일 업로드, 결과 조회, 재검증, 보고서 생성, 파일 내보내기
- **Burp 확장:** Montoya 수집기에서 로컬 수신기로 전달하는 별도 설정 제공
- **MCP:** 검증된 결과를 읽는 stdio 명령 제공. Burp를 직접 조작하는 연결과는 다릅니다.

원본 HTTP 미리보기, 요청 재전송, 능동 스캔, 자동 AI 전송은 제공하지 않습니다.
Live Capture 웹 화면은 준비 상태 확인용이며 수집기 실행을 대신하지 않습니다.
v0.10 이후 변경 사항은 현재 `main` 기준입니다. 기존 릴리스와 새 MCP listener 실험 경계는
[기술 참고](docs/REFERENCE.md)에서 구분해 설명합니다.

## 테스트

```powershell
python -m unittest discover -s tests
python -m compileall burp_ai_redaction_gateway tests
```

테스트에는 가상 데이터를 사용합니다. 실제 고객 기록이나 운영 자격 증명은 포함하지 않습니다.

## 자세한 문서

- [실행 방법과 오류 해결](docs/USAGE.md)
- [결과 파일 안내](docs/OUTPUT_BUNDLE_GUIDE_KO_v0.6.md)
- [Burp 수집기 설정](docs/MONTOYA_COLLECTOR.md)
- [읽기 전용 MCP 설정](docs/READ_ONLY_MCP.md)
- [프로젝트 요약](docs/PORTFOLIO_SUMMARY_KO.md)
- [구성과 기술 참고](docs/REFERENCE.md)
