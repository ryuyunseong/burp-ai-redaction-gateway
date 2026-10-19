# 로컬 수신기

Burp 확장이 보낸 요청·응답에서 민감정보를 제거하고 검증하는 프로그램입니다.
127.0.0.1에서만 실행하며 외부에서 접속할 수 있도록 열지 않습니다.

## 실행

README.md가 있는 폴더에서 실행하고 터미널을 열어 두세요. Python 3.12 이상이 필요합니다.

~~~powershell
python -m burp_ai_redaction_gateway serve --host 127.0.0.1 --port 8765 --output out/receiver --project montoya_receiver_alias
~~~

`--project`에는 실제 고객명이나 서비스명이 아닌 별칭을 사용하세요.
확장 설치와 전송은 [Burp 수집기](MONTOYA_COLLECTOR.md)를 참고하세요.

| 경로 | 용도 |
| --- | --- |
| GET /health | 수신기 응답 확인 |
| POST /ingest/burp-history | Burp 확장에서 기록 한 건 수신 |

수신 자료는 montoya-handoff-v1 형식이어야 합니다.
크기 제한을 넘거나 형식이 다른 요청은 거절합니다.

## 결과 확인

전송 요청 한 번에 기록 한 건을 처리합니다. 원본은 메모리에서만 처리하고 로그에 남기지 않습니다.
민감정보 제거와 검증을 통과한 결과만 Git에서 제외된 출력 폴더에 저장합니다.
전송이 끝나면 수신기 터미널에서 `Ctrl+C`를 눌러 종료한 뒤 검증하세요.

~~~powershell
python -m burp_ai_redaction_gateway verify --input out/receiver
~~~

검증이 실패하면 여기서 멈추고 오류를 확인하세요. 통과했다면 대시보드를 실행합니다.

~~~powershell
python -m burp_ai_redaction_gateway dashboard --host 127.0.0.1 --port 8766 --root out
~~~

[대시보드](http://127.0.0.1:8766/)에서 `receiver/`로 시작하는 기록의 결과 파일 확인을 엽니다.
보고서가 없으면 보고서 다시 만들기를 누르세요. 내용을 읽고 파일 4개 내보내기로 필요한 파일만 내려받습니다.
다 썼으면 대시보드 터미널에서도 `Ctrl+C`로 종료합니다.

finding_candidates.json의 점검 항목은 확인이 필요한 후보입니다.
분석 요약과 프롬프트도 후보를 바탕으로 만들며 실제 취약점 여부나 최종 위험도를 확정하지 않습니다.
원본 기록이나 결과 폴더 전체를 AI에 올리지 마세요.
자동 검사가 모든 민감정보를 찾는 것은 아닙니다. 공유 전 직접 확인하고, 검사를 끄거나 외부 접속을 허용하지 마세요.
