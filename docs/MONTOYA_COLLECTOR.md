# Burp 수집기 설정

Burp의 Proxy 기록을 **이 컴퓨터의 수신기**로 보내는 Java 확장입니다.
수신기가 민감정보를 제거하고 검증합니다. AI로 직접 전송하지 않습니다.

파일을 가끔 처리한다면 확장을 설치하지 않아도 됩니다. 대시보드의 **파일 업로드**를 사용하세요.

## 1. 확장 빌드

Burp Suite와 JDK가 필요합니다. 저장소 폴더에서 실행합니다.

~~~powershell
cd extensions/montoya-collector
.\gradlew.bat clean build
~~~

완성된 JAR은 extensions/montoya-collector/build/libs/에 있습니다.
처음 빌드할 때 Gradle과 의존성을 내려받으므로 인터넷 연결이 필요할 수 있습니다.
Gradle Wrapper는 9.5.1로 고정하고 배포 파일의 체크섬을 확인합니다.
Montoya API 2026.4로 컴파일하며 실행할 때는 Burp가 API를 제공합니다.

## 2. 로컬 수신기 실행

새 터미널에서 저장소 폴더로 이동한 뒤 실행합니다.

~~~powershell
python -m burp_ai_redaction_gateway serve --host 127.0.0.1 --port 8765 --output out/receiver --project montoya_receiver_alias
~~~

터미널을 열어두고, 종료할 때는 Ctrl+C를 누르세요.
자세한 내용은 [로컬 수신기](LOCALHOST_RECEIVER.md)를 참고하세요.

## 3. Burp에 확장 추가

1. Burp의 **Extensions → Installed → Add**를 엽니다.
2. 확장 유형은 **Java**를 선택합니다.
3. 1단계에서 만든 JAR을 선택합니다.
4. Burp의 점검 범위(Scope)에 허가받은 대상만 등록합니다.

## 4. 기록 보내기와 결과 확인

Proxy HTTP history에서 우클릭한 뒤 **점검 범위의 Proxy 기록을 로컬 도구로 보내기**를 선택합니다.
이 메뉴는 선택한 행만 보내는 기능이 아니라, 점검 범위에 포함된 Proxy 기록을 수집합니다.

확장은 Burp 점검 범위와 호스트 정보를 확인한 뒤 전송합니다.
호스트 정보가 없거나 잘못된 경우, 로컬 주소·IP 주소·URL·경로 형식인 경우는 건너뜁니다.
상태에는 items_sent, skipped, out_of_scope_skipped, missing_host_skipped,
invalid_host_skipped 같은 건수만 표시하며 원본과 대상 호스트 값은 남기지 않습니다.

대시보드를 별도로 실행하면 결과를 확인할 수 있습니다.

~~~powershell
python -m burp_ai_redaction_gateway verify --input out/receiver
python -m burp_ai_redaction_gateway dashboard --host 127.0.0.1 --port 8766 --root out
~~~

[대시보드](http://127.0.0.1:8766/)에서 검증된 기록을 선택하세요.
검토·보고서 작성·파일 내보내기는 **결과 파일 확인**에서 사용할 수 있습니다.
점검 결과는 취약점 확정이 아닌 후보입니다.

## 수신 주소를 바꿔야 할 때

기본 주소는 http://127.0.0.1:8765/ingest/burp-history 입니다.
포트를 바꿨다면 다음 환경변수가 적용된 상태에서 Burp를 실행합니다.

~~~powershell
$env:BURP_AI_REDACTION_GATEWAY_URL = "http://127.0.0.1:8765/ingest/burp-history"
~~~

확장은 외부 주소로 전송하지 못하게 제한합니다. 이 제한을 해제하지 마세요.
전송 자료의 request_metadata.host는 호스트 이름만 허용합니다.
인증정보나 URL·경로·개인정보를 넣으면 안 됩니다.

## 주의사항

- 원본은 local_only/ 등 Git에서 제외한 로컬 폴더에만 보관하세요.
- 원본 요청·응답과 실제 호스트를 로그나 저장소에 남기지 마세요.
- 결과는 검증을 통과한 뒤 직접 읽고 필요한 파일만 사용하세요.
- 대시보드의 수집 상태 화면은 확장이나 수신기를 실행하는 버튼이 아닙니다.

관련 자료: [수집 범위 비교 기준](LIVE_CAPTURE_SCOPE_DRIFT_MATRIX_v0.5.md),
[가상 범위 비교 샘플](../samples/synthetic_live_capture_scope_drift_matrix.json).
이 자료는 범위 판정 기준을 설명하며 요청 재전송, 능동 스캔, 원문 조회, 자동 AI 전송 기능을 추가하지 않습니다.

공식 참고: [Burp 확장 만들기](https://portswigger.net/burp/documentation/desktop/extend-burp/extensions/creating),
[Montoya API 문서](https://portswigger.github.io/burp-extensions-montoya-api/javadoc/).
