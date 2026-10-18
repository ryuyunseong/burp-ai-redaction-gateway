# Burp 수집기 설정

Burp 기록을 **내 컴퓨터의 수신기**로 보내는 선택 기능입니다.
원본 요청·응답은 로컬 수신기까지 전달되며, 수신기에서 민감정보를 제거하고 검증합니다. AI로 직접 보내지 않습니다.
파일을 가끔 처리한다면 설치 없이 [파일 업로드](USAGE.md)를 쓰세요.

## 준비

- Python 3.12 이상, Burp Suite, JDK 21이 설치된 컴퓨터에서 진행합니다. JDK 21은 자동 빌드 검사에서 사용하는 버전입니다.
- 모든 명령은 README.md가 있는 폴더의 PowerShell에서 실행합니다.
- 처음 빌드할 때 Gradle과 의존성을 내려받으므로 인터넷 연결이 필요할 수 있습니다.
- Burp 하단의 **Scope settings**를 열고 **Target scope → Include in scope → Add**에서 **허가받은 대상만** 등록합니다.

## 1. 확장 파일 만들기

```powershell
Push-Location extensions/montoya-collector
.\gradlew.bat clean build
Pop-Location
```

`BUILD SUCCESSFUL`이 표시됐는지 확인하세요. 실패했다면 다음 단계로 넘어가지 않습니다.
확장 파일은 `extensions/montoya-collector/build/libs/burp-ai-redaction-gateway-montoya-collector-0.1.0.jar`입니다.

## 2. 수신기 실행하기

```powershell
python -m burp_ai_redaction_gateway serve --host 127.0.0.1 --port 8765 --output out/receiver --project montoya_receiver_alias
```

이 터미널은 열어 둡니다. 기본 수신 주소는 `http://127.0.0.1:8765/ingest/burp-history`입니다.

## 3. Burp에서 기록 보내기

1. **Extensions → Installed → Add**에서 확장 유형 **Java**를 선택합니다.
2. **Select file**로 1단계의 JAR 파일을 선택하고 **Next**로 불러옵니다. **Errors**에 오류가 없으면 **Close**로 닫습니다.
3. **Proxy → HTTP history**에서 우클릭하고 **점검 범위의 Proxy 기록을 로컬 도구로 보내기**를 누릅니다.

**선택한 행만 보내는 메뉴가 아닙니다. 점검 범위에 포함된 Proxy 기록 전체를 확인한 뒤 실행하세요.**
범위 밖 기록과 호스트가 없거나 잘못된 기록, 로컬 주소·IP 주소·URL·경로 형식의 호스트는 제외합니다.
전송 상태에는 건수만 표시하며 원본과 대상 호스트 값은 남기지 않습니다.

## 4. 결과 확인하기

전송이 끝나면 수신기 터미널에서 `Ctrl+C`를 눌러 멈추고, 같은 폴더에서 실행합니다.

```powershell
python -m burp_ai_redaction_gateway verify --input out/receiver
python -m burp_ai_redaction_gateway dashboard --host 127.0.0.1 --port 8766 --root out
```

검증이 실패하면 대시보드로 넘어가지 말고 결과를 확인하세요.
[대시보드](http://127.0.0.1:8766/)에서 `receiver/`로 시작하는 기록의 **결과 파일 확인**을 엽니다.
기록은 요청별 폴더로 저장됩니다. 보고서가 없으면 **보고서 다시 만들기**를 누른 뒤 내용을 읽고 **파일 4개 내보내기**를 사용하세요.

## 연결되지 않을 때

- JAR 빌드 실패: `java -version`으로 JDK 21이 잡히는지 확인하세요. `JAVA_HOME`을 사용한다면 JDK 21 설치 폴더를 가리켜야 합니다. 설치·설정을 바꿨다면 PowerShell을 다시 여세요.
- 전송 실패: 수신기 터미널이 열려 있는지, 두 프로그램이 같은 포트를 쓰는지 확인하세요.
- 전송 건수가 0: 점검 범위와 Proxy 기록의 호스트 정보를 확인하세요. 제한을 해제해 보내지 마세요.
- **Burp 수집 상태** 화면은 확장이나 수신기를 실행하는 버튼이 아닙니다.

## 지켜야 할 점

- 확장은 외부 주소로 전송하지 못하게 제한합니다. 이 제한을 해제하지 마세요.
- 원본은 `local_only/` 등 Git에서 제외한 폴더에만 보관합니다. 원본·인증정보·실제 호스트를 로그나 저장소에 남기지 않습니다.
- 검증을 통과해도 내용을 직접 읽고 필요한 파일만 사용하세요. 점검 결과는 확정 취약점이 아닌 검토 후보입니다.
- 요청 재전송, 능동 스캔, 원문 조회, 자동 AI 전송 기능은 제공하지 않습니다.

<details>
<summary>포트 변경과 기술 참고</summary>

포트 8765를 사용할 수 없다면 수신기 명령을 `--port 8767`로 바꾸고, 아래 환경변수가 적용된 PowerShell에서 Burp를 다시 실행합니다. 이미 열린 Burp에는 적용되지 않습니다.

```powershell
$env:BURP_AI_REDACTION_GATEWAY_URL = "http://127.0.0.1:8767/ingest/burp-history"
```

전송 자료의 `request_metadata.host`는 호스트 이름만 허용합니다. 인증정보, URL·경로, 개인정보를 넣지 않습니다.
상태 값은 `items_sent`(전송), `skipped`(제외 합계), `out_of_scope_skipped`(범위 밖), `missing_host_skipped`(호스트 없음), `invalid_host_skipped`(호스트 형식 오류)입니다.

Gradle Wrapper는 9.5.1로 고정하고 배포 파일의 체크섬을 검사합니다. Montoya API 2026.4로 컴파일하며 실행 시 API는 Burp가 제공합니다.
범위 판정은 [수집 범위 비교 기준](LIVE_CAPTURE_SCOPE_DRIFT_MATRIX_v0.5.md)과 [가상 샘플](../samples/synthetic_live_capture_scope_drift_matrix.json), 수신 동작은 [로컬 수신기](LOCALHOST_RECEIVER.md)를 참고하세요.
공식 자료: [Burp에 확장 추가하기](https://portswigger.net/burp/documentation/desktop/extend-burp/extensions/creating/loading-in-burp), [점검 범위 설정](https://portswigger.net/burp/documentation/desktop/testing-workflow/test-scope), [Montoya API](https://portswigger.github.io/burp-extensions-montoya-api/javadoc/).

</details>
