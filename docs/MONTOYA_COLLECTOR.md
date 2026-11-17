# Burp 수집기 설정

Burp에 설치해 새 Proxy 응답을 자동으로 가져오는 확장입니다. 매번 Export할 필요가 없습니다.
원본 요청·응답을 로컬 수신기로 보내고, 수신기에서 민감정보를 제거한 뒤 검증합니다. AI로 직접 보내지 않습니다.
가끔 파일을 처리한다면 수집기를 설치하지 않고 [파일 업로드](USAGE.md)를 쓰면 됩니다.
확인한 Burp 버전과 실제 화면은 [설치·전송·결과 확인 예제](examples/collector_run.md)에 있습니다.

## 준비

- Python 3.12 이상, Burp Suite, JDK 21을 준비하세요. JDK는 확장 파일을 만드는 데 필요합니다.
- README.md가 있는 폴더에서 PowerShell을 엽니다.
- 처음 확장 파일을 만들 때 Gradle과 필요한 라이브러리를 내려받으므로 인터넷 연결이 필요할 수 있습니다.
- Burp 하단의 Scope settings → Target scope → Include in scope → Add에서 허가받은 대상만 등록합니다.

## 1. 확장 파일 만들기

```powershell
Push-Location extensions/montoya-collector
.\gradlew.bat clean build
Pop-Location
```

`BUILD SUCCESSFUL`이 나오면 성공입니다. 실패하면 아래의 ‘연결되지 않을 때’를 먼저 확인하세요.
만들어진 확장 파일(JAR)은 `extensions/montoya-collector/build/libs/burp-ai-redaction-gateway-montoya-collector-0.1.0.jar`입니다.

## 2. 수신기와 대시보드 실행하기

```powershell
python -m burp_ai_redaction_gateway capture --open
```

터미널은 열어 두세요. 수신기와 결과 화면이 함께 실행됩니다. 기존 대시보드가 같은 포트에서 실행 중이면 먼저 해당 터미널에서 종료하세요.
기본 수신 주소는 `http://127.0.0.1:8765/ingest/burp-history`입니다. 외부에서는 접속할 수 없습니다.

## 3. Burp에서 자동 수집 시작하기

1. Extensions → Installed → Add를 열고 확장 유형에서 Java를 선택합니다.
2. Select file로 1단계의 JAR 파일을 고르고 Next를 누릅니다. Errors에 오류가 없으면 Close로 닫습니다.
3. 로컬 보안 점검 탭에서 자동 수집 시작을 누릅니다. 확장을 설치하거나 다시 불러온 직후에는 꺼져 있습니다.
4. Burp Proxy를 거쳐 웹을 탐색합니다. 점검 범위에 포함된 새 응답만 수집합니다. 탭에서 전송·제외·실패 건수를 확인하세요.
5. 멈추려면 중지를 누릅니다. 대기 중인 원문은 버리며, 이미 전송 중인 1건은 완료될 수 있습니다.

범위 밖 기록, 호스트가 없거나 잘못된 기록은 보내지 않습니다. 로컬 주소·IP 주소·URL·경로 형식의 호스트도 제외합니다.
전송 상태에는 건수만 표시하며 원본과 대상 호스트 값은 남기지 않습니다.
응답이 없는 요청은 자동 수집하지 않습니다. 전송할 JSON이 1 MiB를 넘거나 대기 중인 16건이 차면 제외합니다. 실패한 요청을 자동으로 재전송하지 않습니다.

## 4. 결과 확인하기

[자동 수집 결과](http://127.0.0.1:8766/burp)는 5초마다 갱신됩니다. 최근 50개를 표시하며 전체 결과는 첫 화면에서도 읽을 수 있습니다.
요청별로 마스킹·검증·보고서 작성까지 자동 처리합니다. 검증에 실패한 결과는 게시하지 않습니다.
결과 보기에서 후보·확인 방법·조치 제안을 읽고 보고서를 확인하세요. [VA-01~VA-30 기준](VA_CHECKLIST.md)으로 표시하지만, 전체 항목의 자동 진단이나 취약점 확정을 뜻하지 않습니다.
파일 4개는 각 결과의 `ai_candidates/`에 모입니다. 원본이나 결과 폴더 전체를 공유하지 마세요. AI 검토는 내용을 확인하고 별도로 동의한 뒤에만 실행합니다.
종료할 때는 확장의 중지와 터미널의 `Ctrl+C`를 사용하세요.

과거 기록을 한 번 보내려면 Proxy → HTTP history에서 우클릭한 뒤 Extensions → Burp AI Redaction Gateway Collector → 점검 범위의 Proxy 기록을 로컬 도구로 보내기를 선택합니다. 선택한 행만이 아니라 점검 범위에 포함된 Proxy 기록 전체를 보냅니다. 이 메뉴는 웹 탐색에 요청을 추가로 보내지 않습니다.

## 연결되지 않을 때

- 확장 파일 생성 실패: `java -version`으로 JDK 21인지 확인하세요. `JAVA_HOME`을 설정했다면 JDK 21 설치 폴더를 가리켜야 합니다. 설치나 설정을 바꾼 뒤에는 PowerShell을 다시 여세요.
- 전송 실패: `capture` 터미널이 열려 있는지, 수신 주소의 포트가 명령의 `--receiver-port`와 같은지 확인하세요. 재시도하려면 새로운 응답이 필요합니다.
- `port_unavailable`: 이미 실행 중인 프로그램을 확인하거나 포트를 바꾸세요. 대시보드는 `--port`, 수신기는 `--receiver-port`입니다. 수신기 포트를 바꾸면 확장의 전송 주소도 함께 바꿉니다.
- 전송 건수가 0: 점검 범위와 Proxy 기록의 호스트 정보를 확인하세요. 제한을 해제해 보내지 마세요.
- 대시보드의 ‘Burp 수집 상태’는 상태를 보는 화면입니다. 확장이나 수신기를 실행하지는 않습니다.

## 지켜야 할 점

- 확장은 외부 주소로 전송하지 못하게 제한합니다. 이 제한을 해제하지 마세요.
- 원본을 보관할 때는 `local_only/` 등 Git에서 제외한 폴더만 사용하세요. 원본·인증정보·실제 호스트를 로그나 저장소에 남기지 않습니다.
- 검증을 통과해도 내용을 직접 읽고 필요한 파일만 사용하세요. 점검 결과는 확정 취약점이 아닌 검토 후보입니다.
- 요청 재전송, 능동 스캔, 원문 조회, 자동 AI 전송 기능은 제공하지 않습니다.

<details>
<summary>포트 변경과 기술 참고</summary>

포트 8765가 사용 중이라면 `capture --receiver-port 8767`로 바꾸세요. 아래 명령을 실행한 PowerShell에서 Burp도 다시 실행해야 합니다. 이미 열린 Burp에는 적용되지 않습니다.

```powershell
$env:BURP_AI_REDACTION_GATEWAY_URL = "http://127.0.0.1:8767/ingest/burp-history"
```

`request_metadata.host`에는 호스트 이름만 허용합니다. 인증정보, URL·경로, 개인정보를 넣지 않습니다.
Output의 건수: `items_sent`는 전송, `skipped`는 제외 합계입니다. 제외 이유는 `out_of_scope_skipped`(범위 밖), `missing_host_skipped`(호스트 없음), `invalid_host_skipped`(호스트 형식 오류)로 나뉩니다.

Gradle 9.5.1을 사용하며 내려받은 파일의 체크섬을 검사합니다. Montoya API 2026.4로 확장을 빌드하며 실행 시 API는 Burp가 제공합니다.
범위 판정은 [수집 범위 비교 기준](LIVE_CAPTURE_SCOPE_DRIFT_MATRIX_v0.5.md)과 [가상 샘플](../samples/synthetic_live_capture_scope_drift_matrix.json), 수신 동작은 [로컬 수신기](LOCALHOST_RECEIVER.md)를 참고하세요.
공식 자료: [Burp에 확장 추가하기](https://portswigger.net/burp/documentation/desktop/extend-burp/extensions/creating/loading-in-burp), [점검 범위 설정](https://portswigger.net/burp/documentation/desktop/testing-workflow/test-scope), [Montoya API](https://portswigger.github.io/burp-extensions-montoya-api/javadoc/).

</details>
