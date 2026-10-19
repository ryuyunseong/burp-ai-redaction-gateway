# Windows에서 수신기와 대시보드 함께 실행하기

Burp 수집기를 쓸 때 두 프로그램을 한 번에 여는 선택 기능입니다.
파일 업로드만 필요하면 [README](../README.md)의 실행 방법을 쓰세요. Python 3.12 이상이 필요합니다.

## 1. 실행하기

README.md가 있는 폴더의 PowerShell에서 실행합니다.

```powershell
scripts\start_gateway.ps1
```

수신기와 대시보드를 시작하고 브라우저를 엽니다. 이 명령만으로 Burp 기록을 가져오지는 않습니다.
확장 설치와 전송은 [Burp 수집기](MONTOYA_COLLECTOR.md)를 따르세요.

| 항목 | 기본값 |
| --- | --- |
| 수신기 주소 | `127.0.0.1:8765` |
| 대시보드 주소 | `http://127.0.0.1:8766/` |
| 결과 폴더 | `out\receiver` |
| 프로젝트 별칭 | `receiver_alias` |
| 실행 기록 | `out\.launcher\` |

브라우저를 자동으로 열지 않으려면 `scripts\start_gateway.ps1 -NoBrowser`를 사용합니다.
명령 프롬프트(CMD)에서는 `scripts\start_gateway.bat`로 같은 실행기를 열 수 있습니다.

## 2. 종료하기

```powershell
scripts\stop_gateway.ps1
```

실행기가 시작한 수신기와 대시보드를 함께 종료합니다. 브라우저만 닫아서는 종료되지 않습니다.
종료 명령은 저장된 프로세스 번호(PID)가 이 도구의 실행 명령인지 확인합니다. 다른 프로그램이면 종료하지 않습니다.
수집 결과는 [로컬 수신기](LOCALHOST_RECEIVER.md)의 검증 순서에 따라 확인하세요. 실패한 결과는 사용하지 않습니다.

## 실행되지 않을 때

| 표시된 오류 | 확인할 내용 |
| --- | --- |
| `receiver_port_in_use` / `dashboard_port_in_use` | 이미 실행 중인지 확인하거나 다른 포트를 사용하세요. 다른 프로그램을 임의로 종료하지 마세요. |
| `ports_must_be_distinct` | 수신기와 대시보드는 서로 다른 포트를 써야 합니다. |
| `receiver_already_running` / `dashboard_already_running` | 먼저 기존 실행 상태를 확인하세요. PID 파일만 지워 중복 실행하지 않습니다. |
| `unexpected_process` | 기록된 번호가 다른 프로그램을 가리킵니다. 강제로 종료하지 말고 실행 상태를 확인하세요. |

포트를 바꾸려면 다음처럼 실행합니다. 수신기 포트를 바꾸면 Burp 확장의 전송 주소도 바꿔야 합니다.

```powershell
scripts\start_gateway.ps1 -ReceiverPort 8875 -DashboardPort 8876
```

대시보드는 `http://127.0.0.1:8876/`에서 엽니다. 확장 주소 변경은 [Burp 수집기](MONTOYA_COLLECTOR.md)를 참고하세요.
PowerShell이 스크립트 실행을 막으면 조직의 실행 정책을 유지하세요. 정책을 바꾸는 대신 [수신기](MONTOYA_COLLECTOR.md)와 [대시보드](USAGE.md)를 명령어로 각각 실행할 수 있습니다.

## 결과 폴더와 보안

- 결과는 `out\` 아래의 상대 경로만 허용합니다. `-Output out\receiver -Project receiver_alias`로 지정할 수 있습니다.
- 전체 경로, `..`로 상위 폴더 이동, `local_only`·`raw`·`raw_vault` 폴더는 허용하지 않습니다. 실제 고객명 대신 별칭을 쓰세요.
- 수신기와 대시보드는 `127.0.0.1`에서만 연결합니다. 외부 접속을 허용하지 마세요.
- 실행 기록에는 포트·별칭·프로세스 번호·오류 종류와 `raw_data_included=false`만 남깁니다. 원본 내용은 표시하지 않습니다.
- 원본 Burp 자료, 쿠키·인증 헤더·토큰·세션 값, 개인정보, 실제 대상 주소, HMAC 비밀키·CSRF 값과 내부 오류 상세는 공유하지 않습니다.
- `out\.launcher\`의 PID·로그 파일은 Git에서 제외됩니다. 설정 파일과 함께 저장소에 올리지 마세요.
- 자동 검사가 모든 민감정보를 찾는 것은 아닙니다. 검증 후에도 공유할 파일을 직접 확인하세요.
