# Burp AI Redaction Gateway

**Burp 기록에서 민감정보를 가리고, AI 검토에 쓸 파일 4개를 만드는 로컬 도구입니다.**
쿠키·로그인 토큰·개인정보를 정리하고 보고서 초안을 만듭니다. 처리는 내 컴퓨터에서 진행하며, AI에 자동으로 보내지 않습니다.

## 시작하기

Python 3.12 이상이 필요합니다. 저장소를 내려받아 폴더를 연 뒤 실행하세요. 추가 패키지 설치는 필요 없습니다.

```powershell
python -m burp_ai_redaction_gateway dashboard --host 127.0.0.1 --port 8766 --root out
```

1. 브라우저에서 [대시보드](http://127.0.0.1:8766/)를 열고 **파일 업로드**를 누릅니다.
2. Burp XML 또는 JSON 파일을 선택하고 새 작업 이름을 입력합니다. 처음에는 `samples/synthetic_burp_history.json`으로 시험해 보세요.
3. **민감정보 제거 시작**을 누른 뒤 **결과 파일 확인**에서 내용을 읽고 필요한 파일만 내려받습니다.

웹 업로드는 최대 10 MiB입니다. 원본은 `local_only/`에 보관됩니다.
종료하려면 터미널에서 `Ctrl+C`를 누르세요.

## 결과 파일

| 파일 | 내용 |
| --- | --- |
| `report_draft.md` | 검토하고 수정할 보고서 초안 |
| `chatgpt_prompt.md` | ChatGPT에 검토를 요청할 때 쓸 프롬프트 |
| `codex_task_prompt.md` | Codex에 검토를 요청할 때 쓸 프롬프트 |
| `analysis_packet.json` | 요청 요약과 확인이 필요한 점검 항목 |

검증에 실패하면 처리를 중단합니다. 다만 자동 검사가 모든 민감정보를 찾는 것은 아닙니다.
**공유 전에 파일 내용을 직접 확인하고, 원본이나 결과 폴더 전체를 AI에 올리지 마세요.**
점검 항목과 위험도는 초안이며 실제 취약점 여부는 별도로 확인해야 합니다.

## 실행 화면

공개 가상 샘플을 로컬 대시보드에서 직접 업로드하고 처리한 화면입니다. 실제 고객 기록은 사용하지 않았습니다.

![파일을 선택하고 작업 이름을 입력한 화면](docs/images/dashboard-upload.png)

<details>
<summary>처리 결과 보기</summary>

![전달 후보 파일 4개가 만들어진 화면](docs/images/dashboard-result.png)

가상 요청 10개에서 검토 후보 22개가 나왔습니다. 후보 수는 확정 취약점 수가 아닙니다.

</details>

## 더 알아보기

- [사용 방법과 오류 해결](docs/USAGE.md): 내 Burp 기록 처리, 명령어 실행, 입력 형식
- [결과 파일 안내](docs/OUTPUT_BUNDLE_GUIDE_KO_v0.6.md): 공유 전 확인할 내용
- 선택 설정: [Burp 수집기](docs/MONTOYA_COLLECTOR.md) · [읽기 전용 MCP](docs/READ_ONLY_MCP.md)
- [프로젝트 요약](docs/PORTFOLIO_SUMMARY_KO.md) · [구성과 이전 버전 참고](docs/REFERENCE.md)

Burp 수집기와 MCP는 기본 파일 처리에 필요하지 않습니다.
MCP는 검증된 결과를 읽는 연결이며 Burp를 직접 조작하지 않습니다.
원본 HTTP 조회, 요청 재전송, 능동 스캔은 제공하지 않습니다.
