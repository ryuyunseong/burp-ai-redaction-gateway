# 지원서용 프로젝트 요약

- Burp Suite 보안 점검 기록을 AI 분석에 활용할 때 쿠키, 토큰, 개인정보가 함께 노출될 수 있는 문제를 정의했습니다.
- 모든 처리를 로컬에서 수행하고 인증정보(credential), 실제 대상 식별자,
  개인정보(PII)와 raw HTTP marker가 외부 산출물에 남지 않도록 구현했습니다.
- 민감정보가 하나라도 남으면 결과를 만들지 않는 fail-closed 검증으로 안전 경계를 고정했습니다.
- 검증을 통과한 경우에도 AI 전달 후보를 `analysis_packet.json` 등 파일 4개로 제한했습니다.
- synthetic fixture와 자동 테스트로 redaction, verify, viewer 및 차단 동작을 반복 검증했습니다.
- 실제 transport/listener runtime, replay, active scan과 자동 AI 전송은 구현 범위에서 제외했습니다.
