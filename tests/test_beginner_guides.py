from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
import subprocess
import sys
import tempfile
import unittest
from http.cookies import SimpleCookie
from pathlib import Path

from burp_ai_redaction_gateway.dashboard import MAX_UPLOAD_BYTES, SAFE_PREVIEW_FILES, write_dashboard_action_audit_event
from burp_ai_redaction_gateway.mcp_server import tool_definitions
from burp_ai_redaction_gateway.scanner import assert_no_sensitive_text
from burp_ai_redaction_gateway.viewer import SAFE_FILE_ALLOWLIST
from burp_ai_redaction_gateway.workflow import MAX_INPUT_BYTES


ROOT = Path(__file__).resolve().parents[1]
GUIDES = ("USAGE.md", "MONTOYA_COLLECTOR.md", "READ_ONLY_MCP.md")


def guide(name: str) -> str:
    return (ROOT / "docs" / name).read_text(encoding="utf-8")


def process_command(name: str) -> list[str]:
    line = next(line for line in guide(name).splitlines() if line.startswith("python -m burp_ai_redaction_gateway process "))
    return shlex.split(line)


def codex_server_command(root: Path) -> tuple[list[str], dict[str, str]]:
    line = next(line for line in guide("READ_ONLY_MCP.md").splitlines() if line.startswith("codex mcp add "))
    args = shlex.split(line)
    env = dict(os.environ)
    for index, argument in enumerate(args):
        if argument == "--env":
            key, value = args[index + 1].split("=", 1)
            env[key] = value.replace("$repo", str(ROOT))
    command = [argument.replace("$repo", str(ROOT)) for argument in args[args.index("--") + 1:]]
    command[0] = sys.executable
    command[command.index("--root") + 1] = str(root)
    return command, env


class BeginnerGuideTests(unittest.TestCase):
    def test_current_usage_documents_keep_plain_korean_and_local_links(self) -> None:
        documents = [ROOT / "README.md"] + [ROOT / "docs" / name for name in (
            *GUIDES, "BURP_MANUAL_CHECKS.md", "OUTPUT_BUNDLE_GUIDE_KO_v0.6.md",
            "PORTFOLIO_SUMMARY_KO.md", "REFERENCE.md", "LOCALHOST_RECEIVER.md",
            "SECURITY_MODEL.md", "WINDOWS_LAUNCHER_GUIDE.md", "AUDIT_OPERATIONS_GUIDE.md",
        )]
        for path in documents:
            with self.subTest(document=path.name):
                text = path.read_text(encoding="utf-8")
                self.assertNotIn("**", text)
                self.assertNotIn("<strong", text)
                self.assertNotRegex(text, r"[\ufeff\ufffd\u200b]|\?\?")
                self.assertNotRegex(text, r"[\u3040-\u30ff\u4e00-\u9fff]")
                for heading in re.findall(r"^#{1,3} (.+)$", text, re.MULTILINE):
                    self.assertRegex(heading, r"[가-힣]|Burp AI Redaction Gateway")
                for target in re.findall(r"!?\[[^\]]*\]\(([^)]+)\)", text):
                    if "://" not in target and not target.startswith("#"):
                        self.assertTrue((path.parent / target.split("#")[0]).is_file(), target)
                self.assertNotRegex(text, r"(?<![A-Za-z])[A-Za-z]:[\\/]|/home/|/Users/")

    def test_receiver_steps_stop_on_verification_failure_and_match_buttons(self) -> None:
        text = guide("LOCALHOST_RECEIVER.md")
        self.assertLess(text.index("Ctrl+C"), text.index("verify --input out/receiver"))
        self.assertLess(text.index("verify --input out/receiver"), text.index("검증이 실패하면 여기서 멈추고"))
        self.assertLess(text.index("검증이 실패하면"), text.index("dashboard --host"))
        dashboard = (ROOT / "burp_ai_redaction_gateway" / "dashboard.py").read_text(encoding="utf-8")
        for label in ("결과 파일 확인", "보고서 다시 만들기", "파일 4개 내보내기"):
            self.assertIn(label, text)
            self.assertIn(label, dashboard)
        for phrase in ("127.0.0.1에서만", "실제 고객명이나 서비스명이 아닌 별칭", "확인이 필요한 후보", "결과 폴더 전체를 AI에 올리지", "검사를 끄거나 외부 접속을 허용하지"):
            self.assertIn(phrase, text)
        self.assertNotIn("단계별 명령은", guide("USAGE.md"))

    def test_documented_audit_commands_preserve_source_and_verify_archives(self) -> None:
        text = guide("AUDIT_OPERATIONS_GUIDE.md")
        commands = [shlex.split(line) for line in text.splitlines() if line.startswith("python -m burp_ai_redaction_gateway ")]
        self.assertEqual([command[3] for command in commands], [
            "review-audit", "audit-retention", "audit-retention", "review-audit",
            "audit-hmac", "audit-hmac-verify", "audit-compress", "audit-compress-verify",
            "audit-compressed-hmac", "audit-compressed-hmac-verify",
        ])
        for phrase in ("검사에 실패하면 다음 단계로 넘어가지", "원본은 바꾸지 않습니다", "암호화가 아닙니다", "같은 키", "실패를 숨기려고", "검사를 대신하지", "AI 전달 자료가 아니며", "Git에 올리지"):
            self.assertIn(phrase, text)
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            root = base / "out"
            write_dashboard_action_audit_event(root, action_name="export", output_id="demo", result_status="ok")
            source = root / ".audit" / "mcp_audit.jsonl"
            original_hash = hashlib.sha256(source.read_bytes()).hexdigest()
            test_key = "synthetic-audit-key-for-documentation-test"
            env = dict(os.environ, PYTHONUTF8="1", PYTHONPATH=str(ROOT), BURP_AI_AUDIT_HMAC_KEY=test_key)
            for index, command in enumerate(commands):
                with self.subTest(command=command[3], step=index):
                    command[0] = sys.executable
                    result = subprocess.run(command, cwd=base, env=env, capture_output=True, encoding="utf-8", timeout=30)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertNotIn(test_key, result.stdout + result.stderr)
                    assert_no_sensitive_text(result.stdout + result.stderr)
                    self.assertEqual(hashlib.sha256(source.read_bytes()).hexdigest(), original_hash)
                    if index == 1:
                        self.assertFalse((root / ".audit" / "mcp_audit.retained.jsonl").exists())
            self.assertTrue((root / ".audit" / "mcp_audit.retained.jsonl.gz.manifest.json").is_file())

    def test_project_summary_is_short_and_preserves_security_limits(self) -> None:
        text = guide("PORTFOLIO_SUMMARY_KO.md")
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn("](docs/PORTFOLIO_SUMMARY_KO.md)", readme)
        self.assertNotIn("**", text)
        self.assertLessEqual(len(text.splitlines()), 30)
        self.assertEqual(re.findall(r"^## (.+)$", text, re.MULTILINE), ["만든 이유", "주요 기능", "보안상 한계"])
        for phrase in (
            "내 컴퓨터에서", "쿠키·로그인 토큰·개인정보", "XML·JSON·HAR",
            "AI 전달 후보 파일 4개", "웹 업로드(XML·JSON)", "선택 기능", "검증된 결과",
            "검증에 실패하면 처리를 중단", "전달 후보 폴더를 만들지",
            "자동 검사가 모든 민감정보를 찾는 것은 아닙니다", "공유 전 직접 읽고",
            "원본이나 결과 폴더 전체를 AI에 올리지", "확정 취약점이 아닌 검토 후보",
            "실제 재현·영향과 공유 여부는 사람이 판단", "원문 조회, 요청 재전송, 능동 스캔, 자동 AI 전송은 제공하지",
            "MCP도 Burp를 직접 조작하지", "공개 예제와 테스트는 가상 자료", "실제 서비스의 취약점 재현 결과가 아닙니다",
        ):
            self.assertIn(phrase, text)
        for marker in ("\ufeff", "\ufffd", "\u200b", "??"):
            self.assertNotIn(marker, text)
        for target in re.findall(r"\]\(([^)]+)\)", text):
            self.assertTrue((ROOT / "docs" / target.split("#")[0]).is_file(), target)
        assert_no_sensitive_text(text)

    def test_output_bundle_guide_matches_files_and_preserves_sharing_checks(self) -> None:
        text = guide("OUTPUT_BUNDLE_GUIDE_KO_v0.6.md")
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn("](docs/OUTPUT_BUNDLE_GUIDE_KO_v0.6.md)", readme)
        self.assertNotIn("**", text)
        self.assertLessEqual(len(text.splitlines()), 60)
        rows = re.findall(r"^\| `([^`]+)` \| (.+) \|$", text, re.MULTILINE)
        self.assertEqual(len(rows), 4)
        for allowed in (SAFE_FILE_ALLOWLIST, SAFE_PREVIEW_FILES):
            self.assertEqual({name for name, _ in rows}, set(allowed))
        for _, purpose in rows:
            self.assertRegex(purpose, r"[가-힣]")
        self.assertEqual(re.findall(r"^(\d+)\. ", text, re.MULTILINE), ["1", "2", "3", "4"])
        dashboard = (ROOT / "burp_ai_redaction_gateway" / "dashboard.py").read_text(encoding="utf-8")
        for label in ("결과 파일 확인", "파일 4개 내보내기", "파일 상태"):
            self.assertIn(label, text)
            self.assertIn(label, dashboard)
        for phrase in (
            "검증에 실패한 결과는 사용하지 않습니다", "검사를 끄거나 오류를 무시하지",
            "자동 검사가 모든 민감정보를 찾는 것은 아닙니다", "원본 요청·응답",
            "쿠키·인증 헤더·토큰·세션 값", "개인정보", "실제 URL·도메인·IP", "전체 로컬 경로",
            "결과 폴더 전체를 AI에 올리지", "확정 취약점이 아닌 검토 후보", "위험도는 초안",
            "최종 심각도·CVSS", "직접 판단", "요약에서 생략한 데이터도 민감정보 검사를",
            "코드 수정·요청 재전송·능동 스캔·외부 전송을 실행하라고 요청하지",
            "자동 AI 전송은 제공하지 않습니다", "`ai_candidates/`", "민감정보를 제거한 분석 데이터",
            "크기·수정 시각·해시만으로 공유해도 된다고 판단하지",
        ):
            self.assertIn(phrase, text)
        for marker in ("\ufeff", "\ufffd", "\u200b", "??"):
            self.assertNotIn(marker, text)
        for target in re.findall(r"\]\(([^)]+)\)", text):
            self.assertTrue((ROOT / "docs" / target.split("#")[0]).is_file(), target)
        assert_no_sensitive_text(text)

    def test_burp_manual_guide_covers_all_published_sample_candidates(self) -> None:
        text = guide("BURP_MANUAL_CHECKS.md")
        report = guide("examples/report_draft.md")
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn("](docs/BURP_MANUAL_CHECKS.md)", readme)
        self.assertLessEqual(len(text.splitlines()), 140)
        groups = {
            "접근 권한": {"FC-0004", "FC-0019"},
            "민감정보 포함": {"FC-0005", "FC-0008", "FC-0015", "FC-0020"},
            "쿠키 보호 설정": {"FC-0002", "FC-0010"},
            "캐시 설정": {"FC-0003", "FC-0007", "FC-0014", "FC-0018"},
            "CORS 설정": {"FC-0012"},
            "오류 메시지": {"FC-0016"},
            "보안 헤더": {"FC-0001", "FC-0006", "FC-0009", "FC-0011", "FC-0013", "FC-0017", "FC-0021", "FC-0022"},
        }
        report_candidates = dict(re.findall(r"^## 검토 후보 (FC-\d{4}): (.+)$", report, re.MULTILINE))
        documented = set(re.findall(r"\bFC-\d{4}\b", text))
        self.assertEqual(len(report_candidates), 22)
        self.assertEqual(documented, set(report_candidates))
        for label, ids in groups.items():
            with self.subTest(label=label):
                row = next(line for line in text.splitlines() if line.startswith(f"| {label} "))
                self.assertIn(f"{len(ids)}건", row)
                self.assertEqual(set(re.findall(r"FC-\d{4}", row)), ids)
                self.assertEqual(len({report_candidates[item] for item in ids}), 1)
        for number, title in enumerate(("접근 권한", "민감정보 포함", "쿠키 보호 설정", "캐시 설정", "CORS", "오류 메시지", "보안 헤더"), start=1):
            self.assertIn(f"## {number}. {title}", text)
        self.assertNotIn("**", text)
        sections = re.findall(r"^## [1-7]\. [^\n]+\n(.*?)(?=^## |\Z)", text, re.MULTILINE | re.DOTALL)
        self.assertEqual(len(sections), len(groups))
        for section in sections:
            steps = re.findall(r"^(\d+)\. ", section, re.MULTILINE)
            self.assertIn(len(steps), (2, 3))
            self.assertEqual(steps, [str(number) for number in range(1, len(steps) + 1)])
            self.assertEqual(len(re.findall(r"^- 정상: .+$", section, re.MULTILINE)), 1)
            self.assertEqual(len(re.findall(r"^- (?:문제 의심|추가 검토): .+$", section, re.MULTILINE)), 1)

    def test_burp_manual_guide_preserves_manual_review_and_security_limits(self) -> None:
        text = guide("BURP_MANUAL_CHECKS.md")
        for phrase in (
            "검토 후보는 확정 취약점이 아닙니다", "가상 기록이며 접속할 서버가 아닙니다",
            "허가된 실습 환경", "계정 권한을 바꾸지 않습니다", "읽기 전용 조회",
            "보안 검사·브라우저 보호를 끄거나", "자동 스캔·번호 대입·대량 조회·수정·삭제",
            "로그인 정보와 조회 대상을 동시에 바꾸지", "쿠키를 서로 교환하지",
            "no-store", "private", "no-cache", "캐시 때문인지 접근 권한 누락 때문인지",
            "뒤로가기로 보이는 과거 화면", "OPTIONS", "인증용 쿠키·헤더를 임의로 붙이지",
            'credentials: "include"', "브라우저는 읽기를 차단", "Burp에서 응답이 보이는 것만으로는 부족",
            "미확인", "디버그 모드를 켜거나", "500", "200 OK", "401", "304",
            "실제 값·쿠키·토큰·원문", "위 절차는 사람이 별도로 수행",
            "계정 권한도 그대로 적용", "대상 주소와 메서드는 유지", "기존 쿠키 제한은 유지",
            "쿠키·토큰을 페이지에 직접 붙여 넣지", "캐시를 지우거나 강제로 우회하지",
            "세 가지가 모두 있어야 정상인 것은 아닙니다", "공개 자료의 `*`도 그 자체로 취약점은 아닙니다",
            "헤더 누락만으로 공격 성공이나 피해를 단정하지",
        ):
            self.assertIn(phrase, text)
        for marker in ("\ufeff", "\ufffd", "\u200b", "??"):
            self.assertNotIn(marker, text)
        for target in re.findall(r"\]\(([^)]+)\)", text):
            if "://" not in target:
                self.assertTrue((ROOT / "docs" / target.split("#")[0]).is_file(), target)
        prose = re.sub(r"\]\([^)]+\)", "]", text)
        assert_no_sensitive_text(prose)
        self.assertNotRegex(prose, r"[A-Za-z]:[\\/]|/home/|/Users/")
        self.assertNotRegex(text, r"[\u3040-\u30ff\u4e00-\u9fff]")

    def test_burp_manual_guide_cookie_observations_match_sample_attributes(self) -> None:
        text = guide("BURP_MANUAL_CHECKS.md")
        sample = json.loads((ROOT / "samples" / "synthetic_burp_history.json").read_text(encoding="utf-8"))
        observed = {}
        for event in sample["events"]:
            for name, value in event["response"]["headers"].items():
                if name.lower() != "set-cookie":
                    continue
                for header in value if isinstance(value, list) else [value]:
                    cookies = SimpleCookie()
                    cookies.load(header)
                    for cookie_name, cookie in cookies.items():
                        observed[cookie_name] = (bool(cookie["secure"]), bool(cookie["httponly"]), cookie["samesite"])
        self.assertEqual(observed, {"session": (False, True, "Lax"), "sid": (False, False, "None")})
        for candidate_id, name in (("FC-0002", "session"), ("FC-0010", "sid")):
            secure, httponly, samesite = observed[name]
            self.assertIn(f"| {candidate_id} / {name} | {'있음' if secure else '없음'} | {'있음' if httponly else '없음'} | {samesite} |", text)
        self.assertIn("`SameSite` 속성 누락과 `SameSite=None`인데 `Secure`가 없는 경우를 구분", text)
        self.assertIn("이전에 만든 결과는 다시 처리", text)

    def test_guides_keep_short_korean_steps_and_working_links(self) -> None:
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        for name in GUIDES:
            with self.subTest(name=name):
                text = guide(name)
                self.assertIn(f"docs/{name}", readme)
                self.assertLess(len(text.splitlines()), 105)
                self.assertNotIn("**", text)
                self.assertRegex(text, r"## 1\. [가-힣]")
                self.assertRegex(text, r"## [23]\. [가-힣A-Z]")
                for marker in ("\ufeff", "\ufffd", "\u200b", "??"):
                    self.assertNotIn(marker, text)
                for target in re.findall(r"\]\(([^)]+)\)", text):
                    if "://" not in target and not target.startswith("#"):
                        self.assertTrue((ROOT / "docs" / target.split("#")[0]).is_file(), target)
                self.assertEqual(text.count("<details>"), 1)
                self.assertEqual(text.count("</details>"), 1)

    def test_usage_buttons_and_safety_limits_match_implementation(self) -> None:
        text = guide("USAGE.md")
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertNotIn("**", readme)
        self.assertIn("10 MiB(약 10.5 MB)", readme)
        for mode, limit in (("웹 업로드", MAX_UPLOAD_BYTES), ("명령어 실행", MAX_INPUT_BYTES)):
            row = next(line for line in text.splitlines() if line.startswith(f"| {mode} |"))
            self.assertIn(f"{limit // (1024 * 1024)} MiB(약 {limit / 1_000_000:.1f} MB)", row)
        dashboard = (ROOT / "burp_ai_redaction_gateway" / "dashboard.py").read_text(encoding="utf-8")
        for label in ("파일 업로드", "민감정보 제거 시작", "결과 파일 확인", "파일 4개 내보내기"):
            self.assertIn(label, text)
            self.assertIn(label, dashboard)
        for phrase in ("10 MiB", "16 MiB", "최대 64자", "local_only/", "검사를 끄거나", "확정 취약점이 아니며", "결과 폴더 전체를 AI에 올리지"):
            self.assertIn(phrase, text)

    def test_collector_build_and_scope_steps_match_source(self) -> None:
        text = guide("MONTOYA_COLLECTOR.md")
        self.assertLess(text.index("Push-Location"), text.index(".\\gradlew.bat clean build"))
        self.assertLess(text.index(".\\gradlew.bat clean build"), text.index("Pop-Location"))
        build = (ROOT / "extensions" / "montoya-collector" / "build.gradle").read_text(encoding="utf-8")
        version = re.search(r"^version = '([^']+)'", build, re.MULTILINE).group(1)
        base_name = re.search(r"archiveBaseName = '([^']+)'", build).group(1)
        self.assertIn(f"build/libs/{base_name}-{version}.jar", text)
        self.assertIn("JDK 21", text)
        self.assertIn("java-version: '21'", (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8"))
        source_dir = ROOT / "extensions" / "montoya-collector" / "src" / "main" / "java" / "com" / "ryuyunseong" / "burpai" / "redactiongateway"
        extension = (source_dir / "BurpAiRedactionGatewayExtension.java").read_text(encoding="utf-8")
        menu_label = re.search(r'new JMenuItem\("([^"]+)"\)', extension).group(1)
        self.assertIn(menu_label, text)
        extension_name = re.search(r'api.extension\(\).setName\("([^"\n]+)"\)', extension).group(1)
        self.assertIn(f"Extensions → {extension_name} →", text)
        self.assertIn("‘결과 보기’ → ‘결과 파일 확인’", text)
        self.assertIn("별도 폴더에 복사", text)
        self.assertIn("examples/collector_run.md", text)
        example = (ROOT / "docs" / "examples" / "collector_run.md").read_text(encoding="utf-8")
        self.assertIn("별도 임시 프로젝트", example)
        self.assertIn("items_sent=2", example)
        self.assertIn("skipped=2", example)
        for image in ("collector-handoff.jpg", "collector-export.png"):
            self.assertIn(f"../images/{image}", example)
            self.assertGreater((ROOT / "docs" / "images" / image).stat().st_size, 1000)
        self.assertNotIn("**", example)
        self.assertNotIn("\ufeff", example)
        self.assertNotIn("\ufffd", example)
        self.assertLess(text.index("선택한 행만 보내는 메뉴가 아닙니다"), text.index(menu_label))
        self.assertIn("Output", text)
        self.assertIn("items_sent", text)
        self.assertLess(text.index("Ctrl+C"), text.index("verify --input out/receiver"))
        self.assertLess(text.index("verify --input out/receiver"), text.index("검증이 실패하면 여기서 멈추고"))
        self.assertLess(text.index("검증이 실패하면 여기서 멈추고"), text.index("dashboard --host"))
        for phrase in ("선택한 행만 보내는 메뉴가 아닙니다", "허가받은 대상만", "외부 주소로 전송하지 못하게 제한", "수신기에서 민감정보를 제거", "원본과 대상 호스트 값은 남기지 않습니다", "보고서 다시 만들기"):
            self.assertIn(phrase, text)

    def test_mcp_setup_and_tools_match_documented_sample(self) -> None:
        text = guide("READ_ONLY_MCP.md")
        args = process_command("READ_ONLY_MCP.md")
        self.assertEqual(args[args.index("--output") + 1], "out/codex_mcp_sample/demo")
        self.assertEqual(args[args.index("--project") + 1], "demo")
        for phrase in ("STDIO", "mcp --root out/codex_mcp_sample", "작업 폴더", "project`에 `demo", "22개", "반환할 내용도 다시 검사", "상위 폴더로 벗어나는 경로는 거절", "개인 경로가 든 설정은 저장소에 올리지", "연결 도구의 공유·외부 전송 설정"):
            self.assertIn(phrase, text)
        for tool in tool_definitions():
            self.assertIn(f"`{tool['name']}`", text)
            self.assertTrue(tool["annotations"]["readOnlyHint"])

    def test_codex_mcp_registration_uses_sample_only_root_and_explicit_policy(self) -> None:
        text = guide("READ_ONLY_MCP.md")
        line = next(line for line in text.splitlines() if line.startswith("codex mcp add "))
        self.assertEqual(shlex.split(line), [
            "codex", "mcp", "add", "burp_sample", "--env", "PYTHONPATH=$repo", "--env", "PYTHONUTF8=1",
            "--", "$python", "-m", "burp_ai_redaction_gateway", "mcp",
            "--root", "$repo/out/codex_mcp_sample", "--policy", "$repo/policy.json",
        ])
        for phrase in ("print(sys.executable)", "codex mcp list", "/mcp", "새 대화", "가상 샘플 폴더만", "기존 승인·보안 설정", "도구 호출 기록"):
            self.assertIn(phrase, text)

    def test_codex_app_setup_matches_server_arguments_and_requires_restart(self) -> None:
        text = guide("READ_ONLY_MCP.md")
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        setup_line = next(line for line in readme.splitlines() if line.startswith("1. [MCP 설정 안내]"))
        self.assertIn("](docs/READ_ONLY_MCP.md)", setup_line)
        self.assertIn("FC-0010 실제 조회 예시", setup_line)
        app_settings = dict(re.findall(r"^\| (이름|실행 프로그램|인수|환경변수) \| (.+) \|$", text, re.MULTILINE))
        cli_line = next(line for line in text.splitlines() if line.startswith("codex mcp add "))
        cli_args = shlex.split(cli_line)
        app_args = shlex.split(app_settings["인수"].strip("`").replace("<저장소폴더>", "$repo"))
        self.assertEqual(app_args, cli_args[cli_args.index("--") + 2:])
        self.assertEqual(app_settings["이름"], "`burp_sample`")
        self.assertEqual(app_settings["실행 프로그램"], "위에서 확인한 Python 경로")
        self.assertEqual(re.findall(r"`([^`]+)`", app_settings["환경변수"]), ["PYTHONPATH=<저장소폴더>", "PYTHONUTF8=1"])
        self.assertIn("설정(Settings) → MCP servers → Add server", text)
        self.assertIn("STDIO(표준 입출력)", text)
        self.assertLess(text.index("이미 `burp_sample`"), text.index("## 3."))
        for document in (text, readme):
            self.assertIn("MCP servers → burp_sample → Restart(다시 시작)", document)
            self.assertIn("/mcp", document)
            self.assertIn("실제 MCP 도구로 읽어줘", document)
            self.assertIn("조회할 때 CLI나 별도 서버 터미널", document)
            self.assertIn("검토 후보", document)
        self.assertIn("Codex 앱 대화에서 세 도구를 직접 호출", text)
        self.assertIn("세 응답의 `raw_data_included`는 `false`", text)
        self.assertIn("점검 후보 목록, FC-0010의 상세 근거와 보고서 초안을 실제 MCP 도구로 읽어줘", text)
        self.assertIn("세 도구 모두 `project`에 `demo`", text)
        self.assertIn("`get_finding`의 `finding_id`는 `FC-0010`", text)
        for option in ("dangerously-bypass", "danger-full-access", "default_tools_approval_mode", "--ignore-rules"):
            self.assertNotIn(option, text)
            self.assertNotIn(option, readme)

    def test_codex_mcp_documented_server_reads_sample_from_another_working_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            root = base / "샘플 작업"
            project = root / "demo"
            outside = base / "client"
            outside.mkdir()
            process = process_command("READ_ONLY_MCP.md")
            process[0] = sys.executable
            process[process.index("--output") + 1] = str(project)
            generated = subprocess.run(process, cwd=ROOT, env=dict(os.environ, PYTHONUTF8="1"), capture_output=True, encoding="utf-8", timeout=30)
            self.assertEqual(generated.returncode, 0, generated.stdout + generated.stderr)
            before = {str(path.relative_to(project)): hashlib.sha256(path.read_bytes()).hexdigest() for path in project.rglob("*") if path.is_file()}
            command, env = codex_server_command(root)
            messages = [
                {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "setup-regression", "version": "1"}}},
                {"jsonrpc": "2.0", "method": "notifications/initialized"},
                {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "list_findings", "arguments": {"project": "demo"}}},
                {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "get_report_draft", "arguments": {"project": "demo"}}},
                {"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "get_finding", "arguments": {"project": "demo", "finding_id": "FC-0010"}}},
            ]
            for request_id, name in enumerate(("../outside", "demo/local_only"), start=5):
                messages.append({"jsonrpc": "2.0", "id": request_id, "method": "tools/call", "params": {"name": "get_report_draft", "arguments": {"project": name}}})
            result = subprocess.run(command, cwd=outside, env=env, input="\n".join(json.dumps(message) for message in messages) + "\n", capture_output=True, encoding="utf-8", timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr)
            responses = {message["id"]: message for message in map(json.loads, result.stdout.splitlines())}
            findings = responses[2]["result"]
            self.assertFalse(findings["isError"])
            self.assertEqual(findings["structuredContent"]["candidate_count"], 22)
            self.assertTrue(all(item["manual_verification_required"] for item in findings["structuredContent"]["findings"]))
            report = responses[3]["result"]
            self.assertFalse(report["isError"])
            self.assertEqual(report["structuredContent"]["report_draft"], (project / "report_draft.md").read_text(encoding="utf-8"))
            self.assertIn("검토 후보", report["structuredContent"]["report_draft"])
            report_title = report["structuredContent"]["report_draft"].splitlines()[0].removeprefix("# ")
            self.assertIn(f"| `get_report_draft` | {report_title} |", guide("READ_ONLY_MCP.md"))
            finding = responses[4]["result"]
            self.assertFalse(finding["isError"])
            candidate = finding["structuredContent"]["finding"]
            self.assertEqual(candidate["finding_id"], "FC-0010")
            self.assertTrue(candidate["manual_verification_required"])
            self.assertEqual(candidate["rationale"], [
                "Set-Cookie for sid is missing: Secure, HttpOnly.",
                "Set-Cookie for sid uses SameSite=None without Secure.",
            ])
            cookie_section = (
                report["structuredContent"]["report_draft"]
                .split("\n## 검토 후보 FC-0010:", 1)[1]
                .split("\n## 검토 후보 ", 1)[0]
            )
            for observation in (
                "쿠키 sid에 없는 보호 속성: Secure, HttpOnly.",
                "쿠키 sid는 SameSite=None이지만 Secure가 없습니다.",
            ):
                self.assertIn(observation, cookie_section)
                self.assertIn(observation, guide("READ_ONLY_MCP.md"))
            self.assertNotIn("없는 보호 속성: Secure, HttpOnly, SameSite", cookie_section)
            for request_id, reason in ((5, "path_traversal_forbidden"), (6, "forbidden_directory")):
                blocked = responses[request_id]["result"]
                self.assertTrue(blocked["isError"])
                self.assertEqual(blocked["structuredContent"], {"error_type": reason, "raw_data_included": False})
            for response in responses.values():
                if "structuredContent" in response["result"]:
                    self.assertIs(response["result"]["structuredContent"]["raw_data_included"], False)
                assert_no_sensitive_text(json.dumps(response))
            after = {str(path.relative_to(project)): hashlib.sha256(path.read_bytes()).hexdigest() for path in project.rglob("*") if path.is_file()}
            self.assertEqual(before, after)

    def test_documented_process_commands_generate_verified_four_file_bundle(self) -> None:
        sample = ROOT / "samples" / "synthetic_burp_history.json"
        original_hash = hashlib.sha256(sample.read_bytes()).hexdigest()
        for name in ("USAGE.md", "READ_ONLY_MCP.md"):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                args = process_command(name)
                output = Path(temporary) / "result"
                args[0] = sys.executable
                args[args.index("--input") + 1] = str(ROOT / args[args.index("--input") + 1])
                args[args.index("--output") + 1] = str(output)
                env = dict(os.environ, PYTHONUTF8="1")
                result = subprocess.run(args, cwd=ROOT, env=env, capture_output=True, encoding="utf-8", timeout=30)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                bundle = output / "ai_candidates"
                self.assertEqual({path.name for path in bundle.iterdir()}, {
                    "analysis_packet.json", "chatgpt_prompt.md", "codex_task_prompt.md", "report_draft.md",
                })
                packet = json.loads((bundle / "analysis_packet.json").read_text(encoding="utf-8"))
                self.assertEqual(packet["candidate_count"], 22)
                self.assertIs(packet["raw_data_included"], False)
                for path in bundle.iterdir():
                    assert_no_sensitive_text(path.read_text(encoding="utf-8"))
        self.assertEqual(hashlib.sha256(sample.read_bytes()).hexdigest(), original_hash)
