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
from pathlib import Path

from burp_ai_redaction_gateway.mcp_server import tool_definitions
from burp_ai_redaction_gateway.scanner import assert_no_sensitive_text


ROOT = Path(__file__).resolve().parents[1]
GUIDES = ("USAGE.md", "MONTOYA_COLLECTOR.md", "READ_ONLY_MCP.md")


def guide(name: str) -> str:
    return (ROOT / "docs" / name).read_text(encoding="utf-8")


def process_command(name: str) -> list[str]:
    line = next(line for line in guide(name).splitlines() if line.startswith("python -m burp_ai_redaction_gateway process "))
    return shlex.split(line)


class BeginnerGuideTests(unittest.TestCase):
    def test_guides_keep_short_korean_steps_and_working_links(self) -> None:
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        for name in GUIDES:
            with self.subTest(name=name):
                text = guide(name)
                self.assertIn(f"docs/{name}", readme)
                self.assertLess(len(text.splitlines()), 105)
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
        for phrase in ("선택한 행만 보내는 메뉴가 아닙니다", "허가받은 대상만", "외부 주소로 전송하지 못하게 제한", "수신기에서 민감정보를 제거", "원본과 대상 호스트 값은 남기지 않습니다", "보고서 다시 만들기"):
            self.assertIn(phrase, text)

    def test_mcp_setup_and_tools_match_documented_sample(self) -> None:
        text = guide("READ_ONLY_MCP.md")
        args = process_command("READ_ONLY_MCP.md")
        self.assertEqual(args[args.index("--output") + 1], "out/mcp_demo")
        self.assertEqual(args[args.index("--project") + 1], "mcp_demo")
        for phrase in ("stdio", "mcp --root out", "작업 폴더", "project`에 `mcp_demo", "22개", "반환할 내용도 다시 검사", "상위 폴더로 벗어나는 경로는 거절", "개인 경로가 든 설정은 저장소에 올리지", "연결 도구의 공유·외부 전송 설정"):
            self.assertIn(phrase, text)
        for tool in tool_definitions():
            self.assertIn(f"`{tool['name']}`", text)
            self.assertTrue(tool["annotations"]["readOnlyHint"])

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
