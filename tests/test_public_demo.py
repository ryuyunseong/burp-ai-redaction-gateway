from __future__ import annotations

import json
import re
import struct
import tempfile
import unittest
from pathlib import Path

from burp_ai_redaction_gateway.policy import load_policy
from burp_ai_redaction_gateway.scanner import assert_no_sensitive_text
from burp_ai_redaction_gateway.workflow import process_export


ROOT = Path(__file__).resolve().parents[1]


class PublicDemoTests(unittest.TestCase):
    def test_reference_starts_with_current_guides_and_folds_historical_records(self) -> None:
        reference = (ROOT / "docs" / "REFERENCE.md").read_text(encoding="utf-8")
        current, history = reference.split("<details>", 1)
        self.assertLess(len(current.splitlines()), 60)
        self.assertIn("README", current)
        self.assertIn("기본 파일 처리에는 대시보드만", current)
        for name in ("USAGE.md", "MONTOYA_COLLECTOR.md", "READ_ONLY_MCP.md"):
            self.assertIn(f"]({name})", current)
        for target in re.findall(r"\]\(([^)]+)\)", current):
            self.assertTrue((ROOT / "docs" / target).is_file(), target)
        self.assertNotIn("208개 통과", current)
        self.assertIn("이전 버전 기록 (일반 사용에는 필요하지 않습니다)", history)
        self.assertIn("208개 통과", history)
        self.assertIn("main@4001258da4fba881b3e7e9ef3936e993f05c4f81", history)
        self.assertEqual(reference.count("<details>"), reference.count("</details>"))

    def test_published_prompts_match_current_synthetic_output(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            result = process_export(
                ROOT / "samples" / "synthetic_burp_history.json",
                Path(temporary) / "demo",
                "demo",
                load_policy(),
            )
            for name in ("chatgpt_prompt.md", "codex_task_prompt.md"):
                with self.subTest(name=name):
                    published = (ROOT / "docs" / "examples" / name).read_text(encoding="utf-8")
                    generated = (result.export_dir / name).read_text(encoding="utf-8")
                    self.assertEqual(published, generated)
                    self.assertNotIn("```json", published)
                    self.assertLess(len(published.splitlines()), 350)
                    packet = json.loads((result.export_dir / "analysis_packet.json").read_text(encoding="utf-8"))
                    for candidate in packet["finding_candidates"]:
                        self.assertIn(f"### {candidate['finding_id']}:", published)
                        self.assertIn(candidate["affected_endpoint"], published)
                        for evidence_id in candidate["evidence_ids"]:
                            self.assertIn(evidence_id, published)
                    self.assertEqual(published.count("\n### FC-"), result.candidate_count)
                    self.assertIn(f"docs/examples/{name}", (ROOT / "README.md").read_text(encoding="utf-8"))
                    assert_no_sensitive_text(published)

    def test_published_report_matches_current_synthetic_output(self) -> None:
        published = (ROOT / "docs" / "examples" / "report_draft.md").read_text(encoding="utf-8")
        with tempfile.TemporaryDirectory() as temporary:
            result = process_export(
                ROOT / "samples" / "synthetic_burp_history.json",
                Path(temporary) / "demo",
                "demo",
                load_policy(),
            )
            generated = (result.export_dir / "report_draft.md").read_text(encoding="utf-8")
            self.assertEqual(published, generated)
            self.assertEqual(result.event_count, 10)
            self.assertEqual(result.candidate_count, 22)
            self.assertEqual(len(result.exported_files), 4)
        self.assertIn("취약점 확정 보고서가 아닙니다", published)
        self.assertEqual(published.count("\n## 검토 후보 FC-"), 22)
        assert_no_sensitive_text(published)

    def test_public_images_and_report_are_linked_from_readme(self) -> None:
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn("docs/examples/report_draft.md", readme)
        self.assertIn("공개 가상 샘플", readme)
        for filename in ("dashboard-upload.png", "dashboard-result.png", "dashboard-report.png"):
            with self.subTest(filename=filename):
                self.assertIn(f"docs/images/{filename}", readme)
                data = (ROOT / "docs" / "images" / filename).read_bytes()
                self.assertEqual(data[:8], b"\x89PNG\r\n\x1a\n")
                self.assertEqual(data[12:16], b"IHDR")
                width, height = struct.unpack(">II", data[16:24])
                self.assertGreaterEqual(width, 1000)
                self.assertGreaterEqual(height, 600)
