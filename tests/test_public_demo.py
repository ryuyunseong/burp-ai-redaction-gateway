from __future__ import annotations

import struct
import tempfile
import unittest
from pathlib import Path

from burp_ai_redaction_gateway.policy import load_policy
from burp_ai_redaction_gateway.scanner import assert_no_sensitive_text
from burp_ai_redaction_gateway.workflow import process_export


ROOT = Path(__file__).resolve().parents[1]


class PublicDemoTests(unittest.TestCase):
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
