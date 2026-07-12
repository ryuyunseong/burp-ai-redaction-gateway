from __future__ import annotations

import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from typing import Any

from burp_ai_redaction_gateway.cli import main
from burp_ai_redaction_gateway.viewer import (
    RedactedStaticViewerError,
    render_static_viewer_html,
    write_static_viewer_html,
)


ROOT = Path(__file__).resolve().parents[1]
FIXTURE_DIR = ROOT / "tests" / "fixtures"

VALID_FIXTURE = FIXTURE_DIR / "redacted_viewer_valid.json"
UNREDACTED_LIKE_FIXTURE = FIXTURE_DIR / "redacted_viewer_reject_unredacted_like.json"
CREDENTIAL_LIKE_FIXTURE = FIXTURE_DIR / "redacted_viewer_reject_credential_like.json"
UNSAFE_PATH_FIXTURE = FIXTURE_DIR / "redacted_viewer_reject_unsafe_path.json"


def load_valid_fixture() -> dict[str, Any]:
    return json.loads(VALID_FIXTURE.read_text(encoding="utf-8"))


class RedactedStaticViewerTests(unittest.TestCase):
    def assert_static_html_is_safe(self, html: str) -> None:
        forbidden_snippets = [
            "<script",
            "</script",
            "<form",
            "src=",
            "href=",
            "raw_request",
            "raw_response",
            "GET /",
            "POST /",
            "HTTP/1.",
            "Cookie",
            "Authorization",
            "Bearer ",
            "api_key",
            "password",
            "session_id",
            "token=",
        ]
        for snippet in forbidden_snippets:
            with self.subTest(snippet=snippet):
                self.assertNotIn(snippet, html)

    def test_valid_fixture_generates_static_html(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "viewer.html"
            result = write_static_viewer_html(VALID_FIXTURE, output)
            html = output.read_text(encoding="utf-8")

        self.assertEqual(result.artifact_id, "redacted-viewer-valid-001")
        self.assertEqual(result.finding_count, 1)
        self.assertEqual(result.section_count, 3)
        self.assertFalse(result.raw_data_included)
        self.assertTrue(result.manual_review_required)
        self.assertIn("redacted-viewer-valid-001", html)
        self.assertIn("민감정보 제거 결과 뷰어", html)
        self.assertIn("산출물 상태", html)
        self.assertIn("AI 검토 후보 파일 4개", html)
        self.assertIn("안전 요약", html)
        self.assertIn("후보 테이블", html)
        self.assertIn("합성 검토 후보", html)
        self.assertIn("analysis_packet.json", html)
        self.assert_static_html_is_safe(html)

    def test_all_displayed_values_are_html_escaped(self) -> None:
        artifact = load_valid_fixture()
        artifact["artifact_id"] = 'viewer-escape-<script>alert("x")</script>'
        artifact["findings"][0]["title"] = 'Escaped <b>"candidate"</b>'
        artifact["display_sections"][0]["title"] = "Summary <script>blocked()</script>"
        html = render_static_viewer_html(artifact)

        self.assertIn("viewer-escape-&lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt;", html)
        self.assertIn("Escaped &lt;b&gt;&quot;candidate&quot;&lt;/b&gt;", html)
        self.assertIn("Summary &lt;script&gt;blocked()&lt;/script&gt;", html)
        self.assertNotIn('<script>alert("x")</script>', html)
        self.assertNotIn("<b>\"candidate\"</b>", html)

    def test_negative_fixtures_fail_closed(self) -> None:
        expected = [
            (UNREDACTED_LIKE_FIXTURE, "raw_like_value_detected"),
            (CREDENTIAL_LIKE_FIXTURE, "credential_like_value_detected"),
            (UNSAFE_PATH_FIXTURE, "unsafe_path_label_detected"),
        ]
        for fixture, reason in expected:
            with self.subTest(fixture=fixture.name):
                with self.assertRaises(RedactedStaticViewerError) as raised:
                    write_static_viewer_html(fixture, Path("unused.html"))
                self.assertEqual(raised.exception.error_type, reason)

    def test_malformed_json_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            malformed = Path(tmp) / "artifact.json"
            malformed.write_text("{not-json", encoding="utf-8")
            with self.assertRaises(RedactedStaticViewerError) as raised:
                write_static_viewer_html(malformed, Path(tmp) / "viewer.html")
        self.assertEqual(raised.exception.error_type, "malformed_artifact")

    def test_unsupported_extension_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            artifact = Path(tmp) / "artifact.txt"
            artifact.write_text(VALID_FIXTURE.read_text(encoding="utf-8"), encoding="utf-8")
            with self.assertRaises(RedactedStaticViewerError) as raised:
                write_static_viewer_html(artifact, Path(tmp) / "viewer.html")
        self.assertEqual(raised.exception.error_type, "unsupported_extension")

    def test_oversized_artifact_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            artifact = Path(tmp) / "artifact.json"
            artifact.write_text(VALID_FIXTURE.read_text(encoding="utf-8"), encoding="utf-8")
            with self.assertRaises(RedactedStaticViewerError) as raised:
                write_static_viewer_html(artifact, Path(tmp) / "viewer.html", max_bytes=8)
        self.assertEqual(raised.exception.error_type, "artifact_too_large")

    def test_unsafe_source_alias_fails_closed_without_echoing_value(self) -> None:
        artifact = load_valid_fixture()
        artifact["display_sections"][0]["source_alias"] = "../synthetic-artifact.json"
        with self.assertRaises(RedactedStaticViewerError) as raised:
            render_static_viewer_html(artifact)
        self.assertEqual(raised.exception.error_type, "unsafe_path_label_detected")
        self.assertNotIn("synthetic-artifact", str(raised.exception))

    def test_cli_viewer_command_writes_static_html(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "viewer.html"
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                exit_code = main(["viewer", "--input", str(VALID_FIXTURE), "--output", str(output)])
            html = output.read_text(encoding="utf-8")
        self.assertEqual(exit_code, 0)
        self.assertIn("Static viewer HTML written: <viewer_html_path>", stdout.getvalue())
        self.assertIn("민감정보 제거 결과 뷰어", html)
        self.assertIn("검토 후보", html)
        self.assert_static_html_is_safe(html)

    def test_cli_viewer_command_blocks_negative_fixture(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "viewer.html"
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                exit_code = main(["viewer", "--input", str(CREDENTIAL_LIKE_FIXTURE), "--output", str(output)])
            self.assertFalse(output.exists())
        self.assertEqual(exit_code, 1)
        self.assertIn("Static viewer failed: credential_like_value_detected", stdout.getvalue())


if __name__ == "__main__":
    unittest.main()
