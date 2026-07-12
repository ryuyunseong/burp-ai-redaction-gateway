from __future__ import annotations

import json
import re
import unittest
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
FIXTURE_DIR = ROOT / "tests" / "fixtures"
CONTRACT_DOC = ROOT / "docs" / "REDACTED_VIEWER_FIXTURE_CONTRACT.md"
DESIGN_DOC = ROOT / "docs" / "REDACTED_VIEWER_DESIGN.md"

VALID_FIXTURE = FIXTURE_DIR / "redacted_viewer_valid.json"
RAW_LIKE_FIXTURE = FIXTURE_DIR / "redacted_viewer_reject_unredacted_like.json"
CREDENTIAL_LIKE_FIXTURE = FIXTURE_DIR / "redacted_viewer_reject_credential_like.json"
UNSAFE_PATH_FIXTURE = FIXTURE_DIR / "redacted_viewer_reject_unsafe_path.json"

SCHEMA_VERSION = "redacted-viewer-fixture-contract-v1"
SAFE_FILE_ALLOWLIST = [
    "analysis_packet.json",
    "chatgpt_prompt.md",
    "codex_task_prompt.md",
    "report_draft.md",
]
VALID_REQUIRED_FIELDS = {
    "artifact_id",
    "schema_version",
    "generated_at",
    "source_kind",
    "redaction_status",
    "findings",
    "display_sections",
    "audit",
}
NEGATIVE_REQUIRED_FIELDS = {
    "schema_version",
    "fixture_kind",
    "expected_decision",
    "rejection_reason_code",
    "raw_data_included",
    "manual_review_required",
    "viewer_implementation_included",
    "synthetic_input_label",
    "forbidden_classes",
    "safe_message",
}
FORBIDDEN_VALUE_PATTERNS = [
    re.compile(r'"raw_request"', re.IGNORECASE),
    re.compile(r'"raw_response"', re.IGNORECASE),
    re.compile(r"\bGET\s+/", re.IGNORECASE),
    re.compile(r"\bPOST\s+/", re.IGNORECASE),
    re.compile(r"\bHTTP/1\.[01]\b", re.IGNORECASE),
    re.compile(r"\bCookie\s*[:=]\s*\S+", re.IGNORECASE),
    re.compile(r"\bAuthorization\s*[:=]\s*\S+", re.IGNORECASE),
    re.compile(r"\bBearer\s+[A-Za-z0-9._-]+", re.IGNORECASE),
    re.compile(r"\bapi[_-]?key\s*[:=]\s*\S+", re.IGNORECASE),
    re.compile(r"\bpassword\s*[:=]\s*\S+", re.IGNORECASE),
    re.compile(r"\bsession[_-]?id\s*[:=]\s*\S+", re.IGNORECASE),
    re.compile(r"\btoken\s*[:=]\s*\S+", re.IGNORECASE),
    re.compile(r"sk-[A-Za-z0-9]"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
]


def load_fixture(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def is_unsafe_path_label(label: str) -> bool:
    normalized = label.replace("\\", "/")
    return bool(
        "../" in normalized
        or normalized.startswith("/")
        or re.match(r"^[A-Za-z]:[\\/]", label)
        or normalized.lower().startswith("file://")
        or re.match(r"^[A-Za-z][A-Za-z0-9+.-]*://", label)
    )


class RedactedViewerFixtureContractTests(unittest.TestCase):
    def assert_no_forbidden_values(self, path: Path) -> None:
        text = path.read_text(encoding="utf-8")
        for pattern in FORBIDDEN_VALUE_PATTERNS:
            self.assertIsNone(pattern.search(text), f"{path.name} matched {pattern.pattern}")

    def assert_negative_fixture(self, path: Path, reason_code: str) -> None:
        fixture = load_fixture(path)
        self.assertEqual(fixture["schema_version"], SCHEMA_VERSION)
        self.assertEqual(fixture["fixture_kind"], "negative")
        self.assertEqual(fixture["expected_decision"], "reject")
        self.assertEqual(fixture["rejection_reason_code"], reason_code)
        self.assertFalse(fixture["raw_data_included"])
        self.assertTrue(fixture["manual_review_required"])
        self.assertFalse(fixture["viewer_implementation_included"])
        self.assertTrue(NEGATIVE_REQUIRED_FIELDS.issubset(fixture))
        self.assertTrue(fixture["synthetic_input_label"].startswith("synthetic_"))
        self.assertGreater(len(fixture["forbidden_classes"]), 0)
        self.assertEqual(fixture["expected_response"]["status"], "blocked")
        self.assertEqual(fixture["expected_response"]["reason_code"], reason_code)
        self.assertFalse(fixture["expected_response"]["raw_data_included"])
        self.assertTrue(fixture["expected_response"]["manual_review_required"])
        self.assert_no_forbidden_values(path)

    def test_redacted_viewer_contract_doc_exists_and_links_design(self) -> None:
        self.assertTrue(CONTRACT_DOC.exists())
        self.assertTrue(DESIGN_DOC.exists())
        body = CONTRACT_DOC.read_text(encoding="utf-8")
        self.assertIn("docs/REDACTED_VIEWER_DESIGN.md", body)
        self.assertIn("viewer implementation", body)
        self.assertIn("fail-closed", body)
        self.assertIn("safe file allowlist", body)
        self.assertIn("v0.10 tag or GitHub Release mutation", body)

    def test_valid_redacted_viewer_fixture_contract(self) -> None:
        fixture = load_fixture(VALID_FIXTURE)
        self.assertTrue(VALID_REQUIRED_FIELDS.issubset(fixture))
        self.assertEqual(fixture["schema_version"], SCHEMA_VERSION)
        self.assertEqual(fixture["fixture_kind"], "valid")
        self.assertEqual(fixture["expected_decision"], "accept")
        self.assertEqual(fixture["source_kind"], "verified_redacted_bundle")
        self.assertFalse(fixture["viewer_implementation_included"])
        self.assertFalse(fixture["raw_data_included"])
        self.assertTrue(fixture["manual_review_required"])
        self.assertEqual(fixture["safe_file_allowlist"], SAFE_FILE_ALLOWLIST)
        self.assertEqual(fixture["redaction_status"]["verification_status"], "passed")
        self.assertTrue(fixture["redaction_status"]["raw_free"])

        self.assertGreater(len(fixture["findings"]), 0)
        for finding in fixture["findings"]:
            self.assertEqual(finding["status"], "candidate")
            self.assertEqual(finding["risk"], "draft")
            self.assertFalse(finding["severity_finalized"])
            self.assertTrue(set(finding["evidence_aliases"]).issubset(SAFE_FILE_ALLOWLIST))
            self.assertIn("가상", finding["safe_summary"])
            self.assertIn("원본 웹 요청·응답", finding["safe_summary"])

        for section in fixture["display_sections"]:
            self.assertIn(section["source_alias"], SAFE_FILE_ALLOWLIST)

        self.assert_no_forbidden_values(VALID_FIXTURE)

    def test_raw_like_fixture_fails_closed(self) -> None:
        self.assert_negative_fixture(RAW_LIKE_FIXTURE, "raw_like_value_detected")

    def test_credential_like_fixture_fails_closed(self) -> None:
        self.assert_negative_fixture(CREDENTIAL_LIKE_FIXTURE, "credential_like_value_detected")

    def test_unsafe_path_fixture_fails_closed(self) -> None:
        fixture = load_fixture(UNSAFE_PATH_FIXTURE)
        self.assert_negative_fixture(UNSAFE_PATH_FIXTURE, "unsafe_path_label_detected")
        self.assertIn("synthetic_parent_traversal_label", fixture["unsafe_path_labels"])
        self.assertIn("synthetic_windows_absolute_path_label", fixture["unsafe_path_labels"])
        self.assertIn("synthetic_posix_absolute_path_label", fixture["unsafe_path_labels"])
        self.assertIn("synthetic_file_scheme_path_label", fixture["unsafe_path_labels"])
        self.assertIn("synthetic_external_url_path_label", fixture["unsafe_path_labels"])

    def test_unsafe_path_detector_rejects_required_classes(self) -> None:
        windows_absolute = "C:" + "\\synthetic\\blocked\\artifact.json"
        posix_absolute = "/" + "synthetic/blocked/artifact.json"
        file_scheme = "file:" + "//synthetic/blocked/artifact.json"
        external_url = "https:" + "//" + "synthetic" + ".invalid" + "/artifact.json"
        unsafe_examples = [
            "../synthetic-artifact.json",
            "..\\synthetic-artifact.json",
            windows_absolute,
            posix_absolute,
            file_scheme,
            external_url,
        ]
        for example in unsafe_examples:
            with self.subTest(example=example):
                self.assertTrue(is_unsafe_path_label(example))

    def test_fixture_files_are_raw_free_and_do_not_require_viewer_implementation(self) -> None:
        for fixture_path in [
            VALID_FIXTURE,
            RAW_LIKE_FIXTURE,
            CREDENTIAL_LIKE_FIXTURE,
            UNSAFE_PATH_FIXTURE,
        ]:
            with self.subTest(fixture=fixture_path.name):
                self.assert_no_forbidden_values(fixture_path)
                fixture = load_fixture(fixture_path)
                self.assertFalse(fixture["viewer_implementation_included"])
                self.assertFalse(fixture["raw_data_included"])


if __name__ == "__main__":
    unittest.main()
