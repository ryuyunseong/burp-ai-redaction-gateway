from __future__ import annotations

import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from burp_ai_redaction_gateway.cli import main
from burp_ai_redaction_gateway.dashboard import _discover_outputs
from burp_ai_redaction_gateway.policy import load_policy
from burp_ai_redaction_gateway.verifier import VerificationResult, verify_path
from burp_ai_redaction_gateway.viewer import SAFE_FILE_ALLOWLIST
from burp_ai_redaction_gateway.workflow import WorkflowError, process_export


ROOT = Path(__file__).resolve().parents[1]
SAMPLE = ROOT / "samples" / "synthetic_burp_history.json"


class ProcessWorkflowTests(unittest.TestCase):
    def test_json_and_burp_xml_produce_exactly_four_verified_candidate_files(self) -> None:
        for sample in (SAMPLE, ROOT / "samples" / "burp_xml_base64_history.xml"):
            with self.subTest(sample=sample.name), tempfile.TemporaryDirectory() as temporary:
                output = Path(temporary) / "result"
                result = process_export(sample, output, "demo_check", load_policy())
                self.assertGreater(result.event_count, 0)
                self.assertEqual(set(p.name for p in result.export_dir.iterdir()), set(SAFE_FILE_ALLOWLIST))
                self.assertTrue(verify_path(result.export_dir, load_policy()).passed)
                for name in SAFE_FILE_ALLOWLIST:
                    self.assertEqual((result.export_dir / name).read_bytes(), (output / name).read_bytes())
                packet = json.loads((result.export_dir / "analysis_packet.json").read_text(encoding="utf-8"))
                self.assertIs(packet["raw_data_included"], False)
                self.assertNotIn("redaction_audit.db", result.exported_files)

    def test_existing_output_is_preserved(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "result"
            output.mkdir()
            sentinel = output / "keep.txt"
            sentinel.write_text("existing result", encoding="utf-8")
            with self.assertRaisesRegex(WorkflowError, "output_already_exists"):
                process_export(SAMPLE, output, "demo_check", load_policy())
            self.assertEqual(sentinel.read_text(encoding="utf-8"), "existing result")
            self.assertEqual(list(output.iterdir()), [sentinel])

    def test_candidate_copy_is_not_listed_as_a_second_project(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            process_export(SAMPLE, root / "demo_check", "demo_check", load_policy())
            outputs, blocked_count = _discover_outputs(root, load_policy())
            self.assertEqual([output.output_id for output in outputs], ["demo_check"])
            self.assertEqual(blocked_count, 0)

    def test_har_input_is_supported(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "history.har"
            source.write_text(json.dumps({"log": {"entries": [{
                "request": {"method": "GET", "url": "https://example.test/health", "headers": []},
                "response": {"status": 200, "headers": [], "content": {"text": ""}},
            }]}}), encoding="utf-8")
            result = process_export(source, root / "result", "demo_check", load_policy())
            self.assertEqual(result.event_count, 1)
            self.assertEqual(len(result.exported_files), 4)

    def test_input_limit_and_alias_validation_precede_writes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "result"
            with patch("burp_ai_redaction_gateway.workflow.MAX_INPUT_BYTES", 8):
                with self.assertRaisesRegex(WorkflowError, "input_too_large"):
                    process_export(SAMPLE, output, "demo_check", load_policy())
            with self.assertRaisesRegex(WorkflowError, "invalid_project_alias"):
                process_export(SAMPLE, output, "../demo", load_policy())
            self.assertFalse(output.exists())

    def test_invalid_input_and_empty_export_do_not_publish_results(self) -> None:
        for data in ("{invalid", "[]", '{"events": [null]}'):
            with self.subTest(data=data), tempfile.TemporaryDirectory() as temporary:
                source = Path(temporary) / "input.json"
                source.write_text(data, encoding="utf-8")
                output = Path(temporary) / "result"
                with self.assertRaises(WorkflowError):
                    process_export(source, output, "demo_check", load_policy())
                self.assertFalse(output.exists())

    def test_failed_verification_stops_before_report_and_export(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "result"
            with patch("burp_ai_redaction_gateway.workflow.verify_path", return_value=VerificationResult(7, [object()])), patch(
                "burp_ai_redaction_gateway.workflow.write_report_draft"
            ) as report:
                with self.assertRaisesRegex(WorkflowError, "verification_failed"):
                    process_export(SAMPLE, output, "demo_check", load_policy())
                report.assert_not_called()
            self.assertFalse((output / "ai_candidates").exists())

    def test_failed_export_verification_never_publishes_candidate_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "result"
            with patch("burp_ai_redaction_gateway.workflow.verify_path", side_effect=[VerificationResult(7, []), VerificationResult(4, [object()])]):
                with self.assertRaisesRegex(WorkflowError, "export_verification_failed"):
                    process_export(SAMPLE, output, "demo_check", load_policy())
            self.assertFalse((output / "ai_candidates").exists())
            self.assertFalse(list(output.glob(".candidates-*")))

    def test_cli_failure_does_not_echo_input_path_or_exception(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "private-input.json"
            source.write_text("{invalid", encoding="utf-8")
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                code = main(["process", "--input", str(source), "--output", str(Path(temporary) / "result"), "--project", "demo_check"])
            self.assertEqual(code, 1)
            self.assertNotIn(str(source), stdout.getvalue())
            self.assertNotIn("private-input", stdout.getvalue())
            self.assertNotIn("Traceback", stdout.getvalue())

    def test_cli_success_and_retry(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            args = ["process", "--input", str(SAMPLE), "--output", str(Path(temporary) / "result"), "--project", "demo_check"]
            with redirect_stdout(io.StringIO()):
                self.assertEqual(main(args), 0)
                self.assertEqual(main(args), 1)


if __name__ == "__main__":
    unittest.main()
