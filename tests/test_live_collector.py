from __future__ import annotations

import copy
import io
import json
import os
import socket
import tempfile
import threading
import unittest
from contextlib import redirect_stdout
from http import HTTPStatus
from pathlib import Path
from unittest.mock import MagicMock, patch

from burp_ai_redaction_gateway.capture import run_capture
from burp_ai_redaction_gateway.cli import main
from burp_ai_redaction_gateway.dashboard import DashboardConfig, DashboardError, create_dashboard_server, render_burp_capture
from burp_ai_redaction_gateway.policy import load_policy
from burp_ai_redaction_gateway.receiver import ReceiverConfig, ReceiverError, _IngestHandler, create_server, ingest_montoya_payload
from burp_ai_redaction_gateway.scanner import assert_no_sensitive_text
from burp_ai_redaction_gateway.verifier import verify_path
from burp_ai_redaction_gateway.viewer import SAFE_FILE_ALLOWLIST
from test_collector_workflow import request


ROOT = Path(__file__).resolve().parents[1]
SAMPLE = ROOT / "samples/synthetic_montoya_handoff_payload.json"


class LiveCollectorTests(unittest.TestCase):
    def payload(self, number=1):
        return dict(json.loads(SAMPLE.read_text(encoding="utf-8")), source_event_id=f"burp-live-fixture-{number}")

    def test_complete_capture_generates_verified_report_and_four_files_without_raw_values(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = ReceiverConfig(root / "burp_live", "burp_live", complete_bundle=True)
            for number in (1, 2):
                result = ingest_montoya_payload(self.payload(number), config)
                self.assertEqual((result.status, result.files_written, result.raw_data_included), ("accepted", 13, False))
                output = config.output_dir / result.output_name
                bundle = output / "ai_candidates"
                self.assertEqual({path.name for path in bundle.iterdir()}, set(SAFE_FILE_ALLOWLIST))
                self.assertTrue(verify_path(output, load_policy()).passed)
                report = (bundle / "report_draft.md").read_text(encoding="utf-8")
                self.assertIn("검토 후보", report)
                self.assertIn("VA-", report)
                for path in bundle.iterdir():
                    text = path.read_text(encoding="utf-8")
                    assert_no_sensitive_text(text)
                    self.assertNotIn("DUMMY_COOKIE_VALUE", text)
                    self.assertNotIn("FAKE-client.example.test", text)
            html = render_burp_capture(root, load_policy())
            self.assertIn('http-equiv="refresh" content="5"', html)
            self.assertIn("VA-16", html)
            self.assertIn("burp-live-fixture-1", html)
            self.assertIn("burp-live-fixture-2", html)
            self.assertIn("모든 VA 항목이 정상이라는 뜻은 아닙니다", html)
            self.assertEqual(list(config.output_dir.glob(".ingest-*")), [])

    def test_duplicate_live_identifier_does_not_overwrite_existing_result(self):
        with tempfile.TemporaryDirectory() as temporary:
            config = ReceiverConfig(Path(temporary), "burp_live", complete_bundle=True)
            result = ingest_montoya_payload(self.payload(), config)
            path = config.output_dir / result.output_name / "analysis_packet.json"
            before = path.read_bytes()
            with self.assertRaises(ReceiverError) as caught:
                ingest_montoya_payload(self.payload(), config)
            self.assertEqual(caught.exception.status, HTTPStatus.CONFLICT)
            self.assertEqual(path.read_bytes(), before)

    def test_capture_page_normalizes_relative_result_root_before_boundary_checks(self):
        with tempfile.TemporaryDirectory(prefix="burp-live-root-", dir=ROOT.parent) as temporary:
            root = Path(temporary)
            config = ReceiverConfig(root / "burp_live", "burp_live", complete_bundle=True)
            ingest_montoya_payload(self.payload(), config)
            relative = Path(os.path.relpath(root, Path.cwd()))
            self.assertFalse(relative.is_absolute())
            html = render_burp_capture(relative, load_policy())
            self.assertIn("VA-16", html)
            self.assertIn("burp-live-fixture-1", html)

    def test_failed_verification_does_not_publish_partial_result(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = ReceiverConfig(root, "burp_live", complete_bundle=True)
            with patch("burp_ai_redaction_gateway.receiver.write_report_draft", side_effect=ValueError("synthetic_failure")):
                with self.assertRaises(ValueError):
                    ingest_montoya_payload(self.payload(), config)
            self.assertEqual(list(root.iterdir()), [])

    def test_hidden_capture_staging_is_not_discovered_or_accessible(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = ReceiverConfig(root / ".ingest-fixture", "burp_live")
            ingest_montoya_payload(self.payload(), config)
            server = create_dashboard_server("127.0.0.1", 0, DashboardConfig(root))
            worker = threading.Thread(target=server.serve_forever, daemon=True)
            worker.start()
            try:
                status, html = request(server, "GET", "/burp")
                self.assertEqual(status, 200)
                self.assertNotIn("burp-live-fixture-1", html)
                self.assertEqual(request(server, "GET", "/output?project=.ingest-fixture/burp-live-fixture-1")[0], 403)
            finally:
                server.shutdown()
                server.server_close()
                worker.join(timeout=5)

    def test_http_capture_rejects_out_of_scope_and_oversized_messages(self):
        with tempfile.TemporaryDirectory() as temporary:
            config = ReceiverConfig(Path(temporary), "burp_live", max_body_bytes=20000, complete_bundle=True)
            server = create_server("127.0.0.1", 0, config)
            worker = threading.Thread(target=server.serve_forever, daemon=True)
            worker.start()
            try:
                payload = self.payload()
                before = copy.deepcopy(payload)
                headers = {"Content-Type": "application/json"}
                status, result = request(server, "POST", "/ingest/burp-history", json.dumps(payload), headers)
                self.assertEqual(status, 202)
                self.assertEqual(json.loads(result)["files_written"], 13)
                self.assertEqual(payload, before)
                self.assertEqual(request(server, "POST", "/ingest/burp-history", json.dumps(dict(payload, in_scope=False)), headers)[0], 400)
                self.assertEqual(request(server, "POST", "/ingest/burp-history", "x" * 20001, headers)[0], 413)
                self.assertEqual(request(server, "POST", "/ingest/burp-history", "{}", {"Content-Type": "text/plain"})[0], 415)
            finally:
                server.shutdown()
                server.server_close()
                worker.join(timeout=5)

    def test_capture_cli_stops_both_listeners_and_opens_only_local_dashboard(self):
        with tempfile.TemporaryDirectory() as temporary, redirect_stdout(io.StringIO()) as text:
            from burp_ai_redaction_gateway.dashboard import DashboardHttpServer
            with patch.object(DashboardHttpServer, "serve_forever", side_effect=KeyboardInterrupt), patch("burp_ai_redaction_gateway.capture.webbrowser.open") as browser:
                self.assertEqual(main(["capture", "--root", temporary, "--receiver-port", "0", "--port", "0", "--open"]), 0)
                self.assertRegex(browser.call_args.args[0], r"^http://127\.0\.0\.1:\d+/burp$")
            self.assertIn("종료했습니다", text.getvalue())
            self.assertNotIn(temporary, text.getvalue())

    def test_rejected_body_drain_is_bounded_and_preserves_timeout(self):
        handler = object.__new__(_IngestHandler)
        handler.receiver_config = ReceiverConfig(Path("out"), "test")
        handler.connection = MagicMock()
        handler.connection.gettimeout.return_value = 2.0
        for length in ("2", "20000", "invalid"):
            with self.subTest(length=length):
                handler.headers = {"Content-Length": length}
                handler.rfile = io.BytesIO(b"{}")
                handler._discard_rejected_body()
                self.assertEqual(handler.rfile.tell(), 2 if length == "2" else 0)
        handler.connection.settimeout.assert_called_with(2.0)
        handler.headers = {"Content-Length": "2"}
        handler.rfile = MagicMock()
        handler.rfile.read1.side_effect = TimeoutError()
        handler._discard_rejected_body()
        handler.connection.settimeout.assert_called_with(2.0)

    def test_dashboard_port_failure_releases_receiver_port(self):
        with tempfile.TemporaryDirectory() as temporary:
            with socket.socket() as available:
                available.bind(("127.0.0.1", 0))
                receiver_port = available.getsockname()[1]
            occupied = create_dashboard_server("127.0.0.1", 0, DashboardConfig(Path(temporary)))
            try:
                with self.assertRaises(DashboardError):
                    run_capture(Path(temporary), receiver_port, occupied.server_address[1], None, open_browser=False)
                restarted = create_server("127.0.0.1", receiver_port, ReceiverConfig(Path(temporary), "smoke"))
                restarted.server_close()
            finally:
                occupied.server_close()


if __name__ == "__main__":
    unittest.main()
