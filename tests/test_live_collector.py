from __future__ import annotations

import copy
import io
import json
import os
import shutil
import socket
import tempfile
import threading
import unittest
import uuid
from contextlib import redirect_stdout
from http import HTTPStatus
from pathlib import Path
from unittest.mock import MagicMock, patch

from burp_ai_redaction_gateway.capture import run_capture
from burp_ai_redaction_gateway import dashboard
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
            self.assertNotIn('http-equiv="refresh"', html)
            self.assertIn("VA-16", html)
            self.assertIn("burp-live-fixture-1", html)
            self.assertIn("burp-live-fixture-2", html)
            self.assertIn("모든 VA 항목이 정상이라는 뜻은 아닙니다", html)
            self.assertEqual(list(config.output_dir.glob(".ingest-*")), [])

    def test_capture_refresh_is_opt_in_and_reading_the_guide_stops_it(self):
        with tempfile.TemporaryDirectory() as temporary:
            server = create_dashboard_server("127.0.0.1", 0, DashboardConfig(Path(temporary)))
            worker = threading.Thread(target=server.serve_forever, daemon=True)
            worker.start()
            try:
                for path in ("/burp", "/burp?view=unrecognized-mode", "/burp?view=guide", "/burp?view=live"):
                    with self.subTest(path=path):
                        status, html = request(server, "GET", path)
                        self.assertEqual(status, 200)
                        if path.endswith("=live"):
                            self.assertIn('http-equiv="refresh" content="5"', html)
                            self.assertIn('href="/burp?view=guide#capture-guide"', html)
                            self.assertIn('href="/burp">화면 자동 갱신 끄기', html)
                        else:
                            self.assertNotIn('http-equiv="refresh"', html)
                            self.assertIn('href="/burp?view=live"', html)
                            self.assertIn('id="capture-guide"', html)
                            self.assertNotIn("unrecognized-mode", html)
                            if path.endswith("=guide"):
                                self.assertIn('class="secondary-details" open>', html)
            finally:
                server.shutdown()
                server.server_close()
                worker.join(timeout=5)

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

    def test_collector_uuid_results_appear_in_dashboard_without_exposing_source_identifier(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = ReceiverConfig(root / "burp_live", "burp_live", complete_bundle=True)
            for identity in ("a12b3c45-678d-4ef1-9a02-3b4c5d6e7f89", str(uuid.uuid4())):
                payload = dict(self.payload(), source_event_id=identity)
                result = ingest_montoya_payload(payload, config)
                self.assertEqual(result.status, "accepted")
                self.assertRegex(result.output_name, r"^c[0-9a-f]{20}$")
                self.assertTrue(verify_path(config.output_dir / result.output_name, load_policy()).passed)
                html = render_burp_capture(root, load_policy())
                self.assertIn(result.output_name, html)
                self.assertNotIn(identity, html)
                with self.assertRaises(ReceiverError) as caught:
                    ingest_montoya_payload(payload, config)
                self.assertEqual(caught.exception.status, HTTPStatus.CONFLICT)

    def test_existing_uuid_capture_is_not_replaced_or_republished(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            identity = str(uuid.uuid4())
            (root / identity).mkdir()
            with self.assertRaises(ReceiverError) as caught:
                ingest_montoya_payload(dict(self.payload(), source_event_id=identity), ReceiverConfig(root, "burp_live", complete_bundle=True))
            self.assertEqual(caught.exception.status, HTTPStatus.CONFLICT)
            self.assertEqual(list(root.iterdir()), [root / identity])

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
        for length in (20001, 65537):
            with self.subTest(oversized_length=length):
                handler.headers = {"Content-Length": str(length)}
                handler.rfile = io.BytesIO(b"x" * length)
                handler._discard_rejected_body(max_bytes=64 * 1024)
                self.assertEqual(handler.rfile.tell(), length if length <= 65536 else 0)
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

    def test_live_page_selects_fifty_recent_records_before_verification(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = ReceiverConfig(root / "template", "burp_live", complete_bundle=True)
            result = ingest_montoya_payload(self.payload(), config)
            source = config.output_dir / result.output_name
            captures = root / "burp_live"
            captures.mkdir()
            for index in range(51):
                destination = captures / f"burp-live-window-{index:03d}"
                shutil.copytree(source, destination)
                os.utime(destination, (1_700_000_000 + index, 1_700_000_000 + index))
            with patch("burp_ai_redaction_gateway.dashboard._verified_output", wraps=dashboard._verified_output) as verified:
                html = render_burp_capture(root, load_policy())
            self.assertEqual(verified.call_count, 50)
            self.assertIn("burp-live-window-050", html)
            self.assertNotIn("burp-live-window-000", html)


if __name__ == "__main__":
    unittest.main()
