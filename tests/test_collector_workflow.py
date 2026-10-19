from __future__ import annotations

import http.client
import io
import json
import socket
import tempfile
import threading
import unittest
from contextlib import redirect_stdout
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch
from urllib.parse import urlencode

from burp_ai_redaction_gateway.cli import main
from burp_ai_redaction_gateway.dashboard import DashboardConfig, DashboardError, create_dashboard_server
from burp_ai_redaction_gateway.policy import load_policy
from burp_ai_redaction_gateway.receiver import ReceiverConfig, ReceiverError, create_server
from burp_ai_redaction_gateway.scanner import assert_no_sensitive_text
from burp_ai_redaction_gateway.verifier import verify_path
from burp_ai_redaction_gateway.viewer import SAFE_FILE_ALLOWLIST


ROOT = Path(__file__).resolve().parents[1]


def request(server, method: str, path: str, body=None, headers=None):
    connection = http.client.HTTPConnection("127.0.0.1", server.server_address[1], timeout=10)
    try:
        connection.request(method, path, body=body, headers=headers or {})
        response = connection.getresponse()
        return response.status, response.read().decode("utf-8")
    finally:
        connection.close()


class LocalServerPortTests(unittest.TestCase):
    def factories(self, root: Path):
        return (
            (lambda port: create_dashboard_server("127.0.0.1", port, DashboardConfig(root=root)), DashboardError),
            (lambda port: create_server("127.0.0.1", port, ReceiverConfig(output_dir=root, project="smoke")), ReceiverError),
        )

    def test_existing_reusable_listener_is_not_shared(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            legacy = ThreadingHTTPServer(("127.0.0.1", 0), BaseHTTPRequestHandler)
            try:
                for factory, error_type in self.factories(Path(temporary)):
                    duplicate = None
                    try:
                        with self.assertRaises(error_type) as caught:
                            duplicate = factory(legacy.server_address[1])
                        self.assertEqual(caught.exception.error_type, "port_unavailable")
                    finally:
                        if duplicate is not None:
                            duplicate.server_close()
            finally:
                legacy.server_close()

    def test_receiver_and_dashboard_cannot_share_a_port(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            factories = self.factories(Path(temporary))
            for first_factory, _ in factories:
                first = first_factory(0)
                try:
                    for next_factory, error_type in factories:
                        duplicate = None
                        try:
                            with self.assertRaises(error_type):
                                duplicate = next_factory(first.server_address[1])
                        finally:
                            if duplicate is not None:
                                duplicate.server_close()
                finally:
                    first.server_close()

    def test_windows_listeners_use_exclusive_addresses(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            for factory, _ in self.factories(Path(temporary)):
                server = factory(0)
                try:
                    if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
                        self.assertFalse(server.allow_reuse_address)
                        self.assertEqual(server.socket.getsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE), 1)
                    else:
                        self.assertTrue(server.allow_reuse_address)
                finally:
                    server.server_close()

    def test_busy_port_cli_fails_without_success_message_or_private_path(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            occupied = ThreadingHTTPServer(("127.0.0.1", 0), BaseHTTPRequestHandler)
            try:
                port = str(occupied.server_address[1])
                for command in (
                    ["dashboard", "--port", port, "--root", str(root)],
                    ["serve", "--port", port, "--output", str(root), "--project", "smoke"],
                ):
                    with self.subTest(command=command[0]), redirect_stdout(io.StringIO()) as output:
                        with patch.object(ThreadingHTTPServer, "serve_forever") as serve:
                            self.assertEqual(main(command), 1)
                            serve.assert_not_called()
                        text = output.getvalue()
                        self.assertIn("port_unavailable", text)
                        self.assertIn("--port", text)
                        self.assertNotIn("listening", text)
                        self.assertNotIn(str(root), text)
                        self.assertNotIn("Traceback", text)
                self.assertEqual(list(root.iterdir()), [])
            finally:
                occupied.server_close()

    def test_closed_listener_can_be_started_again(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            for factory, _ in self.factories(Path(temporary)):
                server = factory(0)
                port = server.server_address[1]
                server.server_close()
                restarted = factory(port)
                restarted.server_close()


class CollectorWorkflowTests(unittest.TestCase):
    def test_received_records_can_build_reports_and_export_four_files_with_csrf(self) -> None:
        payload = json.loads((ROOT / "samples" / "synthetic_montoya_handoff_payload.json").read_text(encoding="utf-8"))
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "out"
            receiver = create_server("127.0.0.1", 0, ReceiverConfig(output_dir=root / "receiver", project="smoke"))
            worker = threading.Thread(target=receiver.serve_forever, daemon=True)
            worker.start()
            try:
                for number in (1, 2):
                    item = dict(payload, source_event_id=f"burp-proxy-history-{number}")
                    status, text = request(receiver, "POST", "/ingest/burp-history", json.dumps(item), {"Content-Type": "application/json"})
                    self.assertEqual(status, 202)
                    self.assertFalse(json.loads(text)["raw_data_included"])
                    assert_no_sensitive_text(text)
            finally:
                receiver.shutdown()
                receiver.server_close()
                worker.join(timeout=5)
            self.assertTrue(verify_path(root, load_policy()).passed)
            dashboard = create_dashboard_server("127.0.0.1", 0, DashboardConfig(root=root))
            worker = threading.Thread(target=dashboard.serve_forever, daemon=True)
            worker.start()
            try:
                status, home = request(dashboard, "GET", "/")
                self.assertEqual(status, 200)
                for number in (1, 2):
                    project = f"receiver/burp-proxy-history-{number}"
                    self.assertIn(project, home)
                    output = root / project
                    values = {"project": project, "action": "report"}
                    headers = {"Content-Type": "application/x-www-form-urlencoded"}
                    status, _ = request(dashboard, "POST", "/action", urlencode(values), headers)
                    self.assertEqual(status, 400)
                    self.assertFalse((output / "report_draft.md").exists())
                    values["csrf_token"] = dashboard.csrf_token
                    for action in ("report", "export"):
                        values["action"] = action
                        status, text = request(dashboard, "POST", "/action", urlencode(values), headers)
                        self.assertEqual(status, 200)
                        self.assertIn("통과", text)
                        self.assertNotIn("DUMMY_COOKIE_VALUE", text)
                    exported = root.parent / "exports" / "dashboard" / project.replace("/", "_")
                    self.assertEqual({file.name for file in exported.iterdir()}, set(SAFE_FILE_ALLOWLIST))
                    for file in exported.iterdir():
                        assert_no_sensitive_text(file.read_text(encoding="utf-8"))
                    report = (output / "report_draft.md").read_text(encoding="utf-8")
                    self.assertIn("검토 후보", report)
                    self.assertIn("취약점 확정 보고서가 아닙니다", report)
                    self.assertTrue(verify_path(output, load_policy()).passed)
            finally:
                dashboard.shutdown()
                dashboard.server_close()
                worker.join(timeout=5)
