from __future__ import annotations

import copy
import http.client
import json
import os
import re
import shutil
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.parse import urlencode

from burp_ai_redaction_gateway import ai_review
from burp_ai_redaction_gateway.dashboard import DashboardConfig, create_dashboard_server
from burp_ai_redaction_gateway.policy import load_policy
from burp_ai_redaction_gateway.receiver import INGEST_PATH, ReceiverConfig, create_server
from burp_ai_redaction_gateway.workflow import process_export


ROOT = Path(__file__).resolve().parents[1]
DUMMY_KEY = "sk-" + "DUMMY_" * 5


def model_response(ids=("FC-0004",)):
    result = {"reviews": [{
        "finding_id": value,
        "assessment": "more_evidence",
        "summary": "검토 후보입니다. 현재 자료만으로는 취약점을 확정할 수 없습니다.",
        "evidence_notes": ["응답이 있었다는 사실만으로 권한 검증 실패를 판단할 수 없습니다."],
        "manual_checks": ["허가된 테스트 계정 A와 B로 같은 자료의 접근 결과를 비교하세요.", "다른 계정의 자료가 보이면 접근 권한 검증을 확인하세요."],
        "remediation": ["서버에서 현재 계정과 자료 소유자의 권한을 확인하세요."],
    } for value in ids]}
    return {"status": "completed", "output": [{"type": "message", "role": "assistant", "content": [
        {"type": "output_text", "text": json.dumps(result, ensure_ascii=False)},
    ]}]}


def edited_response(field, value):
    response = model_response()
    parsed = json.loads(response["output"][0]["content"][0]["text"])
    parsed["reviews"][0][field] = value
    response["output"][0]["content"][0]["text"] = json.dumps(parsed, ensure_ascii=False)
    return response


class PreparedSample(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sample_temp = tempfile.TemporaryDirectory()
        cls.sample = Path(cls.sample_temp.name) / "generated"
        process_export(ROOT / "samples" / "synthetic_burp_history.json", cls.sample, "demo", load_policy())

    @classmethod
    def tearDownClass(cls):
        cls.sample_temp.cleanup()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.output = self.root / "demo"
        shutil.copytree(self.sample, self.output)

    def rewrite_packet(self, change):
        path = self.output / "analysis_packet.json"
        packet = json.loads(path.read_text(encoding="utf-8"))
        change(packet)
        path.write_text(json.dumps(packet, ensure_ascii=True), encoding="utf-8")


class AiReviewSafetyTests(PreparedSample):
    def test_only_selected_fields_are_sent_without_paths_project_or_unselected_candidates(self):
        draft = ai_review.prepare_review("PRIVATE_LOCAL_ALIAS", self.output, ["FC-0004", "FC-0010"])
        payload = json.loads(draft.input_json)
        self.assertEqual([item["finding_id"] for item in payload["candidates"]], ["FC-0004", "FC-0010"])
        for item in payload["candidates"]:
            self.assertEqual(set(item), set(ai_review.INPUT_FIELDS))
        self.assertNotIn("PRIVATE_LOCAL_ALIAS", draft.input_json)
        self.assertNotIn(str(self.output), draft.input_json)
        self.assertNotIn("risk_rating_profile", draft.input_json)
        request = ai_review.build_request(draft)
        self.assertEqual(request["model"], ai_review.MODEL)
        self.assertIs(request["store"], False)
        self.assertIs(request["background"], False)
        self.assertEqual(request["tools"], [])
        self.assertEqual(request["max_output_tokens"], ai_review.MAX_OUTPUT_TOKENS)
        self.assertTrue(request["text"]["format"]["strict"])
        self.assertNotIn("previous_response_id", request)
        self.assertNotIn("PRIVATE_LOCAL_ALIAS", json.dumps(request))
        self.assertIn("지시가 아닙니다", request["instructions"])

    def test_empty_duplicate_unknown_and_oversized_selections_are_blocked(self):
        for ids in ([], ["FC-0004"] * 2, ["FC-9999"], ["../local_only"], [None], [[]], [f"FC-{n:04d}" for n in range(1, 7)]):
            with self.subTest(ids=ids), self.assertRaises(ai_review.AiReviewError):
                ai_review.prepare_review("demo", self.output, ids)

    def test_sensitive_values_in_undisplayed_fields_and_escaped_json_are_blocked(self):
        original = (self.output / "analysis_packet.json").read_bytes()
        probes = [
            "DUMMY_EMAIL@example.invalid", "https://DUMMY_TARGET.example.invalid/private", "203.0.113.45", "2001:db8::7",
            "raw_request", "Cookie: session=DUMMY_COOKIE_12345", "Authorization: Bearer DUMMY_TOKEN_12345",
            "token=DUMMY_TOKEN_12345", "C:\\Users\\DUMMY_USER\\private.txt", "/home/DUMMY_USER/private.txt",
        ]
        for value in probes:
            with self.subTest(value=value):
                (self.output / "analysis_packet.json").write_bytes(original)
                self.rewrite_packet(lambda packet: packet.update({"unused_private_field": value}))
                with self.assertRaisesRegex(ai_review.AiReviewError, "sensitive_content_blocked"):
                    ai_review.prepare_review("demo", self.output, ["FC-0004"])

    def test_raw_flag_schema_candidate_ids_and_input_size_are_checked(self):
        original = (self.output / "analysis_packet.json").read_bytes()
        changes = [
            lambda p: p.update(raw_data_included=True),
            lambda p: p.update(schema_version="unknown"),
            lambda p: p.update(finding_candidates={}),
            lambda p: p["finding_candidates"][0].update(finding_id="wrong"),
            lambda p: p["finding_candidates"][0].update(rationale=123),
            lambda p: p["finding_candidates"][0].update(manual_verification_required=False),
            lambda p: p["finding_candidates"].append(copy.deepcopy(p["finding_candidates"][0])),
        ]
        for change in changes:
            (self.output / "analysis_packet.json").write_bytes(original)
            self.rewrite_packet(change)
            with self.assertRaises(ai_review.AiReviewError):
                ai_review.prepare_review("demo", self.output, ["FC-0004"])
        (self.output / "analysis_packet.json").write_bytes(original)
        with patch.object(ai_review, "MAX_INPUT_BYTES", 1), self.assertRaisesRegex(ai_review.AiReviewError, "selection_too_large"):
            ai_review.prepare_review("demo", self.output, ["FC-0004"])
        with patch.object(ai_review, "MAX_PACKET_BYTES", 1), self.assertRaisesRegex(ai_review.AiReviewError, "analysis_too_large"):
            ai_review.prepare_review("demo", self.output, ["FC-0004"])

    def test_symlinked_analysis_file_is_not_read(self):
        packet = self.output / "analysis_packet.json"
        target = self.root / "outside.json"
        packet.rename(target)
        try:
            packet.symlink_to(target)
        except OSError:
            self.skipTest("Symbolic links are unavailable in this Windows environment")
        with self.assertRaisesRegex(ai_review.AiReviewError, "invalid_analysis_file"):
            ai_review.prepare_review("demo", self.output, ["FC-0004"])

    def test_model_response_requires_exact_ids_shape_korean_and_candidate_wording(self):
        draft = ai_review.prepare_review("demo", self.output, ["FC-0004"])
        good = ai_review.validate_response(model_response(), draft)
        self.assertEqual(good["reviews"][0]["finding_id"], "FC-0004")
        invalid = [
            edited_response("finding_id", "FC-9999"), edited_response("assessment", "confirmed"),
            edited_response("summary", "확정 취약점입니다."), edited_response("summary", []),
            edited_response("manual_checks", ["Only English"]), edited_response("manual_checks", []),
            edited_response("remediation", ["조치"] * 5), edited_response("new_field", "추가 값"),
            dict(model_response(), status="incomplete"), {"status": "completed", "output": []},
            {"status": "completed", "output": [{"type": "function_call", "name": "DUMMY_TOOL"}]},
            {"status": "completed", "output": [{"type": "message", "role": "assistant", "content": [{"type": "refusal"}]}]},
        ]
        for response in invalid:
            with self.subTest(response=response), self.assertRaises(ai_review.AiReviewError):
                ai_review.validate_response(response, draft)

    def test_private_model_output_is_not_returned(self):
        draft = ai_review.prepare_review("demo", self.output, ["FC-0004"])
        with self.assertRaisesRegex(ai_review.AiReviewError, "ai_response_sensitive_blocked"):
            ai_review.validate_response(edited_response("summary", "검토 후보: DUMMY_MAIL@example.invalid"), draft)

    def test_time_of_day_is_not_mistaken_for_an_ipv6_address(self):
        ai_review._check_text("허가된 점검 시간은 10:30:45 입니다.")

    def test_credentials_are_not_exposed_and_only_the_expected_local_file_is_read(self):
        key_file = self.root / ".env.local"
        with patch.object(ai_review, "KEY_FILE", key_file), patch.dict(os.environ, {}, clear=True):
            self.assertFalse(ai_review.api_key_configured())
            key_file.write_text('UNRELATED=DUMMY_VALUE\nOPENAI_API_KEY="' + DUMMY_KEY + '"\n', encoding="utf-8")
            self.assertTrue(ai_review.api_key_configured())
            self.assertEqual(ai_review._load_api_key(), DUMMY_KEY)
            with patch.dict(os.environ, {"OPENAI_API_KEY": "DUMMY_INVALID_VALUE"}):
                self.assertFalse(ai_review.api_key_configured())

    def test_fixed_https_destination_no_redirects_no_error_body_or_exception_echo(self):
        draft = ai_review.prepare_review("demo", self.output, ["FC-0004"])
        with patch.object(ai_review.http.client, "HTTPSConnection") as factory:
            connection = factory.return_value
            response = connection.getresponse.return_value
            response.status = 200
            response.read.return_value = json.dumps(model_response()).encode()
            self.assertEqual(ai_review._request_openai(ai_review.build_request(draft), DUMMY_KEY)["status"], "completed")
            self.assertEqual(factory.call_args.args, ("api.openai.com",))
            self.assertTrue(factory.call_args.kwargs["context"].check_hostname)
            self.assertEqual(connection.request.call_args.args[:2], ("POST", "/v1/responses"))
            self.assertEqual(connection.request.call_args.args[3]["Authorization"], "Bearer " + DUMMY_KEY)
            self.assertNotIn(DUMMY_KEY, connection.request.call_args.args[2].decode())
            for status in (301, 302, 307, 401, 403, 429, 500):
                response.reset_mock()
                response.status = status
                with self.assertRaises(ai_review.AiReviewError) as caught:
                    ai_review._request_openai(ai_review.build_request(draft), DUMMY_KEY)
                response.read.assert_not_called()
                self.assertNotIn(DUMMY_KEY, str(caught.exception))
            connection.request.side_effect = OSError("DUMMY_PRIVATE_FAILURE")
            with self.assertRaises(ai_review.AiReviewError) as caught:
                ai_review._request_openai(ai_review.build_request(draft), DUMMY_KEY)
            self.assertNotIn("DUMMY_PRIVATE_FAILURE", str(caught.exception))
            self.assertTrue(connection.close.called)

    def test_timeout_and_oversized_provider_response_are_bounded(self):
        with patch.object(ai_review.http.client, "HTTPSConnection") as factory:
            connection = factory.return_value
            connection.request.side_effect = TimeoutError()
            with self.assertRaisesRegex(ai_review.AiReviewError, "api_timeout"):
                ai_review._request_openai({}, DUMMY_KEY)
            self.assertEqual(connection.request.call_count, 1)
            connection.request.side_effect = None
            connection.getresponse.return_value.status = 200
            connection.getresponse.return_value.read.return_value = b"x" * (ai_review.MAX_RESPONSE_BYTES + 1)
            with self.assertRaisesRegex(ai_review.AiReviewError, "ai_response_too_large"):
                ai_review._request_openai({}, DUMMY_KEY)

    def test_consent_revalidation_single_use_and_refresh_do_not_repeat_requests(self):
        session = ai_review.ReviewSession()
        token, _ = session.prepare("demo", self.output, ["FC-0004"])
        with patch.object(ai_review, "_request_openai", return_value=model_response()) as send, patch.object(ai_review, "_load_api_key", return_value=DUMMY_KEY):
            with self.assertRaisesRegex(ai_review.AiReviewError, "review_consent_required"):
                session.send(token, self.output, False)
            send.assert_not_called()
            result_id = session.send(token, self.output, True)
            for _ in range(2):
                self.assertEqual(session.result(result_id)[0], "demo")
            with self.assertRaisesRegex(ai_review.AiReviewError, "review_confirmation_expired"):
                session.send(token, self.output, True)
            self.assertEqual(send.call_count, 1)

    def test_changes_expiry_missing_key_and_sensitive_result_do_not_publish_success(self):
        session = ai_review.ReviewSession()
        token, _ = session.prepare("demo", self.output, ["FC-0004"])
        self.rewrite_packet(lambda p: p.update(candidate_count=23))
        with patch.object(ai_review, "_request_openai") as send:
            with self.assertRaisesRegex(ai_review.AiReviewError, "review_source_changed"):
                session.send(token, self.output, True)
            send.assert_not_called()
        token, _ = session.prepare("demo", self.output, ["FC-0004"])
        with patch.object(ai_review, "DRAFT_TTL", -1), patch.object(ai_review, "_request_openai") as send:
            with self.assertRaisesRegex(ai_review.AiReviewError, "review_confirmation_expired"):
                session.send(token, self.output, True)
            send.assert_not_called()
        token, _ = session.prepare("demo", self.output, ["FC-0004"])
        with patch.object(ai_review, "_load_api_key", side_effect=ai_review.AiReviewError("api_key_not_configured")), patch.object(ai_review, "_request_openai") as send:
            with self.assertRaisesRegex(ai_review.AiReviewError, "api_key_not_configured"):
                session.send(token, self.output, True)
            send.assert_not_called()
        self.assertEqual(session._results, {})

    def test_session_memory_is_bounded_and_concurrent_send_is_rejected(self):
        session = ai_review.ReviewSession()
        tokens = [session.prepare("demo", self.output, ["FC-0004"])[0] for _ in range(ai_review.MAX_SESSION_ITEMS + 1)]
        with self.assertRaises(ai_review.AiReviewError):
            session.project_for(tokens[0])
        session._sending.acquire()
        try:
            with self.assertRaisesRegex(ai_review.AiReviewError, "ai_review_busy"):
                session.send(tokens[-1], self.output, True)
        finally:
            session._sending.release()


class AiReviewHttpTests(PreparedSample):
    def setUp(self):
        super().setUp()
        self.server = create_dashboard_server("127.0.0.1", 0, DashboardConfig(root=self.root))
        self.worker = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.worker.start()
        self.addCleanup(self.close_server)
        self.origin = f"http://127.0.0.1:{self.server.server_address[1]}"

    def close_server(self):
        self.server.shutdown()
        self.server.server_close()
        self.worker.join(5)

    def request(self, method, path, values=None, **extra_headers):
        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_address[1], timeout=10)
        try:
            headers = {"Origin": self.origin, "Content-Type": "application/x-www-form-urlencoded", **extra_headers}
            connection.request(method, path, body=urlencode(values, doseq=True) if values is not None else None, headers=headers)
            response = connection.getresponse()
            return response.status, response.read().decode(), dict(response.getheaders())
        finally:
            connection.close()

    def prepare(self):
        status, body, _ = self.request("POST", "/ai-review/prepare", {"csrf_token": self.server.csrf_token, "project": "demo", "candidates": ["FC-0004"]})
        self.assertEqual(status, 200)
        self.assertIn("실제로 전송할 자료 전체", body)
        return re.search(r'name="confirmation" value="([A-Za-z0-9_-]+)"', body)[1]

    def test_output_links_selection_preview_and_missing_key_never_call_api(self):
        with patch.object(ai_review, "api_key_configured", return_value=False), patch.object(ai_review, "_request_openai") as send:
            status, output, _ = self.request("GET", "/output?project=demo")
            self.assertEqual(status, 200)
            self.assertIn('href="/ai-review?project=demo"', output)
            status, body, headers = self.request("GET", "/ai-review?project=demo")
            self.assertEqual(status, 200)
            self.assertEqual(body.count('name="candidates"'), 22)
            self.assertNotIn('name="api_key"', body)
            self.assertEqual(headers["Cache-Control"], "no-store")
            self.assertEqual(headers["Referrer-Policy"], "same-origin")
            self.assertIn("frame-ancestors 'none'", headers["Content-Security-Policy"])
            self.prepare()
            send.assert_not_called()

    def test_usage_document_preserves_manual_consent_and_security_limits(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        guide = (ROOT / "docs" / "AI_REVIEW.md").read_text(encoding="utf-8")
        self.assertIn("docs/AI_REVIEW.md", readme)
        self.assertIn("OPENAI_API_KEY=", guide)
        for phrase in ("확정 취약점", "1~5개", "전송할 내용 확인", "동의란", "store=false", "보안 점검용 로그", "종료하면 사라집니다", "결과 파일 4개", "모든 민감정보를 찾는 것은 아닙니다"):
            self.assertIn(phrase, guide)
        self.assertNotIn("**", guide)

    def test_origin_host_csrf_and_extra_fields_block_before_network(self):
        valid = {"csrf_token": self.server.csrf_token, "project": "demo", "candidates": ["FC-0004"]}
        with patch.object(ai_review, "_request_openai") as send:
            for values, headers in ((valid, {"Origin": "https://example.invalid"}), (valid, {"Origin": ""}), (valid, {"Origin": "null"}), (dict(valid, csrf_token="DUMMY_INVALID"), {}), (dict(valid, endpoint="https://example.invalid"), {}), (dict(valid, csrf_token=[self.server.csrf_token, self.server.csrf_token]), {})):
                status, _, _ = self.request("POST", "/ai-review/prepare", values, **headers)
                self.assertIn(status, (400, 403))
            status, _, _ = self.request("GET", "/ai-review?project=demo", Host="example.invalid")
            self.assertEqual(status, 403)
            send.assert_not_called()

    def test_gui_result_uses_post_redirect_get_escapes_html_and_keeps_bundle_unchanged(self):
        before = {path.name: path.read_bytes() for path in (self.output / "ai_candidates").iterdir()}
        response = edited_response("summary", "검토 후보입니다. <script>alert(1)</script>")
        with patch.object(ai_review, "api_key_configured", return_value=True), patch.object(ai_review, "_load_api_key", return_value=DUMMY_KEY), patch.object(ai_review, "_request_openai", return_value=response) as send:
            token = self.prepare()
            values = {"csrf_token": self.server.csrf_token, "confirmation": token, "consent": "yes"}
            status, _, headers = self.request("POST", "/ai-review/send", values)
            self.assertEqual(status, 303)
            for _ in range(2):
                status, body, _ = self.request("GET", headers["Location"])
                self.assertEqual(status, 200)
                self.assertIn("Burp에서 확인할 방법", body)
                self.assertIn("계정 A와 B", body)
                self.assertIn("&lt;script&gt;", body)
                self.assertNotIn("<script>", body)
                self.assertNotIn(DUMMY_KEY, body)
            status, _, _ = self.request("POST", "/ai-review/send", values)
            self.assertEqual(status, 400)
            self.assertEqual(send.call_count, 1)
        after = {path.name: path.read_bytes() for path in (self.output / "ai_candidates").iterdir()}
        self.assertEqual(before, after)

    def test_send_without_consent_and_private_model_result_are_blocked(self):
        with patch.object(ai_review, "api_key_configured", return_value=True), patch.object(ai_review, "_load_api_key", return_value=DUMMY_KEY), patch.object(ai_review, "_request_openai", return_value=edited_response("summary", "검토 후보: DUMMY_USER@example.invalid")) as send:
            token = self.prepare()
            values = {"csrf_token": self.server.csrf_token, "confirmation": token}
            self.assertEqual(self.request("POST", "/ai-review/send", values)[0], 400)
            send.assert_not_called()
            status, body, _ = self.request("POST", "/ai-review/send", dict(values, consent="yes"))
            self.assertEqual(status, 400)
            self.assertIn("차단했습니다", body)
            self.assertNotIn("DUMMY_USER", body)
            self.assertEqual(self.server.ai_reviews._results, {})

    def test_burp_handoff_to_redaction_then_ai_review_uses_only_verified_metadata(self):
        receiver = create_server("127.0.0.1", 0, ReceiverConfig(output_dir=self.root / "receiver", project="demo_receiver"))
        worker = threading.Thread(target=receiver.serve_forever, daemon=True)
        worker.start()
        connection = http.client.HTTPConnection("127.0.0.1", receiver.server_address[1], timeout=10)
        try:
            payload = (ROOT / "samples" / "synthetic_montoya_handoff_payload.json").read_bytes()
            connection.request("POST", INGEST_PATH, payload, {"Content-Type": "application/json"})
            response = connection.getresponse()
            metadata = json.loads(response.read())
            self.assertEqual(response.status, 202)
        finally:
            connection.close()
            receiver.shutdown()
            receiver.server_close()
            worker.join(5)
        project = "receiver/" + metadata["output_name"]
        output = self.root / project
        candidates = ai_review.list_review_candidates(output)
        selected = candidates[0]["finding_id"]
        with patch.object(ai_review, "_load_api_key", return_value=DUMMY_KEY), patch.object(ai_review, "_request_openai", return_value=model_response((selected,))) as send:
            status, body, _ = self.request("POST", "/ai-review/prepare", {"csrf_token": self.server.csrf_token, "project": project, "candidates": [selected]})
            self.assertEqual(status, 200)
            token = re.search(r'name="confirmation" value="([A-Za-z0-9_-]+)"', body)[1]
            status, _, headers = self.request("POST", "/ai-review/send", {"csrf_token": self.server.csrf_token, "confirmation": token, "consent": "yes"})
            self.assertEqual(status, 303)
            self.assertIn("Burp에서 확인할 방법", self.request("GET", headers["Location"])[1])
            text = json.dumps(send.call_args.args[0], ensure_ascii=False)
            self.assertNotIn("demo_receiver", text)
            self.assertNotIn("source_event_id", text)
            self.assertNotIn("raw_request", text)
            self.assertNotIn("example.test", text)
            self.assertNotIn(str(self.root), text)


if __name__ == "__main__":
    unittest.main()
