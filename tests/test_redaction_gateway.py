from __future__ import annotations

import hashlib
import http.client
import json
import tempfile
import threading
import unittest
from pathlib import Path

from burp_ai_redaction_gateway.cli import main
from burp_ai_redaction_gateway.parser import load_events
from burp_ai_redaction_gateway.policy import load_policy
from burp_ai_redaction_gateway.receiver import ReceiverConfig, ReceiverError, create_server, ingest_montoya_payload
from burp_ai_redaction_gateway.redaction import Redactor
from burp_ai_redaction_gateway.scanner import assert_no_sensitive_text, scan_text
from burp_ai_redaction_gateway.verifier import verify_path


ROOT = Path(__file__).resolve().parents[1]
SAMPLE = ROOT / "samples" / "synthetic_burp_history.json"
VARIANTS = ROOT / "samples" / "synthetic_burp_variants.json"
BURP_XML = ROOT / "samples" / "burp_xml_base64_history.xml"
REDACTION_EDGES = ROOT / "samples" / "synthetic_redaction_edges.json"
MONTOYA_DIR = ROOT / "extensions" / "montoya-collector"
MONTOYA_SOURCE_DIR = MONTOYA_DIR / "src" / "main" / "java" / "com" / "ryuyunseong" / "burpai" / "redactiongateway"
MONTOYA_DOC = ROOT / "docs" / "MONTOYA_COLLECTOR.md"
MONTOYA_SCOPE_FIXTURE = ROOT / "samples" / "synthetic_montoya_scope_inventory.json"
MONTOYA_HANDOFF = ROOT / "samples" / "synthetic_montoya_handoff_payload.json"
RECEIVER_DOC = ROOT / "docs" / "LOCALHOST_RECEIVER.md"
EXPECTED_PASSIVE_FINDING_TYPES = {
    "missing_security_headers",
    "weak_cookie_attributes",
    "cache_control_on_authenticated_response",
    "cors_candidate",
    "error_exposure",
    "idor_candidate",
    "sensitive_data_exposure_candidate",
}


class RedactionGatewayTests(unittest.TestCase):
    def test_sample_generates_required_outputs_without_raw_sensitive_values(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir)
            exit_code = main(
                [
                    "generate",
                    "--input",
                    str(SAMPLE),
                    "--output",
                    str(output),
                    "--project",
                    "client_alias_demo",
                ]
            )
            self.assertEqual(exit_code, 0)
            self.assertEqual(main(["verify", "--input", str(output)]), 0)
            for name in [
                "endpoint_inventory.md",
                "sanitized_events.jsonl",
                "finding_candidates.json",
                "analysis_packet.json",
                "chatgpt_prompt.md",
                "codex_task_prompt.md",
                "redaction_audit.json",
                "redaction_audit.db",
            ]:
                self.assertTrue((output / name).exists(), name)

            combined = "\n".join(
                (output / name).read_text(encoding="utf-8")
                for name in [
                    "endpoint_inventory.md",
                    "sanitized_events.jsonl",
                    "finding_candidates.json",
                    "analysis_packet.json",
                    "chatgpt_prompt.md",
                    "codex_task_prompt.md",
                    "redaction_audit.json",
                ]
            )
            assert_no_sensitive_text(combined)
            self.assertNotIn("alice@example.test", combined)
            self.assertNotIn("010-1234-5678", combined)
            self.assertNotIn("900101-1234567", combined)
            self.assertNotIn("demo-session-value", combined)
            self.assertNotIn("SignaturePartForDemoOnly123", combined)
            self.assertNotIn("portal.example.test", combined)

            audit = json.loads((output / "redaction_audit.json").read_text(encoding="utf-8"))
            metadata = audit["metadata"]
            self.assertEqual(metadata["raw_data_included"], False)
            self.assertIn("sanitizer_version", metadata)
            self.assertIn("policy_hash", metadata)
            self.assertIn("generated_at", metadata)
            self.assertEqual(metadata["source_event_count"], 10)
            self.assertIn("redaction_counts", metadata)
            self.assertEqual(metadata["scanner_result"]["status"], "passed")

    def test_path_and_query_values_are_templated_or_schema_only(self) -> None:
        events = load_events(SAMPLE)
        redactor = Redactor(load_policy(None))
        sanitized = [redactor.sanitize_event(event, index) for index, event in enumerate(events, start=1)]
        first = sanitized[0].to_dict()
        self.assertEqual(first["request"]["path_template"], "/api/users/{id}/profile")
        self.assertEqual(first["request"]["query_schema"]["view"]["type"], "string")
        self.assertTrue(first["request"]["query_schema"]["view"]["sample_removed"])

        second = sanitized[1].to_dict()
        self.assertEqual(second["request"]["path_template"], "/api/orders/{uuid}")
        self.assertEqual(second["request"]["query_schema"]["account"]["type"], "financial_id_redacted")
        self.assertEqual(second["request"]["query_schema"]["account"]["transformation"], "redacted_sensitive_parameter")

    def test_finding_candidates_include_required_fields(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir)
            main(["generate", "--input", str(SAMPLE), "--output", str(output), "--project", "client_alias_demo"])
            findings = json.loads((output / "finding_candidates.json").read_text(encoding="utf-8"))
            candidates = findings["finding_candidates"]
            candidate_types = {item["type"] for item in candidates}
            self.assertEqual(candidate_types, EXPECTED_PASSIVE_FINDING_TYPES)
            for item in candidates:
                self.assertIn("finding_id", item)
                self.assertRegex(item["finding_id"], r"^FC-\d{4}$")
                self.assertEqual(item["candidate_id"], item["finding_id"])
                self.assertIn("type", item)
                self.assertIn(item["type"], EXPECTED_PASSIVE_FINDING_TYPES)
                self.assertIn("affected_endpoint", item)
                self.assertIn("evidence_ids", item)
                self.assertIn("confidence", item)
                self.assertIn("rationale", item)
                self.assertIn("recommended_manual_tests", item)
                self.assertIn("do_not_claim", item)
                self.assertTrue(item["evidence_ids"])
                self.assertTrue(item["rationale"])
                self.assertTrue(item["recommended_manual_tests"])
                self.assertIn("Vulnerability confirmed", item["do_not_claim"])
                self.assertNotIn("raw_request", json.dumps(item))
                self.assertNotIn("raw_response", json.dumps(item))

    def test_analysis_packet_prompts_include_only_candidate_fields(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir)
            main(["generate", "--input", str(SAMPLE), "--output", str(output), "--project", "client_alias_demo"])
            packet = json.loads((output / "analysis_packet.json").read_text(encoding="utf-8"))
            self.assertEqual(packet["schema_version"], "analysis-prompt-packet-v1")
            self.assertEqual(packet["source"], "finding_candidates.json")
            self.assertFalse(packet["raw_data_included"])
            self.assertTrue(packet["use_only_after_verify_passed"])
            self.assertEqual(packet["candidate_count"], len(packet["finding_candidates"]))

            for candidate in packet["finding_candidates"]:
                for field in [
                    "summary",
                    "finding_id",
                    "type",
                    "confidence",
                    "affected_endpoint",
                    "evidence_ids",
                    "rationale",
                    "recommended_manual_tests",
                    "do_not_claim",
                ]:
                    self.assertIn(field, candidate)
                self.assertIn("candidate", candidate["summary"])
                self.assertNotIn("raw_request", json.dumps(candidate))
                self.assertNotIn("raw_response", json.dumps(candidate))

            chatgpt_prompt = (output / "chatgpt_prompt.md").read_text(encoding="utf-8")
            codex_prompt = (output / "codex_task_prompt.md").read_text(encoding="utf-8")
            for prompt in [chatgpt_prompt, codex_prompt]:
                self.assertIn("analysis-prompt-packet-v1", prompt)
                self.assertIn("finding_id", prompt)
                self.assertIn("evidence_ids", prompt)
                self.assertIn("affected_endpoint", prompt)
                self.assertIn("confidence", prompt)
                self.assertIn("rationale", prompt)
                self.assertIn("recommended_manual_tests", prompt)
                self.assertIn("do_not_claim", prompt)
                self.assertIn("candidate", prompt)
                self.assertNotIn("raw_request", prompt)
                self.assertNotIn("raw_response", prompt)
            assert_no_sensitive_text(chatgpt_prompt)
            assert_no_sensitive_text(codex_prompt)

    def test_fail_closed_scanner_detects_raw_secret_patterns(self) -> None:
        unsafe = (
            "Authorization: Bearer "
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
            "eyJzdWIiOiIxMjMifQ.SignaturePartForDemoOnly123"
        )
        self.assertTrue(scan_text(unsafe))
        with self.assertRaises(ValueError):
            assert_no_sensitive_text(unsafe)

    def test_variant_fixtures_generate_and_verify(self) -> None:
        for fixture in [VARIANTS, BURP_XML]:
            with self.subTest(fixture=fixture.name):
                with tempfile.TemporaryDirectory() as temp_dir:
                    output = Path(temp_dir)
                    self.assertEqual(
                        main(
                            [
                                "generate",
                                "--input",
                                str(fixture),
                                "--output",
                                str(output),
                                "--project",
                                "client_alias_demo",
                            ]
                        ),
                        0,
                    )
                    self.assertEqual(main(["verify", "--input", str(output)]), 0)
                    text = "\n".join(
                        path.read_text(encoding="utf-8")
                        for path in output.iterdir()
                        if path.suffix in {".json", ".jsonl", ".md", ".txt"}
                    )
                    self.assertNotIn("xml-client.example.test", text)
                    self.assertNotIn("xml-session-demo", text)
                    self.assertNotIn("FormPassword123", text)
                    self.assertNotIn("hidden-csrf-token", text)
                    self.assertNotIn("192.168.10.55", text)
                    self.assertNotIn("AbCdEfGhIjKlMnOpQrStUvWxYz1234567890abcdEFGH", text)

    def test_redaction_edge_fixture_generates_safe_diagnostics(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir)
            self.assertEqual(
                main(
                    [
                        "generate",
                        "--input",
                        str(REDACTION_EDGES),
                        "--output",
                        str(output),
                        "--project",
                        "client_alias_demo",
                    ]
                ),
                0,
            )
            self.assertEqual(main(["verify", "--input", str(output)]), 0)
            text = "\n".join(
                path.read_text(encoding="utf-8")
                for path in output.iterdir()
                if path.suffix in {".json", ".jsonl", ".md", ".txt"}
            )
            blocked_markers = [
                "FAKE-client.example.test",
                "DUMMY-callback.example.test",
                "DUMMY-origin.example.test",
                "DUMMY-referer.example.test",
                "EXAMPLE-redirect.example.test",
                "DUMMY_COOKIE_VALUE",
                "DUMMY_SET_COOKIE",
                "DUMMY_API_KEY",
                "DUMMY_AbCdEfGhIjKlMnOpQrStUvWxYz1234567890",
                "38cd434596c9b0.dict",
                "xjs.hd.ko",
            ]
            for marker in blocked_markers:
                self.assertNotIn(marker, text)
            assert_no_sensitive_text(text)

            events = [
                json.loads(line)
                for line in (output / "sanitized_events.jsonl").read_text(encoding="utf-8").splitlines()
            ]
            diagnostics = [
                item
                for event in events
                for item in event["redaction"].get("diagnostics", [])
            ]
            self.assertTrue(diagnostics)
            for item in diagnostics:
                self.assertEqual(item["value_preview"], "<REDACTED>")
                self.assertIn("failure_type", item)
                self.assertIn("event_id", item)
                self.assertIn("field_path", item)
                self.assertIn("source_kind", item)

    def test_verify_fails_on_raw_output_leakage(self) -> None:
        policy = load_policy(None)
        with tempfile.TemporaryDirectory() as temp_dir:
            leaked = Path(temp_dir) / "leaked.md"
            leaked.write_text(
                "Cookie: JSESSIONID=raw-cookie-value\n"
                "Authorization: Bearer rawBearerToken1234567890\n"
                "email: leaked-user@example.test\n"
                "internal: 192.168.44.12\n"
                "domain: customer.internal.test\n",
                encoding="utf-8",
            )
            result = verify_path(leaked, policy)
            self.assertFalse(result.passed)
            kinds = {finding.match.kind for finding in result.findings}
            self.assertIn("cookie_value", kinds)
            self.assertIn("bearer_token", kinds)
            self.assertIn("email", kinds)
            self.assertIn("internal_ip", kinds)
            self.assertIn("domain", kinds)

    def test_verify_allows_documented_network_buckets(self) -> None:
        policy = load_policy(None)
        with tempfile.TemporaryDirectory() as temp_dir:
            allowed = Path(temp_dir) / "allowed.md"
            # Policy allowlist note: network bucket only, not a raw internal host IP.
            allowed.write_text("internal network bucket: 10.0.0.0/8\n", encoding="utf-8")
            result = verify_path(allowed, policy)
            self.assertTrue(result.passed)

    def test_gitignore_blocks_local_raw_and_generated_data(self) -> None:
        gitignore = (ROOT / ".gitignore").read_text(encoding="utf-8")
        required_patterns = [
            "out/",
            "reports/",
            "exports/",
            "local_only/",
            "raw/",
            "raw_vault/",
            "*.burp",
            "*.burp-project",
            "*.har",
            "*_raw.*",
            "*raw_history*",
            "*burp_history_raw*",
            ".env",
            ".env.*",
            "*.key",
            "*.pem",
            "*.p12",
            "*.pfx",
            "secrets.*",
            "client_*",
            "customer_*",
            "extensions/**/.gradle/",
            "extensions/**/build/",
            "extensions/**/*.jar",
            "!extensions/**/gradle/wrapper/gradle-wrapper.jar",
            "*.class",
        ]
        for pattern in required_patterns:
            self.assertIn(pattern, gitignore)

    def test_pre_commit_scripts_and_gitleaks_config_exist(self) -> None:
        self.assertTrue((ROOT / "scripts" / "pre_commit_check.bat").is_file())
        self.assertTrue((ROOT / "scripts" / "pre_commit_check.sh").is_file())
        self.assertTrue((ROOT / "scripts" / "git_safety_check.bat").is_file())
        self.assertTrue((ROOT / "scripts" / "git_safety_check.sh").is_file())
        self.assertTrue((ROOT / "scripts" / "make_safe_burp_export_sample.py").is_file())
        self.assertTrue((ROOT / "scripts" / "run_safe_sample_smoke_test.bat").is_file())
        self.assertTrue((ROOT / "scripts" / "run_safe_sample_smoke_test.sh").is_file())
        self.assertTrue((ROOT / ".gitleaks.toml").is_file())

    def test_gitleaks_scope_and_redaction_are_documented_in_repo_files(self) -> None:
        config = (ROOT / ".gitleaks.toml").read_text(encoding="utf-8")
        for path in ["local_only", "out", "raw", "raw_vault", "exports", "reports", "extensions"]:
            self.assertIn(path, config)

        pre_commit_bat = (ROOT / "scripts" / "pre_commit_check.bat").read_text(encoding="utf-8")
        pre_commit_sh = (ROOT / "scripts" / "pre_commit_check.sh").read_text(encoding="utf-8")
        self.assertIn("--redact=100", pre_commit_bat)
        self.assertIn("--redact=100", pre_commit_sh)
        self.assertIn("--config .gitleaks.toml", pre_commit_bat)
        self.assertIn("--config .gitleaks.toml", pre_commit_sh)

        sample = SAMPLE.read_text(encoding="utf-8")
        self.assertNotIn("test_api_key_1234567890abcdef", sample)

    def test_security_model_documents_raw_data_boundary(self) -> None:
        security_model = (ROOT / "docs" / "SECURITY_MODEL.md").read_text(encoding="utf-8")
        real_testing = (ROOT / "docs" / "REAL_BURP_EXPORT_TESTING.md").read_text(encoding="utf-8")
        self.assertIn("Raw data must not be sent to AI", security_model)
        self.assertIn("Raw HTTP request or response", security_model)
        self.assertIn("fail-closed", security_model.lower())
        self.assertIn("local_only/", real_testing)
        self.assertIn("Do not move real exports into `samples/`", real_testing)

    def test_git_workflow_documents_safety_gate(self) -> None:
        workflow = (ROOT / "docs" / "GIT_WORKFLOW.md").read_text(encoding="utf-8")
        self.assertIn("git check-ignore", workflow)
        self.assertIn("local_only", workflow)
        self.assertIn("raw_vault", workflow)
        self.assertIn("pre_commit_check", workflow)
        self.assertIn("gitleaks dir -v --redact=100", workflow)
        self.assertIn(".gitleaks.toml", workflow)

    def test_real_like_smoke_test_is_documented_as_synthetic_only(self) -> None:
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        real_testing = (ROOT / "docs" / "REAL_BURP_EXPORT_TESTING.md").read_text(encoding="utf-8")
        self.assertIn("Real-Like Smoke Test", readme)
        self.assertIn("not a substitute for", readme)
        self.assertIn("Safe Real-Like Smoke Test", real_testing)
        self.assertIn("not a real Burp export compatibility test", real_testing)

    def test_montoya_handoff_payload_is_redacted_and_verified(self) -> None:
        payload = json.loads(MONTOYA_HANDOFF.read_text(encoding="utf-8"))
        with tempfile.TemporaryDirectory() as temp_dir:
            output_root = Path(temp_dir)
            result = ingest_montoya_payload(
                payload,
                ReceiverConfig(output_dir=output_root, project="montoya_receiver_alias"),
            )
            self.assertEqual(result.status, "accepted")
            self.assertEqual(result.evidence_id, "EV-0001")
            self.assertEqual(result.files_written, 8)
            self.assertFalse(result.raw_data_included)
            self.assertEqual(main(["verify", "--input", str(output_root)]), 0)

            text = "\n".join(
                path.read_text(encoding="utf-8")
                for path in output_root.rglob("*")
                if path.suffix in {".json", ".jsonl", ".md", ".txt"}
            )
            blocked_markers = [
                "FAKE-client.example.test",
                "DUMMY_QUERY_TOKEN",
                "DUMMY_BEARER_TOKEN",
                "DUMMY_COOKIE_VALUE",
                "DUMMY_SET_COOKIE",
                "DUMMY-user@example.test",
                "010-0000-0000",
                "DUMMY_ACCOUNT_12345",
            ]
            for marker in blocked_markers:
                self.assertNotIn(marker, text)
            assert_no_sensitive_text(text)

    def test_receiver_rejects_non_loopback_bind_and_bad_schema(self) -> None:
        payload = json.loads(MONTOYA_HANDOFF.read_text(encoding="utf-8"))
        with tempfile.TemporaryDirectory() as temp_dir:
            config = ReceiverConfig(output_dir=Path(temp_dir), project="montoya_receiver_alias")
            with self.assertRaises(ReceiverError) as bind_error:
                create_server("0.0.0.0", 0, config)
            self.assertEqual(bind_error.exception.error_type, "non_loopback_bind_rejected")

            bad_payload = dict(payload)
            bad_payload["source_event_id"] = "https://FAKE-client.example.test/raw"
            with self.assertRaises(ValueError):
                ingest_montoya_payload(bad_payload, config)

            out_of_scope = dict(payload)
            out_of_scope["in_scope"] = False
            with self.assertRaises(ReceiverError) as schema_error:
                ingest_montoya_payload(out_of_scope, config)
            self.assertEqual(schema_error.exception.error_type, "out_of_scope_rejected")

    def test_http_receiver_accepts_loopback_json_and_rejects_oversized_payload(self) -> None:
        payload = json.loads(MONTOYA_HANDOFF.read_text(encoding="utf-8"))
        with tempfile.TemporaryDirectory() as temp_dir:
            config = ReceiverConfig(output_dir=Path(temp_dir), project="montoya_receiver_alias", max_body_bytes=20000)
            server = create_server("127.0.0.1", 0, config)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                port = server.server_address[1]
                connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                body = json.dumps(payload).encode("utf-8")
                connection.request(
                    "POST",
                    "/ingest/burp-history",
                    body=body,
                    headers={"Content-Type": "application/json; charset=utf-8"},
                )
                response = connection.getresponse()
                response_body = json.loads(response.read().decode("utf-8"))
                self.assertEqual(response.status, 202)
                self.assertEqual(response_body["status"], "accepted")
                self.assertEqual(response_body["raw_data_included"], False)
                self.assertNotIn("request", response_body)
                self.assertNotIn("response", response_body)
                connection.close()

                small_config_server = create_server(
                    "127.0.0.1",
                    0,
                    ReceiverConfig(output_dir=Path(temp_dir), project="montoya_receiver_alias", max_body_bytes=16),
                )
                small_thread = threading.Thread(target=small_config_server.serve_forever, daemon=True)
                small_thread.start()
                try:
                    small_port = small_config_server.server_address[1]
                    small_connection = http.client.HTTPConnection("127.0.0.1", small_port, timeout=5)
                    small_connection.request(
                        "POST",
                        "/ingest/burp-history",
                        body=body,
                        headers={"Content-Type": "application/json"},
                    )
                    small_response = small_connection.getresponse()
                    small_body = json.loads(small_response.read().decode("utf-8"))
                    self.assertEqual(small_response.status, 413)
                    self.assertEqual(small_body["error_type"], "payload_too_large")
                    small_connection.close()
                finally:
                    small_config_server.shutdown()
                    small_config_server.server_close()
                    small_thread.join(timeout=5)
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)

    def test_montoya_collector_gradle_project_exists(self) -> None:
        self.assertTrue((MONTOYA_DIR / "settings.gradle").is_file())
        build_gradle = (MONTOYA_DIR / "build.gradle").read_text(encoding="utf-8")
        self.assertIn("id 'java'", build_gradle)
        self.assertIn("compileOnly 'net.portswigger.burp.extensions:montoya-api:2026.4'", build_gradle)
        self.assertIn("sourceCompatibility = JavaVersion.VERSION_17", build_gradle)
        self.assertIn("options.release = 17", build_gradle)
        self.assertIn("burp-ai-redaction-gateway-montoya-collector", build_gradle)

    def test_montoya_collector_gradle_wrapper_is_pinned(self) -> None:
        self.assertTrue((MONTOYA_DIR / "gradlew").is_file())
        self.assertTrue((MONTOYA_DIR / "gradlew.bat").is_file())
        wrapper_jar = MONTOYA_DIR / "gradle" / "wrapper" / "gradle-wrapper.jar"
        self.assertTrue(wrapper_jar.is_file())
        wrapper_hash = hashlib.sha256(wrapper_jar.read_bytes()).hexdigest()
        self.assertEqual(wrapper_hash, "497c8c2a7e5031f6aa847f88104aa80a93532ec32ee17bdb8d1d2f67a194a9c7")

        wrapper = (MONTOYA_DIR / "gradle" / "wrapper" / "gradle-wrapper.properties").read_text(encoding="utf-8")
        self.assertIn("distributionUrl=https\\://services.gradle.org/distributions/gradle-9.5.1-bin.zip", wrapper)
        self.assertIn(
            "distributionSha256Sum=bafc141b619ad6350fd975fc903156dd5c151998cc8b058e8c1044ab5f7b031f",
            wrapper,
        )

    def test_montoya_collector_uses_scope_only_loopback_handoff(self) -> None:
        source = "\n".join(path.read_text(encoding="utf-8") for path in MONTOYA_SOURCE_DIR.glob("*.java"))
        self.assertIn("implements BurpExtension", source)
        self.assertIn("api.proxy()", source)
        self.assertIn("proxy.history(requestResponse ->", source)
        self.assertIn("requestResponse.request().isInScope()", source)
        self.assertIn("raw_transport", source)
        self.assertIn("loopback_localhost", source)
        self.assertIn("isLoopbackHost", source)
        self.assertIn("127.0.0.1", source)
        self.assertIn("BURP_AI_REDACTION_GATEWAY_URL", source)

        banned_log_patterns = [
            "logToOutput(item.request",
            "logToOutput(item.response",
            "logToError(item.request",
            "logToError(item.response",
            "logToOutput(payload",
            "logToError(payload",
        ]
        for pattern in banned_log_patterns:
            self.assertNotIn(pattern, source)

        banned_storage_patterns = [
            "FileWriter",
            "FileOutputStream",
            "Files.write",
            "Path.of",
            "createTempFile",
        ]
        for pattern in banned_storage_patterns:
            self.assertNotIn(pattern, source)

    def test_montoya_collector_docs_and_fixture_keep_raw_boundary(self) -> None:
        doc = MONTOYA_DOC.read_text(encoding="utf-8")
        self.assertIn("accepts only items whose request is in Burp suite scope", doc)
        self.assertIn("Raw request and response values are never logged", doc)
        self.assertIn(".\\gradlew.bat clean build", doc)
        self.assertIn("Extensions -> Installed", doc)
        self.assertIn("loopback", doc)
        self.assertIn("non-loopback URLs", doc)
        self.assertIn("verify", doc)

        fixture = json.loads(MONTOYA_SCOPE_FIXTURE.read_text(encoding="utf-8"))
        self.assertEqual(fixture["schema_version"], "montoya-scope-inventory-v1")
        self.assertTrue(all(item["in_scope"] for item in fixture["items"]))
        self.assertTrue(all(item["raw_values_included"] is False for item in fixture["items"]))
        self.assertNotIn("raw_request", json.dumps(fixture))
        self.assertNotIn("raw_response", json.dumps(fixture))

    def test_localhost_receiver_is_documented(self) -> None:
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        doc = RECEIVER_DOC.read_text(encoding="utf-8")
        for text in [readme, doc]:
            self.assertIn("serve --host 127.0.0.1 --port 8765", text)
            self.assertIn("/ingest/burp-history", text)
        self.assertIn("Raw request and response values are not logged", doc)
        self.assertIn("Oversized payloads are rejected", doc)


if __name__ == "__main__":
    unittest.main()
