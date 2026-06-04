from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from burp_ai_redaction_gateway.cli import main
from burp_ai_redaction_gateway.parser import load_events
from burp_ai_redaction_gateway.policy import load_policy
from burp_ai_redaction_gateway.redaction import Redactor
from burp_ai_redaction_gateway.scanner import assert_no_sensitive_text, scan_text
from burp_ai_redaction_gateway.verifier import verify_path


ROOT = Path(__file__).resolve().parents[1]
SAMPLE = ROOT / "samples" / "synthetic_burp_history.json"
VARIANTS = ROOT / "samples" / "synthetic_burp_variants.json"
BURP_XML = ROOT / "samples" / "burp_xml_base64_history.xml"
REDACTION_EDGES = ROOT / "samples" / "synthetic_redaction_edges.json"


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
            self.assertTrue(any(item["type"] == "Potential Broken Access Control / IDOR" for item in candidates))
            for item in candidates:
                self.assertIn("evidence_ids", item)
                self.assertIn("confidence", item)
                self.assertIn("rationale", item)
                self.assertIn("recommended_manual_tests", item)

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
        for path in ["local_only", "out", "raw", "raw_vault", "exports", "reports"]:
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


if __name__ == "__main__":
    unittest.main()
