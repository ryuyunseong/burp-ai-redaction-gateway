from __future__ import annotations

import gzip
import hashlib
import http.client
import io
import json
import re
import tempfile
import threading
import unittest
import uuid
from copy import deepcopy
from contextlib import redirect_stdout
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch
from urllib.parse import urlencode

from burp_ai_redaction_gateway.audit_compressed_hmac import (
    AuditCompressedHmacError,
    create_compressed_audit_hmac_manifest,
    verify_compressed_audit_hmac_manifest,
)
from burp_ai_redaction_gateway.audit_compression import (
    AuditCompressionError,
    compress_audit_jsonl,
    verify_compressed_audit_jsonl,
)
from burp_ai_redaction_gateway.audit_hmac import (
    AuditHmacError,
    create_audit_hmac_manifest,
    verify_audit_hmac_manifest,
)
from burp_ai_redaction_gateway.audit_retention import AuditRetentionError, apply_audit_retention
from burp_ai_redaction_gateway.audit_review import review_audit_path
from burp_ai_redaction_gateway.cli import main
from burp_ai_redaction_gateway.dashboard import (
    DashboardConfig,
    DashboardError,
    create_dashboard_server,
    write_dashboard_action_audit_event,
)
from burp_ai_redaction_gateway.findings import build_finding_candidates
from burp_ai_redaction_gateway.mcp_server import ReadOnlyMcpGateway, ReadOnlyMcpServer, _next_rotated_audit_path
from burp_ai_redaction_gateway.models import SanitizedEvent
from burp_ai_redaction_gateway.parser import load_events
from burp_ai_redaction_gateway.policy import load_policy
from burp_ai_redaction_gateway.receiver import ReceiverConfig, ReceiverError, create_server, ingest_montoya_payload
from burp_ai_redaction_gateway.redaction import Redactor
from burp_ai_redaction_gateway.risk import RISK_RATING_PROFILE_NAMES, build_risk_rating_draft
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
    def assert_audit_hash_chain(
        self, audit_events: list[dict[str, object]], *, allow_prefix_gap: bool = False
    ) -> None:
        self.assertTrue(audit_events)
        previous_hash = audit_events[0]["prev_event_hash"] if allow_prefix_gap else None
        chain_id = None
        start_sequence = int(audit_events[0]["sequence_no"]) if allow_prefix_gap else 1
        for index, event in enumerate(audit_events, start=start_sequence):
            self.assertEqual(event["audit_schema_version"], "1.1")
            uuid.UUID(str(event["event_id"]))
            self.assertEqual(event["sequence_no"], index)
            self.assertEqual(event["hash_algorithm"], "SHA-256")
            self.assertEqual(event["prev_event_hash"], previous_hash)
            if chain_id is None:
                chain_id = event["chain_id"]
                self.assertIsInstance(chain_id, str)
                self.assertTrue(str(chain_id).startswith("mcp-audit-"))
            else:
                self.assertEqual(event["chain_id"], chain_id)
            body = {key: value for key, value in event.items() if key != "event_hash"}
            canonical = json.dumps(body, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
            expected_hash = "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()
            self.assertEqual(event["event_hash"], expected_hash)
            previous_hash = event["event_hash"]

    def read_audit_events(self, audit_files: list[Path]) -> list[dict[str, object]]:
        events = []
        for audit_file in audit_files:
            text = audit_file.read_text(encoding="utf-8")
            assert_no_sensitive_text(text)
            events.extend(json.loads(line) for line in text.splitlines() if line.strip())
        return events

    def write_audit_events(self, audit_file: Path, events: list[dict[str, object]]) -> None:
        audit_file.parent.mkdir(parents=True, exist_ok=True)
        audit_file.write_text(
            "\n".join(json.dumps(event, ensure_ascii=True, sort_keys=True) for event in events) + "\n",
            encoding="utf-8",
        )

    def generated_audit_dir(self, root: Path, *, request_count: int = 3, rotate: bool = False) -> Path:
        output = root / "generated"
        main(["generate", "--input", str(SAMPLE), "--output", str(output), "--project", "client_alias_demo"])
        server = ReadOnlyMcpServer(
            ReadOnlyMcpGateway(root, load_policy(None)),
            audit_stream=io.StringIO(),
            audit_max_bytes=1 if rotate else 10 * 1024 * 1024,
            audit_max_rotated_files=2 if rotate else 20,
        )
        for request_id in range(1, request_count + 1):
            response = server.handle_message(
                {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "method": "tools/call",
                    "params": {"name": "list_prompt_files", "arguments": {"project": "generated"}},
                }
            )
            self.assertFalse(response["result"]["isError"])
        return root / ".audit"

    def audit_event(
        self,
        *,
        sequence_no: int,
        timestamp_utc: str,
        prev_event_hash: str | None,
        chain_id: str = "mcp-audit-20260605",
    ) -> dict[str, object]:
        event: dict[str, object] = {
            "audit_schema_version": "1.1",
            "event_id": str(uuid.uuid4()),
            "sequence_no": sequence_no,
            "chain_id": chain_id,
            "prev_event_hash": prev_event_hash,
            "hash_algorithm": "SHA-256",
            "event_type": "mcp_tool_call",
            "timestamp_utc": timestamp_utc,
            "tool_name": "list_prompt_files",
            "output_id": "demo",
            "result_status": "success",
            "response_class": "prompt_file_list",
            "raw_data_included": False,
        }
        body = {key: value for key, value in event.items() if key != "event_hash"}
        canonical = json.dumps(body, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
        event["event_hash"] = "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        return event

    def audit_event_chain(self, timestamps: list[str]) -> list[dict[str, object]]:
        events = []
        previous_hash = None
        for sequence_no, timestamp in enumerate(timestamps, start=1):
            event = self.audit_event(
                sequence_no=sequence_no,
                timestamp_utc=timestamp,
                prev_event_hash=previous_hash,
            )
            events.append(event)
            previous_hash = str(event["event_hash"])
        return events

    def test_audit_hash_chain_helper_detects_deletion_reorder_and_mutation(self) -> None:
        events = [
            {
                "audit_schema_version": "1.1",
                "event_id": str(uuid.uuid4()),
                "sequence_no": 1,
                "chain_id": "mcp-audit-20260605",
                "prev_event_hash": None,
                "hash_algorithm": "SHA-256",
                "event_type": "mcp_tool_call",
                "timestamp_utc": "2026-06-05T00:00:00Z",
                "tool_name": "list_prompt_files",
                "output_id": "demo",
                "result_status": "success",
                "response_class": "prompt_file_list",
                "raw_data_included": False,
            },
            {
                "audit_schema_version": "1.1",
                "event_id": str(uuid.uuid4()),
                "sequence_no": 2,
                "chain_id": "mcp-audit-20260605",
                "prev_event_hash": "",
                "hash_algorithm": "SHA-256",
                "event_type": "mcp_tool_call",
                "timestamp_utc": "2026-06-05T00:00:01Z",
                "tool_name": "get_report_draft",
                "output_id": "demo",
                "result_status": "success",
                "response_class": "report_draft",
                "raw_data_included": False,
            },
            {
                "audit_schema_version": "1.1",
                "event_id": str(uuid.uuid4()),
                "sequence_no": 3,
                "chain_id": "mcp-audit-20260605",
                "prev_event_hash": "",
                "hash_algorithm": "SHA-256",
                "event_type": "mcp_tool_call",
                "timestamp_utc": "2026-06-05T00:00:02Z",
                "tool_name": "list_findings",
                "output_id": "demo",
                "result_status": "success",
                "response_class": "finding_summary",
                "raw_data_included": False,
            },
        ]
        previous_hash = None
        for event in events:
            event["prev_event_hash"] = previous_hash
            body = {key: value for key, value in event.items() if key != "event_hash"}
            canonical = json.dumps(body, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
            event["event_hash"] = "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()
            previous_hash = event["event_hash"]

        self.assert_audit_hash_chain(events)
        with self.assertRaises(AssertionError):
            self.assert_audit_hash_chain([events[0], events[2]])
        with self.assertRaises(AssertionError):
            self.assert_audit_hash_chain([events[1], events[0], events[2]])
        mutated = [dict(event) for event in events]
        mutated[1]["result_status"] = "blocked"
        with self.assertRaises(AssertionError):
            self.assert_audit_hash_chain(mutated)

    def test_scanner_allows_standard_uuid_only_in_event_id_field(self) -> None:
        numeric_uuid = "01012345-6789-1111-2222-333344444444"
        self.assertTrue(scan_text(numeric_uuid))
        assert_no_sensitive_text(json.dumps({"event_id": numeric_uuid}, ensure_ascii=True))

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
            self.assertEqual(findings["risk_rating_profile"], "conservative")
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
                self.assertIn(item["confidence"], {"low", "medium"})
                self.assertIn("confidence_rationale", item)
                self.assertIn("risk_rating_draft", item)
                self.assertIn("manual_verification_required", item)
                self.assertIn("rationale", item)
                self.assertIn("recommended_manual_tests", item)
                self.assertIn("do_not_claim", item)
                self.assertTrue(item["evidence_ids"])
                self.assertTrue(item["confidence_rationale"])
                self.assertTrue(item["manual_verification_required"])
                self.assertTrue(item["rationale"])
                self.assertTrue(item["recommended_manual_tests"])
                self.assertIn("Vulnerability confirmed", item["do_not_claim"])
                risk_draft = item["risk_rating_draft"]
                self.assertEqual(risk_draft["schema_version"], "risk-rating-draft-v1")
                self.assertEqual(risk_draft["risk_profile"], "conservative")
                self.assertIn(risk_draft["risk_profile"], RISK_RATING_PROFILE_NAMES)
                self.assertIn("risk_profile_conservatism", risk_draft)
                self.assertIn(risk_draft["likelihood_draft"], {"low", "medium", "unknown"})
                self.assertIn(risk_draft["impact_draft"], {"low", "medium", "unknown"})
                self.assertIn(risk_draft["severity_draft"], {"low", "medium", "unknown"})
                self.assertEqual(risk_draft["evidence_confidence"], item["confidence"])
                self.assertFalse(risk_draft["confidence_is_severity"])
                self.assertFalse(risk_draft["risk_rating_finalized"])
                self.assertTrue(risk_draft["manual_verification_required"])
                self.assertTrue(risk_draft["severity_basis"])
                self.assertNotIn("raw_request", json.dumps(item))
                self.assertNotIn("raw_response", json.dumps(item))
            weak_sensitive_candidate = next(
                item
                for item in candidates
                if item["type"] == "sensitive_data_exposure_candidate" and item["evidence_ids"] == ["EV-0002"]
            )
            self.assertEqual(weak_sensitive_candidate["confidence"], "medium")
            idor_candidate = next(item for item in candidates if item["type"] == "idor_candidate")
            self.assertEqual(idor_candidate["confidence"], "medium")
            self.assertEqual(idor_candidate["risk_rating_draft"]["severity_draft"], "medium")

    def test_risk_rating_profiles_remain_draft_and_adjust_conservatism(self) -> None:
        conservative = build_risk_rating_draft("idor_candidate", "medium", "conservative")
        consultant = build_risk_rating_draft("idor_candidate", "medium", "consultant")
        strict = build_risk_rating_draft("idor_candidate", "medium", "strict")

        self.assertEqual(conservative["risk_profile"], "conservative")
        self.assertEqual(consultant["risk_profile"], "consultant")
        self.assertEqual(strict["risk_profile"], "strict")
        self.assertEqual(conservative["severity_draft"], "medium")
        self.assertEqual(consultant["severity_draft"], "medium")
        self.assertEqual(strict["likelihood_draft"], "high")
        self.assertEqual(strict["severity_draft"], "high")
        for draft in [conservative, consultant, strict]:
            self.assertFalse(draft["confidence_is_severity"])
            self.assertFalse(draft["risk_rating_finalized"])
            self.assertTrue(draft["manual_verification_required"])
            self.assertIn("Severity decision made", draft["do_not_claim"])

    def test_generate_accepts_risk_rating_profile_option(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir)
            main(
                [
                    "generate",
                    "--input",
                    str(SAMPLE),
                    "--output",
                    str(output),
                    "--project",
                    "client_alias_demo",
                    "--risk-profile",
                    "strict",
                ]
            )
            findings = json.loads((output / "finding_candidates.json").read_text(encoding="utf-8"))
            packet = json.loads((output / "analysis_packet.json").read_text(encoding="utf-8"))
            self.assertEqual(findings["risk_rating_profile"], "strict")
            self.assertEqual(packet["risk_rating_profile"], "strict")
            idor_candidate = next(item for item in findings["finding_candidates"] if item["type"] == "idor_candidate")
            self.assertEqual(idor_candidate["risk_rating_draft"]["risk_profile"], "strict")
            self.assertEqual(idor_candidate["risk_rating_draft"]["severity_draft"], "high")
            self.assertFalse(idor_candidate["risk_rating_draft"]["risk_rating_finalized"])

    def test_schema_only_sensitive_data_candidate_stays_low_confidence(self) -> None:
        event = SanitizedEvent(
            evidence_id="EV-9001",
            raw_reference="LOCAL_ONLY:synthetic-low-confidence",
            raw_values_included=False,
            request={
                "method": "GET",
                "host": "host_001",
                "path_template": "/public/profile",
                "headers": {},
                "query_schema": {},
                "body_schema": {"type": "empty"},
            },
            response={
                "status": 200,
                "headers": {},
                "body_schema": {"type": "json", "fields": {"supportEmail": "<EMAIL>"}},
            },
            redaction={"strategy": "allowlist_schema_only", "counts": {}, "diagnostics": []},
            signals={
                "method": "GET",
                "host_alias": "host_001",
                "path_template": "/public/profile",
                "query_param_names": [],
                "identifier_observed": False,
                "auth_observed": False,
                "status": 200,
                "content_type": "application/json",
                "response_security_headers": {
                    "Strict-Transport-Security": True,
                    "X-Content-Type-Options": True,
                    "Content-Security-Policy": True,
                    "X-Frame-Options": True,
                },
                "set_cookie_security": [],
                "cors": {},
                "cache_control": "public, max-age=3600",
                "allow_methods": "",
                "response_sensitive_fields": ["$.supportEmail"],
                "user_specific_response": False,
                "error_snippet_present": False,
            },
        )
        findings = build_finding_candidates([event])
        candidate = next(item for item in findings["finding_candidates"] if item["type"] == "sensitive_data_exposure_candidate")
        self.assertEqual(candidate["confidence"], "low")
        self.assertIn("Authenticated or user-specific context observed: False.", candidate["confidence_rationale"])
        self.assertTrue(candidate["manual_verification_required"])
        self.assertEqual(candidate["risk_rating_draft"]["evidence_confidence"], "low")
        self.assertFalse(candidate["risk_rating_draft"]["confidence_is_severity"])

    def test_analysis_packet_prompts_include_only_candidate_fields(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir)
            main(["generate", "--input", str(SAMPLE), "--output", str(output), "--project", "client_alias_demo"])
            packet = json.loads((output / "analysis_packet.json").read_text(encoding="utf-8"))
            self.assertEqual(packet["schema_version"], "analysis-prompt-packet-v1")
            self.assertEqual(packet["source"], "finding_candidates.json")
            self.assertFalse(packet["raw_data_included"])
            self.assertTrue(packet["use_only_after_verify_passed"])
            self.assertEqual(packet["risk_rating_profile"], "conservative")
            self.assertEqual(packet["candidate_count"], len(packet["finding_candidates"]))

            for candidate in packet["finding_candidates"]:
                for field in [
                    "summary",
                    "finding_id",
                    "type",
                    "confidence",
                    "confidence_rationale",
                    "risk_rating_draft",
                    "manual_verification_required",
                    "affected_endpoint",
                    "evidence_ids",
                    "rationale",
                    "recommended_manual_tests",
                    "do_not_claim",
                ]:
                    self.assertIn(field, candidate)
                self.assertIn("candidate", candidate["summary"])
                self.assertEqual(candidate["risk_rating_draft"]["risk_profile"], "conservative")
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
                self.assertIn("confidence_rationale", prompt)
                self.assertIn("risk_rating_draft", prompt)
                self.assertIn("risk_profile", prompt)
                self.assertIn("draft-only", prompt)
                self.assertIn("manual_verification_required", prompt)
                self.assertIn("rationale", prompt)
                self.assertIn("recommended_manual_tests", prompt)
                self.assertIn("do_not_claim", prompt)
                self.assertIn("candidate", prompt)
                self.assertNotIn("raw_request", prompt)
                self.assertNotIn("raw_response", prompt)
            assert_no_sensitive_text(chatgpt_prompt)
            assert_no_sensitive_text(codex_prompt)

    def test_review_command_summarizes_verified_output_and_exports_prompts(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            output = root / "generated"
            export_dir = root / "review_export"
            main(["generate", "--input", str(SAMPLE), "--output", str(output), "--project", "client_alias_demo"])

            buffer = io.StringIO()
            with redirect_stdout(buffer):
                exit_code = main(["review", "--input", str(output), "--export-dir", str(export_dir)])
            self.assertEqual(exit_code, 0)
            text = buffer.getvalue()
            self.assertIn("Review summary", text)
            self.assertIn("Verification: passed", text)
            self.assertIn("Raw data included: false", text)
            self.assertIn("Candidate count:", text)
            self.assertIn("missing_security_headers", text)
            self.assertIn("do_not_claim", text.lower())
            self.assertNotIn("raw_request", text)
            self.assertNotIn("raw_response", text)
            assert_no_sensitive_text(text)

            for name in ["analysis_packet.json", "chatgpt_prompt.md", "codex_task_prompt.md"]:
                copied = export_dir / name
                self.assertTrue(copied.is_file(), name)
                assert_no_sensitive_text(copied.read_text(encoding="utf-8"))

    def test_review_command_blocks_export_when_verify_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            output = root / "generated"
            export_dir = root / "review_export"
            main(["generate", "--input", str(SAMPLE), "--output", str(output), "--project", "client_alias_demo"])
            (output / "unsafe.md").write_text("Authorization: Bearer rawBearerToken1234567890\n", encoding="utf-8")

            buffer = io.StringIO()
            with redirect_stdout(buffer):
                exit_code = main(["review", "--input", str(output), "--export-dir", str(export_dir)])
            self.assertEqual(exit_code, 1)
            text = buffer.getvalue()
            self.assertIn("Review failed: verification_failed", text)
            self.assertFalse(export_dir.exists())

    def test_report_command_generates_cautious_candidate_draft(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            output = root / "generated"
            report_path = root / "report_draft.md"
            main(["generate", "--input", str(SAMPLE), "--output", str(output), "--project", "client_alias_demo"])

            buffer = io.StringIO()
            with redirect_stdout(buffer):
                exit_code = main(["report", "--input", str(output), "--output", str(report_path)])
            self.assertEqual(exit_code, 0)
            self.assertTrue(report_path.is_file())
            stdout = buffer.getvalue()
            self.assertIn("Report draft written: <report_draft_path>", stdout)
            self.assertIn("Profile: conservative", stdout)
            self.assertIn("Raw data included: false", stdout)
            self.assertNotIn(str(report_path), stdout)

            text = report_path.read_text(encoding="utf-8")
            self.assertIn("# Sanitized Candidate Report Draft", text)
            self.assertIn("Report profile: conservative", text)
            self.assertIn("Candidate status: suspected, requires manual verification", text)
            self.assertIn("Evidence confidence:", text)
            self.assertIn("### Rationale", text)
            self.assertIn("### Confidence Rationale", text)
            self.assertIn("### Risk Rating Draft", text)
            self.assertIn("Risk profile: conservative", text)
            self.assertIn("Profile conservatism: most_cautious", text)
            self.assertIn("Severity draft:", text)
            self.assertIn("Risk rating finalized: false", text)
            self.assertIn("Confidence is severity: false", text)
            self.assertIn("### Impact Draft", text)
            self.assertIn("### Additional Verification Steps", text)
            self.assertIn("### Remediation Draft", text)
            self.assertIn("### Claims Not Allowed Before Proof", text)
            self.assertIn("Manual verification required: true", text)
            self.assertIn("missing_security_headers", text)
            self.assertIn("EV-0001", text)
            self.assertIn("not a confirmed vulnerability report", text.lower())
            self.assertNotIn("is a confirmed vulnerability report", text.lower())
            self.assertNotIn("raw_request", text)
            self.assertNotIn("raw_response", text)
            assert_no_sensitive_text(text)

    def test_report_command_supports_consultant_profile_without_confirmed_claims(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            output = root / "generated"
            report_path = root / "consultant_report_draft.md"
            main(["generate", "--input", str(SAMPLE), "--output", str(output), "--project", "client_alias_demo"])

            buffer = io.StringIO()
            with redirect_stdout(buffer):
                exit_code = main(
                    [
                        "report",
                        "--input",
                        str(output),
                        "--output",
                        str(report_path),
                        "--profile",
                        "consultant",
                    ]
                )
            self.assertEqual(exit_code, 0)
            stdout = buffer.getvalue()
            self.assertIn("Profile: consultant", stdout)
            self.assertNotIn(str(report_path), stdout)

            text = report_path.read_text(encoding="utf-8")
            self.assertIn("# Sanitized Consultant Report Draft", text)
            self.assertIn("Report profile: consultant", text)
            self.assertIn("Suspected finding status: candidate only, manual verification required", text)
            self.assertIn("Evidence confidence:", text)
            self.assertIn("### Risk Rating Draft", text)
            self.assertIn("Risk profile: conservative", text)
            self.assertIn("Severity draft:", text)
            self.assertIn("Risk rating finalized: false", text)
            self.assertIn("Manual verification required: true", text)
            self.assertIn("### Assessment Rationale", text)
            self.assertIn("### Potential Impact If Confirmed", text)
            self.assertIn("### Required Manual Verification", text)
            self.assertIn("### Recommended Remediation Draft", text)
            self.assertIn("### Claims To Avoid Before Verification", text)
            self.assertIn("not a confirmed vulnerability report", text.lower())
            self.assertNotIn("is a confirmed vulnerability report", text.lower())
            self.assertNotIn("raw_request", text)
            self.assertNotIn("raw_response", text)
            assert_no_sensitive_text(text)

    def test_report_command_blocks_draft_when_verify_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            output = root / "generated"
            report_path = root / "report_draft.md"
            main(["generate", "--input", str(SAMPLE), "--output", str(output), "--project", "client_alias_demo"])
            (output / "unsafe.md").write_text("Authorization: Bearer rawBearerToken1234567890\n", encoding="utf-8")

            buffer = io.StringIO()
            with redirect_stdout(buffer):
                exit_code = main(["report", "--input", str(output), "--output", str(report_path)])
            self.assertEqual(exit_code, 1)
            self.assertIn("Report draft failed: verification_failed", buffer.getvalue())
            self.assertFalse(report_path.exists())

    def test_dashboard_lists_verified_output_and_previews_safe_files(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            output = root / "generated"
            main(["generate", "--input", str(SAMPLE), "--output", str(output), "--project", "client_alias_demo"])
            main(["report", "--input", str(output), "--output", str(output / "report_draft.md")])

            server = create_dashboard_server("127.0.0.1", 0, DashboardConfig(root=root))
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                port = server.server_address[1]
                connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                connection.request("GET", "/")
                response = connection.getresponse()
                body = response.read().decode("utf-8")
                self.assertEqual(response.status, 200)
                self.assertIn("Burp AI Redaction Gateway", body)
                self.assertIn("generated", body)
                self.assertIn("검증 통과 산출물", body)
                self.assertIn("검증 통과만", body)
                self.assertIn("원문 없음", body)
                self.assertIn("원문 표시 여부", body)
                self.assertIn("CSRF 보호", body)
                self.assertIn("설정/상태", body)
                self.assertNotIn("raw_request", body)
                self.assertNotIn("raw_response", body)
                connection.close()

                connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                connection.request("GET", "/output?project=generated")
                response = connection.getresponse()
                detail = response.read().decode("utf-8")
                self.assertEqual(response.status, 200)
                self.assertIn("탐지 후보", detail)
                self.assertIn("대시보드 실행", detail)
                self.assertIn("POST 실행은 CSRF 보호를 사용합니다", detail)
                self.assertIn("검증", detail)
                self.assertIn("리뷰", detail)
                self.assertIn("보고서", detail)
                self.assertIn("내보내기", detail)
                self.assertIn("새로고침", detail)
                self.assertIn("AI에 넣어도 되는 안전 파일만 표시합니다", detail)
                self.assertIn("증거 신뢰도", detail)
                self.assertIn("수동 확인 필요", detail)
                self.assertIn("판단 근거", detail)
                self.assertIn("위험도 초안", detail)
                self.assertIn("심각도 초안", detail)
                self.assertIn("확정 여부: false", detail)
                self.assertIn("신뢰도 근거", detail)
                self.assertIn("수동 검증", detail)
                self.assertIn("심각도", detail)
                self.assertIn("AI-safe preflight", detail)
                self.assertIn("/preflight?project=generated", detail)
                self.assertIn("preflight detail", detail)
                self.assertIn("/handoff?project=generated", detail)
                self.assertIn("handoff index", detail)
                self.assertIn("/triage?project=generated", detail)
                self.assertIn("triage index", detail)
                self.assertIn("/report-readiness?project=generated", detail)
                self.assertIn("report readiness", detail)
                self.assertIn("/workflow?project=generated", detail)
                self.assertIn("workflow status", detail)
                self.assertNotIn("Confirmed vulnerability", detail)
                connection.close()

                connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                connection.request("GET", "/preflight?project=generated")
                response = connection.getresponse()
                preflight = response.read().decode("utf-8")
                self.assertEqual(response.status, 200)
                self.assertIn("AI-safe preflight", preflight)
                self.assertIn("read-only", preflight)
                self.assertIn("preflight status", preflight)
                self.assertIn("ready candidate", preflight)
                self.assertIn("verify status", preflight)
                self.assertIn("verify files checked", preflight)
                self.assertIn("finding candidate count", preflight)
                self.assertIn("report_draft.md", preflight)
                self.assertIn("forbidden marker scan", preflight)
                self.assertIn("raw_data_included", preflight)
                self.assertIn("false", preflight)
                for name in ["analysis_packet.json", "chatgpt_prompt.md", "codex_task_prompt.md", "report_draft.md"]:
                    self.assertIn(name, preflight)
                for label in [
                    "raw request/response",
                    "Cookie or Authorization values",
                    "token, JWT, or session values",
                    "real domain, URL, or IP values",
                    "personal data",
                    "HMAC secret or CSRF token values",
                    "audit logs, archives, or manifests",
                ]:
                    self.assertIn(label, preflight)
                self.assertIn("candidate until manual verification is complete", preflight)
                self.assertIn("draft, not final severity", preflight)
                self.assertIn("manual decision", preflight)
                self.assertNotIn('name="csrf_token"', preflight)
                self.assertNotIn("<form", preflight)
                self.assertNotIn("<button", preflight)
                self.assertNotIn("raw_request", preflight)
                self.assertNotIn("raw_response", preflight)
                self.assertNotIn(str(root), preflight)
                connection.close()

                connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                connection.request("GET", "/handoff?project=generated")
                response = connection.getresponse()
                handoff = response.read().decode("utf-8")
                self.assertEqual(response.status, 200)
                self.assertIn("AI handoff index", handoff)
                self.assertIn("read-only", handoff)
                self.assertIn("Read-only handoff checklist", handoff)
                self.assertIn("AI-safe candidate files", handoff)
                self.assertIn("verify first", handoff)
                self.assertIn("manual review required", handoff)
                self.assertIn("preflight status", handoff)
                self.assertIn("open preflight checklist", handoff)
                self.assertIn("/preflight?project=generated", handoff)
                self.assertIn("review/report/export flow", handoff)
                self.assertIn("candidate finding", handoff)
                self.assertIn("draft risk", handoff)
                self.assertIn("final severity requires human decision", handoff)
                self.assertIn("size bytes", handoff)
                self.assertIn("modified UTC", handoff)
                self.assertIn("SHA-256", handoff)
                self.assertIn("SHA-256 file fingerprint, not HMAC", handoff)
                for name in ["analysis_packet.json", "chatgpt_prompt.md", "codex_task_prompt.md", "report_draft.md"]:
                    self.assertIn(name, handoff)
                for purpose in [
                    "Read first for structured sanitized candidate evidence.",
                    "Use when asking ChatGPT for manual-review assistance.",
                    "Use when asking Codex for implementation or review assistance.",
                    "Read last as a candidate report draft for human review.",
                ]:
                    self.assertIn(purpose, handoff)
                for label in [
                    "raw request/response",
                    "Cookie or Authorization values",
                    "token, JWT, or session values",
                    "real domain, URL, or IP values",
                    "personal data",
                    "HMAC secret or CSRF token values",
                    "audit logs, archives, or manifests",
                ]:
                    self.assertIn(label, handoff)
                self.assertNotIn('name="csrf_token"', handoff)
                self.assertNotIn("<form", handoff)
                self.assertNotIn("<button", handoff)
                self.assertNotIn("raw_request", handoff)
                self.assertNotIn("raw_response", handoff)
                self.assertNotIn(str(root), handoff)
                connection.close()

                connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                connection.request("GET", "/triage?project=generated")
                response = connection.getresponse()
                triage = response.read().decode("utf-8")
                self.assertEqual(response.status, 200)
                self.assertIn("Finding triage index", triage)
                self.assertIn("read-only", triage)
                self.assertIn("Read-only triage checklist", triage)
                self.assertIn("project alias", triage)
                self.assertIn("finding candidate count", triage)
                self.assertIn(">22<", triage)
                self.assertIn("AI-safe file allowlist", triage)
                for name in ["analysis_packet.json", "chatgpt_prompt.md", "codex_task_prompt.md", "report_draft.md"]:
                    self.assertIn(name, triage)
                self.assertIn("open AI-safe preflight", triage)
                self.assertIn("open AI handoff index", triage)
                self.assertIn("open report readiness index", triage)
                self.assertIn("/report-readiness?project=generated", triage)
                self.assertIn("review/report/export flow", triage)
                self.assertIn("candidate finding", triage)
                self.assertIn("draft risk", triage)
                self.assertIn("evidence confidence, not severity", triage)
                self.assertIn("manual review required", triage)
                self.assertIn("final severity requires manual decision", triage)
                self.assertIn("candidate #1", triage)
                self.assertIn("FC-0001", triage)
                self.assertIn("missing_security_headers", triage)
                self.assertIn("Missing security headers", triage)
                self.assertIn("sanitized summary", triage)
                self.assertIn("severity draft", triage)
                for label in [
                    "raw request/response",
                    "Cookie or Authorization values",
                    "token, JWT, or session values",
                    "real domain, URL, or IP values",
                    "personal data",
                    "HMAC secret or CSRF token values",
                    "full local path",
                ]:
                    self.assertIn(label, triage)
                self.assertNotIn('name="csrf_token"', triage)
                self.assertNotIn("<form", triage)
                self.assertNotIn("<button", triage)
                self.assertNotIn("raw_request", triage)
                self.assertNotIn("raw_response", triage)
                self.assertNotIn("DUMMY_COOKIE_VALUE", triage)
                self.assertNotIn("DUMMY_BEARER_TOKEN", triage)
                self.assertNotIn("safe to share", triage)
                self.assertNotIn("guaranteed safe", triage)
                self.assertNotIn("severity confirmed", triage)
                self.assertNotIn(str(root), triage)
                connection.close()

                connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                connection.request("GET", "/report-readiness?project=generated")
                response = connection.getresponse()
                readiness = response.read().decode("utf-8")
                self.assertEqual(response.status, 200)
                self.assertIn("Report readiness index", readiness)
                self.assertIn("read-only", readiness)
                self.assertIn("Read-only draft report checklist", readiness)
                self.assertIn("project alias", readiness)
                self.assertIn("draft report status", readiness)
                self.assertIn("finding candidate count", readiness)
                self.assertIn(">22<", readiness)
                self.assertIn("report_draft.md", readiness)
                self.assertIn("analysis_packet.json", readiness)
                self.assertIn("draft report status summary", readiness)
                self.assertIn("open finding triage index", readiness)
                self.assertIn("open AI-safe preflight", readiness)
                self.assertIn("open AI handoff index", readiness)
                self.assertIn("export/review/report flow link", readiness)
                self.assertIn("return to verified output detail", readiness)
                self.assertIn("scope confirmation", readiness)
                self.assertIn("affected endpoint confirmation", readiness)
                self.assertIn("evidence quality confirmation", readiness)
                self.assertIn("false positive possibility", readiness)
                self.assertIn("impact statement review", readiness)
                self.assertIn("remediation wording review", readiness)
                self.assertIn("final severity manual decision", readiness)
                self.assertIn("customer submission sensitive-info review", readiness)
                self.assertIn("finding candidates until manual verification is complete", readiness)
                self.assertIn("risk is draft, not severity confirmation", readiness)
                self.assertIn("evidence confidence, not severity", readiness)
                self.assertIn("report_draft.md is a draft report, not a submission report", readiness)
                self.assertIn("final severity is a manual decision", readiness)
                self.assertIn("exists or missing", readiness)
                self.assertIn("file size in bytes", readiness)
                self.assertIn("modified UTC timestamp", readiness)
                self.assertIn("SHA-256 file fingerprint", readiness)
                self.assertIn("SHA-256 file fingerprint, not HMAC", readiness)
                for label in [
                    "raw request/response",
                    "raw audit row body",
                    "Cookie or Authorization values",
                    "token, JWT, or session values",
                    "real domain, URL, or IP values",
                    "personal data",
                    "HMAC secret or CSRF token values",
                    "full local path",
                ]:
                    self.assertIn(label, readiness)
                self.assertNotIn('name="csrf_token"', readiness)
                self.assertNotIn("<form", readiness)
                self.assertNotIn("<button", readiness)
                self.assertNotIn("raw_request", readiness)
                self.assertNotIn("raw_response", readiness)
                self.assertNotIn("DUMMY_COOKIE_VALUE", readiness)
                self.assertNotIn("DUMMY_BEARER_TOKEN", readiness)
                self.assertNotIn("approved", readiness)
                self.assertNotIn("guaranteed safe", readiness)
                self.assertNotIn("safe to share", readiness)
                self.assertNotIn("severity confirmed", readiness)
                self.assertNotIn("ready to submit", readiness)
                self.assertNotIn(str(root), readiness)
                connection.close()

                connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                connection.request("GET", "/workflow?project=generated")
                response = connection.getresponse()
                workflow = response.read().decode("utf-8")
                self.assertEqual(response.status, 200)
                self.assertIn("Workflow status index", workflow)
                self.assertIn("read-only", workflow)
                self.assertIn("Read-only workflow checklist", workflow)
                self.assertIn("project alias", workflow)
                self.assertIn("verify status summary", workflow)
                self.assertIn("review status summary", workflow)
                self.assertIn("finding candidate count", workflow)
                self.assertIn(">22<", workflow)
                self.assertIn("report_draft.md", workflow)
                self.assertIn("analysis_packet.json", workflow)
                self.assertIn("chatgpt_prompt.md", workflow)
                self.assertIn("codex_task_prompt.md", workflow)
                self.assertIn("passed", workflow)
                self.assertIn("candidate available", workflow)
                self.assertIn("draft available", workflow)
                self.assertIn("manual review required", workflow)
                for step in [
                    "Verify",
                    "Review",
                    "Report",
                    "AI-safe preflight",
                    "AI handoff index",
                    "Finding triage index",
                    "Report readiness index",
                    "review/report/export flow",
                ]:
                    self.assertIn(step, workflow)
                for link in [
                    "/preflight?project=generated",
                    "/handoff?project=generated",
                    "/triage?project=generated",
                    "/report-readiness?project=generated",
                    "/output?project=generated",
                ]:
                    self.assertIn(link, workflow)
                self.assertIn("finding is candidate", workflow)
                self.assertIn("risk is draft", workflow)
                self.assertIn("final severity is a manual decision", workflow)
                self.assertIn("report_draft.md is a draft report, not a submission report", workflow)
                for label in [
                    "raw request/response",
                    "raw audit row body",
                    "Cookie or Authorization values",
                    "token, JWT, or session values",
                    "real domain, URL, or IP values",
                    "personal data",
                    "HMAC secret or CSRF token values",
                    "full local path",
                ]:
                    self.assertIn(label, workflow)
                self.assertNotIn('name="csrf_token"', workflow)
                self.assertNotIn("<form", workflow)
                self.assertNotIn("<button", workflow)
                self.assertNotIn('method="post"', workflow)
                self.assertNotIn("raw_request", workflow)
                self.assertNotIn("raw_response", workflow)
                self.assertNotIn("DUMMY_COOKIE_VALUE", workflow)
                self.assertNotIn("DUMMY_BEARER_TOKEN", workflow)
                self.assertNotIn("approved", workflow)
                self.assertNotIn("guaranteed safe", workflow)
                self.assertNotIn("safe to share", workflow)
                self.assertNotIn("severity confirmed", workflow)
                self.assertNotIn("ready to submit", workflow)
                self.assertNotIn(str(root), workflow)
                connection.close()

                connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                connection.request("GET", "/preview?project=generated&file=chatgpt_prompt.md")
                response = connection.getresponse()
                preview = response.read().decode("utf-8")
                self.assertEqual(response.status, 200)
                self.assertIn("analysis-prompt-packet-v1", preview)
                self.assertNotIn("raw_request", preview)
                connection.close()

                connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                connection.request("GET", "/download?project=generated&file=analysis_packet.json")
                response = connection.getresponse()
                downloaded = response.read().decode("utf-8")
                self.assertEqual(response.status, 200)
                self.assertIn("attachment", response.getheader("Content-Disposition", ""))
                self.assertIn('"candidate_count"', downloaded)
                assert_no_sensitive_text(downloaded)
                connection.close()
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)

    def test_dashboard_settings_page_shows_safe_status_only(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir) / "out"
            output = root / "generated"
            main(["generate", "--input", str(SAMPLE), "--output", str(output), "--project", "client_alias_demo"])
            secret_value = "DUMMY_HMAC_SECRET_FOR_SETTINGS_PAGE_1234567890"

            with patch.dict("os.environ", {"BURP_AI_AUDIT_HMAC_KEY": secret_value}, clear=False):
                server = create_dashboard_server("127.0.0.1", 0, DashboardConfig(root=root))
                thread = threading.Thread(target=server.serve_forever, daemon=True)
                thread.start()
                try:
                    port = server.server_address[1]
                    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                    connection.request("GET", "/settings")
                    response = connection.getresponse()
                    body = response.read().decode("utf-8")
                    self.assertEqual(response.status, 200)
                    self.assertIn("설정 및 보안 상태", body)
                    self.assertIn("root alias", body)
                    self.assertIn(">out<", body)
                    self.assertIn("127.0.0.1 only", body)
                    self.assertIn("safe actions enabled", body)
                    self.assertIn("read-only", body)
                    self.assertIn("CSRF 보호", body)
                    self.assertIn("값 숨김", body)
                    self.assertIn("analysis_packet.json", body)
                    self.assertIn("chatgpt_prompt.md", body)
                    self.assertIn("codex_task_prompt.md", body)
                    self.assertIn("report_draft.md", body)
                    self.assertIn("conservative", body)
                    self.assertIn("consultant", body)
                    self.assertIn("strict", body)
                    self.assertIn("risk profiles", body)
                    self.assertIn("default risk profile", body)
                    self.assertIn("draft only", body)
                    self.assertIn("confidence_is_severity", body)
                    self.assertIn("false", body)
                    self.assertIn("audit schema", body)
                    self.assertIn("1.1", body)
                    self.assertIn("HMAC configured", body)
                    self.assertIn("configured", body)
                    self.assertIn("compressed archive", body)
                    self.assertIn("compressed archive verify", body)
                    self.assertIn("compressed archive HMAC manifest", body)
                    self.assertIn("compressed archive HMAC verify", body)
                    self.assertNotIn(secret_value, body)
                    self.assertNotIn("BURP_AI_AUDIT_HMAC_KEY", body)
                    self.assertNotIn(str(root), body)
                    self.assertNotIn('name="csrf_token"', body)
                    self.assertNotIn("<form", body)
                    self.assertNotIn("raw_request", body)
                    self.assertNotIn("raw_response", body)
                    self.assertNotIn("Replay", body)
                    self.assertNotIn("Active scan", body)
                    self.assertNotIn("Delete", body)
                    self.assertNotIn("Edit", body)
                    connection.close()
                finally:
                    server.shutdown()
                    server.server_close()
                    thread.join(timeout=5)

    def test_dashboard_help_page_shows_operations_index_without_actions_or_sensitive_values(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir) / "out"
            output = root / "generated"
            main(["generate", "--input", str(SAMPLE), "--output", str(output), "--project", "client_alias_demo"])
            secret_value = "DUMMY_HELP_PAGE_SECRET_1234567890"

            with patch.dict("os.environ", {"BURP_AI_AUDIT_HMAC_KEY": secret_value}, clear=False):
                server = create_dashboard_server("127.0.0.1", 0, DashboardConfig(root=root))
                thread = threading.Thread(target=server.serve_forever, daemon=True)
                thread.start()
                try:
                    port = server.server_address[1]
                    for linked_path in ("/", "/settings"):
                        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                        connection.request("GET", linked_path)
                        response = connection.getresponse()
                        linked_body = response.read().decode("utf-8")
                        self.assertEqual(response.status, 200)
                        self.assertIn('href="/help"', linked_body)
                        connection.close()

                    for path in ("/help", "/operations"):
                        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                        connection.request("GET", path)
                        response = connection.getresponse()
                        body = response.read().decode("utf-8")
                        self.assertEqual(response.status, 200)
                        self.assertIn("운영 인덱스", body)
                        self.assertIn("조회 전용", body)
                        self.assertIn("실행 버튼 없음", body)
                        self.assertIn("docs/USER_QUICKSTART.md", body)
                        self.assertIn("docs/GUI_USER_FLOW.md", body)
                        self.assertIn("docs/GUI_AI_SAFE_PREFLIGHT.md", body)
                        self.assertIn("docs/GUI_AI_HANDOFF_INDEX.md", body)
                        self.assertIn("docs/GUI_FINDING_TRIAGE_INDEX.md", body)
                        self.assertIn("docs/GUI_REPORT_READINESS_INDEX.md", body)
                        self.assertIn("docs/GUI_WORKFLOW_STATUS_INDEX.md", body)
                        self.assertIn("docs/WINDOWS_LAUNCHER_GUIDE.md", body)
                        self.assertIn("docs/AUDIT_OPERATIONS_GUIDE.md", body)
                        self.assertIn("docs/GUI_AUDIT_PANEL_GUIDE.md", body)
                        self.assertIn("docs/RISK_RATING_GUIDE.md", body)
                        self.assertIn("docs/RELEASE_NOTES_v0.4.md", body)
                        self.assertIn("analysis_packet.json", body)
                        self.assertIn("chatgpt_prompt.md", body)
                        self.assertIn("codex_task_prompt.md", body)
                        self.assertIn("report_draft.md", body)
                        self.assertIn("raw request/response", body)
                        self.assertIn("Cookie", body)
                        self.assertIn("Authorization", body)
                        self.assertIn("token/JWT/session", body)
                        self.assertIn("local_only/", body)
                        self.assertIn("raw_vault/", body)
                        self.assertIn("candidate", body)
                        self.assertIn("draft", body)
                        self.assertIn("final severity", body)
                        self.assertIn("127.0.0.1", body)
                        self.assertIn("HTML escaped", body)
                        self.assertNotIn(secret_value, body)
                        self.assertNotIn("BURP_AI_AUDIT_HMAC_KEY", body)
                        self.assertNotIn(str(root), body)
                        self.assertNotIn('name="csrf_token"', body)
                        self.assertNotIn("<form", body)
                        self.assertNotIn('method="post"', body)
                        self.assertNotIn("raw_request", body)
                        self.assertNotIn("raw_response", body)
                        self.assertNotIn("DUMMY_COOKIE_VALUE", body)
                        self.assertNotIn("DUMMY_BEARER_TOKEN", body)
                        connection.close()
                finally:
                    server.shutdown()
                    server.server_close()
                    thread.join(timeout=5)

    def test_dashboard_blocks_unverified_output_forbidden_paths_and_unsafe_files(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            output = root / "generated"
            main(["generate", "--input", str(SAMPLE), "--output", str(output), "--project", "client_alias_demo"])

            server = create_dashboard_server("127.0.0.1", 0, DashboardConfig(root=root))
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                port = server.server_address[1]
                connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                connection.request("GET", "/preview?project=generated&file=sanitized_events.jsonl")
                response = connection.getresponse()
                body = response.read().decode("utf-8")
                self.assertEqual(response.status, 403)
                self.assertIn("safe_file_not_allowed", body)
                connection.close()

                (output / "unsafe.md").write_text("Authorization: Bearer rawBearerToken1234567890\n", encoding="utf-8")
                connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                connection.request("GET", "/output?project=generated")
                response = connection.getresponse()
                blocked = response.read().decode("utf-8")
                self.assertEqual(response.status, 403)
                self.assertIn("verification_failed", blocked)
                self.assertNotIn("rawBearerToken", blocked)
                connection.close()

                connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                connection.request("GET", "/output?project=..%2Flocal_only")
                response = connection.getresponse()
                traversal = response.read().decode("utf-8")
                self.assertEqual(response.status, 403)
                self.assertIn("forbidden_directory", traversal)
                connection.close()

                connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                connection.request("GET", "/preflight?project=..%2Flocal_only")
                response = connection.getresponse()
                preflight_traversal = response.read().decode("utf-8")
                self.assertEqual(response.status, 403)
                self.assertIn("forbidden_directory", preflight_traversal)
                self.assertNotIn("rawBearerToken", preflight_traversal)
                connection.close()

                connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                connection.request("GET", "/handoff?project=..%2Flocal_only")
                response = connection.getresponse()
                handoff_traversal = response.read().decode("utf-8")
                self.assertEqual(response.status, 403)
                self.assertIn("forbidden_directory", handoff_traversal)
                self.assertNotIn("rawBearerToken", handoff_traversal)
                connection.close()

                connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                connection.request("GET", "/triage?project=..%2Flocal_only")
                response = connection.getresponse()
                triage_traversal = response.read().decode("utf-8")
                self.assertEqual(response.status, 403)
                self.assertIn("forbidden_directory", triage_traversal)
                self.assertNotIn("rawBearerToken", triage_traversal)
                connection.close()

                connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                connection.request("GET", "/report-readiness?project=..%2Flocal_only")
                response = connection.getresponse()
                readiness_traversal = response.read().decode("utf-8")
                self.assertEqual(response.status, 403)
                self.assertIn("forbidden_directory", readiness_traversal)
                self.assertNotIn("rawBearerToken", readiness_traversal)
                connection.close()

                connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                connection.request("GET", "/workflow?project=..%2Flocal_only")
                response = connection.getresponse()
                workflow_traversal = response.read().decode("utf-8")
                self.assertEqual(response.status, 403)
                self.assertIn("forbidden_directory", workflow_traversal)
                self.assertNotIn("rawBearerToken", workflow_traversal)
                connection.close()
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)

            with self.assertRaises(DashboardError) as bind_error:
                create_dashboard_server("0.0.0.0", 0, DashboardConfig(root=root))
            self.assertEqual(bind_error.exception.error_type, "non_loopback_bind_rejected")

    def test_dashboard_actions_require_csrf_and_write_safe_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir) / "out"
            output = root / "generated"
            main(["generate", "--input", str(SAMPLE), "--output", str(output), "--project", "client_alias_demo"])
            server = create_dashboard_server("127.0.0.1", 0, DashboardConfig(root=root))
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                port = server.server_address[1]
                connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                connection.request("GET", "/output?project=generated")
                response = connection.getresponse()
                detail = response.read().decode("utf-8")
                self.assertEqual(response.status, 200)
                token_match = re.search(r'name="csrf_token" value="([0-9a-f]{32})"', detail)
                self.assertIsNotNone(token_match)
                csrf_token = token_match.group(1)
                connection.close()

                connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                missing_body = urlencode({"project": "generated", "action": "verify"})
                connection.request(
                    "POST",
                    "/action",
                    body=missing_body,
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                )
                response = connection.getresponse()
                missing_csrf = response.read().decode("utf-8")
                self.assertEqual(response.status, 400)
                self.assertIn("csrf_token_missing", missing_csrf)
                self.assertNotIn("raw_request", missing_csrf)
                connection.close()

                connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                invalid_body = urlencode({"project": "generated", "action": "verify", "csrf_token": "invalid"})
                connection.request(
                    "POST",
                    "/action",
                    body=invalid_body,
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                )
                response = connection.getresponse()
                blocked = response.read().decode("utf-8")
                self.assertEqual(response.status, 403)
                self.assertIn("csrf_token_invalid", blocked)
                self.assertNotIn("raw_request", blocked)
                connection.close()

                for action in ["verify", "review"]:
                    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                    body = urlencode({"project": "generated", "action": action, "csrf_token": csrf_token})
                    connection.request(
                        "POST",
                        "/action",
                        body=body,
                        headers={"Content-Type": "application/x-www-form-urlencoded"},
                    )
                    response = connection.getresponse()
                    result = response.read().decode("utf-8")
                    self.assertEqual(response.status, 200)
                    self.assertIn("원문 데이터 포함", result)
                    self.assertIn("false", result)
                    self.assertNotIn("raw_request", result)
                    self.assertNotIn("raw_response", result)
                    connection.close()

                connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                report_body = urlencode(
                    {
                        "project": "generated",
                        "action": "report",
                        "profile": "consultant",
                        "csrf_token": csrf_token,
                    }
                )
                connection.request(
                    "POST",
                    "/action",
                    body=report_body,
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                )
                response = connection.getresponse()
                report_result = response.read().decode("utf-8")
                self.assertEqual(response.status, 200)
                self.assertIn("보고서 초안을 생성했습니다", report_result)
                self.assertIn("프로필: consultant", report_result)
                self.assertTrue((output / "report_draft.md").is_file())
                report_text = (output / "report_draft.md").read_text(encoding="utf-8")
                self.assertIn("# Sanitized Consultant Report Draft", report_text)
                assert_no_sensitive_text(report_text)
                connection.close()

                connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                export_body = urlencode({"project": "generated", "action": "export", "csrf_token": csrf_token})
                connection.request(
                    "POST",
                    "/action",
                    body=export_body,
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                )
                response = connection.getresponse()
                export_result = response.read().decode("utf-8")
                self.assertEqual(response.status, 200)
                self.assertIn("안전 파일을 내보냈습니다", export_result)
                self.assertIn("내보내기 디렉터리: &lt;safe_export_dir&gt;", export_result)
                export_dir = Path(temp_dir) / "exports" / "dashboard" / "generated"
                for name in ["analysis_packet.json", "chatgpt_prompt.md", "codex_task_prompt.md", "report_draft.md"]:
                    exported = export_dir / name
                    self.assertTrue(exported.is_file())
                    assert_no_sensitive_text(exported.read_text(encoding="utf-8"))
                connection.close()

                audit_path = root / ".audit" / "mcp_audit.jsonl"
                self.assertTrue(audit_path.is_file())
                audit_text = audit_path.read_text(encoding="utf-8")
                assert_no_sensitive_text(audit_text)
                audit_events = [json.loads(line) for line in audit_text.splitlines() if line.strip()]
                self.assertEqual(len(audit_events), 6)
                self.assert_audit_hash_chain(audit_events)
                self.assertTrue(all(event["event_type"] == "dashboard_action" for event in audit_events))
                self.assertTrue(all(event["raw_data_included"] is False for event in audit_events))
                self.assertEqual(
                    [(event["action_name"], event["result_status"]) for event in audit_events],
                    [
                        ("verify", "blocked"),
                        ("verify", "blocked"),
                        ("verify", "success"),
                        ("review", "success"),
                        ("report", "success"),
                        ("export", "success"),
                    ],
                )
                self.assertEqual(
                    [event.get("blocked_reason", "") for event in audit_events[:2]],
                    ["csrf_missing", "csrf_invalid"],
                )
                self.assertEqual(audit_events[4]["report_profile"], "consultant")
                self.assertEqual(
                    audit_events[5]["exported_files"],
                    ["analysis_packet.json", "chatgpt_prompt.md", "codex_task_prompt.md", "report_draft.md"],
                )
                self.assertNotIn(csrf_token, audit_text)
                self.assertNotIn("csrf_token", audit_text)
                self.assertNotIn("raw_request", audit_text)
                self.assertNotIn("raw_response", audit_text)
                audit_review = review_audit_path(audit_path)
                self.assertTrue(audit_review.passed, audit_review.findings)
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)

    def test_dashboard_shows_audit_status_without_audit_rows(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self.generated_audit_dir(root, request_count=2)

            server = create_dashboard_server("127.0.0.1", 0, DashboardConfig(root=root))
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                port = server.server_address[1]
                connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                connection.request("GET", "/")
                response = connection.getresponse()
                body = response.read().decode("utf-8")
                self.assertEqual(response.status, 200)
                self.assertIn("감사 로그", body)
                self.assertIn("검사한 이벤트", body)
                self.assertIn("통과", body)
                self.assertIn("메타데이터만", body)
                self.assertNotIn("list_prompt_files", body)
                self.assertNotIn("mcp_tool_call", body)
                connection.close()
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)

    def test_dashboard_shows_audit_archive_status_without_archive_rows(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            audit_dir = self.generated_audit_dir(root, request_count=2)
            retained = audit_dir / "mcp_audit.retained.jsonl"
            retained_manifest = audit_dir / "mcp_audit.retained.manifest.json"
            archive = audit_dir / "mcp_audit.retained.jsonl.gz"
            archive_manifest = audit_dir / "mcp_audit.retained.jsonl.gz.manifest.json"
            secret_value = "DUMMY_HMAC_SECRET_FOR_ARCHIVE_PANEL_1234567890"
            secret = secret_value.encode("utf-8")

            self.write_audit_events(
                retained,
                self.audit_event_chain(["2026-06-04T00:00:00Z", "2026-06-05T00:00:00Z"]),
            )
            create_audit_hmac_manifest(retained, retained_manifest, secret=secret)
            compress_audit_jsonl(retained, archive)
            create_compressed_audit_hmac_manifest(archive, archive_manifest, secret=secret)

            with patch.dict("os.environ", {"BURP_AI_AUDIT_HMAC_KEY": secret_value}, clear=False):
                server = create_dashboard_server("127.0.0.1", 0, DashboardConfig(root=root))
                thread = threading.Thread(target=server.serve_forever, daemon=True)
                thread.start()
                try:
                    port = server.server_address[1]
                    for path in ("/", "/settings"):
                        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                        connection.request("GET", path)
                        response = connection.getresponse()
                        body = response.read().decode("utf-8")
                        self.assertEqual(response.status, 200)
                        self.assertIn("compressed archive", body)
                        self.assertIn("compressed archive verify", body)
                        self.assertIn("compressed archive HMAC manifest", body)
                        self.assertIn("compressed archive HMAC verify", body)
                        self.assertIn("present", body)
                        self.assertIn("badge good", body)
                        self.assertNotIn(secret_value, body)
                        self.assertNotIn(str(root), body)
                        self.assertNotIn("list_prompt_files", body)
                        self.assertNotIn("mcp_tool_call", body)
                        self.assertNotIn("raw_request", body)
                        self.assertNotIn("raw_response", body)
                        connection.close()
                finally:
                    server.shutdown()
                    server.server_close()
                    thread.join(timeout=5)

    def test_dashboard_action_audit_redacts_sensitive_output_id(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            write_dashboard_action_audit_event(
                root,
                action_name="verify",
                output_id="customer.example.test",
                result_status="success",
            )
            audit_path = root / ".audit" / "mcp_audit.jsonl"
            audit_text = audit_path.read_text(encoding="utf-8")
            self.assertNotIn("customer.example.test", audit_text)
            assert_no_sensitive_text(audit_text)
            audit_events = [json.loads(line) for line in audit_text.splitlines() if line.strip()]
            self.assertEqual(audit_events[0]["event_type"], "dashboard_action")
            self.assertEqual(audit_events[0]["output_id"], "redacted_output")
            self.assert_audit_hash_chain(audit_events)
            audit_review = review_audit_path(audit_path)
            self.assertTrue(audit_review.passed, audit_review.findings)

    def test_dashboard_escapes_preview_html_special_characters(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            output = root / "generated"
            main(["generate", "--input", str(SAMPLE), "--output", str(output), "--project", "client_alias_demo"])
            (output / "report_draft.md").write_text(
                "# Candidate\n\n<script>alert(1)</script>\n",
                encoding="utf-8",
            )
            self.assertEqual(main(["verify", "--input", str(output)]), 0)

            server = create_dashboard_server("127.0.0.1", 0, DashboardConfig(root=root))
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                port = server.server_address[1]
                connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                connection.request("GET", "/preview?project=generated&file=report_draft.md")
                response = connection.getresponse()
                body = response.read().decode("utf-8")
                self.assertEqual(response.status, 200)
                self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", body)
                self.assertNotIn("<script>alert(1)</script>", body)
                connection.close()
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)

    def test_read_only_mcp_exposes_verified_sanitized_outputs_only(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            output = root / "generated"
            report_path = output / "report_draft.md"
            main(["generate", "--input", str(SAMPLE), "--output", str(output), "--project", "client_alias_demo"])
            main(["report", "--input", str(output), "--output", str(report_path), "--profile", "conservative"])

            server = ReadOnlyMcpServer(ReadOnlyMcpGateway(root, load_policy(None)), audit_stream=io.StringIO())
            tools_response = server.handle_message({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
            self.assertIsInstance(tools_response, dict)
            tool_names = {tool["name"] for tool in tools_response["result"]["tools"]}
            self.assertEqual(
                tool_names,
                {"list_findings", "get_finding", "get_analysis_packet", "get_report_draft", "list_prompt_files"},
            )
            for tool in tools_response["result"]["tools"]:
                self.assertTrue(tool["annotations"]["readOnlyHint"])
                self.assertFalse(tool["annotations"]["destructiveHint"])

            list_response = server.handle_message(
                {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/call",
                    "params": {"name": "list_findings", "arguments": {"project": "generated"}},
                }
            )
            self.assertFalse(list_response["result"]["isError"])
            list_text = list_response["result"]["content"][0]["text"]
            self.assertIn("findings", list_text)
            self.assertNotIn("raw_request", list_text)
            self.assertNotIn("raw_response", list_text)
            assert_no_sensitive_text(list_text)
            risk_draft = list_response["result"]["structuredContent"]["findings"][0]["risk_rating_draft"]
            self.assertEqual(risk_draft["risk_profile"], "conservative")
            self.assertFalse(risk_draft["risk_rating_finalized"])
            self.assertFalse(risk_draft["confidence_is_severity"])

            first_finding = list_response["result"]["structuredContent"]["findings"][0]["finding_id"]
            detail_response = server.handle_message(
                {
                    "jsonrpc": "2.0",
                    "id": 3,
                    "method": "tools/call",
                    "params": {
                        "name": "get_finding",
                        "arguments": {"project": "generated", "finding_id": first_finding},
                    },
                }
            )
            self.assertFalse(detail_response["result"]["isError"])
            self.assertIn("manual_verification_required", detail_response["result"]["content"][0]["text"])

            for request_id, tool_name in [
                (4, "get_analysis_packet"),
                (5, "get_report_draft"),
                (6, "list_prompt_files"),
            ]:
                response = server.handle_message(
                    {
                        "jsonrpc": "2.0",
                        "id": request_id,
                        "method": "tools/call",
                        "params": {"name": tool_name, "arguments": {"project": "generated"}},
                    }
                )
                self.assertFalse(response["result"]["isError"], tool_name)
                assert_no_sensitive_text(response["result"]["content"][0]["text"])

            audit_path = root / ".audit" / "mcp_audit.jsonl"
            self.assertTrue(audit_path.is_file())
            audit_text = audit_path.read_text(encoding="utf-8")
            assert_no_sensitive_text(audit_text)
            audit_events = [json.loads(line) for line in audit_text.splitlines() if line.strip()]
            self.assertEqual(len(audit_events), 5)
            self.assert_audit_hash_chain(audit_events)
            self.assertTrue(all(event["event_type"] == "mcp_tool_call" for event in audit_events))
            self.assertTrue(all(event["result_status"] == "success" for event in audit_events))
            self.assertTrue(all(event["raw_data_included"] is False for event in audit_events))
            self.assertIn("finding_id", audit_events[1])
            self.assertNotIn("Sanitized Candidate Report Draft", audit_text)
            self.assertNotIn("finding_candidates", audit_text)
            self.assertNotIn("raw_request", audit_text)
            self.assertNotIn("raw_response", audit_text)

    def test_read_only_mcp_blocks_path_traversal_forbidden_dirs_and_unverified_output(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            output = root / "generated"
            main(["generate", "--input", str(SAMPLE), "--output", str(output), "--project", "client_alias_demo"])
            server = ReadOnlyMcpServer(ReadOnlyMcpGateway(root, load_policy(None)), audit_stream=io.StringIO())

            traversal_response = server.handle_message(
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/call",
                    "params": {"name": "list_findings", "arguments": {"project": "..\\generated"}},
                }
            )
            self.assertTrue(traversal_response["result"]["isError"])
            self.assertEqual(
                traversal_response["result"]["structuredContent"]["error_type"], "path_traversal_forbidden"
            )

            forbidden_response = server.handle_message(
                {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/call",
                    "params": {"name": "list_findings", "arguments": {"project": "raw"}},
                }
            )
            self.assertTrue(forbidden_response["result"]["isError"])
            self.assertEqual(forbidden_response["result"]["structuredContent"]["error_type"], "forbidden_directory")

            (output / "unsafe.md").write_text("Authorization: Bearer rawBearerToken1234567890\n", encoding="utf-8")
            verify_response = server.handle_message(
                {
                    "jsonrpc": "2.0",
                    "id": 3,
                    "method": "tools/call",
                    "params": {"name": "list_findings", "arguments": {"project": "generated"}},
                }
            )
            self.assertTrue(verify_response["result"]["isError"])
            self.assertEqual(verify_response["result"]["structuredContent"]["error_type"], "verification_failed")
            audit_path = root / ".audit" / "mcp_audit.jsonl"
            self.assertTrue(audit_path.is_file())
            audit_text = audit_path.read_text(encoding="utf-8")
            assert_no_sensitive_text(audit_text)
            audit_events = [json.loads(line) for line in audit_text.splitlines() if line.strip()]
            self.assert_audit_hash_chain(audit_events)
            self.assertEqual(
                [event["blocked_reason"] for event in audit_events],
                ["path_traversal", "forbidden_directory", "verify_failed"],
            )
            self.assertTrue(all(event["result_status"] == "blocked" for event in audit_events))
            self.assertTrue(all(event["raw_data_included"] is False for event in audit_events))
            self.assertTrue(all("error_type" in event for event in audit_events))
            self.assertNotIn("rawBearerToken1234567890", audit_text)
            self.assertNotIn("Authorization", audit_text)
            self.assertNotIn("..\\generated", audit_text)

    def test_read_only_mcp_verifies_hash_chain_across_retained_rotated_files(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            output = root / "generated"
            main(["generate", "--input", str(SAMPLE), "--output", str(output), "--project", "client_alias_demo"])
            server = ReadOnlyMcpServer(
                ReadOnlyMcpGateway(root, load_policy(None)),
                audit_stream=io.StringIO(),
                audit_max_bytes=1,
                audit_max_rotated_files=2,
            )

            for request_id in range(1, 6):
                response = server.handle_message(
                    {
                        "jsonrpc": "2.0",
                        "id": request_id,
                        "method": "tools/call",
                        "params": {"name": "list_prompt_files", "arguments": {"project": "generated"}},
                    }
                )
                self.assertFalse(response["result"]["isError"])

            audit_dir = root / ".audit"
            active = audit_dir / "mcp_audit.jsonl"
            rotated = sorted(audit_dir.glob("mcp_audit.*.jsonl"))
            self.assertTrue(active.is_file())
            self.assertEqual([path.name for path in rotated], ["mcp_audit.000003.jsonl", "mcp_audit.000004.jsonl"])
            self.assertFalse((audit_dir / "mcp_audit.000001.jsonl").exists())
            self.assertFalse((audit_dir / "mcp_audit.000002.jsonl").exists())

            events = self.read_audit_events([*rotated, active])
            self.assertEqual([event["sequence_no"] for event in events], [3, 4, 5])
            self.assert_audit_hash_chain(events, allow_prefix_gap=True)
            self.assertEqual(events[-1]["prev_event_hash"], events[-2]["event_hash"])
            self.assertTrue(all(event["raw_data_included"] is False for event in events))

    def test_audit_rotation_suffix_does_not_reuse_after_zero_file_retention(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            output = root / "generated"
            main(["generate", "--input", str(SAMPLE), "--output", str(output), "--project", "client_alias_demo"])
            server = ReadOnlyMcpServer(
                ReadOnlyMcpGateway(root, load_policy(None)),
                audit_stream=io.StringIO(),
                audit_max_bytes=1,
                audit_max_rotated_files=0,
            )

            for request_id in range(1, 4):
                response = server.handle_message(
                    {
                        "jsonrpc": "2.0",
                        "id": request_id,
                        "method": "tools/call",
                        "params": {"name": "list_prompt_files", "arguments": {"project": "generated"}},
                    }
                )
                self.assertFalse(response["result"]["isError"])

            audit_dir = root / ".audit"
            active = audit_dir / "mcp_audit.jsonl"
            self.assertTrue(active.is_file())
            self.assertEqual(list(audit_dir.glob("mcp_audit.*.jsonl")), [])
            events = self.read_audit_events([active])
            self.assertEqual([event["sequence_no"] for event in events], [3])
            self.assertEqual(_next_rotated_audit_path(active).name, "mcp_audit.000003.jsonl")

    def test_review_audit_command_accepts_rotated_and_active_logs(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            audit_dir = self.generated_audit_dir(Path(temp_dir), request_count=5, rotate=True)
            result = review_audit_path(audit_dir)

            self.assertTrue(result.passed)
            self.assertEqual(result.events_checked, 3)
            self.assertEqual(result.files, ["mcp_audit.000003.jsonl", "mcp_audit.000004.jsonl", "mcp_audit.jsonl"])
            self.assertEqual(result.sequence_start, 3)
            self.assertEqual(result.sequence_end, 5)
            self.assertEqual(result.retention_boundary, "retained_files_only")
            self.assertTrue(result.raw_free_scan_passed)
            self.assertTrue(any(warning.kind == "retention_boundary" for warning in result.warnings))

            with redirect_stdout(io.StringIO()) as stdout:
                exit_code = main(["review-audit", "--input", str(audit_dir)])
            text = stdout.getvalue()
            self.assertEqual(exit_code, 0)
            self.assertIn("Audit review passed.", text)
            self.assertIn("Retention boundary: retained files only", text)
            assert_no_sensitive_text(text)

    def test_review_audit_json_format_is_safe(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            audit_dir = self.generated_audit_dir(Path(temp_dir), request_count=2)

            with redirect_stdout(io.StringIO()) as stdout:
                exit_code = main(["review-audit", "--input", str(audit_dir), "--format", "json"])
            payload = json.loads(stdout.getvalue())

            self.assertEqual(exit_code, 0)
            self.assertEqual(payload["status"], "passed")
            self.assertEqual(payload["events_checked"], 2)
            self.assertEqual(payload["raw_free_scan"], "passed")
            assert_no_sensitive_text(stdout.getvalue())

    def test_review_audit_fails_on_event_hash_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            audit_dir = self.generated_audit_dir(Path(temp_dir), request_count=2)
            active = audit_dir / "mcp_audit.jsonl"
            events = self.read_audit_events([active])
            mutated = deepcopy(events)
            mutated[0]["result_status"] = "blocked"
            self.write_audit_events(active, mutated)

            result = review_audit_path(audit_dir)

            self.assertFalse(result.passed)
            self.assertTrue(any(finding.kind == "event_hash_mismatch" for finding in result.findings))

    def test_review_audit_fails_on_prev_hash_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            audit_dir = self.generated_audit_dir(Path(temp_dir), request_count=3)
            active = audit_dir / "mcp_audit.jsonl"
            events = self.read_audit_events([active])
            mutated = deepcopy(events)
            mutated[2]["prev_event_hash"] = mutated[0]["event_hash"]
            body = {key: value for key, value in mutated[2].items() if key != "event_hash"}
            canonical = json.dumps(body, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
            mutated[2]["event_hash"] = "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()
            self.write_audit_events(active, mutated)

            result = review_audit_path(audit_dir)

            self.assertFalse(result.passed)
            self.assertTrue(any(finding.kind == "prev_event_hash_mismatch" for finding in result.findings))

    def test_review_audit_fails_on_sequence_gap_and_invalid_uuid(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            audit_dir = self.generated_audit_dir(Path(temp_dir), request_count=3)
            active = audit_dir / "mcp_audit.jsonl"
            events = self.read_audit_events([active])
            mutated = deepcopy(events)
            mutated[1]["sequence_no"] = 4
            mutated[1]["event_id"] = "not-a-uuid"
            self.write_audit_events(active, mutated)

            result = review_audit_path(audit_dir)

            self.assertFalse(result.passed)
            self.assertTrue(any(finding.kind == "sequence_no_not_contiguous" for finding in result.findings))
            self.assertTrue(any(finding.kind == "invalid_event_id" for finding in result.findings))

    def test_review_audit_fails_on_raw_keyword_without_printing_value(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            audit_dir = self.generated_audit_dir(Path(temp_dir), request_count=1)
            active = audit_dir / "mcp_audit.jsonl"
            active.write_text(
                active.read_text(encoding="utf-8") + "Authorization: Bearer rawBearerToken1234567890\n",
                encoding="utf-8",
            )

            with redirect_stdout(io.StringIO()) as stdout:
                exit_code = main(["review-audit", "--input", str(audit_dir)])
            text = stdout.getvalue()

            self.assertEqual(exit_code, 1)
            self.assertIn("raw_sensitive_data:bearer_token", text)
            self.assertNotIn("rawBearerToken1234567890", text)

    def test_review_audit_fails_on_invalid_rotated_suffix(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            audit_dir = self.generated_audit_dir(Path(temp_dir), request_count=1)
            (audit_dir / "mcp_audit.latest.jsonl").write_text("", encoding="utf-8")

            result = review_audit_path(audit_dir)

            self.assertFalse(result.passed)
            self.assertTrue(any(finding.kind == "invalid_rotated_suffix" for finding in result.findings))

    def test_review_audit_fails_on_pre_schema_legacy_row(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            audit_dir = Path(temp_dir) / ".audit"
            audit_dir.mkdir()
            (audit_dir / "mcp_audit.jsonl").write_text(
                json.dumps(
                    {
                        "event_type": "mcp_tool_call",
                        "tool_name": "list_prompt_files",
                        "output_id": "demo",
                        "result_status": "success",
                        "response_class": "prompt_file_list",
                        "raw_data_included": False,
                    },
                    ensure_ascii=True,
                    sort_keys=True,
                )
                + "\n",
                encoding="utf-8",
            )

            result = review_audit_path(audit_dir)

            self.assertFalse(result.passed)
            self.assertTrue(any(finding.kind == "missing_field:audit_schema_version" for finding in result.findings))
            self.assertTrue(any(finding.kind == "invalid_audit_schema_version" for finding in result.findings))

    def test_audit_retention_dry_run_counts_rows_without_writing_output(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            audit_file = Path(temp_dir) / "mcp_audit.jsonl"
            output_file = Path(temp_dir) / "mcp_audit.retained.jsonl"
            self.write_audit_events(
                audit_file,
                self.audit_event_chain(
                    [
                        "2026-05-01T00:00:00Z",
                        "2026-06-04T00:00:00Z",
                        "2026-06-05T00:00:00Z",
                    ]
                ),
            )

            result = apply_audit_retention(
                audit_file,
                output_file,
                retention_days=30,
                dry_run=True,
                now=datetime(2026, 6, 5, tzinfo=UTC),
            )

            self.assertEqual(result.total_rows, 3)
            self.assertEqual(result.retained_rows, 2)
            self.assertEqual(result.expired_rows, 1)
            self.assertTrue(result.dry_run)
            self.assertFalse(output_file.exists())

    def test_audit_retention_writes_reviewable_retained_output(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            audit_file = Path(temp_dir) / "mcp_audit.jsonl"
            output_file = Path(temp_dir) / "mcp_audit.retained.jsonl"
            self.write_audit_events(
                audit_file,
                self.audit_event_chain(
                    [
                        "2026-05-01T00:00:00Z",
                        "2026-06-04T00:00:00Z",
                        "2026-06-05T00:00:00Z",
                    ]
                ),
            )

            result = apply_audit_retention(
                audit_file,
                output_file,
                retention_days=30,
                now=datetime(2026, 6, 5, tzinfo=UTC),
            )
            retained = self.read_audit_events([output_file])
            review = review_audit_path(output_file)

            self.assertFalse(result.dry_run)
            self.assertTrue(result.output_written)
            self.assertEqual([event["sequence_no"] for event in retained], [2, 3])
            self.assertTrue(review.passed)
            self.assertEqual(review.retention_boundary, "retained_files_only")
            assert_no_sensitive_text(output_file.read_text(encoding="utf-8"))

    def test_audit_retention_cli_summary_is_raw_free(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            audit_file = Path(temp_dir) / "mcp_audit.jsonl"
            output_file = Path(temp_dir) / "mcp_audit.retained.jsonl"
            self.write_audit_events(
                audit_file,
                self.audit_event_chain(["2026-06-04T00:00:00Z", "2026-06-05T00:00:00Z"]),
            )

            with redirect_stdout(io.StringIO()) as stdout:
                exit_code = main(
                    [
                        "audit-retention",
                        "--input",
                        str(audit_file),
                        "--output",
                        str(output_file),
                        "--retention-days",
                        "30",
                        "--dry-run",
                    ]
                )
            text = stdout.getvalue()

            self.assertEqual(exit_code, 0)
            self.assertIn("Audit retention passed.", text)
            self.assertIn("Dry run: true", text)
            self.assertIn("Raw data included: false", text)
            assert_no_sensitive_text(text)

    def test_audit_retention_rejects_legacy_rows_and_in_place_output(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            audit_file = Path(temp_dir) / "mcp_audit.jsonl"
            audit_file.write_text(
                json.dumps({"event_type": "mcp_tool_call", "raw_data_included": False}, sort_keys=True) + "\n",
                encoding="utf-8",
            )

            with self.assertRaises(AuditRetentionError) as review_error:
                apply_audit_retention(
                    audit_file,
                    Path(temp_dir) / "mcp_audit.retained.jsonl",
                    retention_days=30,
                    now=datetime(2026, 6, 5, tzinfo=UTC),
                )
            self.assertEqual(review_error.exception.error_type, "audit_review_failed")

            valid_file = Path(temp_dir) / "valid_mcp_audit.jsonl"
            self.write_audit_events(valid_file, self.audit_event_chain(["2026-06-05T00:00:00Z"]))
            with self.assertRaises(AuditRetentionError) as in_place_error:
                apply_audit_retention(
                    valid_file,
                    valid_file,
                    retention_days=30,
                    now=datetime(2026, 6, 5, tzinfo=UTC),
                )
            self.assertEqual(in_place_error.exception.error_type, "in_place_output_forbidden")

    def test_audit_retention_rejects_raw_audit_log_without_printing_value(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            audit_file = Path(temp_dir) / "mcp_audit.jsonl"
            audit_file.write_text("Authorization: Bearer rawBearerToken1234567890\n", encoding="utf-8")
            output_file = Path(temp_dir) / "mcp_audit.retained.jsonl"

            with redirect_stdout(io.StringIO()) as stdout:
                exit_code = main(
                    [
                        "audit-retention",
                        "--input",
                        str(audit_file),
                        "--output",
                        str(output_file),
                        "--retention-days",
                        "30",
                    ]
                )
            text = stdout.getvalue()

            self.assertEqual(exit_code, 1)
            self.assertIn("Audit retention failed: audit_review_failed", text)
            self.assertNotIn("rawBearerToken1234567890", text)
            self.assertFalse(output_file.exists())

    def test_audit_compression_cli_creates_and_verifies_raw_free_gzip(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            audit_file = Path(temp_dir) / "mcp_audit.retained.jsonl"
            compressed_file = Path(temp_dir) / "mcp_audit.retained.jsonl.gz"
            self.write_audit_events(
                audit_file,
                self.audit_event_chain(["2026-06-04T00:00:00Z", "2026-06-05T00:00:00Z"]),
            )
            original_text = audit_file.read_text(encoding="utf-8")

            with redirect_stdout(io.StringIO()) as compress_stdout:
                compress_exit = main(
                    [
                        "audit-compress",
                        "--input",
                        str(audit_file),
                        "--output",
                        str(compressed_file),
                    ]
                )
            with redirect_stdout(io.StringIO()) as verify_stdout:
                verify_exit = main(["audit-compress-verify", "--input", str(compressed_file)])

            with gzip.open(compressed_file, "rt", encoding="utf-8") as gzip_file:
                decompressed_text = gzip_file.read()
            review = review_audit_path(audit_file)
            verify_result = verify_compressed_audit_jsonl(compressed_file)

            self.assertEqual(compress_exit, 0)
            self.assertEqual(verify_exit, 0)
            self.assertTrue(audit_file.is_file())
            self.assertTrue(compressed_file.is_file())
            self.assertEqual(decompressed_text, original_text)
            self.assertTrue(review.passed)
            self.assertEqual(verify_result.row_count, 2)
            self.assertGreater(verify_result.original_size_bytes, 0)
            self.assertGreater(verify_result.compressed_size_bytes, 0)
            self.assertIn("Audit compression passed.", compress_stdout.getvalue())
            self.assertIn("Audit compression verification passed.", verify_stdout.getvalue())
            self.assertIn("Output file: <compressed_audit_file>", compress_stdout.getvalue())
            self.assertIn("Raw data included: false", compress_stdout.getvalue())
            self.assertIn("Raw data included: false", verify_stdout.getvalue())
            assert_no_sensitive_text(compress_stdout.getvalue())
            assert_no_sensitive_text(verify_stdout.getvalue())

    def test_audit_compression_result_reports_safe_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            audit_file = Path(temp_dir) / "mcp_audit.retained.jsonl"
            compressed_file = Path(temp_dir) / "mcp_audit.retained.jsonl.gz"
            self.write_audit_events(
                audit_file,
                self.audit_event_chain(["2026-06-04T00:00:00Z", "2026-06-05T00:00:00Z"]),
            )

            result = compress_audit_jsonl(audit_file, compressed_file)

            self.assertEqual(result.input_file, "mcp_audit.retained.jsonl")
            self.assertEqual(result.output_file, "<compressed_audit_file>")
            self.assertEqual(result.row_count, 2)
            self.assertGreater(result.original_size_bytes, 0)
            self.assertGreater(result.compressed_size_bytes, 0)
            self.assertGreater(result.compression_ratio, 0)
            self.assertFalse(result.raw_data_included)
            assert_no_sensitive_text(json.dumps(result.to_json(), ensure_ascii=True, sort_keys=True))

    def test_audit_compression_rejects_raw_log_suffix_and_bad_gzip_safely(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            raw_file = Path(temp_dir) / "mcp_audit.raw.jsonl"
            raw_file.write_text("Authorization: Bearer rawBearerToken1234567890\n", encoding="utf-8")
            compressed_file = Path(temp_dir) / "mcp_audit.raw.jsonl.gz"

            with redirect_stdout(io.StringIO()) as raw_stdout:
                raw_exit = main(
                    [
                        "audit-compress",
                        "--input",
                        str(raw_file),
                        "--output",
                        str(compressed_file),
                    ]
                )
            raw_text = raw_stdout.getvalue()

            self.assertEqual(raw_exit, 1)
            self.assertIn("Audit compression failed: audit_review_failed", raw_text)
            self.assertNotIn("rawBearerToken1234567890", raw_text)
            self.assertFalse(compressed_file.exists())

            audit_file = Path(temp_dir) / "mcp_audit.retained.jsonl"
            self.write_audit_events(audit_file, self.audit_event_chain(["2026-06-05T00:00:00Z"]))
            with self.assertRaises(AuditCompressionError) as suffix_error:
                compress_audit_jsonl(audit_file, Path(temp_dir) / "mcp_audit.retained.gz")
            self.assertEqual(suffix_error.exception.error_type, "invalid_compressed_output_suffix")

            bad_gzip = Path(temp_dir) / "mcp_audit.bad.jsonl.gz"
            bad_gzip.write_text("not gzip data", encoding="utf-8")
            with redirect_stdout(io.StringIO()) as gzip_stdout:
                gzip_exit = main(["audit-compress-verify", "--input", str(bad_gzip)])
            self.assertEqual(gzip_exit, 1)
            self.assertIn("Audit compression verification failed: gzip_read_failed", gzip_stdout.getvalue())
            assert_no_sensitive_text(gzip_stdout.getvalue())

    def test_audit_compressed_hmac_cli_creates_and_verifies_raw_free_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            audit_file = Path(temp_dir) / "mcp_audit.retained.jsonl"
            compressed_file = Path(temp_dir) / "mcp_audit.retained.jsonl.gz"
            manifest_file = Path(temp_dir) / "mcp_audit.retained.jsonl.gz.manifest.json"
            self.write_audit_events(
                audit_file,
                self.audit_event_chain(["2026-06-04T00:00:00Z", "2026-06-05T00:00:00Z"]),
            )
            compress_audit_jsonl(audit_file, compressed_file)

            with patch.dict("os.environ", {"BURP_AI_AUDIT_HMAC_KEY": "DUMMY_HMAC_SECRET_1234567890"}, clear=False):
                with redirect_stdout(io.StringIO()) as create_stdout:
                    create_exit = main(
                        [
                            "audit-compressed-hmac",
                            "--input",
                            str(compressed_file),
                            "--manifest",
                            str(manifest_file),
                        ]
                    )
                with redirect_stdout(io.StringIO()) as verify_stdout:
                    verify_exit = main(
                        [
                            "audit-compressed-hmac-verify",
                            "--input",
                            str(compressed_file),
                            "--manifest",
                            str(manifest_file),
                        ]
                    )

            manifest_text = manifest_file.read_text(encoding="utf-8")
            manifest = json.loads(manifest_text)
            self.assertEqual(create_exit, 0)
            self.assertEqual(verify_exit, 0)
            self.assertEqual(manifest["manifest_schema_version"], "1.0")
            self.assertEqual(manifest["archive_alias"], "<compressed_audit_file>")
            self.assertEqual(manifest["compressed_size_bytes"], compressed_file.stat().st_size)
            self.assertEqual(manifest["hmac_algorithm"], "HMAC-SHA256")
            self.assertFalse(manifest["raw_data_included"])
            self.assertEqual(len(manifest["sha256"]), 64)
            self.assertEqual(len(manifest["hmac"]), 64)
            self.assertIn("Compressed audit HMAC manifest written.", create_stdout.getvalue())
            self.assertIn("Compressed audit HMAC verification passed.", verify_stdout.getvalue())
            self.assertNotIn(str(manifest["hmac"]), create_stdout.getvalue())
            self.assertNotIn(str(manifest["hmac"]), verify_stdout.getvalue())
            assert_no_sensitive_text(manifest_text)
            assert_no_sensitive_text(create_stdout.getvalue())
            assert_no_sensitive_text(verify_stdout.getvalue())

    def test_audit_compressed_hmac_verify_detects_archive_and_manifest_tampering(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            audit_file = Path(temp_dir) / "mcp_audit.retained.jsonl"
            compressed_file = Path(temp_dir) / "mcp_audit.retained.jsonl.gz"
            manifest_file = Path(temp_dir) / "mcp_audit.retained.jsonl.gz.manifest.json"
            secret = b"DUMMY_HMAC_SECRET_1234567890"
            self.write_audit_events(
                audit_file,
                self.audit_event_chain(["2026-06-04T00:00:00Z", "2026-06-05T00:00:00Z"]),
            )
            original_text = audit_file.read_text(encoding="utf-8")
            compress_audit_jsonl(audit_file, compressed_file)
            create_compressed_audit_hmac_manifest(compressed_file, manifest_file, secret=secret)

            with gzip.open(compressed_file, "wt", encoding="utf-8", compresslevel=1) as gzip_file:
                gzip_file.write(original_text)
            with self.assertRaises(AuditCompressedHmacError) as archive_error:
                verify_compressed_audit_hmac_manifest(compressed_file, manifest_file, secret=secret)
            self.assertEqual(archive_error.exception.error_type, "manifest_compressed_size_mismatch")

            compress_audit_jsonl(audit_file, compressed_file)
            create_compressed_audit_hmac_manifest(compressed_file, manifest_file, secret=secret)
            manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
            manifest["hmac"] = "0" * 64
            manifest_file.write_text(json.dumps(manifest, ensure_ascii=True, sort_keys=True) + "\n", encoding="utf-8")
            with self.assertRaises(AuditCompressedHmacError) as manifest_error:
                verify_compressed_audit_hmac_manifest(compressed_file, manifest_file, secret=secret)
            self.assertEqual(manifest_error.exception.error_type, "hmac_mismatch")

    def test_audit_compressed_hmac_rejects_missing_secret_and_bad_archive_safely(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            audit_file = Path(temp_dir) / "mcp_audit.retained.jsonl"
            compressed_file = Path(temp_dir) / "mcp_audit.retained.jsonl.gz"
            manifest_file = Path(temp_dir) / "mcp_audit.retained.jsonl.gz.manifest.json"
            self.write_audit_events(audit_file, self.audit_event_chain(["2026-06-05T00:00:00Z"]))
            compress_audit_jsonl(audit_file, compressed_file)

            with patch.dict("os.environ", {}, clear=True):
                with redirect_stdout(io.StringIO()) as missing_stdout:
                    missing_exit = main(
                        [
                            "audit-compressed-hmac",
                            "--input",
                            str(compressed_file),
                            "--manifest",
                            str(manifest_file),
                        ]
                    )
            self.assertEqual(missing_exit, 1)
            self.assertIn("Compressed audit HMAC failed: hmac_secret_missing", missing_stdout.getvalue())
            self.assertFalse(manifest_file.exists())

            bad_gzip = Path(temp_dir) / "mcp_audit.bad.jsonl.gz"
            bad_gzip.write_text("Authorization: Bearer rawBearerToken1234567890\n", encoding="utf-8")
            with patch.dict("os.environ", {"BURP_AI_AUDIT_HMAC_KEY": "DUMMY_HMAC_SECRET_1234567890"}, clear=False):
                with redirect_stdout(io.StringIO()) as bad_stdout:
                    bad_exit = main(
                        [
                            "audit-compressed-hmac",
                            "--input",
                            str(bad_gzip),
                            "--manifest",
                            str(manifest_file),
                        ]
                    )
            text = bad_stdout.getvalue()
            self.assertEqual(bad_exit, 1)
            self.assertIn("Compressed audit HMAC failed: compressed_gzip_read_failed", text)
            self.assertNotIn("rawBearerToken1234567890", text)
            self.assertFalse(manifest_file.exists())

    def test_audit_hmac_cli_creates_and_verifies_raw_free_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            audit_file = Path(temp_dir) / "mcp_audit.retained.jsonl"
            manifest_file = Path(temp_dir) / "mcp_audit.retained.manifest.json"
            self.write_audit_events(
                audit_file,
                self.audit_event_chain(["2026-06-04T00:00:00Z", "2026-06-05T00:00:00Z"]),
            )

            with patch.dict("os.environ", {"BURP_AI_AUDIT_HMAC_KEY": "DUMMY_HMAC_SECRET_1234567890"}, clear=False):
                with redirect_stdout(io.StringIO()) as create_stdout:
                    create_exit = main(
                        [
                            "audit-hmac",
                            "--input",
                            str(audit_file),
                            "--manifest",
                            str(manifest_file),
                        ]
                    )
                with redirect_stdout(io.StringIO()) as verify_stdout:
                    verify_exit = main(
                        [
                            "audit-hmac-verify",
                            "--input",
                            str(audit_file),
                            "--manifest",
                            str(manifest_file),
                        ]
                    )

            manifest_text = manifest_file.read_text(encoding="utf-8")
            manifest = json.loads(manifest_text)
            self.assertEqual(create_exit, 0)
            self.assertEqual(verify_exit, 0)
            self.assertEqual(manifest["manifest_schema_version"], "1.0")
            self.assertEqual(manifest["audit_schema_version"], "1.1")
            self.assertEqual(manifest["file_alias"], "mcp_audit.retained.jsonl")
            self.assertEqual(manifest["row_count"], 2)
            self.assertEqual(manifest["hmac_algorithm"], "HMAC-SHA256")
            self.assertFalse(manifest["raw_data_included"])
            self.assertEqual(len(manifest["sha256"]), 64)
            self.assertEqual(len(manifest["hmac"]), 64)
            self.assertIn("Audit HMAC manifest written.", create_stdout.getvalue())
            self.assertIn("Audit HMAC verification passed.", verify_stdout.getvalue())
            self.assertNotIn(str(manifest["hmac"]), create_stdout.getvalue())
            self.assertNotIn(str(manifest["hmac"]), verify_stdout.getvalue())
            assert_no_sensitive_text(manifest_text)
            assert_no_sensitive_text(create_stdout.getvalue())
            assert_no_sensitive_text(verify_stdout.getvalue())

    def test_audit_hmac_accepts_local_key_file_without_printing_secret(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            audit_file = Path(temp_dir) / "mcp_audit.retained.jsonl"
            manifest_file = Path(temp_dir) / "mcp_audit.retained.manifest.json"
            key_file = Path(temp_dir) / "secrets.local"
            key_file.write_text("DUMMY_HMAC_SECRET_FILE_1234567890\n", encoding="utf-8")
            self.write_audit_events(audit_file, self.audit_event_chain(["2026-06-05T00:00:00Z"]))

            with redirect_stdout(io.StringIO()) as stdout:
                exit_code = main(
                    [
                        "audit-hmac",
                        "--input",
                        str(audit_file),
                        "--manifest",
                        str(manifest_file),
                        "--key-file",
                        str(key_file),
                    ]
                )
            text = stdout.getvalue()

            self.assertEqual(exit_code, 0)
            self.assertTrue(manifest_file.is_file())
            self.assertNotIn("DUMMY_HMAC_SECRET_FILE_1234567890", text)
            assert_no_sensitive_text(text)

    def test_audit_hmac_verify_detects_file_and_manifest_tampering(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            audit_file = Path(temp_dir) / "mcp_audit.retained.jsonl"
            manifest_file = Path(temp_dir) / "mcp_audit.retained.manifest.json"
            secret = b"DUMMY_HMAC_SECRET_1234567890"
            self.write_audit_events(audit_file, self.audit_event_chain(["2026-06-05T00:00:00Z"]))
            create_audit_hmac_manifest(audit_file, manifest_file, secret=secret)

            audit_file.write_text(audit_file.read_text(encoding="utf-8") + "\n", encoding="utf-8")
            with self.assertRaises(AuditHmacError) as file_error:
                verify_audit_hmac_manifest(audit_file, manifest_file, secret=secret)
            self.assertEqual(file_error.exception.error_type, "sha256_mismatch")

            audit_file.write_text(audit_file.read_text(encoding="utf-8").strip() + "\n", encoding="utf-8")
            manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
            manifest["hmac"] = "0" * 64
            manifest_file.write_text(json.dumps(manifest, ensure_ascii=True, sort_keys=True) + "\n", encoding="utf-8")
            with self.assertRaises(AuditHmacError) as manifest_error:
                verify_audit_hmac_manifest(audit_file, manifest_file, secret=secret)
            self.assertEqual(manifest_error.exception.error_type, "hmac_mismatch")

    def test_audit_hmac_rejects_missing_secret_and_raw_log_without_printing_value(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            audit_file = Path(temp_dir) / "mcp_audit.retained.jsonl"
            manifest_file = Path(temp_dir) / "mcp_audit.retained.manifest.json"
            self.write_audit_events(audit_file, self.audit_event_chain(["2026-06-05T00:00:00Z"]))

            with patch.dict("os.environ", {}, clear=True):
                with redirect_stdout(io.StringIO()) as missing_stdout:
                    missing_exit = main(
                        [
                            "audit-hmac",
                            "--input",
                            str(audit_file),
                            "--manifest",
                            str(manifest_file),
                        ]
                    )
            self.assertEqual(missing_exit, 1)
            self.assertIn("Audit HMAC failed: hmac_secret_missing", missing_stdout.getvalue())
            self.assertFalse(manifest_file.exists())

            raw_file = Path(temp_dir) / "mcp_audit.raw.jsonl"
            raw_file.write_text("Authorization: Bearer rawBearerToken1234567890\n", encoding="utf-8")
            with patch.dict("os.environ", {"BURP_AI_AUDIT_HMAC_KEY": "DUMMY_HMAC_SECRET_1234567890"}, clear=False):
                with redirect_stdout(io.StringIO()) as raw_stdout:
                    raw_exit = main(
                        [
                            "audit-hmac",
                            "--input",
                            str(raw_file),
                            "--manifest",
                            str(manifest_file),
                        ]
                    )
            text = raw_stdout.getvalue()
            self.assertEqual(raw_exit, 1)
            self.assertIn("Audit HMAC failed: audit_review_failed", text)
            self.assertNotIn("rawBearerToken1234567890", text)

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
                    small_connection.putrequest("POST", "/ingest/burp-history")
                    small_connection.putheader("Content-Type", "application/json")
                    small_connection.putheader("Content-Length", str(len(body)))
                    small_connection.endheaders()
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

    def test_windows_launcher_scripts_are_documented_and_raw_free(self) -> None:
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        quickstart = (ROOT / "docs" / "USER_QUICKSTART.md").read_text(encoding="utf-8")
        start_ps1 = (ROOT / "scripts" / "start_gateway.ps1").read_text(encoding="utf-8")
        start_bat = (ROOT / "scripts" / "start_gateway.bat").read_text(encoding="utf-8")
        stop_ps1 = (ROOT / "scripts" / "stop_gateway.ps1").read_text(encoding="utf-8")

        for text in [readme, quickstart]:
            self.assertIn("scripts\\start_gateway.ps1", text)
            self.assertIn("scripts\\stop_gateway.ps1", text)
            self.assertIn("out\\.launcher", text)
            self.assertIn("raw_data_included=false", text)

        self.assertIn("serve", start_ps1)
        self.assertIn("dashboard", start_ps1)
        self.assertIn("--host", start_ps1)
        self.assertIn("127.0.0.1", start_ps1)
        self.assertIn("8765", start_ps1)
        self.assertIn("8766", start_ps1)
        self.assertIn("out\\.launcher", start_ps1)
        self.assertIn("receiver.pid", start_ps1)
        self.assertIn("dashboard.pid", start_ps1)
        self.assertIn("-WindowStyle Hidden", start_ps1)
        self.assertIn("raw_data_included", start_ps1)
        self.assertIn("Stop-Process", stop_ps1)
        self.assertIn("Win32_Process", stop_ps1)
        self.assertIn("unexpected_process", stop_ps1)
        self.assertIn("start_gateway.ps1", start_bat)

        self.assertNotIn("raw request", start_ps1.lower())
        self.assertNotIn("raw response", start_ps1.lower())
        self.assertNotIn("cookie", start_ps1.lower())
        self.assertNotIn("authorization", start_ps1.lower())
        self.assertNotIn("hmac", start_ps1.lower())
        self.assertNotIn("csrf", start_ps1.lower())

    def test_windows_launcher_guide_documents_safe_troubleshooting(self) -> None:
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        quickstart = (ROOT / "docs" / "USER_QUICKSTART.md").read_text(encoding="utf-8")
        guide = (ROOT / "docs" / "WINDOWS_LAUNCHER_GUIDE.md").read_text(encoding="utf-8")

        self.assertIn("WINDOWS_LAUNCHER_GUIDE.md", readme)
        self.assertIn("WINDOWS_LAUNCHER_GUIDE.md", quickstart)
        self.assertIn("scripts\\start_gateway.ps1", guide)
        self.assertIn("scripts\\start_gateway.bat", guide)
        self.assertIn("scripts\\stop_gateway.ps1", guide)
        self.assertIn("http://127.0.0.1:8766/", guide)
        self.assertIn("Receiver port", guide)
        self.assertIn("Dashboard port", guide)
        self.assertIn("Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass", guide)
        self.assertIn("receiver_port_in_use", guide)
        self.assertIn("dashboard_port_in_use", guide)
        self.assertIn("unexpected_process", guide)
        self.assertIn("raw-free metadata only", guide)
        self.assertIn("raw_data_included=false", guide)
        self.assertIn("out\\.launcher", guide)

        blocked_values = [
            "real Burp data",
            "customer domains",
            "tokens",
            "cookies",
            "session values",
            "personal data",
            "HMAC secrets",
            "CSRF values",
        ]
        for value in blocked_values:
            self.assertIn(value, guide)

    def test_gui_user_flow_guide_documents_safe_dashboard_sequence(self) -> None:
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        quickstart = (ROOT / "docs" / "USER_QUICKSTART.md").read_text(encoding="utf-8")
        local_dashboard = (ROOT / "docs" / "LOCAL_DASHBOARD.md").read_text(encoding="utf-8")
        audit_panel_guide = (ROOT / "docs" / "GUI_AUDIT_PANEL_GUIDE.md").read_text(encoding="utf-8")
        user_flow = (ROOT / "docs" / "GUI_USER_FLOW.md").read_text(encoding="utf-8")

        for text in [readme, quickstart, local_dashboard, audit_panel_guide]:
            self.assertIn("GUI_USER_FLOW.md", text)
        for text in [readme, quickstart, local_dashboard, user_flow]:
            self.assertIn("GUI_AI_SAFE_PREFLIGHT.md", text)
            self.assertIn("GUI_AI_HANDOFF_INDEX.md", text)
            self.assertIn("GUI_FINDING_TRIAGE_INDEX.md", text)
            self.assertIn("GUI_REPORT_READINESS_INDEX.md", text)
            self.assertIn("GUI_WORKFLOW_STATUS_INDEX.md", text)

        required = [
            "start receiver and dashboard",
            "send scoped Burp history",
            "verify the selected output",
            "review candidate findings",
            "check finding triage index",
            "generate report_draft.md",
            "check report readiness index",
            "check workflow status index",
            "check AI-safe preflight",
            "check AI handoff index",
            "export safe files",
            "send only verified safe files to AI",
            "http://127.0.0.1:8766/",
            "/triage?project=<alias>",
            "/report-readiness?project=<alias>",
            "/workflow?project=<alias>",
            "/preflight?project=<alias>",
            "/handoff?project=<alias>",
            "/help",
            "/operations",
            "/settings",
            "Verify",
            "Review",
            "Report",
            "Finding triage index",
            "Report readiness index",
            "Workflow status index",
            "AI-safe preflight",
            "AI handoff index",
            "Export",
            "analysis_packet.json",
            "chatgpt_prompt.md",
            "codex_task_prompt.md",
            "report_draft.md",
            "is evidence confidence, not severity",
            "risk_rating_draft",
            "Final severity requires",
            "CVSS is a separate calculation scope",
        ]
        for item in required:
            self.assertIn(item, user_flow)

        blocked_items = [
            "Raw request or response data",
            "Cookie, Authorization, token, JWT, or session values",
            "Real domains, customer names, internal IPs, or personal data",
            "HMAC secrets, CSRF values, or local secret files",
            "raw viewers",
            "replay or active scan",
            "archive or HMAC execution buttons",
            "finding triage execution buttons",
            "report readiness execution buttons",
            "workflow status execution buttons",
            "AI-safe preflight execution buttons",
            "AI handoff execution buttons",
            "risk profile change buttons",
            "delete or edit actions",
            "settings-write actions",
        ]
        for item in blocked_items:
            self.assertIn(item, user_flow)

        self.assertNotIn("raw_request", user_flow)
        self.assertNotIn("raw_response", user_flow)
        self.assertNotIn("DUMMY_COOKIE_VALUE", user_flow)
        self.assertNotIn("DUMMY_BEARER_TOKEN", user_flow)

    def test_gui_ai_safe_preflight_guide_documents_read_only_boundary(self) -> None:
        guide = (ROOT / "docs" / "GUI_AI_SAFE_PREFLIGHT.md").read_text(encoding="utf-8")
        required = [
            "read-only checklist",
            "/preflight?project=<alias>",
            "analysis_packet.json",
            "chatgpt_prompt.md",
            "codex_task_prompt.md",
            "report_draft.md",
            "verify status",
            "verify files checked",
            "finding candidate count",
            "forbidden marker scan",
            "raw_data_included",
            "ready candidate",
            "Verify first",
            "Manual review is required",
            "raw request or response data",
            "Cookie or Authorization values",
            "token, JWT, or session values",
            "real domain, URL, or IP values",
            "personal data",
            "HMAC secret or CSRF token values",
            "candidate",
            "risk_rating_draft",
            "final severity",
            "CVSS is a separate calculation scope",
            "POST action",
            "state-changing button",
            "raw viewer",
            "replay or active scan",
        ]
        for item in required:
            self.assertIn(item, guide)

        self.assertNotIn("raw_request", guide)
        self.assertNotIn("raw_response", guide)
        self.assertNotIn("DUMMY_COOKIE_VALUE", guide)
        self.assertNotIn("DUMMY_BEARER_TOKEN", guide)

    def test_gui_finding_triage_index_guide_documents_read_only_boundary(self) -> None:
        guide = (ROOT / "docs" / "GUI_FINDING_TRIAGE_INDEX.md").read_text(encoding="utf-8")
        required = [
            "read-only triage checklist",
            "/triage?project=<alias>",
            "project alias",
            "finding candidate count",
            "candidate index",
            "stable candidate id",
            "category/type",
            "title",
            "sanitized summary",
            "evidence confidence",
            "draft risk profile",
            "severity draft",
            "likelihood draft",
            "impact draft",
            "manual review required",
            "analysis_packet.json",
            "report_draft.md",
            "candidate finding",
            "Draft risk",
            "Final severity requires manual decision",
            "CVSS is a separate calculation scope",
            "raw request or response data",
            "Cookie or Authorization values",
            "token, JWT, or session values",
            "real domain, URL, or IP values",
            "personal data",
            "HMAC secret or CSRF token values",
            "full local path",
            "POST action",
            "state-changing button",
            "finding body preview",
            "request preview",
            "response preview",
            "raw viewer",
            "replay or active scan",
        ]
        for item in required:
            self.assertIn(item, guide)

        self.assertNotIn("raw_request", guide)
        self.assertNotIn("raw_response", guide)
        self.assertNotIn("DUMMY_COOKIE_VALUE", guide)
        self.assertNotIn("DUMMY_BEARER_TOKEN", guide)
        self.assertNotIn("safe to share", guide)
        self.assertNotIn("approved", guide)
        self.assertNotIn("guaranteed safe", guide)
        self.assertNotIn("severity confirmed", guide)

    def test_gui_report_readiness_index_guide_documents_read_only_boundary(self) -> None:
        guide = (ROOT / "docs" / "GUI_REPORT_READINESS_INDEX.md").read_text(encoding="utf-8")
        required = [
            "read-only draft report checklist",
            "/report-readiness?project=<alias>",
            "project alias",
            "draft report status",
            "analysis_packet.json",
            "report_draft.md",
            "finding candidate count",
            "draft report status summary",
            "triage link",
            "preflight link",
            "handoff link",
            "export/review/report flow link",
            "exists or missing",
            "file size in bytes",
            "modified UTC timestamp",
            "SHA-256 file fingerprint",
            "not HMAC",
            "scope confirmation",
            "affected endpoint confirmation",
            "evidence quality confirmation",
            "false positive possibility",
            "impact statement review",
            "remediation wording review",
            "final severity manual decision",
            "customer submission sensitive-info review",
            "finding candidates",
            "Risk is draft",
            "Evidence confidence is not severity",
            "report_draft.md is a draft report, not a submission report",
            "Final severity is a manual decision",
            "raw request or response data",
            "raw audit row body",
            "Cookie or Authorization values",
            "token, JWT, or session values",
            "real domain, URL, or IP values",
            "personal data",
            "HMAC secret or CSRF token values",
            "full local path",
            "form or POST action",
            "state-changing button",
            "report body preview",
            "request preview",
            "response preview",
            "new download action",
            "raw viewer",
            "replay or active scan",
        ]
        for item in required:
            self.assertIn(item, guide)

        self.assertNotIn("raw_request", guide)
        self.assertNotIn("raw_response", guide)
        self.assertNotIn("DUMMY_COOKIE_VALUE", guide)
        self.assertNotIn("DUMMY_BEARER_TOKEN", guide)
        self.assertNotIn("safe to share", guide)
        self.assertNotIn("approved", guide)
        self.assertNotIn("guaranteed safe", guide)
        self.assertNotIn("severity confirmed", guide)
        self.assertNotIn("ready to submit", guide)

    def test_gui_workflow_status_index_guide_documents_read_only_boundary(self) -> None:
        guide = (ROOT / "docs" / "GUI_WORKFLOW_STATUS_INDEX.md").read_text(encoding="utf-8")
        required = [
            "read-only workflow checklist",
            "/workflow?project=<alias>",
            "project alias",
            "verify status summary",
            "review status summary",
            "finding candidate count",
            "report_draft.md",
            "analysis_packet.json",
            "chatgpt_prompt.md",
            "codex_task_prompt.md",
            "preflight",
            "handoff",
            "triage",
            "report-readiness",
            "review/report/export flow",
            "safe file status",
            "candidate available",
            "draft available",
            "manual review required",
            "finding is candidate",
            "risk is draft",
            "final severity is a manual decision",
            "report_draft.md is a draft report, not a submission report",
            "raw request or response data",
            "raw audit row body",
            "Cookie or Authorization values",
            "token, JWT, or session values",
            "real domain, URL, or IP values",
            "personal data",
            "HMAC secret or CSRF token values",
            "full local path",
            "form or POST action",
            "state-changing button",
            "new download action",
            "raw viewer",
            "replay or active scan",
        ]
        for item in required:
            self.assertIn(item, guide)

        self.assertNotIn("raw_request", guide)
        self.assertNotIn("raw_response", guide)
        self.assertNotIn("DUMMY_COOKIE_VALUE", guide)
        self.assertNotIn("DUMMY_BEARER_TOKEN", guide)
        self.assertNotIn("safe to share", guide)
        self.assertNotIn("approved", guide)
        self.assertNotIn("guaranteed safe", guide)
        self.assertNotIn("severity confirmed", guide)
        self.assertNotIn("ready to submit", guide)

    def test_gui_ai_handoff_index_guide_documents_read_only_boundary(self) -> None:
        guide = (ROOT / "docs" / "GUI_AI_HANDOFF_INDEX.md").read_text(encoding="utf-8")
        required = [
            "read-only checklist",
            "/handoff?project=<alias>",
            "analysis_packet.json",
            "chatgpt_prompt.md",
            "codex_task_prompt.md",
            "report_draft.md",
            "Recommended order",
            "exists or missing",
            "file size in bytes",
            "modified UTC timestamp",
            "SHA-256 file fingerprint",
            "not HMAC",
            "verify first",
            "Manual review is required",
            "candidate finding",
            "draft risk",
            "final severity requires human decision",
            "raw request or response data",
            "Cookie or Authorization values",
            "token, JWT, or session values",
            "real domain, URL, or IP values",
            "personal data",
            "HMAC secret or CSRF token values",
            "POST action",
            "state-changing button",
            "new download action",
            "safe file body preview",
            "raw viewer",
            "replay or active scan",
        ]
        for item in required:
            self.assertIn(item, guide)

        self.assertNotIn("raw_request", guide)
        self.assertNotIn("raw_response", guide)
        self.assertNotIn("DUMMY_COOKIE_VALUE", guide)
        self.assertNotIn("DUMMY_BEARER_TOKEN", guide)
        self.assertNotIn("safe to share", guide)
        self.assertNotIn("approved", guide)
        self.assertNotIn("guaranteed safe", guide)
        self.assertNotIn("severity confirmed", guide)


if __name__ == "__main__":
    unittest.main()
