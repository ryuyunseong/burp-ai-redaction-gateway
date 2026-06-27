from __future__ import annotations

import gzip
import hashlib
import http.client
import io
import json
import re
import subprocess
import tempfile
import threading
import unittest
import uuid
from collections import Counter
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
    _build_live_capture_receiver_output_evidence,
    _verified_output,
    create_dashboard_server,
    write_dashboard_action_audit_event,
)
from burp_ai_redaction_gateway.findings import build_finding_candidates
from burp_ai_redaction_gateway.live_capture_scope import (
    SCOPE_REASON_CONTROL_OR_SPACE,
    SCOPE_REASON_EMPTY,
    SCOPE_REASON_IP_LITERAL,
    SCOPE_REASON_LOOPBACK_NAME,
    SCOPE_REASON_MALFORMED,
    SCOPE_REASON_MALFORMED_LABEL,
    SCOPE_REASON_MATCHED,
    SCOPE_REASON_SUFFIX_MISMATCH,
    SCOPE_REASON_TOO_LONG,
    SCOPE_REASON_URL_OR_PATH,
    SCOPE_REASON_WILDCARD,
    LiveCaptureScopeError,
    evaluate_live_capture_scope_match,
    host_matches_live_capture_scope,
    live_capture_scope_alias,
    normalize_live_capture_scope,
    validate_live_capture_scope,
)
from burp_ai_redaction_gateway.live_capture_receiver_scope import (
    RECEIVER_SCOPE_AUDIT_EVENT_TYPE,
    RECEIVER_SCOPE_DECISION_ACCEPT,
    RECEIVER_SCOPE_DECISION_DROP,
    RECEIVER_SCOPE_REASON_IN_SCOPE,
    RECEIVER_SCOPE_REASON_INVALID_HOST,
    RECEIVER_SCOPE_REASON_INVALID_SCOPE,
    RECEIVER_SCOPE_REASON_MISSING_HOST,
    RECEIVER_SCOPE_REASON_OUT_OF_SCOPE,
    RECEIVER_SCOPE_RESULT_ACCEPTED,
    RECEIVER_SCOPE_RESULT_SKIPPED,
    RECEIVER_SCOPE_SUMMARY_KIND_ACCEPT,
    RECEIVER_SCOPE_SUMMARY_KIND_SKIP,
    SAFE_HOST_METADATA_CONTAINERS,
    SAFE_HOST_METADATA_KEYS,
    build_receiver_scope_audit_event,
    build_receiver_scope_decision_summary,
    evaluate_receiver_scope_decision_summary,
    evaluate_receiver_scope_dry_run,
)
from burp_ai_redaction_gateway.mcp_server import ReadOnlyMcpGateway, ReadOnlyMcpServer, _next_rotated_audit_path
from burp_ai_redaction_gateway.mcp_adapter_dry_run import (
    McpAdapterDryRunError,
    build_adapter_blocked_response_for_case,
    build_adapter_dry_run_plan,
    evaluate_adapter_dry_run_case,
    evaluate_adapter_dry_run_fixture,
)
from burp_ai_redaction_gateway.mcp_listener_skeleton import (
    build_blocked_listener_response,
    build_listener_skeleton_metadata,
)
from burp_ai_redaction_gateway.mcp_minimal_skeleton import (
    build_minimal_skeleton_disabled_response,
    build_minimal_skeleton_metadata,
)
from burp_ai_redaction_gateway.mcp_protocol_parser import (
    BLOCKED_RESPONSE_ALLOWED_FIELDS as PROTOCOL_PARSER_BLOCKED_RESPONSE_ALLOWED_FIELDS,
    NEGATIVE_REASON_CODES as PROTOCOL_PARSER_NEGATIVE_REASON_CODES,
    POSITIVE_REASON_CODES as PROTOCOL_PARSER_POSITIVE_REASON_CODES,
    POSITIVE_RESPONSE_ALLOWED_FIELDS as PROTOCOL_PARSER_POSITIVE_RESPONSE_ALLOWED_FIELDS,
    build_blocked_parser_response,
    build_minimal_protocol_parser_metadata,
    build_positive_parser_response,
    parse_minimal_positive_protocol_message,
    parse_minimal_protocol_message,
    validate_negative_case_fixture,
    validate_positive_case_fixture,
)
from burp_ai_redaction_gateway.mcp_dispatcher import (
    DISPATCHER_RESPONSE_ALLOWED_FIELDS,
    FALLBACK_REASON_CODE,
    NEGATIVE_REASON_CODES,
    SAFE_DISPATCHER_MESSAGE,
    build_blocked_dispatcher_response,
    build_minimal_dispatcher_metadata,
    classify_dispatcher_metadata,
)
from burp_ai_redaction_gateway.mcp_listener_runtime import (
    MinimalListenerRuntimeConfig,
    build_default_listener_runtime_config,
    build_listener_runtime_response,
    build_minimal_listener_local_smoke_summary,
    build_listener_runtime_metadata,
    is_all_interface_host,
    is_loopback_host,
    validate_minimal_listener_startup,
)
from burp_ai_redaction_gateway.mcp_runtime_contract import validate_loopback_host_candidate
from burp_ai_redaction_gateway.mcp_read_only_registry import (
    ALLOWED_TOOL_NAMES,
    BLOCKED_RESPONSE_ALLOWED_FIELDS,
    BLOCKED_RESPONSE_CODES,
    FORBIDDEN_TOOL_CONCEPTS,
    SAFE_FILE_ALLOWLIST,
    McpReadOnlyRegistryError,
    ReadOnlyRegistryEntry,
    build_blocked_response,
    build_read_only_tool_registry,
    build_read_only_registry_metadata,
    validate_registry_against_contract_fixtures,
)
from burp_ai_redaction_gateway.mcp_tool_schema_catalog import (
    McpToolSchemaCatalogError,
    assert_tool_schema_catalog_raw_free,
    build_local_only_tool_schema_catalog,
    validate_tool_schema_catalog_against_fixtures,
    validate_tool_schema_catalog_against_registry,
)
from burp_ai_redaction_gateway.models import HttpRequest, HttpResponse, RawEvent, SanitizedEvent
from burp_ai_redaction_gateway.parser import load_events
from burp_ai_redaction_gateway.policy import load_policy
from burp_ai_redaction_gateway.receiver import ReceiverConfig, ReceiverError, create_server, ingest_montoya_payload
from burp_ai_redaction_gateway.redaction import Redactor, _safe_sensitive_field_path, _template_path, _templated_query
from burp_ai_redaction_gateway.risk import RISK_RATING_PROFILE_NAMES, build_risk_rating_draft
from burp_ai_redaction_gateway.scanner import assert_no_sensitive_text, scan_text
from burp_ai_redaction_gateway.verifier import VerificationResult, verify_path


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
LIVE_CAPTURE_COLLECTOR_CONTRACT_DOC = ROOT / "docs" / "LIVE_CAPTURE_COLLECTOR_CONTRACT_v0.5.md"
LIVE_CAPTURE_COLLECTOR_CONTRACT_FIXTURE = ROOT / "samples" / "synthetic_live_capture_collector_contract.json"
LIVE_CAPTURE_SCOPE_DRIFT_MATRIX_DOC = ROOT / "docs" / "LIVE_CAPTURE_SCOPE_DRIFT_MATRIX_v0.5.md"
LIVE_CAPTURE_SCOPE_DRIFT_MATRIX_FIXTURE = ROOT / "samples" / "synthetic_live_capture_scope_drift_matrix.json"
LIVE_CAPTURE_SCOPE_DRIFT_MATRIX_JAVA_TEST = (
    ROOT
    / "extensions"
    / "montoya-collector"
    / "src"
    / "test"
    / "java"
    / "com"
    / "ryuyunseong"
    / "burpai"
    / "redactiongateway"
    / "CollectorSafeHostMetadataMatrixTest.java"
)
LIVE_CAPTURE_RUNTIME_SMOKE_CHECKLIST_DOC = ROOT / "docs" / "LIVE_CAPTURE_RUNTIME_SMOKE_CHECKLIST_v0.5.md"
LIVE_CAPTURE_RUNTIME_SMOKE_EVIDENCE_TEMPLATE = (
    ROOT / "docs" / "templates" / "LIVE_CAPTURE_RUNTIME_SMOKE_EVIDENCE_TEMPLATE.md"
)
V05_TROUBLESHOOTING_DOC = ROOT / "docs" / "TROUBLESHOOTING_v0.5.md"
LIVE_CAPTURE_DASHBOARD_INTEGRATION_PLAN_DOC = (
    ROOT / "docs" / "LIVE_CAPTURE_DASHBOARD_INTEGRATION_PLAN_v0.5.md"
)
LIVE_CAPTURE_RUNTIME_EVIDENCE_SOURCE_DOC = ROOT / "docs" / "LIVE_CAPTURE_RUNTIME_EVIDENCE_SOURCE_v0.5.md"
LIVE_CAPTURE_LOCAL_EVIDENCE_SCHEMA_DOC = ROOT / "docs" / "LIVE_CAPTURE_LOCAL_EVIDENCE_SCHEMA_v0.5.md"
LIVE_CAPTURE_LOCAL_EVIDENCE_SCHEMA_FIXTURE = (
    ROOT / "samples" / "synthetic_live_capture_local_evidence_schema.json"
)
V05_RELEASE_READINESS_DOC = ROOT / "docs" / "RELEASE_READINESS_v0.5.md"
V05_RC_READINESS_DOC = ROOT / "docs" / "RC_READINESS_v0.5.md"
V05_MONTOYA_RUNTIME_SMOKE_RELEASE_EVIDENCE_DOC = (
    ROOT / "docs" / "V05_MONTOYA_RUNTIME_SMOKE_RELEASE_EVIDENCE.md"
)
ROADMAP_V06_DOC = ROOT / "docs" / "ROADMAP_v0.6.md"
V06_FAST_TRACK_PLAN_DOC = ROOT / "docs" / "V0.6_FAST_TRACK_PLAN.md"
V06_RC_READINESS_CHECKLIST_DOC = ROOT / "docs" / "V0.6_RC_READINESS_CHECKLIST.md"
V06_QUICKSTART_SMOKE_DOC = ROOT / "docs" / "V0.6_QUICKSTART_SMOKE.md"
V06_RELEASE_NOTES_DRAFT_DOC = ROOT / "docs" / "V0.6_RELEASE_NOTES_DRAFT.md"
V06_RC_FINAL_GATE_RUN_DOC = ROOT / "docs" / "V0.6_RC_FINAL_GATE_RUN.md"
V06_RELEASE_APPROVAL_PACKET_DOC = ROOT / "docs" / "V0.6_RELEASE_APPROVAL_PACKET.md"
V061_HOTFIX_TRIAGE_DOC = ROOT / "docs" / "V0.6.1_HOTFIX_TRIAGE.md"
V07_SCOPE_PLAN_DOC = ROOT / "docs" / "V0.7_SCOPE_PLAN.md"
V07_MCP_LISTENER_SKELETON_PLAN_DOC = ROOT / "docs" / "V0.7_MCP_LISTENER_SKELETON_PLAN.md"
V07_MCP_LISTENER_SKELETON_PLAN_FIXTURE = (
    ROOT / "tests" / "fixtures" / "v07_mcp_listener_skeleton_plan.json"
)
MCP_LISTENER_SKELETON_MODULE = ROOT / "burp_ai_redaction_gateway" / "mcp_listener_skeleton.py"
MCP_MINIMAL_SKELETON_MODULE = ROOT / "burp_ai_redaction_gateway" / "mcp_minimal_skeleton.py"
MCP_RUNTIME_CONTRACT_MODULE = ROOT / "burp_ai_redaction_gateway" / "mcp_runtime_contract.py"
V07_LISTENER_RUNTIME_DECISION_PREFLIGHT_DOC = (
    ROOT / "docs" / "V0.7_LISTENER_RUNTIME_DECISION_PREFLIGHT.md"
)
V07_LISTENER_RUNTIME_DECISION_PREFLIGHT_FIXTURE = (
    ROOT / "tests" / "fixtures" / "v07_listener_runtime_decision_preflight.json"
)
V07_MINIMAL_LISTENER_RUNTIME_APPROVAL_PACKET_DOC = (
    ROOT / "docs" / "V0.7_MINIMAL_LISTENER_RUNTIME_APPROVAL_PACKET.md"
)
V07_MINIMAL_LISTENER_RUNTIME_APPROVAL_PACKET_FIXTURE = (
    ROOT / "tests" / "fixtures" / "v07_minimal_listener_runtime_approval_packet.json"
)
V07_MINIMAL_LISTENER_RUNTIME_DESIGN_DOC = (
    ROOT / "docs" / "V0.7_MINIMAL_LISTENER_RUNTIME_DESIGN.md"
)
V07_MINIMAL_LISTENER_RUNTIME_DESIGN_FIXTURE = (
    ROOT / "tests" / "fixtures" / "v07_minimal_listener_runtime_design.json"
)
V07_RUNTIME_SOURCE_CHECK_CONSUMPTION_DOC = ROOT / "docs" / "V0.7_RUNTIME_SOURCE_CHECK_CONSUMPTION.md"
V07_RUNTIME_SOURCE_CHECK_CONSUMPTION_FIXTURE = (
    ROOT / "tests" / "fixtures" / "v07_runtime_source_check_consumption.json"
)
V07_LISTENER_NEGATIVE_TEST_HARNESS_DESIGN_DOC = (
    ROOT / "docs" / "V0.7_LISTENER_NEGATIVE_TEST_HARNESS_DESIGN.md"
)
V07_LISTENER_NEGATIVE_TEST_HARNESS_DESIGN_FIXTURE = (
    ROOT / "tests" / "fixtures" / "v07_listener_negative_test_harness_design.json"
)
V07_MINIMAL_LISTENER_RUNTIME_IMPLEMENTATION_DECISION_DOC = (
    ROOT / "docs" / "V0.7_MINIMAL_LISTENER_RUNTIME_IMPLEMENTATION_DECISION.md"
)
V07_MINIMAL_LISTENER_RUNTIME_IMPLEMENTATION_DECISION_FIXTURE = (
    ROOT / "tests" / "fixtures" / "v07_minimal_listener_runtime_implementation_decision.json"
)
V07_MINIMAL_LISTENER_RUNTIME_IMPLEMENTATION_DOC = (
    ROOT / "docs" / "V0.7_MINIMAL_LISTENER_RUNTIME_IMPLEMENTATION.md"
)
V07_MINIMAL_LISTENER_RUNTIME_IMPLEMENTATION_FIXTURE = (
    ROOT / "tests" / "fixtures" / "v07_minimal_listener_runtime_implementation.json"
)
V07_LISTENER_LOCAL_SMOKE_EVIDENCE_DOC = ROOT / "docs" / "V0.7_LISTENER_LOCAL_SMOKE_EVIDENCE.md"
V07_LISTENER_LOCAL_SMOKE_EVIDENCE_FIXTURE = (
    ROOT / "tests" / "fixtures" / "v07_listener_local_smoke_evidence.json"
)
V07_RC_READINESS_CHECKLIST_DOC = ROOT / "docs" / "V0.7_RC_READINESS_CHECKLIST.md"
V07_RC_READINESS_CHECKLIST_FIXTURE = ROOT / "tests" / "fixtures" / "v07_rc_readiness_checklist.json"
V07_RELEASE_APPROVAL_PACKET_DOC = ROOT / "docs" / "V0.7_RELEASE_APPROVAL_PACKET.md"
V07_RELEASE_APPROVAL_PACKET_FIXTURE = (
    ROOT / "tests" / "fixtures" / "v07_release_approval_packet.json"
)
V07_FINAL_GATE_EXECUTION_DOC = ROOT / "docs" / "V0.7_FINAL_GATE_EXECUTION.md"
V07_FINAL_GATE_EXECUTION_FIXTURE = (
    ROOT / "tests" / "fixtures" / "v07_final_gate_execution.json"
)
V07_RELEASE_NOTES_DRAFT_DOC = ROOT / "docs" / "V0.7_RELEASE_NOTES_DRAFT.md"
V07_RELEASE_NOTES_DRAFT_FIXTURE = (
    ROOT / "tests" / "fixtures" / "v07_release_notes_draft.json"
)
V08_BACKLOG_SPLIT_DOC = ROOT / "docs" / "V0.8_BACKLOG_SPLIT.md"
V08_BACKLOG_SPLIT_FIXTURE = ROOT / "tests" / "fixtures" / "v08_backlog_split.json"
V08_TRANSPORT_DESIGN_DOC = ROOT / "docs" / "V0.8_TRANSPORT_DESIGN.md"
V08_TRANSPORT_DESIGN_FIXTURE = ROOT / "tests" / "fixtures" / "v08_transport_design.json"
V08_PROTOCOL_HANDLER_DESIGN_DOC = ROOT / "docs" / "V0.8_PROTOCOL_HANDLER_DESIGN.md"
V08_PROTOCOL_HANDLER_DESIGN_FIXTURE = (
    ROOT / "tests" / "fixtures" / "v08_protocol_handler_design.json"
)
V08_PROTOCOL_NEGATIVE_HARNESS_DOC = ROOT / "docs" / "V0.8_PROTOCOL_NEGATIVE_TEST_HARNESS.md"
V08_PROTOCOL_NEGATIVE_HARNESS_FIXTURE = (
    ROOT / "tests" / "fixtures" / "v08_protocol_negative_harness.json"
)
V08_TOOL_REGISTRATION_DESIGN_DOC = ROOT / "docs" / "V0.8_TOOL_REGISTRATION_DESIGN.md"
V08_TOOL_REGISTRATION_DESIGN_FIXTURE = (
    ROOT / "tests" / "fixtures" / "v08_tool_registration_design.json"
)
V08_READ_ONLY_TOOL_CONTRACT_DOC = ROOT / "docs" / "V0.8_READ_ONLY_TOOL_CONTRACT.md"
V08_READ_ONLY_TOOL_CONTRACT_FIXTURE = (
    ROOT / "tests" / "fixtures" / "v08_read_only_tool_contract.json"
)
V08_MINIMAL_SKELETON_PLANNING_DOC = ROOT / "docs" / "V0.8_MINIMAL_SKELETON_PLANNING.md"
V08_MINIMAL_SKELETON_PLANNING_FIXTURE = (
    ROOT / "tests" / "fixtures" / "v08_minimal_skeleton_planning.json"
)
V08_SKELETON_APPROVAL_PACKET_DOC = ROOT / "docs" / "V0.8_SKELETON_APPROVAL_PACKET.md"
V08_SKELETON_APPROVAL_PACKET_FIXTURE = (
    ROOT / "tests" / "fixtures" / "v08_skeleton_approval_packet.json"
)
V08_RUNTIME_SOURCE_CHECK_CONSUMPTION_GUARD_DOC = (
    ROOT / "docs" / "V0.8_RUNTIME_SOURCE_CHECK_CONSUMPTION_GUARD.md"
)
V08_RUNTIME_SOURCE_CHECK_CONSUMPTION_GUARD_FIXTURE = (
    ROOT / "tests" / "fixtures" / "v08_runtime_source_check_consumption_guard.json"
)
V08_POST_MERGE_BOUNDARY_NOTE_DOC = ROOT / "docs" / "V0.8_POST_MERGE_BOUNDARY_NOTE.md"
V08_POST_MERGE_BOUNDARY_NOTE_FIXTURE = (
    ROOT / "tests" / "fixtures" / "v08_post_merge_boundary_note.json"
)
V08_SCOPE_FREEZE_RC_READINESS_DOC = ROOT / "docs" / "V0.8_SCOPE_FREEZE_RC_READINESS.md"
V08_SCOPE_FREEZE_RC_READINESS_FIXTURE = (
    ROOT / "tests" / "fixtures" / "v08_scope_freeze_rc_readiness.json"
)
V08_RELEASE_APPROVAL_PACKET_DOC = ROOT / "docs" / "V0.8_RELEASE_APPROVAL_PACKET.md"
V08_RELEASE_APPROVAL_PACKET_FIXTURE = (
    ROOT / "tests" / "fixtures" / "v08_release_approval_packet.json"
)
V08_FINAL_GATE_EVIDENCE_DOC = ROOT / "docs" / "V0.8_FINAL_GATE_EVIDENCE.md"
V08_FINAL_GATE_EVIDENCE_FIXTURE = ROOT / "tests" / "fixtures" / "v08_final_gate_evidence.json"
V09_RUNTIME_SCOPE_DECISION_DOC = ROOT / "docs" / "V0.9_RUNTIME_SCOPE_DECISION.md"
V09_RUNTIME_SCOPE_DECISION_FIXTURE = (
    ROOT / "tests" / "fixtures" / "v09_runtime_scope_decision.json"
)
V09_PROTOCOL_PARSER_APPROVAL_PACKET_DOC = (
    ROOT / "docs" / "V0.9_PROTOCOL_PARSER_APPROVAL_PACKET.md"
)
V09_PROTOCOL_PARSER_APPROVAL_PACKET_FIXTURE = (
    ROOT / "tests" / "fixtures" / "v09_protocol_parser_approval_packet.json"
)
V09_PROTOCOL_PARSER_NEGATIVE_CASES_FIXTURE = (
    ROOT / "tests" / "fixtures" / "v09_protocol_parser_negative_cases.json"
)
V09_PROTOCOL_PARSER_IMPLEMENTATION_DECISION_DOC = (
    ROOT / "docs" / "V0.9_PROTOCOL_PARSER_IMPLEMENTATION_DECISION.md"
)
V09_PROTOCOL_PARSER_IMPLEMENTATION_DECISION_FIXTURE = (
    ROOT / "tests" / "fixtures" / "v09_protocol_parser_implementation_decision.json"
)
V09_PARSER_POSITIVE_SHAPE_DECISION_DOC = (
    ROOT / "docs" / "V0.9_PARSER_POSITIVE_SHAPE_DECISION.md"
)
V09_PARSER_POSITIVE_SHAPE_DECISION_FIXTURE = (
    ROOT / "tests" / "fixtures" / "v09_parser_positive_shape_decision.json"
)
V09_PARSER_POSITIVE_SHAPE_CASES_FIXTURE = (
    ROOT / "tests" / "fixtures" / "v09_parser_positive_shape_cases.json"
)
V09_READ_ONLY_TOOL_REGISTRY_CONTRACT_DOC = (
    ROOT / "docs" / "V0.9_READ_ONLY_TOOL_REGISTRY_CONTRACT.md"
)
V09_READ_ONLY_TOOL_REGISTRY_CONTRACT_FIXTURE = (
    ROOT / "tests" / "fixtures" / "v09_read_only_tool_registry_contract.json"
)
V09_READ_ONLY_TOOL_REGISTRY_IMPLEMENTATION_GUARD_FIXTURE = (
    ROOT / "tests" / "fixtures" / "v09_read_only_tool_registry_implementation_guard.json"
)
V09_READ_ONLY_REGISTRY_DISPATCHER_BOUNDARY_DOC = (
    ROOT / "docs" / "V0.9_READ_ONLY_REGISTRY_DISPATCHER_BOUNDARY.md"
)
V09_READ_ONLY_REGISTRY_DISPATCHER_BOUNDARY_FIXTURE = (
    ROOT / "tests" / "fixtures" / "v09_read_only_registry_dispatcher_boundary.json"
)
V09_DISPATCHER_APPROVAL_PACKET_DOC = (
    ROOT / "docs" / "V0.9_DISPATCHER_APPROVAL_PACKET.md"
)
V09_DISPATCHER_APPROVAL_PACKET_FIXTURE = (
    ROOT / "tests" / "fixtures" / "v09_dispatcher_approval_packet.json"
)
V09_DISPATCHER_NEGATIVE_CASES_FIXTURE = (
    ROOT / "tests" / "fixtures" / "v09_dispatcher_negative_cases.json"
)
V09_DISPATCHER_IMPLEMENTATION_DECISION_DOC = (
    ROOT / "docs" / "V0.9_DISPATCHER_IMPLEMENTATION_DECISION.md"
)
V09_DISPATCHER_IMPLEMENTATION_DECISION_FIXTURE = (
    ROOT / "tests" / "fixtures" / "v09_dispatcher_implementation_decision.json"
)
V09_RELEASE_READINESS_DOC = ROOT / "docs" / "V0.9_RELEASE_READINESS.md"
V09_RELEASE_READINESS_FIXTURE = (
    ROOT / "tests" / "fixtures" / "v09_release_readiness.json"
)
MCP_DISPATCHER_MODULE = ROOT / "burp_ai_redaction_gateway" / "mcp_dispatcher.py"
MCP_PROTOCOL_PARSER_MODULE = ROOT / "burp_ai_redaction_gateway" / "mcp_protocol_parser.py"
MCP_LISTENER_RUNTIME_MODULE = ROOT / "burp_ai_redaction_gateway" / "mcp_listener_runtime.py"
V05_HOTFIX_POLICY_DOC = ROOT / "docs" / "V0.5_HOTFIX_POLICY.md"
MCP_READ_ONLY_TOOL_CONTRACT_MATRIX_V06_DOC = (
    ROOT / "docs" / "MCP_READ_ONLY_TOOL_CONTRACT_MATRIX_v0.6.md"
)
MCP_READ_ONLY_TOOL_CONTRACT_MATRIX_V06_FIXTURE = (
    ROOT / "samples" / "synthetic_mcp_read_only_tool_contract_matrix_v0.6.json"
)
MCP_READ_ONLY_PROTOTYPE_PREFLIGHT_V06_DOC = (
    ROOT / "docs" / "MCP_READ_ONLY_PROTOTYPE_PREFLIGHT_v0.6.md"
)
MCP_READ_ONLY_PROTOTYPE_PREFLIGHT_V06_FIXTURE = (
    ROOT / "samples" / "synthetic_mcp_read_only_prototype_preflight_v0.6.json"
)
MCP_REGISTRY_ADAPTER_DESIGN_V06_DOC = (
    ROOT / "docs" / "MCP_REGISTRY_ADAPTER_DESIGN_v0.6.md"
)
MCP_REGISTRY_ADAPTER_FIXTURE_PLAN_V06_DOC = (
    ROOT / "docs" / "MCP_REGISTRY_ADAPTER_FIXTURE_PLAN_v0.6.md"
)
MCP_REGISTRY_ADAPTER_EXPECTED_BEHAVIOR_V06_FIXTURE = (
    ROOT / "samples" / "synthetic_mcp_registry_adapter_expected_behavior_v0.6.json"
)
MCP_IMPLEMENTATION_GATE_DESIGN_V06_DOC = (
    ROOT / "docs" / "MCP_IMPLEMENTATION_GATE_DESIGN_v0.6.md"
)
MCP_IMPLEMENTATION_GATE_V06_FIXTURE = (
    ROOT / "samples" / "synthetic_mcp_implementation_gate_v0.6.json"
)
MCP_ADAPTER_DRY_RUN_MODULE = ROOT / "burp_ai_redaction_gateway" / "mcp_adapter_dry_run.py"
MCP_TOOL_SCHEMA_CATALOG_MODULE = ROOT / "burp_ai_redaction_gateway" / "mcp_tool_schema_catalog.py"
MCP_TOOL_SCHEMA_CATALOG_DOC = ROOT / "docs" / "MCP_LOCAL_ONLY_TOOL_SCHEMA_CATALOG_v0.6.md"
MCP_RUNTIME_BOUNDARY_DECISION_V06_DOC = ROOT / "docs" / "MCP_RUNTIME_BOUNDARY_DECISION_v0.6.md"
MCP_SERVER_SKELETON_PREFLIGHT_V06_DOC = (
    ROOT / "docs" / "MCP_SERVER_SKELETON_PREFLIGHT_v0.6.md"
)
MCP_SERVER_SKELETON_PREFLIGHT_V06_FIXTURE = (
    ROOT / "tests" / "fixtures" / "mcp_server_skeleton_preflight_v0.6.json"
)
MCP_RUNTIME_BOUNDARY_CONSUMPTION_V06_DOC = (
    ROOT / "docs" / "MCP_RUNTIME_BOUNDARY_CONSUMPTION_v0.6.md"
)
MCP_RUNTIME_BOUNDARY_CONSUMPTION_V06_FIXTURE = (
    ROOT / "tests" / "fixtures" / "mcp_runtime_boundary_consumption_v0.6.json"
)
MCP_LISTENER_SKELETON_DECISION_V06_DOC = (
    ROOT / "docs" / "MCP_LISTENER_SKELETON_DECISION_v0.6.md"
)
MCP_LISTENER_SKELETON_ACCEPTANCE_V06_DOC = (
    ROOT / "docs" / "MCP_LISTENER_SKELETON_ACCEPTANCE_v0.6.md"
)
MCP_LISTENER_SKELETON_ACCEPTANCE_V06_FIXTURE = (
    ROOT / "tests" / "fixtures" / "mcp_listener_skeleton_acceptance_v0.6.json"
)
MCP_LISTENER_RUNTIME_SOURCE_CHECK_V06_DOC = (
    ROOT / "docs" / "MCP_LISTENER_RUNTIME_SOURCE_CHECK_v0.6.md"
)
MCP_LISTENER_RUNTIME_SOURCE_CHECK_V06_FIXTURE = (
    ROOT / "tests" / "fixtures" / "mcp_listener_runtime_source_check_v0.6.json"
)
MCP_INTEGRATION_DESIGN_DOC = ROOT / "docs" / "MCP_INTEGRATION_DESIGN_v0.5.md"
BURP_MCP_COMPATIBILITY_DOC = ROOT / "docs" / "BURP_MCP_COMPATIBILITY_v0.5.md"
WEB_UX_KO_PLAN_DOC = ROOT / "docs" / "WEB_UX_KO_PLAN_v0.5.md"
USER_QUICKSTART_KO_V06_DOC = ROOT / "docs" / "USER_QUICKSTART_KO_v0.6.md"
WEB_OPERATOR_GUIDE_KO_V07_DOC = ROOT / "docs" / "WEB_OPERATOR_GUIDE_KO_v0.7.md"
WEB_OPERATOR_SMOKE_CHECKLIST_KO_V07_DOC = (
    ROOT / "docs" / "WEB_OPERATOR_SMOKE_CHECKLIST_KO_v0.7.md"
)
WEB_UPLOAD_WIZARD_BROWSER_SMOKE_V07_FIXTURE = (
    ROOT / "tests" / "fixtures" / "web_upload_wizard_browser_smoke_v0.7.json"
)
OUTPUT_BUNDLE_GUIDE_KO_V06_DOC = ROOT / "docs" / "OUTPUT_BUNDLE_GUIDE_KO_v0.6.md"
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
    def multipart_form(
        self,
        fields: dict[str, str],
        file_field: str,
        file_name: str,
        file_bytes: bytes,
        *,
        content_type: str = "application/octet-stream",
    ) -> tuple[bytes, str]:
        boundary = "----redaction-gateway-test-boundary"
        chunks: list[bytes] = []
        for name, value in fields.items():
            chunks.extend(
                [
                    f"--{boundary}\r\n".encode("ascii"),
                    f'Content-Disposition: form-data; name="{name}"\r\n\r\n'.encode("ascii"),
                    value.encode("utf-8"),
                    b"\r\n",
                ]
            )
        chunks.extend(
            [
                f"--{boundary}\r\n".encode("ascii"),
                (
                    f'Content-Disposition: form-data; name="{file_field}"; filename="{file_name}"\r\n'
                    f"Content-Type: {content_type}\r\n\r\n"
                ).encode("ascii"),
                file_bytes,
                b"\r\n",
                f"--{boundary}--\r\n".encode("ascii"),
            ]
        )
        return b"".join(chunks), f"multipart/form-data; boundary={boundary}"

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

    def test_redactor_redacts_unsafe_metadata_paths_before_output_scan(self) -> None:
        counters: Counter[str] = Counter()
        opaque_segment = "".join(["AbCdEfGh", "IjKlMnOp", "QrStUvWx", "Yz1234567890"])

        field_path = _safe_sensitive_field_path(f"$.session.{opaque_segment}", counters)
        self.assertEqual(field_path, "$.redacted_field_001")
        self.assertEqual(scan_text(field_path), [])

        path_template, identifier_observed = _template_path(f"/assets/{opaque_segment}", counters)
        self.assertEqual(path_template, "/assets/{secret}")
        self.assertTrue(identifier_observed)
        self.assertEqual(scan_text(path_template), [])

        query_template = _templated_query("session_id=synthetic", counters)
        self.assertEqual(query_template, "?session_id:{value}")
        self.assertEqual(scan_text(f"cookie metadata {query_template}"), [])

        event = RawEvent(
            raw_id="synthetic-unsafe-metadata",
            request=HttpRequest(
                method="GET",
                url=f"https://target.example/assets/{opaque_segment}",
                headers={"Cookie": "session_id=synthetic; preference=synthetic"},
                body="",
            ),
            response=HttpResponse(
                status=200,
                headers={
                    "Content-Type": "text/plain; charset=utf-8",
                    "Cache-Control": "max-age=0",
                    "Set-Cookie": "session_id=synthetic; SameSite=Lax",
                },
                body="ok",
            ),
        )
        sanitized = Redactor().sanitize_event(event, 1)
        self.assertEqual(sanitized.request["path_template"], "/assets/{secret}")
        self.assertEqual(sanitized.signals["path_template"], "/assets/{secret}")
        self.assertIn("charset {value}", sanitized.response["headers"]["Content-Type"])
        self.assertIn("max-age {value}", sanitized.response["headers"]["Cache-Control"])
        self.assertEqual(scan_text(sanitized.request["path_template"]), [])
        self.assertEqual(scan_text(json.dumps(sanitized.to_dict(), sort_keys=True)), [])

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
                self.assertIn("처음 시작하기", body)
                self.assertIn("파일 업로드", body)
                self.assertIn("Live Capture 상태 확인", body)
                self.assertIn("AI에 넣을 수 있는 후보 파일 확인", body)
                self.assertIn("운영 도움말", body)
                self.assertIn('href="/upload"', body)
                self.assertIn('href="/live-capture"', body)
                self.assertIn('href="/safe-files?project=generated"', body)
                self.assertIn('href="/help"', body)
                self.assertIn("safe files 4개", body)
                self.assertIn("analysis_packet.json", body)
                self.assertIn("chatgpt_prompt.md", body)
                self.assertIn("codex_task_prompt.md", body)
                self.assertIn("report_draft.md", body)
                self.assertIn("AI 입력 후보 파일", body)
                self.assertIn("목록의 첫 번째 safe files", body)
                self.assertIn("최종 결과가 아닙니다", body)
                self.assertIn("final severity", body)
                self.assertIn("CVSS", body)
                self.assertNotIn("raw_request", body)
                self.assertNotIn("raw_response", body)
                self.assertNotIn("DUMMY_COOKIE_VALUE", body)
                self.assertNotIn("DUMMY_BEARER_TOKEN", body)
                self.assertNotIn("safe-to-share", body)
                self.assertNotIn("confirmed vulnerability", body)
                self.assertNotIn("final CVSS", body)
                self.assertNotIn(str(root), body)
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
                self.assertIn("AI 안전 사전 점검", detail)
                self.assertIn("/preflight?project=generated", detail)
                self.assertIn("사전 점검 상세", detail)
                self.assertIn("/handoff?project=generated", detail)
                self.assertIn("핸드오프 인덱스", detail)
                self.assertIn("/triage?project=generated", detail)
                self.assertIn("후보 분류 인덱스", detail)
                self.assertIn("/report-readiness?project=generated", detail)
                self.assertIn("보고서 준비", detail)
                self.assertIn("/prompt-readiness?project=generated", detail)
                self.assertIn("Prompt readiness", detail)
                self.assertIn("/evidence-boundary?project=generated", detail)
                self.assertIn("증거 경계", detail)
                self.assertIn("/workflow?project=generated", detail)
                self.assertIn("작업 흐름 상태", detail)
                self.assertIn("/operator-runbook?project=generated", detail)
                self.assertIn("Operator runbook", detail)
                self.assertIn("/safe-files?project=generated", detail)
                self.assertIn("Safe file inventory", detail)
                self.assertNotIn("AI-safe preflight", detail)
                self.assertNotIn("handoff index", detail)
                self.assertNotIn("triage index", detail)
                self.assertNotIn("report readiness", detail)
                self.assertNotIn("workflow status", detail)
                self.assertNotIn("Confirmed vulnerability", detail)
                connection.close()

                connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                connection.request("GET", "/simple?project=generated")
                response = connection.getresponse()
                simple = response.read().decode("utf-8")
                self.assertEqual(response.status, 200)
                self.assertIn('lang="ko"', simple)
                self.assertIn("간단 대시보드", simple)
                self.assertIn("read-only 간단 체크 화면", simple)
                self.assertIn("현재 상태", simple)
                self.assertIn("기본 보기와 고급 산출물", simple)
                self.assertIn("다음 행동", simple)
                self.assertIn("고급 화면", simple)
                self.assertIn("project alias", simple)
                self.assertIn("verify 결과", simple)
                self.assertIn("후보 finding", simple)
                self.assertIn(">22<", simple)
                self.assertIn("report_draft.md", simple)
                self.assertIn("AI 삽입 후보 파일", simple)
                self.assertIn("초안 risk", simple)
                self.assertIn("최종 심각도는 수동 검토가 필요합니다", simple)
                for name in ["analysis_packet.json", "chatgpt_prompt.md", "codex_task_prompt.md", "report_draft.md"]:
                    self.assertIn(name, simple)
                    self.assertIn("exists", simple)
                for link in [
                    "/safe-files?project=generated",
                    "/preflight?project=generated",
                    "/triage?project=generated",
                    "/report-readiness?project=generated",
                    "/workflow?project=generated",
                    "/evidence-boundary?project=generated",
                    "/operator-runbook?project=generated",
                ]:
                    self.assertIn(link, simple)
                for label in [
                    "raw request/response",
                    "Cookie",
                    "Authorization",
                    "token/JWT/session",
                    "무결성 검증 비밀값",
                    "요청 위조 방지 값",
                    "전체 로컬 경로",
                ]:
                    self.assertIn(label, simple)
                self.assertNotIn("<form", simple)
                self.assertNotIn("<button", simple)
                self.assertNotIn('method="post"', simple)
                self.assertNotIn("/download?", simple)
                self.assertNotIn("/preview?", simple)
                self.assertNotIn("HMAC secret", simple)
                self.assertNotIn("CSRF token", simple)
                self.assertNotIn("full local path", simple)
                self.assertNotIn("raw_request", simple)
                self.assertNotIn("raw_response", simple)
                self.assertNotIn("DUMMY_COOKIE_VALUE", simple)
                self.assertNotIn("DUMMY_BEARER_TOKEN", simple)
                self.assertNotIn("safe to share", simple)
                self.assertNotIn("guaranteed safe", simple)
                self.assertNotIn("severity confirmed", simple)
                self.assertNotIn("ready to submit", simple)
                self.assertNotIn(str(root), simple)
                connection.close()

                connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                connection.request("GET", "/dashboard-simple?project=generated")
                response = connection.getresponse()
                simple_alias = response.read().decode("utf-8")
                self.assertEqual(response.status, 200)
                self.assertIn("간단 대시보드", simple_alias)
                self.assertNotIn("<form", simple_alias)
                self.assertNotIn("<button", simple_alias)
                connection.close()

                connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                connection.request("GET", "/preflight?project=generated")
                response = connection.getresponse()
                preflight = response.read().decode("utf-8")
                self.assertEqual(response.status, 200)
                self.assertIn("AI 안전 사전 점검", preflight)
                self.assertIn("조회 전용", preflight)
                self.assertIn("사전 점검 상태", preflight)
                self.assertIn("후보 준비됨", preflight)
                self.assertIn("검증 상태", preflight)
                self.assertIn("검증한 파일 수", preflight)
                self.assertIn("finding 후보 수", preflight)
                self.assertIn("report_draft.md", preflight)
                self.assertIn("금지 마커 스캔", preflight)
                self.assertIn("raw_data_included", preflight)
                self.assertIn("false", preflight)
                for name in ["analysis_packet.json", "chatgpt_prompt.md", "codex_task_prompt.md", "report_draft.md"]:
                    self.assertIn(name, preflight)
                for label in [
                    "raw 요청/응답",
                    "Cookie 또는 Authorization 값",
                    "token, JWT, session 값",
                    "실제 도메인, URL, IP 값",
                    "개인정보",
                    "무결성 검증 비밀값 또는 요청 위조 방지 값",
                    "감사 로그, 압축 archive, manifest",
                ]:
                    self.assertIn(label, preflight)
                self.assertIn("수동 검증이 끝날 때까지 후보입니다", preflight)
                self.assertIn("초안이며 최종 심각도가 아닙니다", preflight)
                self.assertIn("수동 결정", preflight)
                self.assertNotIn("AI-safe preflight", preflight)
                self.assertNotIn("preflight status", preflight)
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
                self.assertIn("AI 핸드오프 인덱스", handoff)
                self.assertIn("조회 전용", handoff)
                self.assertIn("조회 전용 핸드오프 점검", handoff)
                self.assertIn("AI 안전 후보 파일", handoff)
                self.assertIn("먼저 verify", handoff)
                self.assertIn("수동 검토 필요", handoff)
                self.assertIn("사전 점검 상태", handoff)
                self.assertIn("사전 점검 열기", handoff)
                self.assertIn("/preflight?project=generated", handoff)
                self.assertIn("리뷰/보고서/내보내기 흐름", handoff)
                self.assertIn("수동 검증이 끝날 때까지 후보입니다", handoff)
                self.assertIn("초안이며 심각도 확정이 아닙니다", handoff)
                self.assertIn("최종 심각도는 사람이 결정합니다", handoff)
                self.assertIn("크기(bytes)", handoff)
                self.assertIn("수정 시각(UTC)", handoff)
                self.assertIn("SHA-256", handoff)
                self.assertIn("SHA-256 파일 fingerprint이며 HMAC이 아닙니다", handoff)
                for name in ["analysis_packet.json", "chatgpt_prompt.md", "codex_task_prompt.md", "report_draft.md"]:
                    self.assertIn(name, handoff)
                for purpose in [
                    "정제된 후보 증거 구조를 먼저 확인합니다.",
                    "ChatGPT에 수동 검토 보조를 요청할 때 사용합니다.",
                    "Codex에 구현 또는 리뷰 보조를 요청할 때 사용합니다.",
                    "사람이 검토할 후보 보고서 초안으로 마지막에 읽습니다.",
                ]:
                    self.assertIn(purpose, handoff)
                for label in [
                    "raw 요청/응답",
                    "Cookie 또는 Authorization 값",
                    "token, JWT, session 값",
                    "실제 도메인, URL, IP 값",
                    "개인정보",
                    "무결성 검증 비밀값 또는 요청 위조 방지 값",
                    "감사 로그, 압축 archive, manifest",
                ]:
                    self.assertIn(label, handoff)
                self.assertNotIn("AI handoff index", handoff)
                self.assertNotIn("Read-only handoff checklist", handoff)
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
                self.assertIn("Finding 후보 분류 인덱스", triage)
                self.assertIn("조회 전용", triage)
                self.assertIn("조회 전용 분류 점검", triage)
                self.assertIn("프로젝트 별칭", triage)
                self.assertIn("finding 후보 수", triage)
                self.assertIn(">22<", triage)
                self.assertIn("AI 안전 파일 allowlist", triage)
                for name in ["analysis_packet.json", "chatgpt_prompt.md", "codex_task_prompt.md", "report_draft.md"]:
                    self.assertIn(name, triage)
                self.assertIn("AI 안전 사전 점검 열기", triage)
                self.assertIn("AI 핸드오프 인덱스 열기", triage)
                self.assertIn("보고서 준비 인덱스 열기", triage)
                self.assertIn("/report-readiness?project=generated", triage)
                self.assertIn("리뷰/보고서/내보내기 흐름", triage)
                self.assertIn("수동 검증이 끝날 때까지 후보입니다", triage)
                self.assertIn("초안이며 심각도 확정이 아닙니다", triage)
                self.assertIn("증거 신뢰도이며 심각도가 아닙니다", triage)
                self.assertIn("수동 검토 필요", triage)
                self.assertIn("최종 심각도는 수동 결정이 필요합니다", triage)
                self.assertIn("후보 #1", triage)
                self.assertIn("FC-0001", triage)
                self.assertIn("missing_security_headers", triage)
                self.assertIn("Missing security headers", triage)
                self.assertIn("정제된 요약", triage)
                self.assertIn("심각도 초안", triage)
                for label in [
                    "raw 요청/응답",
                    "Cookie 또는 Authorization 값",
                    "token, JWT, session 값",
                    "실제 도메인, URL, IP 값",
                    "개인정보",
                    "무결성 검증 비밀값 또는 요청 위조 방지 값",
                    "전체 로컬 경로",
                ]:
                    self.assertIn(label, triage)
                self.assertNotIn("Finding triage index", triage)
                self.assertNotIn("Read-only triage checklist", triage)
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
                self.assertIn("보고서 준비 인덱스", readiness)
                self.assertIn("조회 전용", readiness)
                self.assertIn("조회 전용 보고서 초안 점검", readiness)
                self.assertIn("프로젝트 별칭", readiness)
                self.assertIn("보고서 초안 상태", readiness)
                self.assertIn("finding 후보 수", readiness)
                self.assertIn(">22<", readiness)
                self.assertIn("report_draft.md", readiness)
                self.assertIn("analysis_packet.json", readiness)
                self.assertIn("보고서 초안 상태 요약", readiness)
                self.assertIn("finding 후보 분류 인덱스 열기", readiness)
                self.assertIn("AI 안전 사전 점검 열기", readiness)
                self.assertIn("AI 핸드오프 인덱스 열기", readiness)
                self.assertIn("내보내기/리뷰/보고서 흐름 링크", readiness)
                self.assertIn("검증된 산출물 상세로 돌아가기", readiness)
                self.assertIn("범위 확인", readiness)
                self.assertIn("영향 endpoint 확인", readiness)
                self.assertIn("증거 품질 확인", readiness)
                self.assertIn("false positive 가능성 검토", readiness)
                self.assertIn("영향 설명 검토", readiness)
                self.assertIn("조치 문구 검토", readiness)
                self.assertIn("최종 심각도 수동 결정", readiness)
                self.assertIn("고객 제출 전 민감정보 검토", readiness)
                self.assertIn("수동 검증이 끝날 때까지 finding 후보입니다", readiness)
                self.assertIn("초안이며 심각도 확정이 아닙니다", readiness)
                self.assertIn("증거 신뢰도이며 심각도가 아닙니다", readiness)
                self.assertIn("report_draft.md는 제출용 보고서가 아니라 초안입니다", readiness)
                self.assertIn("최종 심각도는 수동 결정입니다", readiness)
                self.assertIn("존재 여부", readiness)
                self.assertIn("파일 크기(bytes)", readiness)
                self.assertIn("수정 시각(UTC)", readiness)
                self.assertIn("SHA-256 파일 fingerprint", readiness)
                self.assertIn("SHA-256 파일 fingerprint이며 HMAC이 아닙니다", readiness)
                for label in [
                    "raw 요청/응답",
                    "raw 감사 row body",
                    "Cookie 또는 Authorization 값",
                    "token, JWT, session 값",
                    "실제 도메인, URL, IP 값",
                    "개인정보",
                    "무결성 검증 비밀값 또는 요청 위조 방지 값",
                    "전체 로컬 경로",
                ]:
                    self.assertIn(label, readiness)
                self.assertNotIn("Report readiness index", readiness)
                self.assertNotIn("Read-only draft report checklist", readiness)
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
                self.assertIn("작업 흐름 상태 인덱스", workflow)
                self.assertIn("조회 전용", workflow)
                self.assertIn("조회 전용 작업 흐름 점검", workflow)
                self.assertIn("프로젝트 별칭", workflow)
                self.assertIn("검증 상태 요약", workflow)
                self.assertIn("리뷰 상태 요약", workflow)
                self.assertIn("finding 후보 수", workflow)
                self.assertIn(">22<", workflow)
                self.assertIn("report_draft.md", workflow)
                self.assertIn("analysis_packet.json", workflow)
                self.assertIn("chatgpt_prompt.md", workflow)
                self.assertIn("codex_task_prompt.md", workflow)
                self.assertIn("통과", workflow)
                self.assertIn("후보 있음", workflow)
                self.assertIn("초안 있음", workflow)
                self.assertIn("수동 검토 필요", workflow)
                for step in [
                    "검증",
                    "리뷰",
                    "보고서",
                    "AI 안전 사전 점검",
                    "AI 핸드오프 인덱스",
                    "Prompt readiness 인덱스",
                    "Evidence boundary 인덱스",
                    "Finding 후보 분류 인덱스",
                    "보고서 준비 인덱스",
                    "리뷰/보고서/내보내기 흐름",
                ]:
                    self.assertIn(step, workflow)
                for link in [
                    "/preflight?project=generated",
                    "/handoff?project=generated",
                    "/prompt-readiness?project=generated",
                    "/triage?project=generated",
                    "/report-readiness?project=generated",
                    "/output?project=generated",
                    "/operator-runbook?project=generated",
                ]:
                    self.assertIn(link, workflow)
                self.assertIn("수동 검증이 끝날 때까지 후보입니다", workflow)
                self.assertIn("초안이며 별도 검토가 필요합니다", workflow)
                self.assertIn("최종 심각도는 수동 결정입니다", workflow)
                self.assertNotIn("Workflow status index", workflow)
                self.assertNotIn("Read-only workflow checklist", workflow)
                self.assertIn("report_draft.md는 제출용 보고서가 아니라 초안입니다", workflow)
                for label in [
                    "raw 요청/응답",
                    "raw 감사 row body",
                    "Cookie 또는 Authorization 값",
                    "token, JWT, session 값",
                    "실제 도메인, URL, IP 값",
                    "개인정보",
                    "무결성 검증 비밀값 또는 요청 위조 방지 값",
                    "전체 로컬 경로",
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
                connection.request("GET", "/prompt-readiness?project=generated")
                response = connection.getresponse()
                prompt_readiness = response.read().decode("utf-8")
                self.assertEqual(response.status, 200)
                self.assertIn("Prompt readiness 인덱스", prompt_readiness)
                self.assertIn("조회 전용", prompt_readiness)
                self.assertIn("조회 전용 prompt readiness checklist", prompt_readiness)
                self.assertIn("프로젝트 별칭", prompt_readiness)
                self.assertIn("chatgpt_prompt.md", prompt_readiness)
                self.assertIn("codex_task_prompt.md", prompt_readiness)
                self.assertIn("analysis_packet.json", prompt_readiness)
                self.assertIn("report_draft.md", prompt_readiness)
                self.assertIn("safe files 4개", prompt_readiness)
                self.assertIn("Prompt 파일 메타데이터", prompt_readiness)
                self.assertIn("SHA-256 fingerprint", prompt_readiness)
                self.assertIn("SHA-256은 HMAC이 아닌 파일 fingerprint입니다", prompt_readiness)
                self.assertIn("Prompt readiness 점검", prompt_readiness)
                self.assertIn("safe files 4개 언급", prompt_readiness)
                self.assertIn("forbidden data warning", prompt_readiness)
                self.assertIn("verify-first warning", prompt_readiness)
                self.assertIn("candidate/draft/manual review boundary", prompt_readiness)
                self.assertIn("최종 심각도 수동 결정 경고", prompt_readiness)
                self.assertIn("raw data prohibition warning", prompt_readiness)
                self.assertIn("Codex prompt 범위 구분", prompt_readiness)
                self.assertIn("ChatGPT prompt 분석 경계", prompt_readiness)
                self.assertIn("Prompt 목적과 차이", prompt_readiness)
                self.assertIn("ChatGPT용 prompt", prompt_readiness)
                self.assertIn("Codex용 prompt", prompt_readiness)
                self.assertIn("수동 검증이 끝날 때까지 후보입니다", prompt_readiness)
                self.assertIn("초안이며 심각도 확정이 아닙니다", prompt_readiness)
                self.assertIn("최종 심각도 결정", prompt_readiness)
                self.assertIn("사람이 결정합니다", prompt_readiness)
                self.assertIn("사람이 직접 검토해야 합니다", prompt_readiness)
                for link in [
                    "/preflight?project=generated",
                    "/handoff?project=generated",
                    "/workflow?project=generated",
                    "/evidence-boundary?project=generated",
                    "/triage?project=generated",
                    "/report-readiness?project=generated",
                ]:
                    self.assertIn(link, prompt_readiness)
                for label in [
                    "raw 요청/응답",
                    "raw 감사 row body",
                    "Cookie 또는 Authorization 값",
                    "token, JWT, session 값",
                    "실제 도메인, URL, IP 값",
                    "개인정보",
                    "무결성 검증 비밀값 또는 요청 위조 방지 값",
                    "전체 로컬 경로",
                ]:
                    self.assertIn(label, prompt_readiness)
                self.assertNotIn("<pre", prompt_readiness)
                self.assertNotIn("analysis-prompt-packet-v1", prompt_readiness)
                self.assertNotIn('name="csrf_token"', prompt_readiness)
                self.assertNotIn("<form", prompt_readiness)
                self.assertNotIn("<button", prompt_readiness)
                self.assertNotIn('method="post"', prompt_readiness)
                self.assertNotIn("raw_request", prompt_readiness)
                self.assertNotIn("raw_response", prompt_readiness)
                self.assertNotIn("DUMMY_COOKIE_VALUE", prompt_readiness)
                self.assertNotIn("DUMMY_BEARER_TOKEN", prompt_readiness)
                self.assertNotIn("approved", prompt_readiness)
                self.assertNotIn("guaranteed safe", prompt_readiness)
                self.assertNotIn("safe to share", prompt_readiness)
                self.assertNotIn("severity confirmed", prompt_readiness)
                self.assertNotIn("ready to submit", prompt_readiness)
                self.assertNotIn("제출 가능", prompt_readiness)
                self.assertNotIn("승인 완료", prompt_readiness)
                self.assertNotIn("안전 보장", prompt_readiness)
                self.assertNotIn(str(root), prompt_readiness)
                connection.close()

                connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                connection.request("GET", "/evidence-boundary?project=generated")
                response = connection.getresponse()
                evidence_boundary = response.read().decode("utf-8")
                self.assertEqual(response.status, 200)
                self.assertIn("Evidence boundary 인덱스", evidence_boundary)
                self.assertIn("조회 전용 evidence boundary checklist", evidence_boundary)
                self.assertIn("조회 전용 증거 경계 요약", evidence_boundary)
                self.assertIn("정제 evidence", evidence_boundary)
                self.assertIn("finding candidate", evidence_boundary)
                self.assertIn("candidate count", evidence_boundary)
                self.assertIn(">22<", evidence_boundary)
                self.assertIn("analysis_packet.json", evidence_boundary)
                self.assertIn("report_draft.md", evidence_boundary)
                self.assertIn("chatgpt_prompt.md", evidence_boundary)
                self.assertIn("codex_task_prompt.md", evidence_boundary)
                self.assertIn("정제 증거 파일 메타데이터", evidence_boundary)
                self.assertIn("SHA-256 fingerprint", evidence_boundary)
                self.assertIn("허용되는 evidence 범위", evidence_boundary)
                self.assertIn("금지되는 raw evidence 범위", evidence_boundary)
                self.assertIn("수동 검증이 끝날 때까지 candidate입니다", evidence_boundary)
                self.assertIn("draft이며 severity 결정으로 취급하지 않습니다", evidence_boundary)
                self.assertIn("증거 신뢰도이며 severity가 아닙니다", evidence_boundary)
                self.assertIn("최종 심각도", evidence_boundary)
                self.assertIn("CVSS", evidence_boundary)
                for link in [
                    "/preflight?project=generated",
                    "/handoff?project=generated",
                    "/prompt-readiness?project=generated",
                    "/evidence-boundary?project=generated",
                    "/triage?project=generated",
                    "/report-readiness?project=generated",
                    "/workflow?project=generated",
                    "/operator-runbook?project=generated",
                ]:
                    self.assertIn(link, evidence_boundary)
                for label in [
                    "raw 요청/응답 본문",
                    "raw 감사 row 전문",
                    "Cookie 또는 Authorization 값",
                    "token, JWT, session 값",
                    "실제 도메인, URL, IP 값",
                    "개인정보",
                    "무결성 검증 비밀값 또는 요청 위조 방지 값",
                    "전체 로컬 경로",
                ]:
                    self.assertIn(label, evidence_boundary)
                self.assertNotIn("<pre", evidence_boundary)
                self.assertNotIn('name="csrf_token"', evidence_boundary)
                self.assertNotIn("<form", evidence_boundary)
                self.assertNotIn("<button", evidence_boundary)
                self.assertNotIn('method="post"', evidence_boundary)
                self.assertNotIn("download?project=generated", evidence_boundary)
                self.assertNotIn("raw_request", evidence_boundary)
                self.assertNotIn("raw_response", evidence_boundary)
                self.assertNotIn("DUMMY_COOKIE_VALUE", evidence_boundary)
                self.assertNotIn("DUMMY_BEARER_TOKEN", evidence_boundary)
                self.assertNotIn(str(root), evidence_boundary)
                connection.close()

                connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                connection.request("GET", "/operator-runbook?project=generated")
                response = connection.getresponse()
                operator_runbook = response.read().decode("utf-8")
                self.assertEqual(response.status, 200)
                self.assertIn("Operator runbook 인덱스", operator_runbook)
                self.assertIn("조회 전용 operator runbook checklist", operator_runbook)
                self.assertIn("운영 runbook 요약", operator_runbook)
                self.assertIn("운영 순서", operator_runbook)
                self.assertIn("프로젝트 별칭", operator_runbook)
                self.assertIn("verify gate", operator_runbook)
                self.assertIn("finding candidate count", operator_runbook)
                self.assertIn(">22<", operator_runbook)
                self.assertIn("report_draft.md", operator_runbook)
                self.assertIn("analysis_packet.json", operator_runbook)
                self.assertIn("chatgpt_prompt.md", operator_runbook)
                self.assertIn("codex_task_prompt.md", operator_runbook)
                self.assertIn("raw_data_included", operator_runbook)
                self.assertIn("body preview", operator_runbook)
                self.assertIn("전체 로컬 경로 표시", operator_runbook)
                self.assertIn("safe files 4개", operator_runbook)
                for step in [
                    "Burp HTTP history 수집",
                    "localhost receiver 저장",
                    "redaction/verify",
                    "review candidate findings",
                    "report_draft.md 생성",
                    "preflight",
                    "handoff",
                    "triage",
                    "report-readiness",
                    "prompt-readiness",
                    "evidence-boundary",
                    "workflow status recap",
                ]:
                    self.assertIn(step, operator_runbook)
                for link in [
                    "/help",
                    "/operations",
                    "/output?project=generated",
                    "/preflight?project=generated",
                    "/handoff?project=generated",
                    "/triage?project=generated",
                    "/report-readiness?project=generated",
                    "/prompt-readiness?project=generated",
                    "/evidence-boundary?project=generated",
                    "/workflow?project=generated",
                    "/safe-files?project=generated",
                ]:
                    self.assertIn(link, operator_runbook)
                for label in [
                    "raw request/response body",
                    "raw audit row 전문",
                    "Cookie 값",
                    "Authorization 값",
                    "token/JWT/session 값",
                    "실제 URL/도메인/IP",
                    "개인정보",
                    "무결성 검증 비밀값",
                    "요청 위조 방지 값",
                    "전체 로컬 경로",
                ]:
                    self.assertIn(label, operator_runbook)
                self.assertIn("수동 검증이 끝날 때까지 candidate입니다", operator_runbook)
                self.assertIn("risk rating은 draft이며 최종 심각도가 아닙니다", operator_runbook)
                self.assertIn("evidence confidence이며 severity가 아닙니다", operator_runbook)
                self.assertIn("최종 심각도", operator_runbook)
                self.assertIn("사람이 수동 결정합니다", operator_runbook)
                self.assertIn("최종 보고서가 아니라 수동 검토용 초안입니다", operator_runbook)
                self.assertIn("prompt/evidence/report", operator_runbook)
                self.assertIn("모두 AI 투입 또는 공유 전 사람 검토가 필요합니다", operator_runbook)
                self.assertNotIn("<pre", operator_runbook)
                self.assertNotIn('name="csrf_token"', operator_runbook)
                self.assertNotIn("<form", operator_runbook)
                self.assertNotIn("<button", operator_runbook)
                self.assertNotIn('method="post"', operator_runbook)
                self.assertNotIn("download?project=generated", operator_runbook)
                self.assertNotIn("raw_request", operator_runbook)
                self.assertNotIn("raw_response", operator_runbook)
                self.assertNotIn("DUMMY_COOKIE_VALUE", operator_runbook)
                self.assertNotIn("DUMMY_BEARER_TOKEN", operator_runbook)
                self.assertNotIn("approved", operator_runbook)
                self.assertNotIn("guaranteed safe", operator_runbook)
                self.assertNotIn("safe to share", operator_runbook)
                self.assertNotIn("severity confirmed", operator_runbook)
                self.assertNotIn("ready to submit", operator_runbook)
                self.assertNotIn("제출 가능", operator_runbook)
                self.assertNotIn("승인 완료", operator_runbook)
                self.assertNotIn("안전 보장", operator_runbook)
                self.assertNotIn(str(root), operator_runbook)
                connection.close()

                connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                connection.request("GET", "/safe-files?project=generated")
                response = connection.getresponse()
                safe_files = response.read().decode("utf-8")
                self.assertEqual(response.status, 200)
                self.assertIn("Safe file inventory 인덱스", safe_files)
                self.assertIn("조회 전용 safe file inventory checklist", safe_files)
                self.assertIn("Inventory 요약", safe_files)
                self.assertIn("safe files 4개", safe_files)
                self.assertIn("파일 inventory", safe_files)
                self.assertIn("exists", safe_files)
                self.assertIn("파일 목적", safe_files)
                self.assertIn("권장 사용 위치", safe_files)
                self.assertIn("verify 선행 필요", safe_files)
                self.assertIn("file size", safe_files)
                self.assertIn("modified UTC", safe_files)
                self.assertIn("SHA-256 fingerprint", safe_files)
                self.assertIn("사람 수동 검토", safe_files)
                self.assertIn("body preview", safe_files)
                self.assertIn("false", safe_files)
                self.assertIn("analysis_packet.json", safe_files)
                self.assertIn("chatgpt_prompt.md", safe_files)
                self.assertIn("codex_task_prompt.md", safe_files)
                self.assertIn("report_draft.md", safe_files)
                self.assertIn("finding candidate count", safe_files)
                self.assertIn(">22<", safe_files)
                self.assertIn("수동 검증이 끝날 때까지 candidate입니다", safe_files)
                self.assertIn("risk rating은 초안이며 최종 심각도가 아닙니다", safe_files)
                self.assertIn("evidence confidence이며 severity가 아닙니다", safe_files)
                self.assertIn("사람이 수동 결정합니다", safe_files)
                self.assertIn("final report가 아니라 수동 검토용 보고서 초안입니다", safe_files)
                for link in [
                    "/preflight?project=generated",
                    "/handoff?project=generated",
                    "/prompt-readiness?project=generated",
                    "/evidence-boundary?project=generated",
                    "/triage?project=generated",
                    "/report-readiness?project=generated",
                    "/workflow?project=generated",
                    "/operator-runbook?project=generated",
                ]:
                    self.assertIn(link, safe_files)
                for label in [
                    "raw request/response body",
                    "request body 또는 response body preview",
                    "prompt/report/evidence body preview",
                    "Cookie 값",
                    "Authorization 값",
                    "token/JWT/session 값",
                    "실제 URL/도메인/IP",
                    "개인정보",
                    "무결성 검증 비밀값",
                    "요청 위조 방지 값",
                    "전체 로컬 경로",
                ]:
                    self.assertIn(label, safe_files)
                self.assertNotIn("<pre", safe_files)
                self.assertNotIn('name="csrf_token"', safe_files)
                self.assertNotIn("<form", safe_files)
                self.assertNotIn("<button", safe_files)
                self.assertNotIn('method="post"', safe_files)
                self.assertNotIn("download?project=generated", safe_files)
                self.assertNotIn("preview?project=generated", safe_files)
                self.assertNotIn("raw_request", safe_files)
                self.assertNotIn("raw_response", safe_files)
                self.assertNotIn("DUMMY_COOKIE_VALUE", safe_files)
                self.assertNotIn("DUMMY_BEARER_TOKEN", safe_files)
                self.assertNotIn("approved", safe_files)
                self.assertNotIn("guaranteed safe", safe_files)
                self.assertNotIn("safe to share", safe_files)
                self.assertNotIn("severity confirmed", safe_files)
                self.assertNotIn("ready to submit", safe_files)
                self.assertNotIn(str(root), safe_files)
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

    def test_dashboard_output_alias_selector_uses_verified_aliases_only(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir) / "out"
            verified = root / "generated"
            unverified = root / "unverified"
            main(["generate", "--input", str(SAMPLE), "--output", str(verified), "--project", "client_alias_demo"])
            main(["generate", "--input", str(SAMPLE), "--output", str(unverified), "--project", "client_alias_demo"])
            (unverified / "unsafe.md").write_text(
                "Authorization: Bearer DUMMY_BEARER_TOKEN\n",
                encoding="utf-8",
            )

            server = create_dashboard_server("127.0.0.1", 0, DashboardConfig(root=root))
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                port = server.server_address[1]

                def get(path: str) -> str:
                    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                    connection.request("GET", path)
                    response = connection.getresponse()
                    body = response.read().decode("utf-8")
                    connection.close()
                    self.assertEqual(response.status, 200)
                    return body

                pages = {
                    "/": get("/"),
                    "/safe-files": get("/safe-files?project=generated"),
                    "/triage": get("/triage?project=generated"),
                    "/report-readiness": get("/report-readiness?project=generated"),
                    "/workflow": get("/workflow?project=generated"),
                    "/live-capture": get("/live-capture?project=generated"),
                }

                for body in pages.values():
                    self.assertIn("검증된 output 산출물 선택", body)
                    self.assertIn("Safe files는 AI 입력 후보이며 수동 검토가 필요합니다", body)
                    self.assertIn("Finding은 후보, risk는 초안입니다", body)
                    self.assertIn("Final severity와 CVSS는 사람이 수동 결정합니다", body)
                    self.assertIn("Raw traffic은 표시하지 않습니다", body)
                    self.assertIn("generated", body)
                    self.assertIn("/safe-files?project=generated", body)
                    self.assertIn("/triage?project=generated", body)
                    self.assertIn("/report-readiness?project=generated", body)
                    self.assertIn("/workflow?project=generated", body)
                    self.assertNotIn("/safe-files?project=unverified", body)
                    self.assertNotIn("/triage?project=unverified", body)
                    self.assertNotIn("/report-readiness?project=unverified", body)
                    self.assertNotIn("/workflow?project=unverified", body)
                    self.assertNotIn(str(root), body)
                    self.assertNotIn("raw_request", body)
                    self.assertNotIn("raw_response", body)
                    self.assertNotIn("DUMMY_COOKIE_VALUE", body)
                    self.assertNotIn("DUMMY_BEARER_TOKEN", body)
                    self.assertNotIn("Authorization:", body)
                    self.assertNotIn("Cookie:", body)
                    self.assertNotIn("safe-to-share", body)
                    self.assertNotIn("safe to share", body.lower())
                    self.assertNotIn("confirmed vulnerability", body.lower())
                    self.assertNotIn("final CVSS confirmed", body)
                    self.assertNotIn("severity confirmed", body.lower())
                    self.assertNotIn("<form", body)
                    self.assertNotIn("<button", body)
                    self.assertNotIn('method="post"', body)
                    self.assertNotIn('action="/action"', body)

                self.assertIn("선택됨", pages["/safe-files"])
                self.assertIn("별칭만 표시합니다. 로컬 경로와 target 식별자는 표시하지 않습니다.", pages["/"])
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)

    def test_dashboard_output_alias_selector_falls_back_when_no_verified_output_exists(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir) / "out"
            root.mkdir()

            server = create_dashboard_server("127.0.0.1", 0, DashboardConfig(root=root))
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                port = server.server_address[1]
                connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                connection.request("GET", "/")
                response = connection.getresponse()
                body = response.read().decode("utf-8")
                connection.close()

                self.assertEqual(response.status, 200)
                self.assertIn("검증된 output 산출물 선택", body)
                self.assertIn("검증을 통과한 output 별칭이 아직 없습니다.", body)
                self.assertIn("운영 가이드 보기", body)
                self.assertIn('href="/help"', body)
                self.assertNotIn(str(root), body)
                self.assertNotIn("raw_request", body)
                self.assertNotIn("raw_response", body)
                self.assertNotIn("DUMMY_COOKIE_VALUE", body)
                self.assertNotIn("DUMMY_BEARER_TOKEN", body)
                self.assertNotIn("<form", body)
                self.assertNotIn("<button", body)
                self.assertNotIn('method="post"', body)
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)

    def test_dashboard_read_only_ux_bundle_panels_are_safe(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir) / "out"
            output = root / "generated"
            main(["generate", "--input", str(SAMPLE), "--output", str(output), "--project", "client_alias_demo"])

            server = create_dashboard_server("127.0.0.1", 0, DashboardConfig(root=root))
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                port = server.server_address[1]

                def get(path: str) -> str:
                    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                    connection.request("GET", path)
                    response = connection.getresponse()
                    body = response.read().decode("utf-8")
                    connection.close()
                    self.assertEqual(response.status, 200)
                    return body

                pages = {
                    "/": get("/"),
                    "/help": get("/help"),
                    "/operations": get("/operations"),
                    "/live-capture": get("/live-capture?project=generated"),
                }

                for path, body in pages.items():
                    self.assertIn("Read-only troubleshooting categories", body)
                    self.assertIn("setup friction", body)
                    self.assertIn("upload/export friction", body)
                    self.assertIn("verify/review/report friction", body)
                    self.assertIn("live-capture friction", body)
                    self.assertIn("safe-files friction", body)
                    self.assertIn("MCP boundary friction", body)
                    self.assertIn("read-only navigation only", body)
                    self.assertNotRegex(body, r'href=["\']docs/')
                    self.assertNotIn(str(root), body)
                    self.assertNotIn("raw_request", body)
                    self.assertNotIn("raw_response", body)
                    self.assertNotIn("DUMMY_COOKIE_VALUE", body)
                    self.assertNotIn("DUMMY_BEARER_TOKEN", body)
                    self.assertNotIn("Authorization:", body)
                    self.assertNotIn("Cookie:", body)
                    self.assertNotIn("safe-to-share", body)
                    self.assertNotIn("safe to share", body.lower())
                    self.assertNotIn("confirmed vulnerability", body.lower())
                    self.assertNotIn("final CVSS confirmed", body)
                    self.assertNotIn("severity confirmed", body.lower())
                    self.assertNotIn("<form", body)
                    self.assertNotIn("<button", body)
                    self.assertNotIn('method="post"', body)
                    self.assertNotIn('action="/action"', body)

                for path in ["/", "/help", "/operations"]:
                    body = pages[path]
                    self.assertIn("Release readiness status", body)
                    self.assertIn("v0.5 local-use baseline", body)
                    self.assertIn("v0.6 planning", body)
                    self.assertIn("v0.5 hotfix policy", body)
                    self.assertIn("tag action", body)
                    self.assertIn("not available in dashboard", body)
                    self.assertIn("GitHub Release action", body)
                    self.assertIn("<code>docs/RELEASE_READINESS_v0.5.md</code>", body)
                    self.assertNotRegex(body, r'<a[^>]+href=["\']docs/')

                self.assertIn("receiver output alias", pages["/live-capture"])
                for linked_route in ["/help", "/upload", "/operations", "/live-capture"]:
                    get(linked_route)
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)

    def test_dashboard_read_only_ux_bundle_docs_are_raw_free(self) -> None:
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        local_dashboard = (ROOT / "docs" / "LOCAL_DASHBOARD.md").read_text(encoding="utf-8")
        roadmap = ROADMAP_V06_DOC.read_text(encoding="utf-8")

        combined = "\n".join([readme, local_dashboard, roadmap])
        for required in [
            "read-only troubleshooting",
            "release readiness status",
            "setup",
            "upload/export",
            "verify/review/report",
            "live-capture",
            "safe-files",
            "MCP boundary",
            "tag 생성",
            "GitHub Release 생성",
            "POST action",
            "Read-only release readiness status panel",
            "Dashboard는 `docs/*.md`를 직접",
        ]:
            self.assertIn(required, combined)

        for forbidden in [
            "safe-to-share",
            "guaranteed safe",
            "confirmed vulnerability",
            "final CVSS confirmed",
            "raw_request",
            "raw_response",
            "cookie_value",
            "authorization_value",
            "Authorization: Bearer",
            "Cookie:",
            "DUMMY_COOKIE_VALUE",
            "DUMMY_BEARER_TOKEN",
            "C:\\coding\\",
            "C:\\Users\\",
            "real_export_",
            "actual.local",
            "example.com",
        ]:
            self.assertNotIn(forbidden, combined)

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
                    self.assertIn("root 별칭", body)
                    self.assertIn(">out<", body)
                    self.assertIn("127.0.0.1 전용", body)
                    self.assertIn("안전 action 사용 가능", body)
                    self.assertIn("조회 전용", body)
                    self.assertIn("CSRF 보호", body)
                    self.assertIn("값 숨김", body)
                    self.assertIn("analysis_packet.json", body)
                    self.assertIn("chatgpt_prompt.md", body)
                    self.assertIn("codex_task_prompt.md", body)
                    self.assertIn("report_draft.md", body)
                    self.assertIn("conservative", body)
                    self.assertIn("consultant", body)
                    self.assertIn("strict", body)
                    self.assertIn("위험도 profile", body)
                    self.assertIn("기본 위험도 profile", body)
                    self.assertIn("초안 전용", body)
                    self.assertIn("confidence_is_severity", body)
                    self.assertIn("false", body)
                    self.assertIn("감사 schema", body)
                    self.assertIn("1.1", body)
                    self.assertIn("HMAC 설정", body)
                    self.assertIn("configured", body)
                    self.assertIn("압축 archive", body)
                    self.assertIn("압축 archive 검증", body)
                    self.assertIn("압축 archive HMAC manifest", body)
                    self.assertIn("압축 archive HMAC 검증", body)
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
                        if linked_path == "/":
                            self.assertIn('href="/upload"', linked_body)
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
                        self.assertIn("docs/LIVE_CAPTURE_WIZARD_DESIGN_v0.5.md", body)
                        self.assertIn('href="/live-capture"', body)
                        self.assertIn("docs/GUI_UPLOAD_WIZARD.md", body)
                        self.assertIn('href="/upload"', body)
                        self.assertIn("docs/GUI_SIMPLE_DASHBOARD.md", body)
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
                        self.assertIn("raw 요청/응답", body)
                        self.assertIn("Cookie", body)
                        self.assertIn("Authorization", body)
                        self.assertIn("token/JWT/session 값", body)
                        self.assertIn("local_only/", body)
                        self.assertIn("raw_vault/", body)
                        self.assertIn("후보", body)
                        self.assertIn("초안", body)
                        self.assertIn("최종 심각도", body)
                        self.assertIn("127.0.0.1", body)
                        self.assertIn("HTML escape 적용", body)
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

    def test_live_capture_scope_guard_normalizes_matches_and_rejects_raw_free(self) -> None:
        self.assertEqual(normalize_live_capture_scope("Example.COM"), "example.com")
        self.assertEqual(normalize_live_capture_scope("Example.COM."), "example.com")

        scope = validate_live_capture_scope("Example.COM.")
        self.assertEqual(scope.normalized, "example.com")
        self.assertFalse(scope.raw_data_included)
        self.assertRegex(scope.alias, r"^target_alias_[0-9a-f]{12}$")
        self.assertEqual(scope.alias, live_capture_scope_alias("example.com"))
        self.assertNotIn("example.com", scope.alias)

        self.assertTrue(host_matches_live_capture_scope("example.com", "example.com"))
        self.assertTrue(host_matches_live_capture_scope("sub.example.com", "example.com"))
        self.assertFalse(host_matches_live_capture_scope("example.com.evil.test", "example.com"))
        self.assertFalse(host_matches_live_capture_scope("badexample.com", "example.com"))

        exact_match = evaluate_live_capture_scope_match("sub.example.com.", "example.com")
        self.assertTrue(exact_match.matched)
        self.assertEqual(exact_match.reason, SCOPE_REASON_MATCHED)
        self.assertFalse(exact_match.raw_data_included)
        self.assertRegex(exact_match.host_alias, r"^target_alias_[0-9a-f]{12}$")
        self.assertRegex(exact_match.scope_alias, r"^target_alias_[0-9a-f]{12}$")

        lookalike_match = evaluate_live_capture_scope_match("example.com.evil.test", "example.com")
        self.assertFalse(lookalike_match.matched)
        self.assertEqual(lookalike_match.reason, SCOPE_REASON_SUFFIX_MISMATCH)
        self.assertFalse(lookalike_match.raw_data_included)
        self.assertNotIn("example.com", str(lookalike_match))

        invalid_cases = [
            ("", SCOPE_REASON_EMPTY),
            (" example.com", SCOPE_REASON_CONTROL_OR_SPACE),
            ("example.com ", SCOPE_REASON_CONTROL_OR_SPACE),
            ("example com", SCOPE_REASON_CONTROL_OR_SPACE),
            ("*.example.com", SCOPE_REASON_WILDCARD),
            ("http://example.com", SCOPE_REASON_URL_OR_PATH),
            ("https://example.com/path", SCOPE_REASON_URL_OR_PATH),
            ("example.com/path", SCOPE_REASON_URL_OR_PATH),
            ("example.com?debug=1", SCOPE_REASON_URL_OR_PATH),
            ("example.com:443", SCOPE_REASON_URL_OR_PATH),
            ("localhost", SCOPE_REASON_LOOPBACK_NAME),
            ("service.localhost", SCOPE_REASON_LOOPBACK_NAME),
            ("local", SCOPE_REASON_LOOPBACK_NAME),
            ("127.0.0.1", SCOPE_REASON_IP_LITERAL),
            ("10.0.0.1", SCOPE_REASON_IP_LITERAL),
            ("172.16.0.1", SCOPE_REASON_IP_LITERAL),
            ("192.168.1.1", SCOPE_REASON_IP_LITERAL),
            ("::1", SCOPE_REASON_IP_LITERAL),
            ("example..com", SCOPE_REASON_MALFORMED_LABEL),
            ("-example.com", SCOPE_REASON_MALFORMED_LABEL),
            ("example-.com", SCOPE_REASON_MALFORMED_LABEL),
            ("exa_mple.com", SCOPE_REASON_MALFORMED),
            (f"{'a' * 64}.com", SCOPE_REASON_MALFORMED_LABEL),
            (f"{'a' * 250}.com", SCOPE_REASON_TOO_LONG),
        ]
        for raw_value, expected_reason in invalid_cases:
            with self.subTest(raw_value=raw_value):
                with self.assertRaises(LiveCaptureScopeError) as context:
                    validate_live_capture_scope(raw_value)
                self.assertEqual(context.exception.reason, expected_reason)
                self.assertEqual(str(context.exception), expected_reason)
                if raw_value:
                    self.assertNotIn(raw_value.lower(), str(context.exception))

    def test_receiver_scope_dry_run_uses_safe_host_metadata_without_ingest(self) -> None:
        raw_markers = [
            "GET /secret?token=DUMMY_QUERY_TOKEN HTTP/1.1",
            "Host: api.example.test",
            "Authorization: Bearer DUMMY_BEARER_TOKEN",
            "Cookie: DUMMY_SESSION=DUMMY_COOKIE_VALUE",
            "HTTP/1.1 200 OK",
        ]
        base_payload = {
            "schema_version": "montoya-handoff-v1",
            "source": "burp_proxy_history",
            "request": "\r\n".join(raw_markers),
            "response": "HTTP/1.1 200 OK\r\n\r\nDUMMY_BODY_VALUE",
        }

        exact = evaluate_receiver_scope_dry_run({"request_host": "example.test"}, "example.test")
        self.assertEqual(exact.decision, RECEIVER_SCOPE_DECISION_ACCEPT)
        self.assertEqual(exact.reason, RECEIVER_SCOPE_REASON_IN_SCOPE)
        self.assertEqual(exact.match_reason, SCOPE_REASON_MATCHED)
        self.assertFalse(exact.raw_data_included)
        self.assertFalse(exact.ingest_performed)
        self.assertRegex(exact.host_alias, r"^target_alias_[0-9a-f]{12}$")

        subdomain = evaluate_receiver_scope_dry_run({"request_metadata": {"host": "api.example.test"}}, "example.test")
        self.assertEqual(subdomain.decision, RECEIVER_SCOPE_DECISION_ACCEPT)
        self.assertEqual(subdomain.match_reason, SCOPE_REASON_MATCHED)

        out_of_scope = evaluate_receiver_scope_dry_run({"request_host": "other.test"}, "example.test")
        self.assertEqual(out_of_scope.decision, RECEIVER_SCOPE_DECISION_DROP)
        self.assertEqual(out_of_scope.reason, RECEIVER_SCOPE_REASON_OUT_OF_SCOPE)
        self.assertEqual(out_of_scope.match_reason, SCOPE_REASON_SUFFIX_MISMATCH)

        lookalike = evaluate_receiver_scope_dry_run({"request_host": "example.test.evil.test"}, "example.test")
        self.assertEqual(lookalike.decision, RECEIVER_SCOPE_DECISION_DROP)
        self.assertEqual(lookalike.reason, RECEIVER_SCOPE_REASON_OUT_OF_SCOPE)
        self.assertEqual(lookalike.match_reason, SCOPE_REASON_SUFFIX_MISMATCH)

        missing = evaluate_receiver_scope_dry_run(base_payload, "example.test")
        self.assertEqual(missing.decision, RECEIVER_SCOPE_DECISION_DROP)
        self.assertEqual(missing.reason, RECEIVER_SCOPE_REASON_MISSING_HOST)
        self.assertEqual(missing.host_alias, "")
        self.assertFalse(missing.ingest_performed)

        invalid_host = evaluate_receiver_scope_dry_run({"request_host": "127.0.0.1"}, "example.test")
        self.assertEqual(invalid_host.decision, RECEIVER_SCOPE_DECISION_DROP)
        self.assertEqual(invalid_host.reason, RECEIVER_SCOPE_REASON_INVALID_HOST)
        self.assertEqual(invalid_host.match_reason, SCOPE_REASON_IP_LITERAL)

        malformed_host = evaluate_receiver_scope_dry_run({"request_host": "https://example.test/path"}, "example.test")
        self.assertEqual(malformed_host.reason, RECEIVER_SCOPE_REASON_INVALID_HOST)
        self.assertEqual(malformed_host.match_reason, SCOPE_REASON_URL_OR_PATH)

        invalid_scope = evaluate_receiver_scope_dry_run({"request_host": "example.test"}, "*.example.test")
        self.assertEqual(invalid_scope.decision, RECEIVER_SCOPE_DECISION_DROP)
        self.assertEqual(invalid_scope.reason, RECEIVER_SCOPE_REASON_INVALID_SCOPE)
        self.assertEqual(invalid_scope.match_reason, SCOPE_REASON_WILDCARD)

        summaries = [
            exact.to_summary(),
            subdomain.to_summary(),
            out_of_scope.to_summary(),
            lookalike.to_summary(),
            missing.to_summary(),
            invalid_host.to_summary(),
            malformed_host.to_summary(),
            invalid_scope.to_summary(),
        ]
        summary_text = json.dumps(summaries, sort_keys=True)
        self.assertNotIn("example.test", summary_text)
        self.assertNotIn("other.test", summary_text)
        self.assertNotIn("127.0.0.1", summary_text)
        for marker in raw_markers:
            self.assertNotIn(marker, summary_text)
        self.assertNotIn("DUMMY_BODY_VALUE", summary_text)

    def test_receiver_scope_summary_and_audit_event_are_raw_free(self) -> None:
        raw_payload_markers = {
            "request": "DUMMY_RAW_REQUEST_MARKER token=DUMMY_TOKEN_MARKER",
            "response": "DUMMY_RAW_RESPONSE_MARKER",
            "authorization_hint": "DUMMY_AUTHORIZATION_MARKER",
            "cookie_hint": "DUMMY_COOKIE_MARKER",
            "local_path_hint": "DUMMY_FULL_LOCAL_PATH_MARKER",
            "personal_data_hint": "DUMMY_PERSONAL_DATA_MARKER",
        }
        cases = [
            (
                "out_of_scope",
                {"request_host": "other.test", **raw_payload_markers},
                RECEIVER_SCOPE_DECISION_DROP,
                RECEIVER_SCOPE_REASON_OUT_OF_SCOPE,
                SCOPE_REASON_SUFFIX_MISMATCH,
                RECEIVER_SCOPE_SUMMARY_KIND_SKIP,
                RECEIVER_SCOPE_RESULT_SKIPPED,
            ),
            (
                "missing_host",
                dict(raw_payload_markers),
                RECEIVER_SCOPE_DECISION_DROP,
                RECEIVER_SCOPE_REASON_MISSING_HOST,
                RECEIVER_SCOPE_REASON_MISSING_HOST,
                RECEIVER_SCOPE_SUMMARY_KIND_SKIP,
                RECEIVER_SCOPE_RESULT_SKIPPED,
            ),
            (
                "invalid_host",
                {"request_host": "127.0.0.1", **raw_payload_markers},
                RECEIVER_SCOPE_DECISION_DROP,
                RECEIVER_SCOPE_REASON_INVALID_HOST,
                SCOPE_REASON_IP_LITERAL,
                RECEIVER_SCOPE_SUMMARY_KIND_SKIP,
                RECEIVER_SCOPE_RESULT_SKIPPED,
            ),
            (
                "in_scope",
                {"request_metadata": {"host": "api.example.test"}, **raw_payload_markers},
                RECEIVER_SCOPE_DECISION_ACCEPT,
                RECEIVER_SCOPE_REASON_IN_SCOPE,
                SCOPE_REASON_MATCHED,
                RECEIVER_SCOPE_SUMMARY_KIND_ACCEPT,
                RECEIVER_SCOPE_RESULT_ACCEPTED,
            ),
        ]
        expected_event_keys = {
            "event_type",
            "summary_kind",
            "decision",
            "reason",
            "match_reason",
            "result_status",
            "accepted",
            "dropped",
            "host_alias",
            "scope_alias",
            "raw_data_included",
            "ingest_performed",
            "collector_changed",
            "receiver_ingest_changed",
        }
        forbidden_fragments = [
            "DUMMY_RAW_REQUEST_MARKER",
            "DUMMY_RAW_RESPONSE_MARKER",
            "DUMMY_TOKEN_MARKER",
            "DUMMY_AUTHORIZATION_MARKER",
            "DUMMY_COOKIE_MARKER",
            "DUMMY_FULL_LOCAL_PATH_MARKER",
            "DUMMY_PERSONAL_DATA_MARKER",
            "other.test",
            "127.0.0.1",
            "api.example.test",
            "example.test",
        ]

        for name, payload, decision, reason, match_reason, summary_kind, result_status in cases:
            with self.subTest(name=name):
                dry_run = evaluate_receiver_scope_dry_run(payload, "example.test")
                summary = build_receiver_scope_decision_summary(dry_run)
                direct_summary = evaluate_receiver_scope_decision_summary(payload, "example.test")
                event = build_receiver_scope_audit_event(summary)

                self.assertEqual(summary, direct_summary)
                self.assertEqual(summary.summary_kind, summary_kind)
                self.assertEqual(summary.decision, decision)
                self.assertEqual(summary.reason, reason)
                self.assertEqual(summary.match_reason, match_reason)
                self.assertEqual(summary.result_status, result_status)
                self.assertEqual(summary.accepted, decision == RECEIVER_SCOPE_DECISION_ACCEPT)
                self.assertEqual(summary.dropped, decision == RECEIVER_SCOPE_DECISION_DROP)
                self.assertFalse(summary.raw_data_included)
                self.assertFalse(summary.ingest_performed)
                self.assertFalse(summary.collector_changed)
                self.assertFalse(summary.receiver_ingest_changed)

                self.assertEqual(set(event), expected_event_keys)
                self.assertEqual(event["event_type"], RECEIVER_SCOPE_AUDIT_EVENT_TYPE)
                self.assertEqual(event["summary_kind"], summary_kind)
                self.assertEqual(event["decision"], decision)
                self.assertEqual(event["reason"], reason)
                self.assertEqual(event["result_status"], result_status)
                self.assertFalse(event["raw_data_included"])
                self.assertFalse(event["ingest_performed"])
                self.assertFalse(event["collector_changed"])
                self.assertFalse(event["receiver_ingest_changed"])

                result_text = json.dumps([summary.to_summary(), event], sort_keys=True)
                self.assertRegex(result_text, r"target_alias_[0-9a-f]{12}|\"host_alias\": \"\"")
                for fragment in forbidden_fragments:
                    self.assertNotIn(fragment, result_text)

    def test_live_capture_collector_contract_fixture_matches_receiver_helpers(self) -> None:
        fixture = json.loads(LIVE_CAPTURE_COLLECTOR_CONTRACT_FIXTURE.read_text(encoding="utf-8"))
        self.assertEqual(fixture["schema_version"], "live-capture-collector-contract-v1")
        self.assertFalse(fixture["raw_data_included"])
        self.assertTrue(fixture["collector_forwarding_changed"])
        self.assertFalse(fixture["receiver_ingest_changed"])
        self.assertFalse(fixture["audit_file_write_changed"])
        self.assertFalse(fixture["redaction_pipeline_auto_run"])
        self.assertEqual(fixture["collector_payload_preferred_container"], "request_metadata")
        self.assertEqual(fixture["collector_payload_preferred_key"], "host")
        self.assertEqual(
            fixture["collector_status_values_included"],
            [
                "items_sent",
                "skipped",
                "out_of_scope_skipped",
                "missing_host_skipped",
                "invalid_host_skipped",
            ],
        )
        self.assertEqual(
            fixture["collector_decision_reasons"],
            [
                "collector_scope_in_scope",
                "collector_scope_out_of_burp_scope",
                "collector_scope_missing_host",
                "collector_scope_invalid_host",
            ],
        )
        self.assertEqual(fixture["expected_safe_host_metadata_keys"], list(SAFE_HOST_METADATA_KEYS))
        self.assertEqual(fixture["expected_safe_host_metadata_containers"], list(SAFE_HOST_METADATA_CONTAINERS))

        missing_payload = {
            "schema_version": "montoya-handoff-v1",
            "source": "burp_proxy_history",
            "request": "DUMMY_CONTRACT_RAW_REQUEST_MARKER Host: hidden.test",
            "response": "DUMMY_CONTRACT_RAW_RESPONSE_MARKER",
        }
        cases = [
            (
                "missing_safe_host_metadata",
                missing_payload,
                RECEIVER_SCOPE_DECISION_DROP,
                RECEIVER_SCOPE_REASON_MISSING_HOST,
            ),
            (
                "invalid_safe_host_metadata",
                {"request_metadata": {"host": "127.0.0.1"}, **missing_payload},
                RECEIVER_SCOPE_DECISION_DROP,
                RECEIVER_SCOPE_REASON_INVALID_HOST,
            ),
            (
                "out_of_scope_safe_host_metadata",
                {"request_metadata": {"host": "other.test"}, **missing_payload},
                RECEIVER_SCOPE_DECISION_DROP,
                RECEIVER_SCOPE_REASON_OUT_OF_SCOPE,
            ),
            (
                "in_scope_safe_host_metadata",
                {"request_metadata": {"host": "api.example.test"}, **missing_payload},
                RECEIVER_SCOPE_DECISION_ACCEPT,
                RECEIVER_SCOPE_REASON_IN_SCOPE,
            ),
        ]
        fixture_cases = {item["case"]: item for item in fixture["contract_cases"]}
        forbidden_fragments = [
            "DUMMY_CONTRACT_RAW_REQUEST_MARKER",
            "DUMMY_CONTRACT_RAW_RESPONSE_MARKER",
            "hidden.test",
            "other.test",
            "127.0.0.1",
            "api.example.test",
            "example.test",
        ]
        for name, payload, expected_decision, expected_reason in cases:
            with self.subTest(name=name):
                self.assertIn(name, fixture_cases)
                self.assertEqual(fixture_cases[name]["expected_decision"], expected_decision)
                self.assertEqual(fixture_cases[name]["expected_reason"], expected_reason)
                summary = evaluate_receiver_scope_decision_summary(payload, "example.test")
                event = build_receiver_scope_audit_event(summary)
                self.assertEqual(summary.decision, expected_decision)
                self.assertEqual(summary.reason, expected_reason)
                self.assertFalse(summary.raw_data_included)
                self.assertFalse(summary.ingest_performed)
                self.assertFalse(summary.collector_changed)
                self.assertFalse(summary.receiver_ingest_changed)
                self.assertFalse(event["raw_data_included"])
                self.assertFalse(event["ingest_performed"])
                self.assertFalse(event["collector_changed"])
                self.assertFalse(event["receiver_ingest_changed"])
                result_text = json.dumps([summary.to_summary(), event], sort_keys=True)
                for fragment in forbidden_fragments:
                    self.assertNotIn(fragment, result_text)

    def test_live_capture_collector_contract_docs_are_raw_free_and_filter_bound(self) -> None:
        contract_doc = LIVE_CAPTURE_COLLECTOR_CONTRACT_DOC.read_text(encoding="utf-8")
        fixture_text = LIVE_CAPTURE_COLLECTOR_CONTRACT_FIXTURE.read_text(encoding="utf-8")
        combined = "\n".join([contract_doc, fixture_text])
        self.assertIn("collector-side filter is implemented", contract_doc)
        self.assertIn("request_metadata.host", contract_doc)
        self.assertIn("out_of_scope_skipped", contract_doc)
        self.assertIn("receiver ingest behavior changes", contract_doc)
        self.assertIn("ChatGPT automatic handoff", contract_doc)
        self.assertIn("Findings remain candidates", contract_doc)
        self.assertIn("Risk remains draft", contract_doc)
        self.assertIn("Final severity and CVSS remain", contract_doc)

        forbidden_fragments = [
            "DUMMY_BEARER_TOKEN",
            "DUMMY_COOKIE_VALUE",
            "Authorization: Bearer",
            "Cookie:",
            "Set-Cookie:",
            "C:\\",
            "C:/",
            "safe-to-share guaranteed",
            "guaranteed safe",
            "confirmed vulnerability",
            "final severity confirmed",
            "confirmed CVSS",
        ]
        for fragment in forbidden_fragments:
            self.assertNotIn(fragment, combined)
        self.assertIsNone(re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", fixture_text))

    def test_live_capture_scope_drift_matrix_matches_receiver_guard_and_docs(self) -> None:
        doc = LIVE_CAPTURE_SCOPE_DRIFT_MATRIX_DOC.read_text(encoding="utf-8")
        fixture = json.loads(LIVE_CAPTURE_SCOPE_DRIFT_MATRIX_FIXTURE.read_text(encoding="utf-8"))
        self.assertEqual(fixture["schema_version"], "live-capture-scope-drift-matrix-v1")
        self.assertFalse(fixture["raw_data_included"])
        self.assertFalse(fixture["collector_runtime_changed"])
        self.assertFalse(fixture["receiver_ingest_changed"])
        self.assertFalse(fixture["dashboard_changed"])
        self.assertIn("fixture and documentation boundary only", doc)
        self.assertIn("does not change collector forwarding behavior", doc)
        self.assertIn("samples/synthetic_live_capture_scope_drift_matrix.json", doc)
        java_matrix_test = LIVE_CAPTURE_SCOPE_DRIFT_MATRIX_JAVA_TEST.read_text(encoding="utf-8")
        self.assertIn("CollectorSafeHostMetadata.evaluate", java_matrix_test)
        self.assertIn("collector_scope_in_scope", java_matrix_test)
        self.assertIn("collector_scope_invalid_host", java_matrix_test)
        self.assertIn("collector_scope_out_of_burp_scope", java_matrix_test)

        expected_categories = {
            "normal host",
            "uppercase host",
            "host with trailing dot",
            "URL shape",
            "path/query included",
            "wildcard",
            "localhost",
            "loopback IPv4",
            "IP literal",
            "private-looking IP",
            "malformed label",
            "lookalike suffix",
            "subdomain",
            "out-of-scope host",
        }
        self.assertEqual({case["category"] for case in fixture["cases"]}, expected_categories)
        for case in fixture["cases"]:
            self.assertIn(case["case"], java_matrix_test)

        java_source = "\n".join(path.read_text(encoding="utf-8") for path in MONTOYA_SOURCE_DIR.glob("*.java"))
        for marker in [
            "request.isInScope()",
            "request.httpService().host()",
            "normalizeHost",
            "isValidHost",
            "collector_scope_out_of_burp_scope",
            "collector_scope_invalid_host",
            "collector_scope_in_scope",
        ]:
            self.assertIn(marker, java_source)

        for case in fixture["cases"]:
            with self.subTest(case=case["case"]):
                host = case["safe_host_metadata"]
                payload = {"request_metadata": {"host": host}}
                summary = evaluate_receiver_scope_decision_summary(payload, "example.test")
                self.assertEqual(summary.decision, case["expected_receiver_decision"])
                self.assertEqual(summary.reason, case["expected_receiver_reason"])
                self.assertEqual(summary.match_reason, case["expected_receiver_match_reason"])
                self.assertFalse(summary.raw_data_included)
                self.assertFalse(summary.ingest_performed)
                self.assertFalse(summary.collector_changed)
                self.assertFalse(summary.receiver_ingest_changed)

                if not case["burp_in_scope"]:
                    expected_collector_reason = "collector_scope_out_of_burp_scope"
                    expected_collector_allowed = False
                else:
                    try:
                        validate_live_capture_scope(host)
                    except LiveCaptureScopeError:
                        expected_collector_reason = "collector_scope_invalid_host"
                        expected_collector_allowed = False
                    else:
                        expected_collector_reason = "collector_scope_in_scope"
                        expected_collector_allowed = True
                self.assertEqual(case["expected_collector_reason"], expected_collector_reason)
                self.assertEqual(case["expected_collector_allowed"], expected_collector_allowed)

                summary_text = json.dumps(summary.to_summary(), sort_keys=True)
                self.assertNotIn(host, summary_text)
                self.assertNotIn("example.test", summary_text)

        fixture_text = json.dumps(fixture, sort_keys=True)
        for forbidden_key in ["raw_request", "raw_response", "cookie_value", "authorization_value"]:
            self.assertNotIn(forbidden_key, fixture_text)

    def test_live_capture_runtime_smoke_checklist_is_raw_free_and_count_based(self) -> None:
        checklist = LIVE_CAPTURE_RUNTIME_SMOKE_CHECKLIST_DOC.read_text(encoding="utf-8")
        template = LIVE_CAPTURE_RUNTIME_SMOKE_EVIDENCE_TEMPLATE.read_text(encoding="utf-8")
        roadmap = (ROOT / "docs" / "ROADMAP_v0.5.md").read_text(encoding="utf-8")
        combined = "\n".join([checklist, template, roadmap])

        self.assertIn("LIVE_CAPTURE_RUNTIME_SMOKE_EVIDENCE_TEMPLATE.md", checklist)
        self.assertIn("LIVE_CAPTURE_RUNTIME_SMOKE_CHECKLIST_v0.5.md", roadmap)
        for marker in [
            "extension load",
            "local receiver",
            "in-scope handoff count",
            "out-of-scope skip count",
            "missing_host_skipped",
            "invalid_host_skipped",
            "receiver verify",
            "raw markers in extension output",
            "actual target identifiers recorded",
            "raw request/response recorded",
            "token/JWT/session values recorded",
            "final severity or CVSS",
        ]:
            self.assertIn(marker, combined)

        for failure_category in [
            "extension_load_failed",
            "receiver_unavailable",
            "no_in_scope_handoff",
            "no_out_of_scope_skip",
            "verify_failed_safely",
        ]:
            self.assertIn(failure_category, checklist)

        for forbidden in [
            "safe-to-share",
            "confirmed vulnerability",
            "raw_request",
            "raw_response",
            "cookie_value",
            "authorization_value",
        ]:
            self.assertNotIn(forbidden, combined)
        self.assertIsNone(re.search(r"https?://", combined))
        self.assertIsNone(re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", combined))

    def test_v08_skeleton_approval_packet_is_planning_only_and_raw_free(self) -> None:
        doc = V08_SKELETON_APPROVAL_PACKET_DOC.read_text(encoding="utf-8")
        fixture = json.loads(V08_SKELETON_APPROVAL_PACKET_FIXTURE.read_text(encoding="utf-8"))
        fixture_text = json.dumps(fixture, sort_keys=True)
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        backlog = V08_BACKLOG_SPLIT_DOC.read_text(encoding="utf-8")
        planning = V08_MINIMAL_SKELETON_PLANNING_DOC.read_text(encoding="utf-8")
        normalized_doc = " ".join(doc.split())
        normalized_doc_lower = normalized_doc.lower()

        self.assertTrue(V08_SKELETON_APPROVAL_PACKET_DOC.exists())
        self.assertTrue(V08_SKELETON_APPROVAL_PACKET_FIXTURE.exists())
        for linked_text in [readme, backlog, planning]:
            self.assertIn("V0.8_SKELETON_APPROVAL_PACKET.md", linked_text)

        for section in [
            "## Purpose",
            "## Current v0.8 baseline",
            "## Approval packet scope",
            "## Explicit non-goals",
            "## Required approval inputs",
            "## Pre-implementation blockers",
            "## Disabled-by-default approval conditions",
            "## Runtime boundary constraints",
            "## Raw-free response requirements",
            "## Rollback requirements",
            "## Required negative tests",
            "## Source-check requirements",
            "## Security review requirements",
            "## Deferred decisions",
        ]:
            self.assertIn(section, doc)

        for required_text in [
            "approval-planning and review-boundary document",
            "explicit human approval before any runtime pr",
            "target branch and expected base commit named",
            "implementation scope limited to disabled-by-default behavior",
            "loopback-only condition stated if runtime is later approved",
            "source-check consumption listed",
            "rollback command or plan documented",
            "release tag movement prohibited",
            "github release mutation prohibited",
            "raw-free blocked or disabled response contract listed",
            "manual review and the four-file safe candidate boundary unchanged",
            "missing explicit human approval",
            "dirty git status",
            "base branch is not main",
            "unexpected base commit",
            "missing source-check consumption guard",
            "missing raw-free response contract",
            "missing rollback plan",
            "scope contains a protocol parser",
            "scope contains a request dispatcher",
            "scope contains tool execution",
            "scope contains a local evidence reader",
            "scope contains raw preview or raw download",
            "scope contains external handoff",
            "scope contains tag or release mutation",
            "no raw request or response",
            "no credential value",
            "no session value",
            "no token value",
            "no full local path",
            "no actual target identifier",
            "no file body",
            "candidate findings only",
            "risk draft only",
            "final severity is manual",
            "final scoring is manual",
        ]:
            self.assertIn(required_text.lower(), normalized_doc_lower)

        self.assertEqual(fixture["schema_version"], "v08_skeleton_approval_packet.v1")
        for true_flag in [
            "skeleton_approval_packet_only",
            "v08_backlog_split_consumed",
            "v08_transport_design_consumed",
            "v08_protocol_handler_design_consumed",
            "v08_protocol_negative_harness_consumed",
            "v08_tool_registration_design_consumed",
            "v08_read_only_tool_contract_consumed",
            "v08_minimal_skeleton_planning_consumed",
            "explicit_human_approval_required",
        ]:
            self.assertIs(fixture[true_flag], True)

        for false_flag in [
            "implementation_included",
            "skeleton_runtime_implemented",
            "socket_bind_implemented",
            "socket_listen_implemented",
            "socket_accept_implemented",
            "stdio_transport_runtime_implemented",
            "http_transport_runtime_implemented",
            "protocol_parser_implemented",
            "json_rpc_parser_implemented",
            "request_dispatcher_implemented",
            "tool_registration_runtime_implemented",
            "tool_discovery_runtime_implemented",
            "tool_execution_implemented",
            "local_evidence_reader_implemented",
            "safe_file_body_reader_implemented",
            "raw_preview_download_implemented",
            "replay_active_scan_implemented",
            "automatic_chatgpt_handoff_implemented",
            "dashboard_state_changing_control_implemented",
            "upload_import_action_implemented",
            "tag_github_release_modified",
            "output_bundle_structure_changed",
        ]:
            self.assertIs(fixture[false_flag], False)

        for item in [
            "explicit_human_approval_required_before_runtime_pr",
            "target_branch_and_expected_base_commit_named",
            "implementation_scope_disabled_by_default_only",
            "loopback_only_condition_if_runtime_approved",
            "source_check_consumption_listed",
            "rollback_command_or_plan_documented",
            "release_tag_movement_prohibited",
            "github_release_mutation_prohibited",
            "raw_free_blocked_disabled_response_contract_listed",
            "manual_review_and_four_file_boundary_unchanged",
        ]:
            self.assertIn(item, fixture["required_approval_inputs"])

        for blocker in [
            "missing_explicit_human_approval",
            "dirty_git_status",
            "base_branch_not_main",
            "unexpected_base_commit",
            "missing_source_check_consumption_guard",
            "missing_raw_free_response_contract",
            "missing_rollback_plan",
            "scope_contains_protocol_parser",
            "scope_contains_request_dispatcher",
            "scope_contains_tool_execution",
            "scope_contains_local_evidence_reader",
            "scope_contains_raw_preview_download",
            "scope_contains_external_handoff",
            "scope_contains_tag_or_release_mutation",
        ]:
            self.assertIn(blocker, fixture["pre_implementation_blockers"])

        for requirement in [
            "no_raw_request_response",
            "no_credential_value",
            "no_session_value",
            "no_token_value",
            "no_hmac_secret",
            "no_csrf_token_value",
            "no_full_local_path",
            "no_actual_target_identifier",
            "no_stack_trace",
            "no_file_body",
            "no_external_handoff",
            "candidate_findings_only",
            "risk_draft_only",
            "final_severity_manual",
            "final_cvss_manual",
        ]:
            self.assertIn(requirement, fixture["raw_free_response_requirements"])

        for requirement in [
            "revert_runtime_pr_without_release_tag_movement",
            "revert_runtime_pr_without_github_release_mutation",
            "output_bundle_structure_unchanged",
            "manual_review_and_four_file_boundary_unchanged",
            "raw_free_blocked_disabled_response_after_rollback",
        ]:
            self.assertIn(requirement, fixture["rollback_requirements"])

        for negative in [
            "skeleton_runtime_marker_check",
            "socket_bind_listen_accept_marker_check",
            "stdio_http_runtime_marker_check",
            "protocol_parser_marker_check",
            "json_rpc_parser_marker_check",
            "request_dispatcher_marker_check",
            "tool_registration_runtime_marker_check",
            "tool_execution_marker_check",
            "local_evidence_reader_marker_check",
            "safe_file_body_reader_marker_check",
            "raw_preview_download_marker_check",
            "replay_active_scan_marker_check",
            "automatic_handoff_marker_check",
            "dashboard_state_changing_marker_check",
            "upload_import_marker_check",
            "tag_release_mutation_marker_check",
        ]:
            self.assertIn(negative, fixture["required_negative_tests"])

        self.assertEqual(
            fixture["recommended_next_order"][:2],
            ["runtime_facing_source_check_consumption_guard", "minimal_skeleton_runtime_pr_after_explicit_approval"],
        )

        combined = "\n".join([doc, fixture_text])
        for forbidden in [
            "\ufeff",
            "\ufffd",
            "??",
            "safe-to-share",
            "safe to share",
            "guaranteed safe",
            "confirmed vulnerability",
            "confirmed finding",
            "confirmed issue count",
            "final CVSS",
            "\"raw_request\"",
            "\"raw_response\"",
            "raw_request:",
            "raw_response:",
            "Cookie:",
            "Authorization:",
            "Bearer ",
            "JWT ",
            "session=",
            "token=",
            "HMAC secret:",
            "CSRF token:",
            "C:\\coding\\",
            "C:\\Users\\",
            "local_only/",
            "real_export_",
            "actual.local",
            "example.com",
            "approved for external sharing",
            "ready to submit",
        ]:
            self.assertNotIn(forbidden, combined)
        self.assertIsNone(re.search(r"https?://", combined))
        self.assertIsNone(re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", combined))

    def test_v08_runtime_source_check_consumption_guard_is_guard_only(self) -> None:
        doc = V08_RUNTIME_SOURCE_CHECK_CONSUMPTION_GUARD_DOC.read_text(encoding="utf-8")
        fixture = json.loads(
            V08_RUNTIME_SOURCE_CHECK_CONSUMPTION_GUARD_FIXTURE.read_text(encoding="utf-8")
        )
        fixture_text = json.dumps(fixture, sort_keys=True)
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        approval = V08_SKELETON_APPROVAL_PACKET_DOC.read_text(encoding="utf-8")
        planning = V08_MINIMAL_SKELETON_PLANNING_DOC.read_text(encoding="utf-8")
        normalized_doc = " ".join(doc.split())
        normalized_doc_lower = normalized_doc.lower()

        self.assertTrue(V08_RUNTIME_SOURCE_CHECK_CONSUMPTION_GUARD_DOC.exists())
        self.assertTrue(V08_RUNTIME_SOURCE_CHECK_CONSUMPTION_GUARD_FIXTURE.exists())
        for linked_text in [readme, approval, planning]:
            self.assertIn("V0.8_RUNTIME_SOURCE_CHECK_CONSUMPTION_GUARD.md", linked_text)

        for section in [
            "## Purpose",
            "## Current v0.8 baseline",
            "## Guard scope",
            "## Explicit non-goals",
            "## Runtime-facing file declaration requirements",
            "## Approval packet consumption requirements",
            "## Forbidden marker categories",
            "## Source-check failure conditions",
            "## Required negative tests",
            "## Security review requirements",
            "## Rollback expectations",
            "## Deferred decisions",
        ]:
            self.assertIn(section, doc)

        for consumed_baseline in [
            "v08_backlog_split",
            "v08_transport_design",
            "v08_protocol_handler_design",
            "v08_protocol_negative_harness",
            "v08_tool_registration_design",
            "v08_read_only_tool_contract",
            "v08_minimal_skeleton_planning",
            "v08_skeleton_approval_packet",
        ]:
            self.assertIn(consumed_baseline, doc)

        for required_text in [
            "fixture, test, and review-boundary document only",
            "does not implement skeleton runtime",
            "does not implement or approve",
            "skeleton runtime",
            "socket, bind, listen, or accept behavior",
            "stdio transport runtime",
            "http transport runtime",
            "protocol parser",
            "json-rpc parser",
            "request dispatcher",
            "executable tool registration",
            "tool registry runtime",
            "tool discovery runtime",
            "actual tool execution",
            "local evidence reader",
            "safe file body reader",
            "raw preview or raw download",
            "dashboard start or stop control",
            "upload or import action",
            "replay or active scan",
            "automatic chatgpt handoff",
            "tag changes",
            "github release changes",
            "runtime_facing_file_missing_from_fixture",
            "fixture_missing_approval_packet_consumption",
            "fixture_flag_drift_to_true",
            "forbidden_marker_present_without_approval",
            "raw_free_contract_missing",
            "rollback_requirement_missing",
            "tag_release_mutation_marker_present",
            "output_bundle_structure_change_marker_present",
        ]:
            self.assertIn(required_text.lower(), normalized_doc_lower)

        self.assertEqual(
            fixture["schema_version"], "v08_runtime_source_check_consumption_guard.v1"
        )
        for true_flag in [
            "runtime_source_check_consumption_guard_only",
            "v08_backlog_split_consumed",
            "v08_transport_design_consumed",
            "v08_protocol_handler_design_consumed",
            "v08_protocol_negative_harness_consumed",
            "v08_tool_registration_design_consumed",
            "v08_read_only_tool_contract_consumed",
            "v08_minimal_skeleton_planning_consumed",
            "v08_skeleton_approval_packet_consumed",
            "explicit_human_approval_required",
            "runtime_facing_files_declared",
        ]:
            self.assertIs(fixture[true_flag], True)

        for false_flag in [
            "implementation_included",
            "skeleton_runtime_implemented",
            "socket_bind_implemented",
            "socket_listen_implemented",
            "socket_accept_implemented",
            "stdio_transport_runtime_implemented",
            "http_transport_runtime_implemented",
            "protocol_parser_implemented",
            "json_rpc_parser_implemented",
            "request_dispatcher_implemented",
            "tool_registration_runtime_implemented",
            "tool_discovery_runtime_implemented",
            "tool_execution_implemented",
            "local_evidence_reader_implemented",
            "safe_file_body_reader_implemented",
            "raw_preview_download_implemented",
            "replay_active_scan_implemented",
            "automatic_chatgpt_handoff_implemented",
            "dashboard_state_changing_control_implemented",
            "upload_import_action_implemented",
            "tag_github_release_modified",
            "output_bundle_structure_changed",
        ]:
            self.assertIs(fixture[false_flag], False)

        for runtime_file in [
            "burp_ai_redaction_gateway/mcp_minimal_skeleton.py",
            "burp_ai_redaction_gateway/mcp_runtime_contract.py",
        ]:
            self.assertIn(runtime_file, fixture["runtime_facing_files"])

        for requirement in [
            "consume_v08_skeleton_approval_packet",
            "explicit_human_approval_required",
            "expected_base_commit_required",
            "disabled_by_default_required",
            "loopback_only_if_runtime_approved",
            "raw_free_blocked_disabled_response_required",
            "rollback_without_tag_release_mutation_required",
            "four_file_safe_candidate_boundary_required",
        ]:
            self.assertIn(requirement, fixture["approval_packet_consumption_requirements"])

        for category in [
            "socket_bind_listen_accept",
            "stdio_http_runtime",
            "protocol_parser",
            "json_rpc_parser",
            "request_dispatcher",
            "executable_tool_registration",
            "tool_registry_runtime",
            "tool_discovery_runtime",
            "actual_tool_execution",
            "local_evidence_reader",
            "safe_file_body_reader",
            "raw_preview_download",
            "replay_active_scan",
            "automatic_chatgpt_handoff",
            "dashboard_state_changing_control",
            "upload_import_action",
            "tag_release_mutation",
        ]:
            self.assertIn(category, fixture["forbidden_marker_categories"])

        for failure_condition in [
            "runtime_facing_file_missing_from_fixture",
            "fixture_missing_approval_packet_consumption",
            "fixture_flag_drift_to_true",
            "forbidden_marker_present_without_approval",
            "raw_free_contract_missing",
            "rollback_requirement_missing",
            "tag_release_mutation_marker_present",
            "output_bundle_structure_change_marker_present",
        ]:
            self.assertIn(failure_condition, fixture["source_check_failure_conditions"])

        for rollback in [
            "revert_runtime_facing_files_without_release_tag_movement",
            "revert_runtime_facing_files_without_github_release_mutation",
            "output_bundle_structure_unchanged",
            "manual_review_and_four_file_boundary_unchanged",
            "raw_free_blocked_disabled_response_after_rollback",
        ]:
            self.assertIn(rollback, fixture["rollback_requirements"])

        self.assertEqual(
            fixture["recommended_next_order"][:2],
            [
                "minimal_skeleton_runtime_approval_decision",
                "minimal_skeleton_runtime_pr_after_explicit_approval",
            ],
        )

        combined = "\n".join([doc, fixture_text])
        for forbidden in [
            "\ufeff",
            "\ufffd",
            "??",
            "safe-to-share",
            "safe to share",
            "guaranteed safe",
            "confirmed vulnerability",
            "confirmed finding",
            "confirmed issue count",
            "final CVSS",
            "\"raw_request\"",
            "\"raw_response\"",
            "raw_request:",
            "raw_response:",
            "Cookie:",
            "Authorization:",
            "Bearer ",
            "JWT ",
            "session=",
            "token=",
            "HMAC secret:",
            "CSRF token:",
            "C:\\coding\\",
            "C:\\Users\\",
            "local_only/",
            "real_export_",
            "actual.local",
            "example.com",
            "approved for external sharing",
            "ready to submit",
        ]:
            self.assertNotIn(forbidden, combined)
        self.assertIsNone(re.search(r"https?://", combined))
        self.assertIsNone(re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", combined))

    def test_v08_post_merge_boundary_note_is_helper_only_and_raw_free(self) -> None:
        doc = V08_POST_MERGE_BOUNDARY_NOTE_DOC.read_text(encoding="utf-8")
        fixture = json.loads(V08_POST_MERGE_BOUNDARY_NOTE_FIXTURE.read_text(encoding="utf-8"))
        fixture_text = json.dumps(fixture, sort_keys=True)
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        normalized_doc = " ".join(doc.split())
        normalized_doc_lower = normalized_doc.lower()

        self.assertTrue(V08_POST_MERGE_BOUNDARY_NOTE_DOC.exists())
        self.assertTrue(V08_POST_MERGE_BOUNDARY_NOTE_FIXTURE.exists())
        self.assertIn("V0.8_POST_MERGE_BOUNDARY_NOTE.md", readme)

        for section in [
            "## Purpose",
            "## Current baseline",
            "## Implemented helper boundary",
            "## Not implemented",
            "## Follow-up PR split rules",
            "## Required checks before follow-up runtime work",
            "## Release boundary",
            "## Deferred decisions",
        ]:
            self.assertIn(section, doc)

        for required_text in [
            "pr #130",
            "fcc0dd947ec9c62410cc5715cce7ae623bc32aa8",
            "disabled-by-default minimal skeleton helper",
            "raw-free disabled response helpers",
            "loopback candidate validation helper",
            "listener startup",
            "socket, bind, listen, or accept behavior",
            "stdio runtime",
            "http runtime",
            "protocol parser",
            "json-rpc parser",
            "request dispatcher",
            "executable tool registration",
            "actual tool execution",
            "local evidence reader",
            "safe file body reader",
            "raw preview or raw download",
            "dashboard start or stop control",
            "upload or import action",
            "replay or active scan",
            "automatic chatgpt handoff",
            "tag changes",
            "github release changes",
            "four-file ai input candidate boundary",
        ]:
            self.assertIn(required_text.lower(), normalized_doc_lower)

        self.assertEqual(fixture["schema_version"], "v08_post_merge_boundary_note.v1")
        self.assertIs(fixture["post_merge_boundary_note_only"], True)
        self.assertEqual(fixture["pr_number"], 130)
        self.assertEqual(
            fixture["merge_commit"], "fcc0dd947ec9c62410cc5715cce7ae623bc32aa8"
        )
        self.assertEqual(fixture["implemented_helper_file_count"], 2)
        for helper_file in [
            "burp_ai_redaction_gateway/mcp_minimal_skeleton.py",
            "burp_ai_redaction_gateway/mcp_runtime_contract.py",
        ]:
            self.assertIn(helper_file, fixture["implemented_scope"])

        for false_flag in [
            "listener_startup_implemented",
            "socket_bind_implemented",
            "socket_listen_implemented",
            "socket_accept_implemented",
            "stdio_transport_runtime_implemented",
            "http_transport_runtime_implemented",
            "protocol_parser_implemented",
            "json_rpc_parser_implemented",
            "request_dispatcher_implemented",
            "tool_registration_runtime_implemented",
            "tool_discovery_runtime_implemented",
            "tool_execution_implemented",
            "local_evidence_reader_implemented",
            "safe_file_body_reader_implemented",
            "raw_preview_download_implemented",
            "dashboard_state_changing_control_implemented",
            "upload_import_action_implemented",
            "replay_active_scan_implemented",
            "automatic_chatgpt_handoff_implemented",
            "tag_github_release_modified",
            "output_bundle_structure_changed",
            "raw_data_included",
            "file_body_included",
        ]:
            self.assertIs(fixture[false_flag], False)

        self.assertIs(fixture["manual_review_required"], True)
        self.assertEqual(
            fixture["output_bundle_files"],
            ["analysis_packet.json", "chatgpt_prompt.md", "codex_task_prompt.md", "report_draft.md"],
        )

        for split_requirement in [
            "transport_protocol_separate",
            "protocol_dispatcher_separate",
            "tool_registration_discovery_execution_separate",
            "local_evidence_reader_separate",
            "dashboard_state_changing_action_separate",
            "upload_import_action_separate",
            "replay_active_scan_deferred",
            "automatic_chatgpt_handoff_deferred",
            "tag_release_action_separate",
        ]:
            self.assertIn(split_requirement, fixture["follow_up_pr_split_requirements"])

        for required_check in [
            "runtime_facing_files_declared",
            "forbidden_marker_checks_cover_new_files",
            "runtime_flags_remain_false_unless_approved",
            "raw_free_disabled_blocked_response",
            "output_bundle_structure_unchanged",
            "rollback_without_tag_release_mutation",
        ]:
            self.assertIn(required_check, fixture["required_follow_up_checks"])

        combined = "\n".join([doc, fixture_text])
        for forbidden in [
            "\ufeff",
            "\ufffd",
            "??",
            "safe-to-share",
            "safe to share",
            "guaranteed safe",
            "confirmed vulnerability",
            "confirmed finding",
            "confirmed issue count",
            "final CVSS",
            "\"raw_request\"",
            "\"raw_response\"",
            "raw_request:",
            "raw_response:",
            "Cookie:",
            "Authorization:",
            "Bearer ",
            "JWT ",
            "session=",
            "token=",
            "HMAC secret:",
            "CSRF token:",
            "C:\\coding\\",
            "C:\\Users\\",
            "local_only/",
            "real_export_",
            "actual.local",
            "approved for external sharing",
            "ready to submit",
        ]:
            self.assertNotIn(forbidden, combined)
        self.assertIsNone(re.search(r"https?://", combined))
        self.assertIsNone(re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", combined))

    def test_v08_scope_freeze_rc_readiness_is_boundary_helper_only(self) -> None:
        doc = V08_SCOPE_FREEZE_RC_READINESS_DOC.read_text(encoding="utf-8")
        fixture = json.loads(V08_SCOPE_FREEZE_RC_READINESS_FIXTURE.read_text(encoding="utf-8"))
        fixture_text = json.dumps(fixture, sort_keys=True)
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        normalized_doc = " ".join(doc.split())
        normalized_doc_lower = normalized_doc.lower()

        self.assertTrue(V08_SCOPE_FREEZE_RC_READINESS_DOC.exists())
        self.assertTrue(V08_SCOPE_FREEZE_RC_READINESS_FIXTURE.exists())
        self.assertIn("V0.8_SCOPE_FREEZE_RC_READINESS.md", readme)

        for section in [
            "## Purpose",
            "## Current baseline",
            "## Recommended release type",
            "## Included scope",
            "## Excluded scope",
            "## Release blockers",
            "## Required final gate",
            "## Rollback expectation",
            "## Deferred work",
            "## Acceptance criteria",
        ]:
            self.assertIn(section, doc)

        for required_text in [
            "boundary/helper release candidate",
            "pr #130",
            "fcc0dd947ec9c62410cc5715cce7ae623bc32aa8",
            "pr #131",
            "bb484ea21d90759125a7224fedaec6a9ee7b75fc",
            "recommended v0.8 release type is `boundary_helper`",
            "four ai input candidate files",
            "dashboard read-only and raw-free baseline",
            "disabled-by-default mcp helper files",
            "post-merge boundary note",
            "source-check and fixture guard evidence",
            "listener startup",
            "socket, bind, listen, or accept behavior",
            "stdio runtime",
            "http runtime",
            "protocol parser",
            "json-rpc parser",
            "request dispatcher",
            "executable tool registration",
            "tool registry runtime",
            "tool discovery runtime",
            "actual tool execution",
            "local evidence reader",
            "safe file body reader",
            "raw preview or download",
            "replay or active scan",
            "dashboard state-changing control",
            "upload or import action",
            "automatic chatgpt handoff",
            "v0.8 tag creation",
            "github release creation",
            "unit tests fail",
            "gitleaks directory scan reports a finding",
            "gitleaks git scan reports a finding",
            "git safety check fails",
            "raw marker or credential marker",
            "unreviewed runtime surface",
            "reverting only the release-prep pr",
        ]:
            self.assertIn(required_text.lower(), normalized_doc_lower)

        self.assertEqual(fixture["schema_version"], "v08_scope_freeze_rc_readiness.v1")
        self.assertIs(fixture["scope_freeze_recommended"], True)
        self.assertEqual(fixture["recommended_release_type"], "boundary_helper")
        self.assertEqual(
            fixture["pr130_merge_commit"], "fcc0dd947ec9c62410cc5715cce7ae623bc32aa8"
        )
        self.assertEqual(
            fixture["pr131_merge_commit"], "bb484ea21d90759125a7224fedaec6a9ee7b75fc"
        )
        self.assertIs(fixture["tag_github_release_modified"], False)
        self.assertIs(fixture["release_created"], False)
        self.assertIs(fixture["manual_review_required"], True)
        self.assertIs(fixture["raw_data_included"], False)
        self.assertIs(fixture["output_bundle_structure_changed"], False)
        self.assertEqual(
            fixture["output_bundle_files"],
            ["analysis_packet.json", "chatgpt_prompt.md", "codex_task_prompt.md", "report_draft.md"],
        )

        for included in [
            "redaction_verify_review_report_pipeline",
            "four_ai_input_candidate_files",
            "dashboard_read_only_raw_free_baseline",
            "disabled_by_default_mcp_helper_files",
            "post_merge_boundary_note",
            "source_check_fixture_guard_evidence",
            "release_readiness_evidence",
        ]:
            self.assertIn(included, fixture["included_scope"])

        for excluded in [
            "listener_startup",
            "socket_bind_listen_accept",
            "stdio_runtime",
            "http_runtime",
            "protocol_parser",
            "json_rpc_parser",
            "request_dispatcher",
            "executable_tool_registration",
            "tool_registry_runtime",
            "tool_discovery_runtime",
            "actual_tool_execution",
            "local_evidence_reader",
            "safe_file_body_reader",
            "raw_preview_download",
            "replay_active_scan",
            "dashboard_state_changing_control",
            "upload_import_action",
            "automatic_chatgpt_handoff",
            "v08_tag_creation",
            "github_release_creation",
        ]:
            self.assertIn(excluded, fixture["excluded_scope"])

        for blocker in [
            "unittest_failure",
            "gitleaks_dir_finding",
            "gitleaks_git_finding",
            "git_safety_failure",
            "raw_marker_or_credential_marker_in_docs_or_fixtures",
            "unexpected_v08_tag_exists",
            "unexpected_github_release_v08_exists",
            "unreviewed_runtime_surface_present",
            "output_bundle_structure_changed",
            "tag_or_release_mutation_before_explicit_approval",
        ]:
            self.assertIn(blocker, fixture["release_blockers"])

        for final_gate in [
            "python_compileall",
            "python_unittest_discover",
            "gitleaks_dir",
            "gitleaks_git",
            "git_safety_check",
            "git_diff_check",
            "git_status_clean",
            "v08_tag_absence_check",
            "github_release_v08_absence_check",
        ]:
            self.assertIn(final_gate, fixture["required_final_gate"])

        for deferred in [
            "protocol_parser_approval_packet",
            "protocol_negative_harness",
            "transport_approval_packet",
            "dispatcher_approval_packet",
            "read_only_tool_registry_contract_follow_up",
            "local_evidence_reader_approval_packet",
            "dashboard_state_changing_action_approval_packet",
            "upload_import_action_approval_packet",
            "automatic_chatgpt_handoff_decision",
        ]:
            self.assertIn(deferred, fixture["deferred_work"])

        combined = "\n".join([doc, fixture_text])
        for forbidden in [
            "\ufeff",
            "\ufffd",
            "??",
            "safe-to-share",
            "safe to share",
            "guaranteed safe",
            "confirmed vulnerability",
            "confirmed finding",
            "confirmed issue count",
            "final CVSS",
            "\"raw_request\"",
            "\"raw_response\"",
            "raw_request:",
            "raw_response:",
            "Cookie:",
            "Authorization:",
            "Bearer ",
            "JWT ",
            "session=",
            "token=",
            "HMAC secret:",
            "CSRF token:",
            "C:\\coding\\",
            "C:\\Users\\",
            "local_only/",
            "real_export_",
            "actual.local",
            "approved for external sharing",
            "ready to submit",
        ]:
            self.assertNotIn(forbidden, combined)
        self.assertIsNone(re.search(r"https?://", combined))
        self.assertIsNone(re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", combined))

    def test_v08_release_approval_packet_is_approval_only_and_raw_free(self) -> None:
        approval_packet = V08_RELEASE_APPROVAL_PACKET_DOC.read_text(encoding="utf-8")
        fixture = json.loads(V08_RELEASE_APPROVAL_PACKET_FIXTURE.read_text(encoding="utf-8"))
        fixture_text = json.dumps(fixture, sort_keys=True)
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        scope_freeze = V08_SCOPE_FREEZE_RC_READINESS_DOC.read_text(encoding="utf-8")
        combined = "\n".join([approval_packet, fixture_text])
        normalized = " ".join(approval_packet.split())
        normalized_lower = normalized.lower()

        self.assertTrue(V08_RELEASE_APPROVAL_PACKET_DOC.exists())
        self.assertTrue(V08_RELEASE_APPROVAL_PACKET_FIXTURE.exists())
        self.assertIn("V0.8_RELEASE_APPROVAL_PACKET.md", readme)
        self.assertIn("V0.8_RELEASE_APPROVAL_PACKET.md", scope_freeze)

        for section in [
            "## Purpose",
            "## Target commit",
            "## Baseline PRs",
            "## Release type",
            "## Included scope",
            "## Excluded scope",
            "## Release blockers",
            "## Required final gate",
            "## Proposed release note body",
            "## Required release body hygiene",
            "## Required tag checks",
            "## Required GitHub Release checks",
            "## Rollback requirements",
            "## Human approval boundary",
            "## Deferred work",
        ]:
            self.assertIn(section, approval_packet)

        for required_text in [
            "release approval packet only",
            "does not create a tag",
            "does not create a github release",
            "does not approve release execution by itself",
            "58c7190e5cde43ca2ae4bddf056360eda649622b",
            "fcc0dd947ec9c62410cc5715cce7ae623bc32aa8",
            "bb484ea21d90759125a7224fedaec6a9ee7b75fc",
            "boundary_helper",
            "not as a read-only mcp runtime release",
            "four ai input candidate files",
            "dashboard read-only and raw-free baseline",
            "disabled-by-default mcp helper files",
            "post-merge boundary note",
            "scope freeze / rc readiness evidence",
            "listener startup",
            "socket, bind, listen, or accept behavior",
            "stdio runtime",
            "http runtime",
            "protocol parser",
            "json-rpc parser",
            "request dispatcher",
            "executable tool registration",
            "tool registry runtime",
            "actual tool execution",
            "local evidence reader",
            "safe file body reader",
            "raw preview or download",
            "replay or active scan",
            "dashboard state-changing control",
            "upload or import action",
            "automatic chatgpt handoff",
            "unit tests fail",
            "gitleaks directory scan reports a finding",
            "gitleaks git scan reports a finding",
            "git safety check fails",
            "working tree is dirty",
            "v0.8 tag already exists unexpectedly",
            "github release v0.8 already exists unexpectedly",
            "raw marker or credential marker",
            "output bundle structure changes",
            "unreviewed runtime surface",
            "separate explicit human approval",
            "after a tag or github release exists",
        ]:
            self.assertIn(required_text, normalized_lower)

        self.assertEqual(fixture["schema_version"], "v08_release_approval_packet.v1")
        self.assertIs(fixture["release_approval_packet_only"], True)
        self.assertEqual(fixture["release_type"], "boundary_helper")
        self.assertEqual(
            fixture["target_commit"], "58c7190e5cde43ca2ae4bddf056360eda649622b"
        )
        self.assertEqual(
            fixture["pr130_merge_commit"], "fcc0dd947ec9c62410cc5715cce7ae623bc32aa8"
        )
        self.assertEqual(
            fixture["pr131_merge_commit"], "bb484ea21d90759125a7224fedaec6a9ee7b75fc"
        )
        self.assertEqual(
            fixture["pr132_merge_commit"], "58c7190e5cde43ca2ae4bddf056360eda649622b"
        )
        self.assertIs(fixture["tag_created"], False)
        self.assertIs(fixture["github_release_created"], False)
        self.assertIs(fixture["explicit_release_approval_required"], True)
        self.assertIs(fixture["manual_review_required"], True)
        self.assertIs(fixture["raw_data_included"], False)
        self.assertIs(fixture["output_bundle_structure_changed"], False)
        self.assertIs(fixture["read_only_mcp_runtime_release"], False)
        self.assertEqual(
            fixture["output_bundle_files"],
            ["analysis_packet.json", "chatgpt_prompt.md", "codex_task_prompt.md", "report_draft.md"],
        )

        for included in [
            "redaction_verify_review_report_pipeline",
            "four_ai_input_candidate_files",
            "dashboard_read_only_raw_free_baseline",
            "disabled_by_default_mcp_helper_files",
            "post_merge_boundary_note",
            "scope_freeze_rc_readiness_evidence",
        ]:
            self.assertIn(included, fixture["included_scope"])

        for excluded in [
            "listener_startup",
            "socket_bind_listen_accept",
            "stdio_runtime",
            "http_runtime",
            "protocol_parser",
            "json_rpc_parser",
            "request_dispatcher",
            "executable_tool_registration",
            "tool_registry_runtime",
            "tool_discovery_runtime",
            "actual_tool_execution",
            "local_evidence_reader",
            "safe_file_body_reader",
            "raw_preview_download",
            "replay_active_scan",
            "dashboard_state_changing_control",
            "upload_import_action",
            "automatic_chatgpt_handoff",
        ]:
            self.assertIn(excluded, fixture["excluded_scope"])

        for blocker in [
            "unittest_failure",
            "gitleaks_dir_finding",
            "gitleaks_git_finding",
            "git_safety_failure",
            "dirty_working_tree",
            "unexpected_v08_tag_exists",
            "unexpected_github_release_v08_exists",
            "raw_marker_or_credential_marker_in_docs_or_fixtures",
            "output_bundle_structure_drift",
            "unreviewed_runtime_surface_present",
        ]:
            self.assertIn(blocker, fixture["release_blockers"])

        for final_gate in [
            "python_compileall",
            "python_unittest_discover",
            "gitleaks_dir",
            "gitleaks_git",
            "git_safety_check",
            "git_diff_check",
            "git_status_clean",
            "v08_tag_absence_check",
            "github_release_v08_absence_check",
            "release_body_hygiene_check",
            "tag_target_verification",
            "release_target_verification",
        ]:
            self.assertIn(final_gate, fixture["required_final_gate"])

        for release_section in [
            "summary",
            "included_boundary_helper_scope",
            "not_included",
            "safety_and_privacy_boundaries",
            "verification_evidence",
            "manual_review_requirements",
            "known_limitations",
            "rollback_notes",
        ]:
            self.assertIn(release_section, fixture["proposed_release_note_sections"])

        for rollback_requirement in [
            "before_tag_revert_approval_packet_pr_and_recheck_main_head",
            "after_tag_or_release_requires_explicit_rollback_plan",
            "no_tag_movement_in_this_packet",
            "no_github_release_mutation_in_this_packet",
        ]:
            self.assertIn(rollback_requirement, fixture["rollback_requirements"])

        for forbidden in [
            "\ufeff",
            "\ufffd",
            "??",
            "safe-to-share",
            "safe to share",
            "guaranteed safe",
            "confirmed vulnerability",
            "confirmed finding",
            "confirmed issue count",
            "final CVSS",
            "\"raw_request\"",
            "\"raw_response\"",
            "raw_request:",
            "raw_response:",
            "Cookie:",
            "Authorization:",
            "Bearer ",
            "JWT ",
            "session=",
            "token=",
            "HMAC secret:",
            "CSRF token:",
            "HMAC secret",
            "CSRF token",
            "C:\\coding\\",
            "C:\\Users\\",
            "local_only/",
            "real_export_",
            "actual.local",
            "approved for external sharing",
            "ready to submit",
        ]:
            self.assertNotIn(forbidden, combined)
        self.assertIsNone(re.search(r"https?://", combined))
        self.assertIsNone(re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", combined))

    def test_v08_final_gate_evidence_is_evidence_only_and_raw_free(self) -> None:
        final_gate = V08_FINAL_GATE_EVIDENCE_DOC.read_text(encoding="utf-8")
        fixture = json.loads(V08_FINAL_GATE_EVIDENCE_FIXTURE.read_text(encoding="utf-8"))
        fixture_text = json.dumps(fixture, sort_keys=True)
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        approval_packet = V08_RELEASE_APPROVAL_PACKET_DOC.read_text(encoding="utf-8")
        normalized = " ".join(final_gate.split())
        normalized_lower = normalized.lower()

        self.assertTrue(V08_FINAL_GATE_EVIDENCE_DOC.exists())
        self.assertTrue(V08_FINAL_GATE_EVIDENCE_FIXTURE.exists())
        self.assertIn("V0.8_FINAL_GATE_EVIDENCE.md", readme)
        self.assertIn("V0.8_FINAL_GATE_EVIDENCE.md", approval_packet)

        for section in [
            "## Purpose",
            "## Final Gate Target Commit",
            "## Approval Packet Target Drift Note",
            "## Baseline PRs",
            "## Release Type",
            "## Included Scope",
            "## Excluded Scope",
            "## Final Gate Results",
            "## Final Gate Commands",
            "## Release Body Hygiene Requirements",
            "## Rollback Requirements",
            "## Human Approval Boundary",
            "## Deferred Work",
        ]:
            self.assertIn(section, final_gate)

        for required_text in [
            "final gate evidence only",
            "does not create a tag",
            "does not create a GitHub Release",
            "boundary_helper",
            "not a read-only MCP runtime release",
            "c5ff5c396d7e84a25d94d9ef12aeb85a03ac6b06",
            "58c7190e5cde43ca2ae4bddf056360eda649622b",
            "fcc0dd947ec9c62410cc5715cce7ae623bc32aa8",
            "bb484ea21d90759125a7224fedaec6a9ee7b75fc",
            "main HEAD before PR #133 was merged",
            "Python compile check: passed",
            "Python unit test discovery: passed",
            "gitleaks directory scan: passed",
            "gitleaks git scan: passed",
            "git safety check: passed",
            "diff whitespace check: passed",
            "working tree check: clean",
            "v0.8 tag check: absent",
            "GitHub Release v0.8 check: absent",
            "listener startup",
            "socket, bind, listen, or accept behavior",
            "stdio runtime",
            "HTTP runtime",
            "protocol parser",
            "JSON-RPC parser",
            "request dispatcher",
            "executable tool registration",
            "tool registry runtime",
            "actual tool execution",
            "local evidence reader",
            "safe file body reader",
            "raw preview or download",
            "replay or active scan",
            "dashboard state-changing control",
            "upload or import action",
            "automatic ChatGPT handoff",
            "separate explicit human approval",
        ]:
            self.assertIn(required_text, normalized)

        self.assertEqual(fixture["schema_version"], "v08_final_gate_evidence.v1")
        self.assertIs(fixture["final_gate_evidence_only"], True)
        self.assertEqual(fixture["release_type"], "boundary_helper")
        self.assertEqual(
            fixture["final_gate_target_commit"], "c5ff5c396d7e84a25d94d9ef12aeb85a03ac6b06"
        )
        self.assertEqual(
            fixture["approval_packet_target_commit"],
            "58c7190e5cde43ca2ae4bddf056360eda649622b",
        )
        self.assertEqual(
            fixture["pr130_merge_commit"], "fcc0dd947ec9c62410cc5715cce7ae623bc32aa8"
        )
        self.assertEqual(
            fixture["pr131_merge_commit"], "bb484ea21d90759125a7224fedaec6a9ee7b75fc"
        )
        self.assertEqual(
            fixture["pr132_merge_commit"], "58c7190e5cde43ca2ae4bddf056360eda649622b"
        )
        self.assertEqual(
            fixture["pr133_merge_commit"], "c5ff5c396d7e84a25d94d9ef12aeb85a03ac6b06"
        )
        self.assertIs(fixture["tag_created"], False)
        self.assertIs(fixture["github_release_created"], False)
        self.assertIs(fixture["explicit_release_approval_required"], True)
        self.assertIs(fixture["read_only_mcp_runtime_release"], False)
        self.assertIs(fixture["manual_review_required"], True)
        self.assertIs(fixture["raw_data_included"], False)
        self.assertIs(fixture["output_bundle_structure_changed"], False)
        self.assertEqual(
            fixture["output_bundle_files"],
            ["analysis_packet.json", "chatgpt_prompt.md", "codex_task_prompt.md", "report_draft.md"],
        )

        for included in [
            "redaction_verify_review_report_pipeline",
            "four_ai_input_candidate_files",
            "dashboard_read_only_raw_free_baseline",
            "disabled_by_default_mcp_helper_files",
            "post_merge_boundary_note",
            "scope_freeze_rc_readiness_evidence",
            "release_approval_packet",
        ]:
            self.assertIn(included, fixture["included_scope"])

        for excluded in [
            "listener_startup",
            "socket_bind_listen_accept",
            "stdio_runtime",
            "http_runtime",
            "protocol_parser",
            "json_rpc_parser",
            "request_dispatcher",
            "executable_tool_registration",
            "tool_registry_runtime",
            "tool_discovery_runtime",
            "actual_tool_execution",
            "local_evidence_reader",
            "safe_file_body_reader",
            "raw_preview_download",
            "replay_active_scan",
            "dashboard_state_changing_control",
            "upload_import_action",
            "automatic_chatgpt_handoff",
        ]:
            self.assertIn(excluded, fixture["excluded_scope"])

        for gate in [
            "python_compileall",
            "python_unittest_discover",
            "gitleaks_dir",
            "gitleaks_git",
            "git_safety_check",
            "git_diff_check",
            "git_status_clean",
            "v08_tag_absence_check",
            "github_release_v08_absence_check",
        ]:
            self.assertIn(gate, fixture["final_gate_commands"])
            self.assertIn(gate, fixture["final_gate_results"])

        for hygiene in [
            "state_boundary_helper_release",
            "state_not_read_only_mcp_runtime_release",
            "no_raw_request_response_content",
            "no_actual_target_identifiers",
            "no_credential_values",
            "no_hmac_key_material",
            "no_csrf_credential_value",
            "no_full_local_paths",
            "no_safety_guarantee_claim",
            "no_verified_finding_claim",
            "no_fixed_scoring_claim",
            "candidate_findings_only",
            "draft_risk_only",
            "manual_review_required",
            "no_automatic_chatgpt_handoff_claim",
        ]:
            self.assertIn(hygiene, fixture["release_body_hygiene_requirements"])

        for rollback_requirement in [
            "before_tag_revert_final_gate_evidence_pr_and_recheck_main_head",
            "after_tag_or_release_requires_explicit_rollback_plan",
            "no_tag_movement_in_this_evidence",
            "no_github_release_mutation_in_this_evidence",
        ]:
            self.assertIn(rollback_requirement, fixture["rollback_requirements"])

        combined = final_gate + "\n" + fixture_text
        for forbidden in [
            "\ufeff",
            "\ufffd",
            "??",
            "safe-to-share",
            "safe to share",
            "guaranteed safe",
            "confirmed vulnerability",
            "confirmed finding",
            "confirmed issue count",
            "final CVSS",
            "\"raw_request\"",
            "\"raw_response\"",
            "raw_request:",
            "raw_response:",
            "Cookie:",
            "Authorization:",
            "Bearer ",
            "JWT ",
            "session=",
            "token=",
            "HMAC secret:",
            "CSRF token:",
            "HMAC secret",
            "CSRF token",
            "C:\\coding\\",
            "C:\\Users\\",
            "local_only/",
            "real_export_",
            "actual.local",
            "approved for external sharing",
            "ready to submit",
        ]:
            self.assertNotIn(forbidden, combined)
        self.assertIsNone(re.search(r"https?://", combined))
        self.assertIsNone(re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", combined))

    def test_v09_runtime_scope_decision_is_planning_only_and_raw_free(self) -> None:
        decision = V09_RUNTIME_SCOPE_DECISION_DOC.read_text(encoding="utf-8")
        fixture = json.loads(V09_RUNTIME_SCOPE_DECISION_FIXTURE.read_text(encoding="utf-8"))
        fixture_text = json.dumps(fixture, sort_keys=True)
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        normalized = " ".join(decision.split())

        self.assertTrue(V09_RUNTIME_SCOPE_DECISION_DOC.exists())
        self.assertTrue(V09_RUNTIME_SCOPE_DECISION_FIXTURE.exists())
        self.assertIn("V0.9_RUNTIME_SCOPE_DECISION.md", readme)

        for section in [
            "## Purpose",
            "## Current Baseline",
            "## Decision Scope",
            "## Explicit Non-goals",
            "## v0.9 Candidate Options",
            "## Recommended First Step",
            "## Security Risk Summary",
            "## Test Requirements",
            "## PR Split Rules",
            "## Forbidden Scope",
            "## Required Acceptance Criteria",
            "## Deferred Work",
        ]:
            self.assertIn(section, decision)

        for required_text in [
            "planning-only decision record",
            "v0.8 tag and GitHub Release are published",
            "946db3dca6d2fa9988f847648041e4a45fcd2f9d",
            "v0.8 remains a boundary/helper release",
            "It is not a read-only MCP runtime release",
            "Option A: Protocol Parser Approval Packet First",
            "Option B: Transport And Listener Approval Packet First",
            "Option C: Read-only Tool Registry Contract First",
            "Option D: Local Evidence Reader Deferred",
            "The recommended first v0.9 step is Option A",
            "listener and transport from protocol parser",
            "protocol parser from dispatcher",
            "dispatcher from tool execution",
            "read-only tool registry contract from actual tool execution",
            "local evidence reader from all runtime, parser, dispatcher, and registry work",
            "automatic ChatGPT handoff from every v0.9 runtime path",
        ]:
            self.assertIn(required_text, normalized)

        self.assertEqual(fixture["schema_version"], "v09_runtime_scope_decision.v1")
        self.assertIs(fixture["planning_only"], True)
        self.assertIs(fixture["implementation_pr"], False)
        self.assertIs(fixture["v08_release_completed"], True)
        self.assertEqual(fixture["v08_release_type"], "boundary_helper")
        self.assertEqual(
            fixture["v08_release_target_commit"],
            "946db3dca6d2fa9988f847648041e4a45fcd2f9d",
        )
        self.assertEqual(
            fixture["recommended_first_step"], "protocol_parser_approval_packet_first"
        )
        self.assertIs(fixture["metadata_only_decision"], True)
        self.assertIs(fixture["raw_data_included"], False)
        self.assertIs(fixture["manual_review_required"], True)
        self.assertIs(fixture["source_check_required_before_runtime"], True)
        self.assertIs(fixture["negative_tests_required_before_runtime"], True)
        self.assertIs(fixture["output_bundle_structure_changed"], False)
        self.assertEqual(
            fixture["output_bundle_files"],
            ["analysis_packet.json", "chatgpt_prompt.md", "codex_task_prompt.md", "report_draft.md"],
        )

        for false_flag in [
            "runtime_implemented",
            "listener_startup_implemented",
            "socket_bind_implemented",
            "socket_listen_implemented",
            "socket_accept_implemented",
            "transport_implemented",
            "protocol_parser_implemented",
            "json_rpc_parser_implemented",
            "dispatcher_implemented",
            "tool_registry_runtime_implemented",
            "tool_discovery_runtime_implemented",
            "executable_tool_registration_implemented",
            "actual_tool_execution_implemented",
            "local_evidence_reader_implemented",
            "safe_file_body_reader_implemented",
            "raw_preview_download_implemented",
            "dashboard_state_changing_action_implemented",
            "upload_import_action_implemented",
            "replay_active_scan_implemented",
            "automatic_chatgpt_handoff_implemented",
            "tag_github_release_modified",
        ]:
            self.assertIn(false_flag, fixture)
            self.assertIs(fixture[false_flag], False)

        self.assertEqual(
            {option["id"] for option in fixture["candidate_options"]},
            {"option_a", "option_b", "option_c", "option_d"},
        )
        recommended_options = {
            option["name"] for option in fixture["candidate_options"] if option["recommended"]
        }
        self.assertIn("protocol_parser_approval_packet_first", recommended_options)
        self.assertIn("local_evidence_reader_deferred", recommended_options)

        for split_rule in [
            "listener_transport_split_from_protocol_parser",
            "protocol_parser_split_from_dispatcher",
            "dispatcher_split_from_tool_execution",
            "tool_registry_contract_split_from_actual_tool_execution",
            "local_evidence_reader_deferred_until_threat_boundary",
            "raw_preview_download_requires_separate_approval",
            "automatic_chatgpt_handoff_requires_separate_approval",
        ]:
            self.assertIn(split_rule, fixture["required_split_rules"])

        for negative_test in [
            "planning_only_flag_check",
            "runtime_implementation_flag_false_check",
            "listener_startup_marker_check",
            "protocol_parser_marker_check",
            "dispatcher_marker_check",
            "tool_execution_marker_check",
            "local_evidence_reader_marker_check",
            "four_file_output_bundle_check",
            "raw_free_hygiene_check",
        ]:
            self.assertIn(negative_test, fixture["required_negative_tests"])

        combined = decision + "\n" + fixture_text
        for forbidden in [
            "\ufeff",
            "\ufffd",
            "??",
            "safe-to-share",
            "safe to share",
            "guaranteed safe",
            "confirmed vulnerability",
            "confirmed finding",
            "confirmed issue",
            "final CVSS",
            "\"raw_request\"",
            "\"raw_response\"",
            "raw_request:",
            "raw_response:",
            "Cookie:",
            "Authorization:",
            "Bearer ",
            "JWT ",
            "session=",
            "token=",
            "HMAC secret:",
            "CSRF token:",
            "C:\\coding\\",
            "C:\\Users\\",
            "local_only/",
            "real_export_",
            "actual.local",
            "approved for external sharing",
            "ready to submit",
        ]:
            self.assertNotIn(forbidden, combined)
        self.assertIsNone(re.search(r"https?://", combined))
        self.assertIsNone(re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", combined))

    def test_v09_protocol_parser_approval_packet_is_planning_only_and_raw_free(self) -> None:
        packet = V09_PROTOCOL_PARSER_APPROVAL_PACKET_DOC.read_text(encoding="utf-8")
        fixture = json.loads(
            V09_PROTOCOL_PARSER_APPROVAL_PACKET_FIXTURE.read_text(encoding="utf-8")
        )
        fixture_text = json.dumps(fixture, sort_keys=True)
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        scope_decision = V09_RUNTIME_SCOPE_DECISION_DOC.read_text(encoding="utf-8")
        normalized = " ".join(packet.split())

        self.assertTrue(V09_PROTOCOL_PARSER_APPROVAL_PACKET_DOC.exists())
        self.assertTrue(V09_PROTOCOL_PARSER_APPROVAL_PACKET_FIXTURE.exists())
        self.assertIn("V0.9_PROTOCOL_PARSER_APPROVAL_PACKET.md", readme)
        self.assertIn("V0.9_PROTOCOL_PARSER_APPROVAL_PACKET.md", scope_decision)

        for section in [
            "## Purpose",
            "## Current Baseline",
            "## Approval Scope",
            "## Explicit Non-goals",
            "## Malformed Input Classes",
            "## Blocked Response Requirements",
            "## Echo-forbidden Value Classes",
            "## Source-check Requirements",
            "## Required Negative Tests",
            "## PR Split Requirements",
            "## Security Review Checklist",
            "## Deferred Work",
        ]:
            self.assertIn(section, packet)

        for required_text in [
            "approval packet fixes the protocol parser boundary",
            "does not implement a protocol parser",
            "fc9a83b2e5e34d1d2ea098898b4af138a5c4b4dc",
            "protocol parser approval packet first",
            "This packet does not approve parser implementation",
            "Blocked parser responses may include only",
            "Every blocked response must set `parser_approved` to false",
            "Tests may use synthetic labels for these classes",
            "protocol parser implementation from dispatcher implementation",
            "local evidence reader from parser, dispatcher, registry, and runtime work",
        ]:
            self.assertIn(required_text, normalized)

        self.assertEqual(fixture["schema_version"], "v09_protocol_parser_approval_packet.v1")
        self.assertIs(fixture["approval_packet_only"], True)
        self.assertIs(fixture["raw_data_included"], False)
        self.assertIs(fixture["manual_review_required"], True)
        self.assertIs(fixture["output_bundle_structure_changed"], False)
        self.assertEqual(
            fixture["output_bundle_files"],
            ["analysis_packet.json", "chatgpt_prompt.md", "codex_task_prompt.md", "report_draft.md"],
        )

        for false_flag in [
            "protocol_parser_implemented",
            "json_rpc_parser_implemented",
            "dispatcher_implemented",
            "listener_startup_implemented",
            "transport_implemented",
            "executable_tool_registration_implemented",
            "actual_tool_execution_implemented",
            "local_evidence_reader_implemented",
            "safe_file_body_reader_implemented",
            "raw_preview_download_implemented",
            "replay_active_scan_implemented",
            "automatic_chatgpt_handoff_implemented",
            "tag_github_release_created",
        ]:
            self.assertIn(false_flag, fixture)
            self.assertIs(fixture[false_flag], False)

        for category in [
            "empty_message",
            "invalid_json_shape",
            "unsupported_protocol_version",
            "unknown_method",
            "missing_required_field",
            "oversized_message",
            "nested_payload_too_deep",
            "raw_value_probe",
            "credential_echo_probe",
            "local_path_echo_probe",
            "target_identifier_echo_probe",
        ]:
            self.assertIn(category, fixture["malformed_input_classes"])
            self.assertIn(f"`{category}`", packet)

        self.assertEqual(
            fixture["blocked_response_allowed_fields"],
            [
                "status",
                "reason_code",
                "parser_approved",
                "raw_data_included",
                "manual_review_required",
                "safe_message",
            ],
        )

        for value_class in [
            "raw_request_response",
            "credential_value",
            "token_value",
            "session_value",
            "target_identifier",
            "url_domain_ip",
            "full_local_path",
            "local_only_filename",
            "stack_trace",
            "local_evidence_body",
        ]:
            self.assertIn(value_class, fixture["echo_forbidden_value_classes"])

        for negative_test in [
            "malformed_input_blocked",
            "raw_value_not_echoed",
            "credential_value_not_echoed",
            "target_identifier_not_echoed",
            "local_path_not_echoed",
            "unknown_method_blocked",
            "oversized_message_blocked",
            "dispatcher_absent",
            "tool_execution_absent",
            "local_evidence_reader_absent",
        ]:
            self.assertIn(negative_test, fixture["required_negative_tests"])

        combined = packet + "\n" + fixture_text
        for forbidden in [
            "\ufeff",
            "\ufffd",
            "??",
            "safe-to-share",
            "safe to share",
            "guaranteed safe",
            "confirmed vulnerability",
            "confirmed finding",
            "confirmed issue",
            "final CVSS",
            "\"raw_request\"",
            "\"raw_response\"",
            "raw_request:",
            "raw_response:",
            "Cookie:",
            "Authorization:",
            "Bearer ",
            "JWT ",
            "session=",
            "token=",
            "HMAC secret:",
            "CSRF token:",
            "C:\\coding\\",
            "C:\\Users\\",
            "local_only/",
            "real_export_",
            "actual.local",
            "approved for external sharing",
            "ready to submit",
        ]:
            self.assertNotIn(forbidden, combined)
        self.assertIsNone(re.search(r"https?://", combined))
        self.assertIsNone(re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", combined))

    def test_v09_protocol_parser_negative_fixture_harness_is_raw_free(self) -> None:
        approval = json.loads(
            V09_PROTOCOL_PARSER_APPROVAL_PACKET_FIXTURE.read_text(encoding="utf-8")
        )
        negative = json.loads(
            V09_PROTOCOL_PARSER_NEGATIVE_CASES_FIXTURE.read_text(encoding="utf-8")
        )
        negative_text = json.dumps(negative, sort_keys=True)
        packet = V09_PROTOCOL_PARSER_APPROVAL_PACKET_DOC.read_text(encoding="utf-8")
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        scope_decision = V09_RUNTIME_SCOPE_DECISION_DOC.read_text(encoding="utf-8")
        combined = "\n".join([negative_text, packet, scope_decision])

        self.assertTrue(V09_PROTOCOL_PARSER_NEGATIVE_CASES_FIXTURE.exists())
        self.assertEqual(negative["schema_version"], "v09_protocol_parser_negative_cases.v1")
        self.assertIs(negative["parser_implemented"], False)
        self.assertIs(negative["json_rpc_parser_implemented"], False)
        self.assertIs(negative["dispatcher_implemented"], False)
        self.assertIs(negative["tool_execution_implemented"], False)
        self.assertIs(negative["local_evidence_reader_implemented"], False)
        self.assertIs(negative["raw_data_included"], False)
        self.assertIs(negative["manual_review_required"], True)
        self.assertIs(negative["approval_packet_consumed"], True)
        self.assertIs(negative["source_check_required"], True)
        self.assertIn("v09_protocol_parser_negative_cases.json", readme)
        self.assertIn("v09_protocol_parser_negative_cases.json", scope_decision)
        self.assertIn("v09_protocol_parser_negative_cases.json", packet)
        self.assertIn("does not implement a protocol parser", packet)
        self.assertIn("future parser implementation PR must consume this fixture", packet)

        required_categories = [
            "empty_message",
            "invalid_json_shape",
            "unsupported_protocol_version",
            "unknown_method",
            "missing_required_field",
            "oversized_message",
            "nested_payload_too_deep",
            "raw_value_probe",
            "credential_echo_probe",
            "local_path_echo_probe",
            "target_identifier_echo_probe",
        ]
        case_categories = [case["category"] for case in negative["cases"]]
        self.assertEqual(case_categories, required_categories)
        self.assertEqual(
            sorted(set(case_categories)),
            sorted(set(approval["malformed_input_classes"])),
        )
        self.assertEqual(len(case_categories), len(set(case_categories)))

        allowed_fields = approval["blocked_response_allowed_fields"]
        allowed_echo_classes = set(approval["echo_forbidden_value_classes"])
        for case in negative["cases"]:
            self.assertRegex(case["id"], r"^v09-parser-neg-\d{3}$")
            self.assertTrue(case["synthetic_input_label"].startswith("synthetic_"))
            self.assertEqual(case["expected_status"], "blocked")
            self.assertEqual(case["expected_reason_code"], case["category"])
            self.assertIs(case["parser_approved"], False)
            self.assertIs(case["raw_data_included"], False)
            self.assertIs(case["manual_review_required"], True)
            self.assertIs(case["echo_forbidden"], True)
            self.assertEqual(case["allowed_response_fields"], allowed_fields)
            self.assertGreater(len(case["forbidden_echo_classes"]), 0)
            self.assertTrue(set(case["forbidden_echo_classes"]).issubset(allowed_echo_classes))

        for forbidden in [
            "\ufeff",
            "\ufffd",
            "??",
            "safe-to-share",
            "safe to share",
            "guaranteed safe",
            "confirmed vulnerability",
            "confirmed finding",
            "confirmed issue",
            "final CVSS",
            "\"raw_request\"",
            "\"raw_response\"",
            "raw_request:",
            "raw_response:",
            "Cookie:",
            "Authorization:",
            "Bearer ",
            "JWT ",
            "session=",
            "token=",
            "HMAC secret:",
            "CSRF token:",
            "C:\\coding\\",
            "C:\\Users\\",
            "local_only/",
            "real_export_",
            "actual.local",
            "approved for external sharing",
            "ready to submit",
        ]:
            self.assertNotIn(forbidden, combined)
        self.assertIsNone(re.search(r"https?://", combined))
        self.assertIsNone(re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", combined))

    def test_v09_protocol_parser_implementation_decision_is_planning_only(self) -> None:
        decision = V09_PROTOCOL_PARSER_IMPLEMENTATION_DECISION_DOC.read_text(
            encoding="utf-8"
        )
        decision_fixture = json.loads(
            V09_PROTOCOL_PARSER_IMPLEMENTATION_DECISION_FIXTURE.read_text(
                encoding="utf-8"
            )
        )
        approval = json.loads(
            V09_PROTOCOL_PARSER_APPROVAL_PACKET_FIXTURE.read_text(encoding="utf-8")
        )
        negative = json.loads(
            V09_PROTOCOL_PARSER_NEGATIVE_CASES_FIXTURE.read_text(encoding="utf-8")
        )
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        packet = V09_PROTOCOL_PARSER_APPROVAL_PACKET_DOC.read_text(encoding="utf-8")
        fixture_text = json.dumps(decision_fixture, sort_keys=True)
        normalized = " ".join(decision.split())

        self.assertTrue(V09_PROTOCOL_PARSER_IMPLEMENTATION_DECISION_DOC.exists())
        self.assertTrue(V09_PROTOCOL_PARSER_IMPLEMENTATION_DECISION_FIXTURE.exists())
        self.assertIn("V0.9_PROTOCOL_PARSER_IMPLEMENTATION_DECISION.md", readme)
        self.assertIn("V0.9_PROTOCOL_PARSER_IMPLEMENTATION_DECISION.md", packet)

        for section in [
            "## Purpose",
            "## Current Baseline",
            "## Implementation Decision Status",
            "## Allowed Implementation Candidate",
            "## Forbidden Scope",
            "## Negative Fixture Consumption",
            "## Required Tests",
            "## Source-check Requirements",
            "## Rollback Expectation",
            "## Explicit Approval Requirement",
            "## Deferred Work",
        ]:
            self.assertIn(section, decision)

        for required_text in [
            "does not implement parser behavior",
            "pending explicit approval",
            "5a2dc00e78e88fcd855bcee7c781abf520108311",
            "minimal parser function",
            "consumes `tests/fixtures/v09_protocol_parser_negative_cases.json`",
            "emits only the allowlisted blocked response fields",
            "never echoes raw input",
            "never echoes credential, session, or token values",
            "never echoes target identifiers",
            "never echoes local paths",
            "dispatcher implementation",
            "actual tool execution",
            "local evidence reader",
            "listener startup",
            "transport runtime",
            "This decision record does not authorize implementation by itself",
        ]:
            self.assertIn(required_text, normalized)

        self.assertEqual(
            decision_fixture["schema_version"],
            "v09_protocol_parser_implementation_decision.v1",
        )
        self.assertIs(decision_fixture["implementation_decision_only"], True)
        self.assertIs(
            decision_fixture["explicit_implementation_approval_required"], True
        )
        self.assertEqual(
            decision_fixture["implementation_status"], "pending_explicit_approval"
        )
        self.assertEqual(
            decision_fixture["negative_fixture_path"],
            "tests/fixtures/v09_protocol_parser_negative_cases.json",
        )
        self.assertIs(decision_fixture["negative_fixture_required"], True)

        for false_flag in [
            "parser_implementation_started",
            "json_rpc_parser_implemented",
            "dispatcher_implemented",
            "tool_execution_implemented",
            "local_evidence_reader_implemented",
            "listener_transport_implemented",
            "raw_preview_download_implemented",
            "automatic_chatgpt_handoff_implemented",
            "tag_github_release_created",
        ]:
            self.assertIn(false_flag, decision_fixture)
            self.assertIs(decision_fixture[false_flag], False)

        negative_categories = [case["category"] for case in negative["cases"]]
        self.assertEqual(
            decision_fixture["required_negative_categories"], negative_categories
        )
        self.assertEqual(
            decision_fixture["required_negative_categories"],
            approval["malformed_input_classes"],
        )
        self.assertEqual(
            decision_fixture["allowed_response_fields"],
            approval["blocked_response_allowed_fields"],
        )
        self.assertEqual(
            decision_fixture["forbidden_echo_classes"],
            approval["echo_forbidden_value_classes"],
        )

        for expectation in [
            "all_negative_cases_blocked",
            "parser_approved_false",
            "raw_data_included_false",
            "manual_review_required_true",
            "allowed_response_fields_only",
            "forbidden_echo_classes_not_echoed",
            "dispatcher_absent",
            "tool_execution_absent",
            "local_evidence_reader_absent",
        ]:
            self.assertIn(expectation, decision_fixture["required_test_expectations"])

        for allowed_candidate in [
            "minimal_parser_function_only",
            "consume_negative_fixture",
            "return_blocked_response_for_malformed_input",
            "allowlisted_response_fields_only",
            "no_raw_input_echo",
            "no_credential_session_token_echo",
            "no_target_identifier_echo",
            "no_local_path_echo",
        ]:
            self.assertIn(
                allowed_candidate,
                decision_fixture["allowed_implementation_candidate"],
            )

        for forbidden_scope in [
            "dispatcher",
            "tool_registration",
            "tool_execution",
            "local_evidence_reader",
            "listener_startup",
            "transport",
            "raw_preview_download",
            "automatic_chatgpt_handoff",
        ]:
            self.assertIn(forbidden_scope, decision_fixture["forbidden_scope"])

        combined = decision + "\n" + fixture_text
        for forbidden in [
            "\ufeff",
            "\ufffd",
            "??",
            "safe-to-share",
            "safe to share",
            "guaranteed safe",
            "confirmed vulnerability",
            "confirmed finding",
            "confirmed issue",
            "final CVSS",
            "\"raw_request\"",
            "\"raw_response\"",
            "raw_request:",
            "raw_response:",
            "Cookie:",
            "Authorization:",
            "Bearer ",
            "JWT ",
            "session=",
            "token=",
            "HMAC secret:",
            "CSRF token:",
            "C:\\coding\\",
            "C:\\Users\\",
            "local_only/",
            "real_export_",
            "actual.local",
            "approved for external sharing",
            "ready to submit",
        ]:
            self.assertNotIn(forbidden, combined)
        self.assertIsNone(re.search(r"https?://", combined))
        self.assertIsNone(re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", combined))

    def test_v09_parser_positive_shape_decision_is_planning_only(self) -> None:
        decision = V09_PARSER_POSITIVE_SHAPE_DECISION_DOC.read_text(encoding="utf-8")
        fixture = json.loads(
            V09_PARSER_POSITIVE_SHAPE_DECISION_FIXTURE.read_text(encoding="utf-8")
        )
        fixture_text = json.dumps(fixture, sort_keys=True)
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        implementation_decision = (
            V09_PROTOCOL_PARSER_IMPLEMENTATION_DECISION_DOC.read_text(
                encoding="utf-8"
            )
        )
        normalized = " ".join(decision.split())

        self.assertTrue(V09_PARSER_POSITIVE_SHAPE_DECISION_DOC.exists())
        self.assertTrue(V09_PARSER_POSITIVE_SHAPE_DECISION_FIXTURE.exists())
        self.assertIn("V0.9_PARSER_POSITIVE_SHAPE_DECISION.md", readme)
        self.assertIn(
            "V0.9_PARSER_POSITIVE_SHAPE_DECISION.md",
            implementation_decision,
        )

        for section in [
            "## Purpose",
            "## Current Baseline",
            "## Decision Status",
            "## Allowed Future Positive Shape Candidate",
            "## Allowed Positive Response Fields",
            "## Forbidden Positive Response Fields",
            "## Required Tests",
            "## Forbidden Scope",
            "## Source-check Requirements",
            "## Rollback Requirements",
            "## Deferred Work",
        ]:
            self.assertIn(section, decision)

        for required_text in [
            "planning only",
            "separate explicit approval",
            "bc4b950cf20aee24f968e9ff28f037cf1072b741",
            "minimal blocked-only parser: merged",
            "positive parser shape: not implemented",
            "read-only structured parse metadata only",
            "without invoking a dispatcher",
            "avoid tool lookup and executable tool registration",
            "avoid actual tool execution",
            "avoid local evidence reader and safe file body reader behavior",
            "avoid raw input echo",
            "avoid credential, session, or token echo",
            "normalized_method_label",
            "must be an allowlisted synthetic label",
            "This decision does not approve",
            "positive parser implementation",
            "dashboard state-changing control",
            "v0.9 tag creation",
            "GitHub Release v0.9 creation",
        ]:
            self.assertIn(required_text, normalized)

        self.assertEqual(
            fixture["schema_version"],
            "v09_parser_positive_shape_decision.v1",
        )
        self.assertIs(fixture["positive_shape_decision_only"], True)
        self.assertIs(
            fixture["explicit_positive_shape_implementation_approval_required"],
            True,
        )
        self.assertEqual(
            fixture["blocked_parser_baseline_commit"],
            "bc4b950cf20aee24f968e9ff28f037cf1072b741",
        )

        for false_flag in [
            "positive_shape_implemented",
            "dispatcher_implemented",
            "tool_execution_implemented",
            "listener_transport_implemented",
            "local_evidence_reader_implemented",
            "raw_preview_download_implemented",
            "automatic_chatgpt_handoff_implemented",
        ]:
            self.assertIn(false_flag, fixture)
            self.assertIs(fixture[false_flag], False)

        allowed_fields = [
            "status",
            "reason_code",
            "parser_approved",
            "raw_data_included",
            "manual_review_required",
            "safe_message",
            "message_kind",
            "protocol_version_supported",
            "normalized_method_label",
        ]
        self.assertEqual(fixture["allowed_positive_response_fields"], allowed_fields)
        for allowed_field in allowed_fields:
            self.assertIn(f"`{allowed_field}`", decision)

        for forbidden_field in [
            "raw_input",
            "raw_request",
            "raw_response",
            "target",
            "url",
            "domain",
            "ip",
            "credential",
            "token",
            "session",
            "local_path",
            "file_body",
            "stack_trace",
        ]:
            self.assertIn(forbidden_field, fixture["forbidden_positive_response_fields"])
            self.assertIn(f"`{forbidden_field}`", decision)

        for expectation in [
            "positive_shape_allowed_fields_only",
            "positive_shape_no_raw_input_echo",
            "positive_shape_no_credential_session_token_echo",
            "positive_shape_no_target_identifier_echo",
            "positive_shape_no_url_domain_ip_echo",
            "positive_shape_no_local_path_echo",
            "no_dispatcher_side_effect",
            "no_tool_lookup_registration_or_execution",
            "no_local_evidence_reader_or_file_body_reader",
            "blocked_negative_cases_remain_unchanged",
            "raw_data_included_false",
            "manual_review_required_true",
        ]:
            self.assertIn(expectation, fixture["required_test_expectations"])

        for deferred in [
            "positive_shape_fixture_harness",
            "minimal_positive_parser_implementation",
            "dispatcher_approval_packet",
            "read_only_tool_registry_contract_review",
            "actual_tool_execution_threat_boundary",
            "local_evidence_reader_threat_boundary",
        ]:
            self.assertIn(deferred, fixture["deferred_work"])

        combined = "\n".join([decision, fixture_text, implementation_decision])
        for forbidden in [
            "\ufeff",
            "\ufffd",
            "??",
            "safe-to-share",
            "safe to share",
            "guaranteed safe",
            "confirmed vulnerability",
            "confirmed finding",
            "confirmed issue",
            "final CVSS",
            "raw_request:",
            "raw_response:",
            "Cookie:",
            "Authorization:",
            "Bearer ",
            "JWT ",
            "session=",
            "token=",
            "HMAC secret:",
            "CSRF token:",
            "C:\\coding\\",
            "C:\\Users\\",
            "local_only/",
            "real_export_",
            "actual.local",
            "approved for external sharing",
            "ready to submit",
        ]:
            self.assertNotIn(forbidden, combined)
        self.assertIsNone(re.search(r"https?://", combined))
        self.assertIsNone(re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", combined))

    def test_v09_parser_positive_shape_fixture_harness_is_raw_free(self) -> None:
        decision_doc = V09_PARSER_POSITIVE_SHAPE_DECISION_DOC.read_text(
            encoding="utf-8"
        )
        implementation_decision = (
            V09_PROTOCOL_PARSER_IMPLEMENTATION_DECISION_DOC.read_text(
                encoding="utf-8"
            )
        )
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        decision = json.loads(
            V09_PARSER_POSITIVE_SHAPE_DECISION_FIXTURE.read_text(encoding="utf-8")
        )
        positive = json.loads(
            V09_PARSER_POSITIVE_SHAPE_CASES_FIXTURE.read_text(encoding="utf-8")
        )
        positive_text = json.dumps(positive, sort_keys=True)
        combined = "\n".join([decision_doc, implementation_decision, positive_text])
        normalized_decision_doc = " ".join(decision_doc.split())
        normalized_implementation_decision = " ".join(
            implementation_decision.split()
        )

        self.assertTrue(V09_PARSER_POSITIVE_SHAPE_CASES_FIXTURE.exists())
        self.assertEqual(
            positive["schema_version"],
            "v09_parser_positive_shape_cases.v1",
        )
        self.assertIs(positive["positive_shape_fixture_harness_only"], True)
        self.assertIs(positive["positive_shape_decision_consumed"], True)
        self.assertIn("v09_parser_positive_shape_cases.json", readme)
        self.assertIn("v09_parser_positive_shape_cases.json", decision_doc)
        self.assertIn(
            "v09_parser_positive_shape_cases.json",
            implementation_decision,
        )
        self.assertIn(
            "not a positive parser implementation",
            normalized_decision_doc,
        )
        self.assertIn(
            "future positive parser implementation PR must consume this fixture",
            normalized_decision_doc,
        )
        self.assertIn(
            "not a parser implementation",
            normalized_implementation_decision,
        )

        for false_flag in [
            "positive_parser_implemented",
            "dispatcher_implemented",
            "tool_execution_implemented",
            "listener_transport_implemented",
            "local_evidence_reader_implemented",
            "raw_preview_download_implemented",
            "automatic_chatgpt_handoff_implemented",
        ]:
            self.assertIn(false_flag, positive)
            self.assertIs(positive[false_flag], False)

        allowed_fields = decision["allowed_positive_response_fields"]
        forbidden_fields = decision["forbidden_positive_response_fields"]
        self.assertEqual(positive["allowed_response_fields"], allowed_fields)
        self.assertEqual(positive["forbidden_response_fields"], forbidden_fields)

        required_categories = [
            "supported_protocol_version_metadata",
            "known_read_only_method_label",
            "unknown_but_blocked_method_label",
            "metadata_only_notification_label",
            "safe_empty_params_label",
        ]
        case_categories = [case["category"] for case in positive["cases"]]
        self.assertEqual(case_categories, required_categories)
        self.assertEqual(len(case_categories), len(set(case_categories)))

        for case in positive["cases"]:
            self.assertRegex(case["id"], r"^v09-parser-pos-\d{3}$")
            self.assertTrue(case["synthetic_input_label"].startswith("synthetic_"))
            self.assertIn(case["category"], case["synthetic_input_label"])
            self.assertIn(case["expected_status"], ["parsed", "blocked"])
            self.assertIs(case["raw_data_included"], False)
            self.assertIs(case["manual_review_required"], True)
            self.assertIs(case["dispatcher_invoked"], False)
            self.assertIs(case["tool_execution_invoked"], False)
            self.assertIs(case["local_evidence_reader_invoked"], False)
            self.assertIs(case["echo_forbidden"], True)
            self.assertEqual(case["allowed_response_fields"], allowed_fields)
            self.assertEqual(case["forbidden_response_fields"], forbidden_fields)

        blocked_case = positive["cases"][2]
        self.assertEqual(blocked_case["category"], "unknown_but_blocked_method_label")
        self.assertEqual(blocked_case["expected_status"], "blocked")
        self.assertIs(blocked_case["parser_approved"], False)
        for parsed_case in [
            positive["cases"][0],
            positive["cases"][1],
            positive["cases"][3],
            positive["cases"][4],
        ]:
            self.assertEqual(parsed_case["expected_status"], "parsed")
            self.assertIs(parsed_case["parser_approved"], True)

        for forbidden in [
            "\ufeff",
            "\ufffd",
            "??",
            "safe-to-share",
            "safe to share",
            "guaranteed safe",
            "confirmed vulnerability",
            "confirmed finding",
            "confirmed issue",
            "final CVSS",
            "raw_request:",
            "raw_response:",
            "Cookie:",
            "Authorization:",
            "Bearer ",
            "JWT ",
            "session=",
            "token=",
            "HMAC secret:",
            "CSRF token:",
            "C:\\coding\\",
            "C:\\Users\\",
            "local_only/",
            "real_export_",
            "actual.local",
            "approved for external sharing",
            "ready to submit",
        ]:
            self.assertNotIn(forbidden, combined)
        self.assertIsNone(re.search(r"https?://", combined))
        self.assertIsNone(re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", combined))

    def test_v09_minimal_positive_parser_consumes_shape_fixture(self) -> None:
        decision = json.loads(
            V09_PARSER_POSITIVE_SHAPE_DECISION_FIXTURE.read_text(encoding="utf-8")
        )
        positive = json.loads(
            V09_PARSER_POSITIVE_SHAPE_CASES_FIXTURE.read_text(encoding="utf-8")
        )
        negative = json.loads(
            V09_PROTOCOL_PARSER_NEGATIVE_CASES_FIXTURE.read_text(encoding="utf-8")
        )
        metadata = build_minimal_protocol_parser_metadata()
        allowed_fields = decision["allowed_positive_response_fields"]
        forbidden_fields = set(decision["forbidden_positive_response_fields"])
        case_categories = [case["category"] for case in positive["cases"]]

        self.assertIs(metadata["parser_only_implementation"], True)
        self.assertIs(metadata["positive_fixture_consumed"], True)
        self.assertEqual(
            list(PROTOCOL_PARSER_POSITIVE_RESPONSE_ALLOWED_FIELDS),
            allowed_fields,
        )
        self.assertEqual(list(PROTOCOL_PARSER_POSITIVE_REASON_CODES), case_categories)
        self.assertEqual(metadata["positive_response_allowed_fields"], allowed_fields)
        self.assertEqual(metadata["supported_positive_categories"], case_categories)

        for false_flag in [
            "json_rpc_parser_implemented",
            "dispatcher_implemented",
            "listener_startup_implemented",
            "transport_implemented",
            "executable_tool_registration_implemented",
            "actual_tool_execution_implemented",
            "local_evidence_reader_implemented",
            "safe_file_body_reader_implemented",
            "automatic_chatgpt_handoff_implemented",
            "tag_github_release_created",
        ]:
            self.assertIn(false_flag, metadata)
            self.assertIs(metadata[false_flag], False)

        summary = validate_positive_case_fixture(positive, decision)
        self.assertEqual(
            summary,
            {
                "ok": True,
                "case_count": 5,
                "parsed_count": 4,
                "blocked_count": 1,
                "raw_data_included": False,
                "manual_review_required": True,
                "allowed_response_fields": allowed_fields,
                "forbidden_response_fields_returned": False,
                "dispatcher_invoked": False,
                "tool_execution_invoked": False,
                "local_evidence_reader_invoked": False,
            },
        )

        for case in positive["cases"]:
            response = parse_minimal_positive_protocol_message(
                case["synthetic_input_label"],
                positive_case=case,
            )
            self.assertEqual(list(response), allowed_fields)
            self.assertEqual(response["status"], case["expected_status"])
            self.assertEqual(response["reason_code"], case["expected_reason_code"])
            self.assertIs(response["parser_approved"], case["parser_approved"])
            self.assertIs(response["raw_data_included"], False)
            self.assertIs(response["manual_review_required"], True)
            self.assertIsInstance(response["safe_message"], str)
            self.assertNotEqual(response["safe_message"], "")
            self.assertNotIn(case["synthetic_input_label"], str(response))
            self.assertTrue(forbidden_fields.isdisjoint(response))
            self.assertNotIn("raw", response["safe_message"].lower())
            self.assertNotIn("credential", response["safe_message"].lower())
            self.assertNotIn("token", response["safe_message"].lower())
            self.assertNotIn("session", response["safe_message"].lower())

        parsed_response = build_positive_parser_response("known_read_only_method_label")
        self.assertEqual(list(parsed_response), allowed_fields)
        self.assertEqual(parsed_response["status"], "parsed")
        self.assertEqual(
            parsed_response["normalized_method_label"],
            "known_read_only_method_label",
        )
        blocked_response = build_positive_parser_response("unsafe user supplied reason")
        self.assertEqual(list(blocked_response), allowed_fields)
        self.assertEqual(blocked_response["status"], "blocked")
        self.assertEqual(blocked_response["reason_code"], "unknown_method")
        self.assertNotIn("unsafe user supplied reason", str(blocked_response))

        untrusted_response = parse_minimal_positive_protocol_message(
            {"synthetic": "known_read_only_method_label"}
        )
        self.assertEqual(
            list(untrusted_response),
            list(PROTOCOL_PARSER_BLOCKED_RESPONSE_ALLOWED_FIELDS),
        )
        self.assertEqual(untrusted_response["status"], "blocked")
        self.assertEqual(untrusted_response["reason_code"], "unknown_method")
        self.assertNotIn("known_read_only_method_label", str(untrusted_response))

        negative_summary = validate_negative_case_fixture(negative)
        self.assertIs(negative_summary["all_blocked"], True)
        self.assertIs(negative_summary["raw_data_included"], False)

    def test_v09_read_only_tool_registry_contract_is_contract_only(self) -> None:
        doc = V09_READ_ONLY_TOOL_REGISTRY_CONTRACT_DOC.read_text(encoding="utf-8")
        fixture = json.loads(
            V09_READ_ONLY_TOOL_REGISTRY_CONTRACT_FIXTURE.read_text(encoding="utf-8")
        )
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        positive_doc = V09_PARSER_POSITIVE_SHAPE_DECISION_DOC.read_text(
            encoding="utf-8"
        )
        implementation_decision = (
            V09_PROTOCOL_PARSER_IMPLEMENTATION_DECISION_DOC.read_text(
                encoding="utf-8"
            )
        )
        positive_cases = json.loads(
            V09_PARSER_POSITIVE_SHAPE_CASES_FIXTURE.read_text(encoding="utf-8")
        )
        positive_decision = json.loads(
            V09_PARSER_POSITIVE_SHAPE_DECISION_FIXTURE.read_text(encoding="utf-8")
        )
        negative_cases = json.loads(
            V09_PROTOCOL_PARSER_NEGATIVE_CASES_FIXTURE.read_text(encoding="utf-8")
        )
        fixture_text = json.dumps(fixture, sort_keys=True)
        combined = "\n".join([doc, fixture_text, positive_doc, implementation_decision])
        normalized_doc = " ".join(doc.split())

        self.assertTrue(V09_READ_ONLY_TOOL_REGISTRY_CONTRACT_DOC.exists())
        self.assertTrue(V09_READ_ONLY_TOOL_REGISTRY_CONTRACT_FIXTURE.exists())
        for linked_text in [readme, positive_doc, implementation_decision]:
            self.assertIn("V0.9_READ_ONLY_TOOL_REGISTRY_CONTRACT.md", linked_text)
            self.assertIn("v09_read_only_tool_registry_contract.json", linked_text)

        for section in [
            "## Purpose",
            "## Current Baseline",
            "## Contract Scope",
            "## Explicit Non-goals",
            "## Allowed Registry Metadata Fields",
            "## Forbidden Registry Fields",
            "## Parser Behavior Guard",
            "## Required Test Expectations",
            "## PR Split Requirements",
            "## Rollback Requirements",
            "## Deferred Work",
        ]:
            self.assertIn(section, doc)

        for required_text in [
            "contract-only planning record",
            "does not implement a dispatcher",
            "does not turn parser output into an executable tool call",
            "separate explicit approval",
            "parser positive and negative behavior remain unchanged",
            "dispatcher implementation",
            "executable tool registration",
            "actual tool execution",
            "local evidence reader",
            "v0.9 tag creation",
            "GitHub Release v0.9 creation",
        ]:
            self.assertIn(required_text, normalized_doc)

        self.assertEqual(
            fixture["schema_version"],
            "v09_read_only_tool_registry_contract.v1",
        )
        self.assertIs(fixture["registry_contract_only"], True)
        for false_flag in [
            "registry_implemented",
            "executable_tool_registration_implemented",
            "actual_tool_execution_implemented",
            "dispatcher_implemented",
            "listener_transport_implemented",
            "local_evidence_reader_implemented",
            "safe_file_body_reader_implemented",
            "raw_preview_download_implemented",
            "replay_active_scan_implemented",
            "dashboard_state_changing_control_implemented",
            "upload_import_action_implemented",
            "automatic_chatgpt_handoff_implemented",
            "tag_github_release_created",
            "raw_data_included",
        ]:
            self.assertIn(false_flag, fixture)
            self.assertIs(fixture[false_flag], False)

        self.assertIs(fixture["parser_positive_behavior_unchanged_required"], True)
        self.assertIs(fixture["parser_negative_behavior_unchanged_required"], True)
        self.assertIs(fixture["manual_review_required"], True)

        allowed_fields = [
            "registry_schema_version",
            "registry_contract_only",
            "read_only_capability_labels",
            "tool_execution_allowed",
            "dispatcher_invocation_allowed",
            "local_evidence_access_allowed",
            "raw_data_included",
            "manual_review_required",
        ]
        self.assertEqual(fixture["allowed_registry_metadata_fields"], allowed_fields)
        for allowed_field in allowed_fields:
            self.assertIn(f"`{allowed_field}`", doc)

        for forbidden_field in [
            "raw_input",
            "raw_request",
            "raw_response",
            "target",
            "url",
            "domain",
            "ip",
            "credential",
            "token",
            "session",
            "local_path",
            "file_body",
            "command",
            "executable",
            "handler",
            "callback",
            "stack_trace",
        ]:
            self.assertIn(forbidden_field, fixture["forbidden_registry_fields"])
            self.assertIn(f"`{forbidden_field}`", doc)

        self.assertTrue(
            set(fixture["allowed_registry_metadata_fields"]).isdisjoint(
                fixture["forbidden_registry_fields"]
            )
        )
        for capability_label in fixture["read_only_capability_labels"]:
            self.assertTrue(capability_label.endswith("_metadata"))

        for expectation in [
            "registry_contract_document_exists",
            "registry_contract_fixture_exists",
            "registry_contract_only_true",
            "registry_implemented_false",
            "executable_tool_registration_false",
            "actual_tool_execution_false",
            "dispatcher_implemented_false",
            "listener_transport_implemented_false",
            "local_evidence_reader_implemented_false",
            "allowed_registry_metadata_fields_only",
            "parser_positive_behavior_unchanged_required",
            "parser_negative_behavior_unchanged_required",
            "no_dashboard_state_change",
            "no_upload_import_action",
            "no_tag_or_release_creation",
        ]:
            self.assertIn(expectation, fixture["required_test_expectations"])

        for deferred in [
            "dispatcher_approval_packet",
            "dispatcher_implementation",
            "executable_tool_registration_decision",
            "actual_tool_execution_threat_boundary",
            "local_evidence_reader_threat_boundary",
            "safe_file_body_reader_threat_boundary",
            "raw_preview_download_approval_packet",
            "automatic_chatgpt_handoff_decision",
        ]:
            self.assertIn(deferred, fixture["deferred_work"])

        positive_summary = validate_positive_case_fixture(
            positive_cases,
            positive_decision,
        )
        negative_summary = validate_negative_case_fixture(negative_cases)
        self.assertEqual(positive_summary["parsed_count"], 4)
        self.assertEqual(positive_summary["blocked_count"], 1)
        self.assertIs(positive_summary["raw_data_included"], False)
        self.assertIs(negative_summary["all_blocked"], True)
        self.assertIs(negative_summary["raw_data_included"], False)

        for forbidden in [
            "\ufeff",
            "\ufffd",
            "??",
            "safe-to-share",
            "safe to share",
            "guaranteed safe",
            "confirmed vulnerability",
            "confirmed finding",
            "confirmed issue",
            "final CVSS",
            "raw_request:",
            "raw_response:",
            "Cookie:",
            "Authorization:",
            "Bearer ",
            "JWT ",
            "session=",
            "token=",
            "HMAC secret:",
            "CSRF token:",
            "C:\\coding\\",
            "C:\\Users\\",
            "local_only/",
            "real_export_",
            "actual.local",
            "approved for external sharing",
            "ready to submit",
        ]:
            self.assertNotIn(forbidden, combined)
        self.assertIsNone(re.search(r"https?://", combined))
        self.assertIsNone(re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", combined))

    def test_v09_read_only_registry_implementation_guard_consumes_contract(self) -> None:
        guard = json.loads(
            V09_READ_ONLY_TOOL_REGISTRY_IMPLEMENTATION_GUARD_FIXTURE.read_text(
                encoding="utf-8"
            )
        )
        contract = json.loads(
            V09_READ_ONLY_TOOL_REGISTRY_CONTRACT_FIXTURE.read_text(encoding="utf-8")
        )
        doc = V09_READ_ONLY_TOOL_REGISTRY_CONTRACT_DOC.read_text(encoding="utf-8")
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        positive_cases = json.loads(
            V09_PARSER_POSITIVE_SHAPE_CASES_FIXTURE.read_text(encoding="utf-8")
        )
        positive_decision = json.loads(
            V09_PARSER_POSITIVE_SHAPE_DECISION_FIXTURE.read_text(encoding="utf-8")
        )
        negative_cases = json.loads(
            V09_PROTOCOL_PARSER_NEGATIVE_CASES_FIXTURE.read_text(encoding="utf-8")
        )
        guard_text = json.dumps(guard, sort_keys=True)
        combined = "\n".join([guard_text, doc])

        self.assertTrue(
            V09_READ_ONLY_TOOL_REGISTRY_IMPLEMENTATION_GUARD_FIXTURE.exists()
        )
        self.assertIn(
            "v09_read_only_tool_registry_implementation_guard.json",
            readme,
        )
        self.assertIn(
            "v09_read_only_tool_registry_implementation_guard.json",
            doc,
        )
        self.assertEqual(
            guard["schema_version"],
            "v09_read_only_tool_registry_implementation_guard.v1",
        )
        self.assertIs(guard["registry_implementation_guard_only"], True)
        self.assertIs(guard["registry_contract_consumed_required"], True)
        self.assertEqual(
            guard["contract_fixture_path"],
            "tests/fixtures/v09_read_only_tool_registry_contract.json",
        )
        self.assertTrue((ROOT / guard["contract_fixture_path"]).exists())
        self.assertEqual(
            guard["required_contract_fields"],
            contract["allowed_registry_metadata_fields"],
        )

        false_flags = [
            "registry_implemented",
            "executable_tool_registration_implemented",
            "actual_tool_execution_implemented",
            "dispatcher_implemented",
            "listener_transport_implemented",
            "local_evidence_reader_implemented",
            "safe_file_body_reader_implemented",
            "raw_preview_download_implemented",
            "replay_active_scan_implemented",
            "dashboard_state_changing_control_implemented",
            "upload_import_action_implemented",
            "automatic_chatgpt_handoff_implemented",
            "tag_github_release_created",
            "raw_data_included",
        ]
        for false_flag in false_flags:
            self.assertIn(false_flag, guard)
            self.assertIs(guard[false_flag], False)

        self.assertIs(guard["parser_positive_behavior_unchanged_required"], True)
        self.assertIs(guard["parser_negative_behavior_unchanged_required"], True)
        self.assertIs(guard["manual_review_required"], True)

        false_only_flags = [
            "tool_execution_allowed",
            "dispatcher_invocation_allowed",
            "local_evidence_access_allowed",
        ]
        self.assertEqual(guard["false_only_flags"], false_only_flags)
        self.assertEqual(
            set(guard["false_only_flags"]),
            set(guard["false_only_flag_values"]),
        )
        for false_only_flag in false_only_flags:
            self.assertIn(false_only_flag, contract["allowed_registry_metadata_fields"])
            self.assertIs(guard["false_only_flag_values"][false_only_flag], False)

        for surface in [
            "executable_registry",
            "dispatcher",
            "listener_transport",
            "executable_tool_registration",
            "actual_tool_execution",
            "local_evidence_reader",
            "safe_file_body_reader",
            "raw_preview_download",
            "replay_active_scan",
            "dashboard_state_changing_control",
            "upload_import_action",
            "automatic_chatgpt_handoff",
        ]:
            self.assertIn(surface, guard["forbidden_runtime_surfaces"])

        for expectation in [
            "implementation_guard_fixture_exists",
            "contract_fixture_path_resolves",
            "required_contract_fields_match_allowed_registry_metadata_fields",
            "false_only_flags_are_allowed_contract_fields",
            "runtime_surface_flags_remain_false",
            "parser_positive_behavior_unchanged_required",
            "parser_negative_behavior_unchanged_required",
            "source_check_files_have_no_forbidden_markers",
            "no_tag_or_release_creation",
        ]:
            self.assertIn(expectation, guard["required_test_expectations"])

        for source_check_file in guard["source_check_files"]:
            source_path = ROOT / source_check_file
            self.assertTrue(source_path.exists())
            source = source_path.read_text(encoding="utf-8")
            for marker in guard["forbidden_source_markers"]:
                self.assertNotIn(marker, source)

        positive_summary = validate_positive_case_fixture(
            positive_cases,
            positive_decision,
        )
        negative_summary = validate_negative_case_fixture(negative_cases)
        self.assertEqual(positive_summary["parsed_count"], 4)
        self.assertEqual(positive_summary["blocked_count"], 1)
        self.assertIs(positive_summary["raw_data_included"], False)
        self.assertIs(negative_summary["all_blocked"], True)
        self.assertIs(negative_summary["raw_data_included"], False)

        for forbidden in [
            "\ufeff",
            "\ufffd",
            "??",
            "safe-to-share",
            "safe to share",
            "guaranteed safe",
            "confirmed vulnerability",
            "confirmed finding",
            "confirmed issue",
            "final CVSS",
            "raw_request:",
            "raw_response:",
            "Cookie:",
            "Authorization:",
            "Bearer ",
            "JWT ",
            "session=",
            "token=",
            "HMAC secret:",
            "CSRF token:",
            "C:\\coding\\",
            "C:\\Users\\",
            "local_only/",
            "real_export_",
            "actual.local",
            "approved for external sharing",
            "ready to submit",
        ]:
            self.assertNotIn(forbidden, combined)
        self.assertIsNone(re.search(r"https?://", combined))
        self.assertIsNone(re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", combined))

    def test_v09_read_only_registry_metadata_implementation_consumes_contract_and_guard(self) -> None:
        contract = json.loads(
            V09_READ_ONLY_TOOL_REGISTRY_CONTRACT_FIXTURE.read_text(encoding="utf-8")
        )
        guard = json.loads(
            V09_READ_ONLY_TOOL_REGISTRY_IMPLEMENTATION_GUARD_FIXTURE.read_text(
                encoding="utf-8"
            )
        )
        positive_cases = json.loads(
            V09_PARSER_POSITIVE_SHAPE_CASES_FIXTURE.read_text(encoding="utf-8")
        )
        positive_decision = json.loads(
            V09_PARSER_POSITIVE_SHAPE_DECISION_FIXTURE.read_text(encoding="utf-8")
        )
        negative_cases = json.loads(
            V09_PROTOCOL_PARSER_NEGATIVE_CASES_FIXTURE.read_text(encoding="utf-8")
        )

        metadata = build_read_only_registry_metadata(contract, guard)

        self.assertEqual(
            tuple(metadata),
            tuple(contract["allowed_registry_metadata_fields"]),
        )
        self.assertEqual(
            tuple(metadata),
            tuple(guard["required_contract_fields"]),
        )
        self.assertEqual(
            metadata,
            {
                "registry_schema_version": "v09_read_only_tool_registry_contract.v1",
                "registry_contract_only": True,
                "read_only_capability_labels": contract["read_only_capability_labels"],
                "tool_execution_allowed": False,
                "dispatcher_invocation_allowed": False,
                "local_evidence_access_allowed": False,
                "raw_data_included": False,
                "manual_review_required": True,
            },
        )
        self.assertTrue(
            set(metadata).isdisjoint(contract["forbidden_registry_fields"])
        )
        for false_only_flag in guard["false_only_flags"]:
            self.assertIs(metadata[false_only_flag], False)

        positive_summary = validate_positive_case_fixture(
            positive_cases,
            positive_decision,
        )
        negative_summary = validate_negative_case_fixture(negative_cases)
        self.assertEqual(positive_summary["parsed_count"], 4)
        self.assertEqual(positive_summary["blocked_count"], 1)
        self.assertIs(positive_summary["raw_data_included"], False)
        self.assertIs(negative_summary["all_blocked"], True)
        self.assertIs(negative_summary["raw_data_included"], False)

        serialized_metadata = json.dumps(metadata, sort_keys=True)
        for forbidden in [
            "\ufeff",
            "\ufffd",
            "??",
            "safe-to-share",
            "safe to share",
            "guaranteed safe",
            "confirmed vulnerability",
            "confirmed finding",
            "confirmed issue",
            "final CVSS",
            "raw_request:",
            "raw_response:",
            "Cookie:",
            "Authorization:",
            "Bearer ",
            "JWT ",
            "session=",
            "token=",
            "HMAC secret:",
            "CSRF token:",
            "C:\\coding\\",
            "C:\\Users\\",
            "local_only/",
            "real_export_",
            "actual.local",
            "approved for external sharing",
            "ready to submit",
        ]:
            self.assertNotIn(forbidden, serialized_metadata)
        self.assertIsNone(re.search(r"https?://", serialized_metadata))
        self.assertIsNone(re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", serialized_metadata))

        changed_guard = deepcopy(guard)
        changed_guard["false_only_flag_values"]["tool_execution_allowed"] = True
        with self.assertRaisesRegex(McpReadOnlyRegistryError, "false_only_value"):
            build_read_only_registry_metadata(contract, changed_guard)

        changed_contract = deepcopy(contract)
        changed_contract["allowed_registry_metadata_fields"].append("unexpected_field")
        with self.assertRaisesRegex(
            McpReadOnlyRegistryError,
            "allowed_registry_metadata_fields",
        ):
            build_read_only_registry_metadata(changed_contract, guard)

        changed_contract = deepcopy(contract)
        changed_contract["forbidden_registry_fields"].append("manual_review_required")
        with self.assertRaisesRegex(
            McpReadOnlyRegistryError,
            "allowed_forbidden_overlap",
        ):
            build_read_only_registry_metadata(changed_contract, guard)

    def test_v09_read_only_registry_dispatcher_boundary_decision_hygiene(self) -> None:
        doc = V09_READ_ONLY_REGISTRY_DISPATCHER_BOUNDARY_DOC.read_text(
            encoding="utf-8"
        )
        fixture = json.loads(
            V09_READ_ONLY_REGISTRY_DISPATCHER_BOUNDARY_FIXTURE.read_text(
                encoding="utf-8"
            )
        )
        contract = json.loads(
            V09_READ_ONLY_TOOL_REGISTRY_CONTRACT_FIXTURE.read_text(encoding="utf-8")
        )
        guard = json.loads(
            V09_READ_ONLY_TOOL_REGISTRY_IMPLEMENTATION_GUARD_FIXTURE.read_text(
                encoding="utf-8"
            )
        )
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        contract_doc = V09_READ_ONLY_TOOL_REGISTRY_CONTRACT_DOC.read_text(
            encoding="utf-8"
        )
        metadata = build_read_only_registry_metadata(contract, guard)
        fixture_text = json.dumps(fixture, sort_keys=True)
        combined = "\n".join([doc, fixture_text])
        normalized_doc = " ".join(doc.split())

        self.assertTrue(V09_READ_ONLY_REGISTRY_DISPATCHER_BOUNDARY_DOC.exists())
        self.assertTrue(V09_READ_ONLY_REGISTRY_DISPATCHER_BOUNDARY_FIXTURE.exists())
        for linked_text in [readme, contract_doc]:
            self.assertIn("V0.9_READ_ONLY_REGISTRY_DISPATCHER_BOUNDARY.md", linked_text)
            self.assertIn("v09_read_only_registry_dispatcher_boundary.json", linked_text)

        for section in [
            "## Purpose",
            "## Current Baseline",
            "## Boundary Decision",
            "## Explicit Non-goals",
            "## Registry Metadata Scope",
            "## Dispatcher Invocation Boundary",
            "## Executable Registration Boundary",
            "## Actual Tool Execution Boundary",
            "## Source-check Requirements",
            "## Required Negative Tests",
            "## PR Split Requirements",
            "## Security Review Checklist",
            "## Deferred Work",
        ]:
            self.assertIn(section, doc)

        for required_text in [
            "not dispatcher approval",
            "not executable registration",
            "not actual tool execution",
            "metadata labels only",
            "four-file candidate inventory metadata only",
            "does not approve reading file bodies",
            "Dispatcher invocation remains blocked",
            "Executable tool registration is blocked",
            "Actual tool execution is blocked",
            "local evidence reader",
            "v0.9 tag: not created",
            "GitHub Release v0.9: not created",
        ]:
            self.assertIn(required_text, normalized_doc)

        self.assertEqual(
            fixture["schema_version"],
            "v09_read_only_registry_dispatcher_boundary.v1",
        )
        self.assertIs(fixture["boundary_decision_only"], True)
        self.assertIs(fixture["registry_metadata_helper_consumed"], True)
        for false_flag in [
            "dispatcher_approved",
            "dispatcher_implemented",
            "dispatcher_invocation_allowed",
            "executable_tool_registration_approved",
            "executable_tool_registration_implemented",
            "actual_tool_execution_approved",
            "actual_tool_execution_implemented",
            "local_evidence_reader_approved",
            "local_evidence_reader_implemented",
            "safe_file_body_reader_implemented",
            "raw_preview_download_implemented",
            "replay_active_scan_implemented",
            "automatic_chatgpt_handoff_implemented",
            "tag_github_release_created",
            "raw_data_included",
        ]:
            self.assertIn(false_flag, fixture)
            self.assertIs(fixture[false_flag], False)
        self.assertIs(fixture["manual_review_required"], True)

        self.assertEqual(
            fixture["allowed_registry_metadata_fields"],
            contract["allowed_registry_metadata_fields"],
        )
        self.assertEqual(
            tuple(fixture["allowed_registry_metadata_fields"]),
            tuple(metadata),
        )
        self.assertIs(metadata["dispatcher_invocation_allowed"], False)
        self.assertIs(metadata["tool_execution_allowed"], False)
        self.assertIs(metadata["local_evidence_access_allowed"], False)

        for surface in [
            "dispatcher_invocation",
            "executable_tool_registration",
            "actual_tool_execution",
            "local_evidence_reader",
            "safe_file_body_reader",
            "raw_preview_download",
            "replay_active_scan",
            "automatic_chatgpt_handoff",
        ]:
            self.assertIn(surface, fixture["blocked_future_surfaces"])

        for expectation in [
            "dispatcher_approval_false",
            "dispatcher_implementation_false",
            "dispatcher_invocation_false",
            "executable_registration_false",
            "actual_tool_execution_false",
            "local_evidence_reader_false",
            "allowed_registry_metadata_fields_match_helper",
            "blocked_future_surfaces_declared",
            "source_check_files_have_no_forbidden_markers",
            "no_tag_or_release_creation",
        ]:
            self.assertIn(expectation, fixture["required_negative_tests"])

        for source_check_file in fixture["source_check_files"]:
            source_path = ROOT / source_check_file
            self.assertTrue(source_path.exists())
            source = source_path.read_text(encoding="utf-8")
            for marker in fixture["forbidden_source_markers"]:
                self.assertNotIn(marker, source)

        for forbidden in [
            "\ufeff",
            "\ufffd",
            "??",
            "safe-to-share",
            "safe to share",
            "guaranteed safe",
            "confirmed vulnerability",
            "confirmed finding",
            "confirmed issue",
            "final CVSS",
            "raw_request:",
            "raw_response:",
            "Cookie:",
            "Authorization:",
            "Bearer ",
            "JWT ",
            "session=",
            "token=",
            "HMAC secret:",
            "CSRF token:",
            "C:\\coding\\",
            "C:\\Users\\",
            "local_only/",
            "real_export_",
            "actual.local",
            "approved for external sharing",
            "ready to submit",
        ]:
            self.assertNotIn(forbidden, combined)
        self.assertIsNone(re.search(r"https?://", combined))
        self.assertIsNone(re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", combined))

    def test_v09_dispatcher_approval_packet_is_planning_only_and_raw_free(self) -> None:
        doc = V09_DISPATCHER_APPROVAL_PACKET_DOC.read_text(encoding="utf-8")
        fixture = json.loads(
            V09_DISPATCHER_APPROVAL_PACKET_FIXTURE.read_text(encoding="utf-8")
        )
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        boundary_doc = V09_READ_ONLY_REGISTRY_DISPATCHER_BOUNDARY_DOC.read_text(
            encoding="utf-8"
        )
        fixture_text = json.dumps(fixture, sort_keys=True)
        combined = "\n".join([doc, fixture_text])
        normalized_doc = " ".join(doc.split())

        self.assertTrue(V09_DISPATCHER_APPROVAL_PACKET_DOC.exists())
        self.assertTrue(V09_DISPATCHER_APPROVAL_PACKET_FIXTURE.exists())
        for linked_text in [readme, boundary_doc]:
            self.assertIn("V0.9_DISPATCHER_APPROVAL_PACKET.md", linked_text)
            self.assertIn("v09_dispatcher_approval_packet.json", linked_text)

        for section in [
            "## Purpose",
            "## Current Baseline",
            "## Approval Scope",
            "## Explicit Non-goals",
            "## Dispatcher Input Boundary",
            "## Dispatcher Output Boundary",
            "## Blocked Response Requirements",
            "## Audit Boundary",
            "## Required Negative Tests",
            "## Source-check Requirements",
            "## PR Split Requirements",
            "## Security Review Checklist",
            "## Deferred Work",
        ]:
            self.assertIn(section, doc)

        for required_text in [
            "documentation, fixture, and negative-test planning only",
            "This packet does not approve dispatcher implementation",
            "Future dispatcher input may accept only parser metadata",
            "raw request or response content",
            "credential, token, or session values",
            "actual target identifiers",
            "full local paths",
            "local evidence bodies",
            "safe file bodies",
            "Every dispatcher-denied response must set",
            "Future dispatcher audit records must remain raw-free",
            "No dispatcher implementation file is added",
            "parser behavior remains unchanged",
            "v0.9 tag: not created",
            "GitHub Release v0.9: not created",
        ]:
            self.assertIn(required_text, normalized_doc)

        self.assertEqual(
            fixture["schema_version"],
            "v09_dispatcher_approval_packet.v1",
        )
        self.assertIs(fixture["approval_packet_only"], True)
        self.assertIs(fixture["registry_dispatcher_boundary_consumed"], True)
        self.assertIs(fixture["parser_boundary_consumed"], True)
        for false_flag in [
            "dispatcher_approved",
            "dispatcher_implemented",
            "dispatcher_invocation_allowed",
            "executable_tool_registration_approved",
            "executable_tool_registration_implemented",
            "actual_tool_execution_approved",
            "actual_tool_execution_implemented",
            "local_evidence_reader_approved",
            "local_evidence_reader_implemented",
            "safe_file_body_reader_implemented",
            "raw_preview_download_implemented",
            "replay_active_scan_implemented",
            "automatic_chatgpt_handoff_implemented",
            "listener_startup_implemented",
            "transport_runtime_implemented",
            "tag_github_release_created",
            "output_bundle_structure_changed",
            "raw_data_included",
        ]:
            self.assertIn(false_flag, fixture)
            self.assertIs(fixture[false_flag], False)
        self.assertIs(fixture["manual_review_required"], True)

        allowed_fields = [
            "status",
            "reason_code",
            "dispatcher_approved",
            "dispatcher_invocation_allowed",
            "tool_execution_allowed",
            "raw_data_included",
            "manual_review_required",
            "safe_message",
        ]
        forbidden_fields = [
            "tool_result",
            "evidence_body",
            "raw_body",
            "local_file_path",
            "target_identifier",
            "credential_value",
            "stack_trace",
            "callback_handle",
            "command",
            "handler_name",
        ]
        self.assertEqual(fixture["allowed_dispatcher_output_fields"], allowed_fields)
        self.assertEqual(
            fixture["forbidden_dispatcher_output_fields"],
            forbidden_fields,
        )
        self.assertTrue(
            set(fixture["allowed_dispatcher_output_fields"]).isdisjoint(
                fixture["forbidden_dispatcher_output_fields"]
            )
        )

        for expectation in [
            "dispatcher_approval_false",
            "dispatcher_invocation_false",
            "tool_execution_absent",
            "executable_registration_absent",
            "local_evidence_reader_absent",
            "raw_input_rejected",
            "credential_input_rejected",
            "target_identifier_input_rejected",
            "local_path_input_rejected",
            "audit_raw_free",
            "output_allowed_fields_only",
        ]:
            self.assertIn(expectation, fixture["required_negative_tests"])

        self.assertEqual(
            fixture["source_check_scope"],
            ["approval_document", "approval_fixture", "hygiene_test"],
        )
        for marker in [
            "dispatch_tool(",
            "execute_tool(",
            "register_tool(",
            "callback_handle",
            "command",
            "handler_name",
            "read_local_evidence(",
            "read_file_body(",
            "raw_preview",
            "replay",
            "active_scan",
            "automatic_chatgpt_handoff",
        ]:
            self.assertIn(marker, fixture["forbidden_source_markers"])

        self.assertFalse((ROOT / "burp_ai_redaction_gateway" / "mcp_tool_dispatcher.py").exists())

        for forbidden in [
            "\ufeff",
            "\ufffd",
            "??",
            "safe-to-share",
            "safe to share",
            "guaranteed safe",
            "confirmed vulnerability",
            "confirmed finding",
            "confirmed issue",
            "final CVSS",
            "raw_request",
            "raw_response",
            "Cookie:",
            "Authorization:",
            "Bearer ",
            "JWT ",
            "session=",
            "token=",
            "HMAC secret:",
            "CSRF token:",
            "C:\\coding\\",
            "C:\\Users\\",
            "local_only/",
            "real_export_",
            "actual.local",
            "approved for external sharing",
            "ready to submit",
        ]:
            self.assertNotIn(forbidden, combined)
        self.assertIsNone(re.search(r"https?://", combined))
        self.assertIsNone(re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", combined))

    def test_v09_dispatcher_negative_fixture_harness_is_raw_free(self) -> None:
        approval = json.loads(
            V09_DISPATCHER_APPROVAL_PACKET_FIXTURE.read_text(encoding="utf-8")
        )
        fixture = json.loads(
            V09_DISPATCHER_NEGATIVE_CASES_FIXTURE.read_text(encoding="utf-8")
        )
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        approval_doc = V09_DISPATCHER_APPROVAL_PACKET_DOC.read_text(encoding="utf-8")
        boundary_doc = V09_READ_ONLY_REGISTRY_DISPATCHER_BOUNDARY_DOC.read_text(
            encoding="utf-8"
        )
        fixture_text = json.dumps(fixture, sort_keys=True)
        combined = "\n".join([fixture_text, approval_doc, boundary_doc])

        self.assertTrue(V09_DISPATCHER_NEGATIVE_CASES_FIXTURE.exists())
        for linked_text in [readme, approval_doc, boundary_doc]:
            self.assertIn("v09_dispatcher_negative_cases.json", linked_text)
        self.assertIn(
            "future dispatcher implementation PRs must consume this fixture",
            readme,
        )
        self.assertIn(
            "future dispatcher implementation PR must consume this fixture",
            approval_doc,
        )

        self.assertEqual(
            fixture["schema_version"],
            "v09_dispatcher_negative_cases.v1",
        )
        for false_flag in [
            "dispatcher_implemented",
            "dispatcher_invocation_allowed",
            "executable_tool_registration_implemented",
            "actual_tool_execution_implemented",
            "local_evidence_reader_implemented",
            "safe_file_body_reader_implemented",
            "raw_preview_download_implemented",
            "replay_active_scan_implemented",
            "automatic_chatgpt_handoff_implemented",
            "listener_startup_implemented",
            "transport_runtime_implemented",
            "raw_data_included",
        ]:
            self.assertIn(false_flag, fixture)
            self.assertIs(fixture[false_flag], False)
        self.assertIs(fixture["manual_review_required"], True)
        self.assertIs(fixture["dispatcher_approval_packet_consumed"], True)
        self.assertIs(fixture["registry_dispatcher_boundary_consumed"], True)
        self.assertIs(fixture["parser_boundary_consumed"], True)

        required_categories = [
            "raw_input_rejected",
            "credential_input_rejected",
            "target_identifier_input_rejected",
            "local_path_input_rejected",
            "local_evidence_body_rejected",
            "safe_file_body_rejected",
            "callback_handle_rejected",
            "handler_name_rejected",
            "command_string_rejected",
            "tool_result_rejected",
            "dispatcher_invocation_blocked",
            "audit_raw_free",
            "output_allowed_fields_only",
        ]
        cases = fixture["cases"]
        self.assertEqual([case["category"] for case in cases], required_categories)
        allowed_fields = approval["allowed_dispatcher_output_fields"]
        for case in cases:
            self.assertRegex(case["id"], r"^dispatcher-negative-\d{3}$")
            self.assertTrue(case["synthetic_input_label"].startswith("synthetic_"))
            self.assertEqual(case["expected_status"], "blocked")
            self.assertEqual(case["expected_reason_code"], case["category"])
            self.assertIs(case["dispatcher_approved"], False)
            self.assertIs(case["dispatcher_invocation_allowed"], False)
            self.assertIs(case["tool_execution_allowed"], False)
            self.assertIs(case["raw_data_included"], False)
            self.assertIs(case["manual_review_required"], True)
            self.assertIs(case["echo_forbidden"], True)
            self.assertGreater(len(case["forbidden_echo_classes"]), 0)
            self.assertEqual(case["allowed_response_fields"], allowed_fields)

        expected_echo_classes = {
            "raw_traffic_body",
            "credential_value",
            "token_value",
            "session_value",
            "target_identifier",
            "url_domain_ip",
            "full_local_path",
            "local_only_filename",
            "local_evidence_body",
            "safe_file_body",
            "callback_handle",
            "handler_name",
            "command_string",
            "tool_execution_result",
            "dispatcher_invocation",
            "tool_result",
            "evidence_body",
            "raw_body",
        }
        actual_echo_classes = {
            echo_class
            for case in cases
            for echo_class in case["forbidden_echo_classes"]
        }
        self.assertTrue(expected_echo_classes.issubset(actual_echo_classes))

        self.assertFalse(
            (ROOT / "burp_ai_redaction_gateway/mcp_tool_dispatcher.py").exists()
        )

        for forbidden in [
            "\ufeff",
            "\ufffd",
            "??",
            "safe-to-share",
            "safe to share",
            "guaranteed safe",
            "confirmed vulnerability",
            "confirmed finding",
            "confirmed issue",
            "final CVSS",
            "\"raw_request\"",
            "\"raw_response\"",
            "raw_request:",
            "raw_response:",
            "Cookie:",
            "Authorization:",
            "Bearer ",
            "JWT ",
            "session=",
            "token=",
            "HMAC secret:",
            "CSRF token:",
            "C:\\coding\\",
            "C:\\Users\\",
            "local_only/",
            "real_export_",
            "actual.local",
            "approved for external sharing",
            "ready to submit",
        ]:
            self.assertNotIn(forbidden, combined)
        self.assertIsNone(re.search(r"https?://", combined))
        self.assertIsNone(re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", combined))

    def test_v09_dispatcher_implementation_decision_is_planning_only_and_raw_free(self) -> None:
        approval = json.loads(
            V09_DISPATCHER_APPROVAL_PACKET_FIXTURE.read_text(encoding="utf-8")
        )
        negative = json.loads(
            V09_DISPATCHER_NEGATIVE_CASES_FIXTURE.read_text(encoding="utf-8")
        )
        decision = json.loads(
            V09_DISPATCHER_IMPLEMENTATION_DECISION_FIXTURE.read_text(
                encoding="utf-8"
            )
        )
        doc = V09_DISPATCHER_IMPLEMENTATION_DECISION_DOC.read_text(encoding="utf-8")
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        approval_doc = V09_DISPATCHER_APPROVAL_PACKET_DOC.read_text(encoding="utf-8")
        boundary_doc = V09_READ_ONLY_REGISTRY_DISPATCHER_BOUNDARY_DOC.read_text(
            encoding="utf-8"
        )
        fixture_text = json.dumps(decision, sort_keys=True)
        combined = "\n".join([doc, fixture_text])
        normalized_doc = " ".join(doc.split())

        self.assertTrue(V09_DISPATCHER_IMPLEMENTATION_DECISION_DOC.exists())
        self.assertTrue(V09_DISPATCHER_IMPLEMENTATION_DECISION_FIXTURE.exists())
        for linked_text in [readme, approval_doc, boundary_doc]:
            self.assertIn("V0.9_DISPATCHER_IMPLEMENTATION_DECISION.md", linked_text)
            self.assertIn("v09_dispatcher_implementation_decision.json", linked_text)

        for section in [
            "## Purpose",
            "## Current Baseline",
            "## Decision Scope",
            "## Explicit Non-goals",
            "## Required Fixture Consumption",
            "## Dispatcher Implementation Candidate Scope",
            "## Dispatcher Input Boundary",
            "## Dispatcher Output Boundary",
            "## Blocked Response Boundary",
            "## Audit Boundary",
            "## Source-check Requirements",
            "## Required Implementation Tests",
            "## PR Split Requirements",
            "## Security Review Checklist",
            "## Deferred Work",
        ]:
            self.assertIn(section, doc)

        for required_text in [
            "documentation, fixture, and source-check planning only",
            "This decision does not approve adding dispatcher source code",
            "A future dispatcher implementation PR must consume",
            "allowed response field drift and forbidden echo class drift must fail",
            "Future dispatcher input may accept only parser metadata",
            "Future dispatcher output must preserve the allowed dispatcher output fields",
            "Blocked dispatcher responses must be raw-free metadata only",
            "Future dispatcher audit metadata may include only synthetic case labels",
            "The original decision PR did not add dispatcher implementation files",
            "The minimal helper follow-up adds only",
            "Parser behavior must not change",
            "output bundle files remain unchanged",
            "v0.9 tag: not created",
            "GitHub Release v0.9: not created",
        ]:
            self.assertIn(required_text.lower(), normalized_doc.lower())

        self.assertEqual(
            decision["schema_version"],
            "v09_dispatcher_implementation_decision.v1",
        )
        for true_flag in [
            "decision_only",
            "dispatcher_implementation_candidate_defined",
            "dispatcher_approval_packet_consumed",
            "dispatcher_negative_fixture_consumed",
            "registry_dispatcher_boundary_consumed",
            "parser_boundary_consumed",
            "allowed_response_fields_drift_must_fail",
            "forbidden_echo_classes_drift_must_fail",
        ]:
            self.assertIn(true_flag, decision)
            self.assertIs(decision[true_flag], True)

        for false_flag in [
            "dispatcher_implementation_allowed_in_this_pr",
            "dispatcher_implemented",
            "dispatcher_invocation_allowed",
            "executable_tool_registration_implemented",
            "actual_tool_execution_implemented",
            "local_evidence_reader_implemented",
            "safe_file_body_reader_implemented",
            "raw_preview_download_implemented",
            "replay_active_scan_implemented",
            "automatic_chatgpt_handoff_implemented",
            "listener_startup_implemented",
            "transport_runtime_implemented",
            "parser_behavior_changed",
            "output_bundle_structure_changed",
            "tag_github_release_created",
            "raw_data_included",
        ]:
            self.assertIn(false_flag, decision)
            self.assertIs(decision[false_flag], False)
        self.assertIs(decision["manual_review_required"], True)

        required_fixture_paths = [
            "tests/fixtures/v09_dispatcher_approval_packet.json",
            "tests/fixtures/v09_dispatcher_negative_cases.json",
            "tests/fixtures/v09_read_only_registry_dispatcher_boundary.json",
        ]
        self.assertEqual(decision["required_fixture_paths"], required_fixture_paths)
        for fixture_path in required_fixture_paths:
            self.assertTrue((ROOT / fixture_path).exists())

        allowed_fields = approval["allowed_dispatcher_output_fields"]
        negative_categories = [case["category"] for case in negative["cases"]]
        self.assertEqual(decision["allowed_dispatcher_output_fields"], allowed_fields)
        self.assertEqual(decision["required_negative_categories"], negative_categories)

        required_future_tests = [
            "consumes_dispatcher_negative_cases",
            "preserves_allowed_dispatcher_output_fields",
            "rejects_forbidden_echo_classes",
            "blocks_raw_input",
            "blocks_credential_input",
            "blocks_target_identifier_input",
            "blocks_local_path_input",
            "blocks_local_evidence_body",
            "blocks_safe_file_body",
            "blocks_callback_handle",
            "blocks_handler_name",
            "blocks_command_string",
            "blocks_tool_result",
            "keeps_audit_raw_free",
            "no_tool_execution",
            "no_local_evidence_reader",
            "no_listener_transport_runtime",
        ]
        self.assertEqual(
            decision["required_future_implementation_tests"],
            required_future_tests,
        )

        blocked_surfaces = [
            "executable_tool_registration",
            "actual_tool_execution",
            "local_evidence_reader",
            "safe_file_body_reader",
            "raw_preview_download",
            "replay_active_scan",
            "automatic_chatgpt_handoff",
            "listener_startup",
            "transport_runtime",
        ]
        self.assertEqual(decision["blocked_surfaces"], blocked_surfaces)

        self.assertTrue(MCP_DISPATCHER_MODULE.exists())
        self.assertFalse(
            (ROOT / "burp_ai_redaction_gateway/mcp_tool_dispatcher.py").exists()
        )

        for forbidden in [
            "\ufeff",
            "\ufffd",
            "??",
            "safe-to-share",
            "safe to share",
            "guaranteed safe",
            "confirmed vulnerability",
            "confirmed finding",
            "confirmed issue",
            "final CVSS",
            "\"raw_request\"",
            "\"raw_response\"",
            "raw_request:",
            "raw_response:",
            "Cookie:",
            "Authorization:",
            "Bearer ",
            "JWT ",
            "session=",
            "token=",
            "HMAC secret:",
            "CSRF token:",
            "C:\\coding\\",
            "C:\\Users\\",
            "local_only/",
            "real_export_",
            "actual.local",
            "approved for external sharing",
            "ready to submit",
        ]:
            self.assertNotIn(forbidden, combined)
        self.assertIsNone(re.search(r"https?://", combined))
        self.assertIsNone(re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", combined))

    def test_v09_release_readiness_scope_and_gate_hygiene(self) -> None:
        self.assertTrue(V09_RELEASE_READINESS_DOC.exists())
        self.assertTrue(V09_RELEASE_READINESS_FIXTURE.exists())

        doc_text = V09_RELEASE_READINESS_DOC.read_text(encoding="utf-8")
        fixture = json.loads(V09_RELEASE_READINESS_FIXTURE.read_text(encoding="utf-8"))
        readme_text = (ROOT / "README.md").read_text(encoding="utf-8")
        combined = "\n".join(
            [
                doc_text,
                json.dumps(fixture, sort_keys=True),
            ]
        )

        for section in [
            "## Purpose",
            "## Release target",
            "## Current safe-core scope",
            "## Explicit deferred scope",
            "## Included PRs",
            "## Required gate evidence",
            "## Security and privacy checklist",
            "## Raw-free assurance limits",
            "## Tag and GitHub Release preconditions",
            "## Rollback plan",
            "## Release notes draft",
            "## Final decision",
            "## Deferred work",
        ]:
            self.assertIn(section, doc_text)

        self.assertIn("docs/V0.9_RELEASE_READINESS.md", readme_text)
        self.assertIn("tests/fixtures/v09_release_readiness.json", readme_text)

        self.assertEqual(fixture["schema_version"], "v09_release_readiness.v1")
        self.assertIs(fixture["readiness_only"], True)
        self.assertIs(fixture["release_tag_created"], False)
        self.assertIs(fixture["github_release_created"], False)
        self.assertEqual(
            fixture["release_candidate_commit"],
            "6343b761d6076c825035dc4a1e83f367ab0f1168",
        )
        self.assertIs(fixture["raw_data_included"], False)
        self.assertIs(fixture["manual_review_required"], True)

        self.assertEqual(
            fixture["included_prs"],
            [135, 136, 145, 146, 147, 148, 149, 150],
        )

        for safe_core_item in [
            "redaction_verify_review_report",
            "ai_candidate_four_file_boundary",
            "dashboard_read_only_boundary",
            "mcp_parser_boundary",
            "read_only_registry_metadata_helper",
            "minimal_dispatcher_decision_helper",
        ]:
            self.assertIn(safe_core_item, fixture["safe_core_scope"])

        for deferred_surface in [
            "executable_tool_registration",
            "actual_tool_execution",
            "local_evidence_reader",
            "safe_file_body_reader",
            "raw_preview_download",
            "replay_active_scan",
            "automatic_chatgpt_handoff",
            "listener_startup",
            "transport_runtime",
            "dashboard_state_changing_action",
            "upload_import_action",
        ]:
            self.assertIn(deferred_surface, fixture["deferred_surfaces"])

        for required_gate in [
            "python -m compileall burp_ai_redaction_gateway tests",
            "python -m unittest discover -s tests",
            "python -m unittest discover -s tests -k v09_minimal_dispatcher",
            "gitleaks dir -v --redact=100 --config .gitleaks.toml .",
            "gitleaks git -v --redact=100 --config .gitleaks.toml .",
            "scripts\\git_safety_check.bat",
            "git diff --check",
            "git status --short --untracked-files=all",
        ]:
            self.assertIn(required_gate, fixture["required_gates"])

        for release_check in [
            "no_v09_tag_before_release_approval",
            "no_github_release_v09_before_release_approval",
            "no_raw_preview",
            "no_tool_execution",
            "no_local_evidence_reader",
            "no_listener_transport_runtime",
            "release_notes_include_deferred_scope",
            "release_notes_do_not_claim_safe_to_share",
        ]:
            self.assertIn(release_check, fixture["required_release_checks"])

        source_check_text = MCP_DISPATCHER_MODULE.read_text(encoding="utf-8")
        for allowed_literal in [
            *NEGATIVE_REASON_CODES,
            "raw_preview_download_implemented",
            "replay_active_scan_implemented",
            "automatic_chatgpt_handoff_implemented",
        ]:
            source_check_text = source_check_text.replace(f'"{allowed_literal}"', '""')
        for forbidden_source_marker in [
            "execute_tool(",
            "register_tool(",
            "read_local_evidence(",
            "read_file_body(",
            "callback_handle",
            "handler_name",
            "command",
            "raw_preview",
            "replay",
            "active_scan",
            "automatic_chatgpt_handoff",
            "serve_forever",
            "bind(",
            "listen(",
            "accept(",
            "subprocess",
            "requests",
            "urllib.request",
            "http.server",
            "socketserver",
        ]:
            self.assertNotIn(forbidden_source_marker, source_check_text)

        for forbidden in [
            "\ufeff",
            "\ufffd",
            "??",
            "safe-to-share",
            "safe to share",
            "guaranteed safe",
            "confirmed vulnerability",
            "confirmed finding",
            "confirmed issue",
            "final CVSS",
            "\"raw_request\"",
            "\"raw_response\"",
            "raw_request:",
            "raw_response:",
            "Cookie:",
            "Authorization:",
            "Bearer ",
            "JWT ",
            "session=",
            "token=",
            "HMAC secret:",
            "CSRF token:",
            "C:\\coding\\",
            "C:\\Users\\",
            "local_only/",
            "real_export_",
            "actual.local",
            "approved for external sharing",
            "ready to submit",
        ]:
            self.assertNotIn(forbidden, combined)
        self.assertIsNone(re.search(r"https?://", combined))
        self.assertIsNone(re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", combined))

    def test_v09_minimal_dispatcher_decision_helper_consumes_decision_and_negative_cases(self) -> None:
        approval = json.loads(
            V09_DISPATCHER_APPROVAL_PACKET_FIXTURE.read_text(encoding="utf-8")
        )
        negative = json.loads(
            V09_DISPATCHER_NEGATIVE_CASES_FIXTURE.read_text(encoding="utf-8")
        )
        decision = json.loads(
            V09_DISPATCHER_IMPLEMENTATION_DECISION_FIXTURE.read_text(
                encoding="utf-8"
            )
        )
        registry_boundary = json.loads(
            V09_READ_ONLY_REGISTRY_DISPATCHER_BOUNDARY_FIXTURE.read_text(
                encoding="utf-8"
            )
        )
        module_text = MCP_DISPATCHER_MODULE.read_text(encoding="utf-8")
        metadata = build_minimal_dispatcher_metadata()
        allowed_fields = approval["allowed_dispatcher_output_fields"]
        negative_categories = [case["category"] for case in negative["cases"]]

        self.assertTrue(MCP_DISPATCHER_MODULE.exists())
        self.assertEqual(
            metadata["schema_version"],
            "v09_minimal_dispatcher_decision_helper.v1",
        )
        self.assertIs(metadata["minimal_dispatcher_decision_helper"], True)
        self.assertIs(metadata["dispatcher_approval_packet_consumed"], True)
        self.assertIs(metadata["dispatcher_negative_fixture_consumed"], True)
        self.assertIs(metadata["dispatcher_implementation_decision_consumed"], True)
        self.assertIs(metadata["registry_dispatcher_boundary_consumed"], True)
        self.assertEqual(metadata["allowed_dispatcher_output_fields"], allowed_fields)
        self.assertEqual(list(DISPATCHER_RESPONSE_ALLOWED_FIELDS), allowed_fields)
        self.assertEqual(decision["allowed_dispatcher_output_fields"], allowed_fields)
        self.assertEqual(decision["required_negative_categories"], negative_categories)
        self.assertEqual(len(negative["cases"]), 13)
        self.assertEqual(list(NEGATIVE_REASON_CODES), negative_categories)
        for fixture_path in decision["required_fixture_paths"]:
            self.assertTrue((ROOT / fixture_path).exists())

        for false_flag in [
            "dispatcher_invocation_allowed",
            "executable_tool_registration_implemented",
            "actual_tool_execution_implemented",
            "local_evidence_reader_implemented",
            "safe_file_body_reader_implemented",
            "raw_preview_download_implemented",
            "replay_active_scan_implemented",
            "automatic_chatgpt_handoff_implemented",
            "listener_startup_implemented",
            "transport_runtime_implemented",
            "raw_data_included",
        ]:
            self.assertIn(false_flag, metadata)
            self.assertIs(metadata[false_flag], False)
        self.assertIs(metadata["manual_review_required"], True)
        self.assertIs(registry_boundary["dispatcher_invocation_allowed"], False)
        self.assertIs(registry_boundary["actual_tool_execution_implemented"], False)
        self.assertIs(registry_boundary["local_evidence_reader_implemented"], False)

        required_future_tests = set(decision["required_future_implementation_tests"])
        for expected_test in [
            "consumes_dispatcher_negative_cases",
            "preserves_allowed_dispatcher_output_fields",
            "rejects_forbidden_echo_classes",
            "blocks_raw_input",
            "blocks_credential_input",
            "blocks_target_identifier_input",
            "blocks_local_path_input",
            "blocks_local_evidence_body",
            "blocks_safe_file_body",
            "blocks_callback_handle",
            "blocks_handler_name",
            "blocks_command_string",
            "blocks_tool_result",
            "keeps_audit_raw_free",
            "no_tool_execution",
            "no_local_evidence_reader",
            "no_listener_transport_runtime",
        ]:
            self.assertIn(expected_test, required_future_tests)

        response_texts = []
        for case in negative["cases"]:
            response = classify_dispatcher_metadata(case)
            self.assertEqual(list(response), allowed_fields)
            self.assertEqual(response["status"], case["expected_status"])
            self.assertEqual(response["reason_code"], case["category"])
            self.assertEqual(response["reason_code"], case["expected_reason_code"])
            self.assertIs(response["dispatcher_approved"], False)
            self.assertIs(response["dispatcher_invocation_allowed"], False)
            self.assertIs(response["tool_execution_allowed"], False)
            self.assertIs(response["raw_data_included"], False)
            self.assertIs(response["manual_review_required"], True)
            self.assertEqual(response["safe_message"], SAFE_DISPATCHER_MESSAGE)
            self.assertNotIn(case["synthetic_input_label"], str(response))
            response_without_reason = dict(response)
            response_without_reason.pop("reason_code")
            response_value_text = json.dumps(
                list(response_without_reason.values()),
                sort_keys=True,
            )
            for echo_class in case["forbidden_echo_classes"]:
                self.assertNotIn(echo_class, response["safe_message"])
                self.assertNotIn(echo_class, response_value_text)
            response_texts.append(json.dumps(response, sort_keys=True))

        fallback_reason_codes = {
            "unknown_reason_code": "unknown_reason_code",
            "arbitrary_safe_looking_label": "synthetic_safe_label",
            "token_like_reason": "token_like_reason",
            "session_like_reason": "session_like_reason",
            "url_like_reason": "synthetic://redacted",
            "local_path_like_reason": "synthetic\\redacted",
            "ip_like_reason": "999.999.999.999",
            "raw_request": "raw_request",
            "raw_response": "raw_response",
            "authorization": "authorization",
            "cookie": "cookie",
            "bearer": "bearer",
            "jwt": "jwt",
            "hmac": "hmac",
            "csrf": "csrf",
            "handler_name": "handler_name",
            "command_string": "command_string",
        }
        for label, reason_code in fallback_reason_codes.items():
            response = build_blocked_dispatcher_response(reason_code)
            self.assertEqual(response["reason_code"], FALLBACK_REASON_CODE, label)
            self.assertNotIn(reason_code, json.dumps(response, sort_keys=True))
            response_texts.append(json.dumps(response, sort_keys=True))

        unsafe_response = build_blocked_dispatcher_response(
            "token=synthetic",
            safe_message="Cookie: synthetic",
        )
        self.assertEqual(unsafe_response["reason_code"], FALLBACK_REASON_CODE)
        self.assertEqual(unsafe_response["safe_message"], SAFE_DISPATCHER_MESSAGE)
        response_texts.append(json.dumps(unsafe_response, sort_keys=True))

        combined_responses = "\n".join(response_texts)
        for forbidden in [
            "raw_request",
            "raw_response",
            "Cookie:",
            "Authorization:",
            "Bearer ",
            "JWT ",
            "authorization",
            "bearer",
            "cookie",
            "jwt",
            "session=",
            "token=",
            "session_like_reason",
            "token_like_reason",
            "HMAC secret:",
            "CSRF token:",
            "hmac",
            "csrf",
            "C:\\coding\\",
            "C:\\Users\\",
            "actual.local",
        ]:
            self.assertNotIn(forbidden, combined_responses)
        self.assertIsNone(re.search(r"https?://", combined_responses))
        self.assertIsNone(
            re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", combined_responses)
        )

        source_check_text = module_text
        for allowed_literal in [
            *NEGATIVE_REASON_CODES,
            "raw_preview_download_implemented",
            "replay_active_scan_implemented",
            "automatic_chatgpt_handoff_implemented",
        ]:
            source_check_text = source_check_text.replace(f'"{allowed_literal}"', '""')

        for forbidden_source_marker in [
            "execute_tool(",
            "register_tool(",
            "read_local_evidence(",
            "read_file_body(",
            "callback_handle",
            "handler_name",
            "command",
            "raw_preview",
            "replay",
            "active_scan",
            "automatic_chatgpt_handoff",
            "serve_forever",
            "bind(",
            "listen(",
            "accept(",
            "subprocess",
            "requests",
            "urllib.request",
            "http.server",
            "socketserver",
        ]:
            self.assertNotIn(forbidden_source_marker, source_check_text)

    def test_v09_minimal_protocol_parser_blocks_negative_fixture_cases(self) -> None:
        approval = json.loads(
            V09_PROTOCOL_PARSER_APPROVAL_PACKET_FIXTURE.read_text(encoding="utf-8")
        )
        negative = json.loads(
            V09_PROTOCOL_PARSER_NEGATIVE_CASES_FIXTURE.read_text(encoding="utf-8")
        )
        decision = json.loads(
            V09_PROTOCOL_PARSER_IMPLEMENTATION_DECISION_FIXTURE.read_text(
                encoding="utf-8"
            )
        )
        module_text = MCP_PROTOCOL_PARSER_MODULE.read_text(encoding="utf-8")
        metadata = build_minimal_protocol_parser_metadata()
        allowed_fields = approval["blocked_response_allowed_fields"]
        negative_categories = [case["category"] for case in negative["cases"]]

        self.assertTrue(MCP_PROTOCOL_PARSER_MODULE.exists())
        self.assertEqual(metadata["schema_version"], "v09_minimal_protocol_parser.v1")
        self.assertIs(metadata["parser_only_implementation"], True)
        self.assertIs(metadata["negative_fixture_consumed"], True)
        self.assertIs(metadata["raw_data_included"], False)
        self.assertIs(metadata["manual_review_required"], True)
        self.assertEqual(
            list(PROTOCOL_PARSER_BLOCKED_RESPONSE_ALLOWED_FIELDS),
            allowed_fields,
        )
        self.assertEqual(list(PROTOCOL_PARSER_NEGATIVE_REASON_CODES), negative_categories)
        self.assertEqual(metadata["blocked_response_allowed_fields"], allowed_fields)
        self.assertEqual(metadata["supported_negative_categories"], negative_categories)
        self.assertEqual(decision["required_negative_categories"], negative_categories)
        self.assertEqual(decision["allowed_response_fields"], allowed_fields)
        self.assertEqual(
            decision["forbidden_echo_classes"],
            approval["echo_forbidden_value_classes"],
        )

        for false_flag in [
            "json_rpc_parser_implemented",
            "dispatcher_implemented",
            "listener_startup_implemented",
            "transport_implemented",
            "executable_tool_registration_implemented",
            "actual_tool_execution_implemented",
            "local_evidence_reader_implemented",
            "safe_file_body_reader_implemented",
            "automatic_chatgpt_handoff_implemented",
            "tag_github_release_created",
        ]:
            self.assertIn(false_flag, metadata)
            self.assertIs(metadata[false_flag], False)

        summary = validate_negative_case_fixture(negative)
        self.assertEqual(
            summary,
            {
                "ok": True,
                "case_count": 11,
                "all_blocked": True,
                "parser_approved": False,
                "raw_data_included": False,
                "manual_review_required": True,
                "allowed_response_fields": allowed_fields,
            },
        )

        for case in negative["cases"]:
            response = parse_minimal_protocol_message(
                case["synthetic_input_label"],
                negative_case=case,
            )
            self.assertEqual(list(response), allowed_fields)
            self.assertEqual(response["status"], "blocked")
            self.assertEqual(response["reason_code"], case["expected_reason_code"])
            self.assertIs(response["parser_approved"], False)
            self.assertIs(response["raw_data_included"], False)
            self.assertIs(response["manual_review_required"], True)
            response_text = str(response)
            self.assertNotIn(case["synthetic_input_label"], response_text)
            for forbidden_echo_class in case["forbidden_echo_classes"]:
                self.assertNotIn(forbidden_echo_class, response["safe_message"])

        unknown_response = build_blocked_parser_response("unsafe user supplied reason")
        self.assertEqual(list(unknown_response), allowed_fields)
        self.assertEqual(unknown_response["status"], "blocked")
        self.assertEqual(unknown_response["reason_code"], "unknown_method")
        self.assertNotIn("unsafe user supplied reason", str(unknown_response))
        self.assertEqual(
            parse_minimal_protocol_message(None)["reason_code"],
            "empty_message",
        )
        self.assertEqual(
            parse_minimal_protocol_message("")["reason_code"],
            "empty_message",
        )
        self.assertEqual(
            parse_minimal_protocol_message("x" * 9000)["reason_code"],
            "oversized_message",
        )
        self.assertEqual(
            parse_minimal_protocol_message({"synthetic": "value"})["reason_code"],
            "unknown_method",
        )

        for forbidden_marker in [
            "http.server",
            "socketserver",
            "http.client",
            "subprocess",
            "requests",
            "urllib",
            "bind(",
            "listen(",
            "accept(",
            "serve_forever",
            "run_server",
            "create_server",
            "register_tool",
            "dispatch_tool",
            "tool_execute",
            "execute_tool",
            "read_local_evidence",
            "read_file_body",
            "open(",
            "Path(",
        ]:
            self.assertNotIn(forbidden_marker, module_text)

        combined = module_text + "\n" + json.dumps(metadata, sort_keys=True)
        for forbidden in [
            "\ufeff",
            "\ufffd",
            "??",
            "safe-to-share",
            "safe to share",
            "guaranteed safe",
            "confirmed vulnerability",
            "confirmed finding",
            "confirmed issue",
            "final CVSS",
            "\"raw_request\"",
            "\"raw_response\"",
            "raw_request:",
            "raw_response:",
            "Cookie:",
            "Authorization:",
            "Bearer ",
            "JWT ",
            "session=",
            "token=",
            "HMAC secret:",
            "CSRF token:",
            "C:\\coding\\",
            "C:\\Users\\",
            "local_only/",
            "real_export_",
            "actual.local",
            "approved for external sharing",
            "ready to submit",
        ]:
            self.assertNotIn(forbidden, combined)
        self.assertIsNone(re.search(r"https?://", combined))
        self.assertIsNone(re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", combined))

    def test_v08_minimal_skeleton_runtime_is_disabled_and_raw_free(self) -> None:
        guard_fixture = json.loads(
            V08_RUNTIME_SOURCE_CHECK_CONSUMPTION_GUARD_FIXTURE.read_text(encoding="utf-8")
        )
        source_check_fixture = json.loads(
            MCP_LISTENER_RUNTIME_SOURCE_CHECK_V06_FIXTURE.read_text(encoding="utf-8")
        )
        runtime_files = [
            "burp_ai_redaction_gateway/mcp_minimal_skeleton.py",
            "burp_ai_redaction_gateway/mcp_runtime_contract.py",
        ]

        self.assertEqual(guard_fixture["runtime_facing_files"], runtime_files)
        declared_scope = source_check_fixture["source_check_policy"][
            "declared_runtime_facing_source_scope"
        ]
        for runtime_file in runtime_files:
            source_file = ROOT / Path(runtime_file)
            self.assertTrue(source_file.exists(), runtime_file)
            self.assertIn(runtime_file, declared_scope)

        metadata = build_minimal_skeleton_metadata()
        self.assertEqual(metadata["schema_version"], "v08_disabled_minimal_skeleton.v1")
        self.assertIs(metadata["minimal_skeleton_runtime_file_added"], True)
        self.assertIs(metadata["source_check_guard_consumed"], True)
        self.assertIs(metadata["approval_packet_consumed"], True)
        self.assertIs(metadata["disabled_by_default"], True)
        self.assertIs(metadata["runtime_enabled"], False)
        self.assertIs(metadata["listener_started"], False)
        self.assertIs(metadata["startup_permitted"], False)
        self.assertIs(metadata["transport_enabled"], False)
        self.assertIs(metadata["protocol_handler_enabled"], False)
        self.assertIs(metadata["executable_tool_registration_enabled"], False)
        self.assertIs(metadata["actual_tool_execution_enabled"], False)
        self.assertIs(metadata["local_evidence_reader_enabled"], False)
        self.assertIs(metadata["safe_file_body_reader_enabled"], False)
        self.assertIs(metadata["raw_preview_download_enabled"], False)
        self.assertIs(metadata["dashboard_state_changing_control_enabled"], False)
        self.assertIs(metadata["upload_import_action_enabled"], False)
        self.assertIs(metadata["automatic_chatgpt_handoff_enabled"], False)
        self.assertIs(metadata["tag_github_release_mutation_enabled"], False)
        self.assertIs(metadata["output_bundle_structure_changed"], False)
        self.assertEqual(
            metadata["output_bundle_files"],
            ["analysis_packet.json", "chatgpt_prompt.md", "codex_task_prompt.md", "report_draft.md"],
        )
        self.assertEqual(
            metadata["consumed_guards"],
            ["v08_skeleton_approval_packet", "v08_runtime_source_check_consumption_guard"],
        )
        self.assertEqual(
            metadata["allowed_operations"],
            ["describe_boundary", "build_disabled_response", "validate_loopback_candidate"],
        )

        default_response = build_minimal_skeleton_disabled_response()
        self.assertEqual(default_response["status"], "disabled")
        self.assertEqual(default_response["reason_code"], "runtime_disabled_by_default")
        self.assertIs(default_response["runtime_enabled"], False)
        self.assertIs(default_response["listener_started"], False)
        self.assertIs(default_response["startup_permitted"], False)
        self.assertIs(default_response["raw_data_included"], False)
        self.assertIs(default_response["manual_review_required"], True)
        self.assertIs(default_response["host_value_included"], False)
        self.assertIs(default_response["credential_values_included"], False)
        self.assertIs(default_response["file_body_included"], False)

        unknown_response = build_minimal_skeleton_disabled_response("unreviewed input")
        self.assertEqual(unknown_response["reason_code"], "unknown_disabled_surface")
        self.assertNotIn("unreviewed input", json.dumps(unknown_response, sort_keys=True))

        enabled_response = build_minimal_skeleton_disabled_response(
            "runtime_start_blocked", enabled=True, host="localhost"
        )
        self.assertEqual(enabled_response["status"], "blocked")
        self.assertEqual(enabled_response["reason_code"], "runtime_start_blocked")
        self.assertEqual(enabled_response["host_validation_status"], "allowed")
        self.assertIs(enabled_response["loopback_candidate_allowed"], True)
        self.assertIs(enabled_response["runtime_enabled"], False)
        self.assertIs(enabled_response["startup_permitted"], False)
        self.assertIs(enabled_response["listener_started"], False)

        all_interface_candidate = validate_loopback_host_candidate("*")
        self.assertEqual(all_interface_candidate["status"], "blocked")
        self.assertEqual(all_interface_candidate["reason_code"], "all_interface_host_blocked")
        self.assertIs(all_interface_candidate["host_value_included"], False)
        self.assertIs(all_interface_candidate["raw_data_included"], False)

        source_text = "\n".join(
            path.read_text(encoding="utf-8")
            for path in [MCP_MINIMAL_SKELETON_MODULE, MCP_RUNTIME_CONTRACT_MODULE]
        )
        for forbidden_marker in source_check_fixture["forbidden_source_markers"]:
            self.assertNotIn(forbidden_marker, source_text, forbidden_marker)
        for forbidden_marker in [
            "raw_request",
            "raw_response",
            "Cookie:",
            "Authorization:",
            "Bearer ",
            "JWT ",
            "session=",
            "token=",
            "HMAC secret:",
            "CSRF token:",
            "C:\\coding\\",
            "C:\\Users\\",
            "local_only/",
            "real_export_",
            "actual.local",
            "example.com",
            "safe-to-share",
            "confirmed vulnerability",
            "final CVSS",
        ]:
            self.assertNotIn(forbidden_marker, source_text)
        self.assertIsNone(re.search(r"https?://", source_text))
        self.assertIsNone(re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", source_text))

    def test_v05_troubleshooting_index_is_raw_free_and_category_based(self) -> None:
        troubleshooting = V05_TROUBLESHOOTING_DOC.read_text(encoding="utf-8")
        roadmap = (ROOT / "docs" / "ROADMAP_v0.5.md").read_text(encoding="utf-8")
        combined = "\n".join([troubleshooting, roadmap])

        self.assertIn("TROUBLESHOOTING_v0.5.md", roadmap)
        for failure_category in [
            "extension_load_failed",
            "receiver_unavailable",
            "no_in_scope_handoff",
            "no_out_of_scope_skip",
            "verify_failed_safely",
            "upload_validation_failed",
            "invalid_project_alias",
            "dashboard_server_not_running",
            "scope_mismatch",
        ]:
            self.assertIn(failure_category, troubleshooting)

        for related_doc in [
            "LIVE_CAPTURE_RUNTIME_SMOKE_CHECKLIST_v0.5.md",
            "LIVE_CAPTURE_RUNTIME_SMOKE_EVIDENCE_TEMPLATE.md",
            "LIVE_CAPTURE_SCOPE_DRIFT_MATRIX_v0.5.md",
            "LIVE_CAPTURE_COLLECTOR_CONTRACT_v0.5.md",
            "MONTOYA_COLLECTOR.md",
            "LOCALHOST_RECEIVER.md",
            "GUI_UPLOAD_WIZARD.md",
            "LOCAL_DASHBOARD.md",
        ]:
            self.assertIn(related_doc, troubleshooting)

        for required_boundary in [
            "Findings remain candidates",
            "Risk remains draft",
            "Final severity and CVSS remain manual decisions",
            "does not change runtime behavior",
            "raw-free metadata",
        ]:
            self.assertIn(required_boundary, troubleshooting)

        for forbidden in [
            "safe-to-share",
            "confirmed vulnerability",
            "confirmed issue",
            "raw_request",
            "raw_response",
            "cookie_value",
            "authorization_value",
            "Authorization: Bearer",
            "Cookie:",
            "C:\\coding\\",
            "C:\\Users\\",
        ]:
            self.assertNotIn(forbidden, combined)
        self.assertIsNone(re.search(r"https?://", combined))
        self.assertIsNone(re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", combined))

    def test_live_capture_dashboard_integration_plan_is_read_only_and_phase_based(self) -> None:
        plan = LIVE_CAPTURE_DASHBOARD_INTEGRATION_PLAN_DOC.read_text(encoding="utf-8")
        roadmap = (ROOT / "docs" / "ROADMAP_v0.5.md").read_text(encoding="utf-8")
        local_dashboard = (ROOT / "docs" / "LOCAL_DASHBOARD.md").read_text(encoding="utf-8")
        wizard_design = (ROOT / "docs" / "LIVE_CAPTURE_WIZARD_DESIGN_v0.5.md").read_text(
            encoding="utf-8"
        )
        troubleshooting = V05_TROUBLESHOOTING_DOC.read_text(encoding="utf-8")

        for linked_text in [roadmap, local_dashboard, wizard_design, troubleshooting]:
            self.assertIn("LIVE_CAPTURE_DASHBOARD_INTEGRATION_PLAN_v0.5.md", linked_text)

        for required in [
            "Phase 1",
            "Phase 2",
            "Phase 3",
            "read-only runtime smoke status panel",
            "local-only evidence status panel",
            "operator checklist",
            "safe files",
            "receiver output alias",
            "CSRF-protected dashboard action",
            "does not change runtime behavior",
            "collector forwarding",
            "receiver ingest",
            "dashboard state-changing action",
            "ChatGPT automatic handoff is prohibited",
            "raw request/response preview is prohibited",
            "raw traffic download is prohibited",
            "replay is prohibited",
            "active scan is prohibited",
            "Findings remain candidates",
            "Risk remains draft",
            "Final severity and CVSS remain manual decisions",
        ]:
            self.assertIn(required, plan)

        for troubleshooting_category in [
            "live_capture_status_missing",
            "receiver_output_alias_missing",
            "receiver_verify_not_run",
            "receiver_verify_failed_safely",
            "runtime_smoke_evidence_incomplete",
            "scope_mismatch",
            "dashboard_read_only_boundary_confusion",
        ]:
            self.assertIn(troubleshooting_category, plan)

        for forbidden in [
            "safe-to-share",
            "confirmed vulnerability",
            "confirmed issue",
            "final CVSS",
            "evidence import",
            "upload evidence",
            "submit evidence",
            "create evidence",
            "run capture",
            "start capture from dashboard",
            "raw_request",
            "raw_response",
            "cookie_value",
            "authorization_value",
            "Authorization: Bearer",
            "Cookie:",
            "C:\\coding\\",
            "C:\\Users\\",
        ]:
            self.assertNotIn(forbidden, plan)
        self.assertIsNone(re.search(r"https?://", plan))
        self.assertIsNone(re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", plan))

    def test_live_capture_runtime_evidence_source_is_raw_free_and_non_mutating(self) -> None:
        evidence_source = LIVE_CAPTURE_RUNTIME_EVIDENCE_SOURCE_DOC.read_text(encoding="utf-8")
        roadmap = (ROOT / "docs" / "ROADMAP_v0.5.md").read_text(encoding="utf-8")
        local_dashboard = (ROOT / "docs" / "LOCAL_DASHBOARD.md").read_text(encoding="utf-8")
        wizard_design = (ROOT / "docs" / "LIVE_CAPTURE_WIZARD_DESIGN_v0.5.md").read_text(
            encoding="utf-8"
        )
        troubleshooting = V05_TROUBLESHOOTING_DOC.read_text(encoding="utf-8")

        for linked_text in [roadmap, local_dashboard, wizard_design, troubleshooting]:
            self.assertIn("LIVE_CAPTURE_RUNTIME_EVIDENCE_SOURCE_v0.5.md", linked_text)

        for required in [
            "planning document only",
            "planning document only for new evidence intake sources",
            "first implemented source is a read-only receiver output evidence model",
            "does not read local-only smoke evidence files or accept manual evidence input",
            "read-only status panel",
            "Candidate Evidence Sources",
            "Existing Receiver Output Alias",
            "Local-Only Smoke Evidence File",
            "Manual Count And Status Summary",
            "Recommended First Source",
            "Raw-Free Schema",
            "Forbidden Fields",
            "Verify-First Safe Navigation",
            "Future Action Boundary",
            "does not add runtime behavior",
            "collector forwarding",
            "receiver ingest",
            "dashboard state-changing actions",
            "metadata-only fields",
            "receiver output alias",
            "evidence_source: receiver_output_alias",
            "safe file existence status",
            "raw_data_included",
            "Safe navigation links must stay hidden unless receiver output verification has",
            "Findings remain candidates",
            "Risk remains draft",
            "Final severity and CVSS remain manual decisions",
        ]:
            self.assertIn(required, evidence_source)

        for allowed_link in [
            "simple dashboard",
            "safe files",
            "triage",
            "report readiness",
            "workflow",
            "analysis_packet.json",
            "chatgpt_prompt.md",
            "codex_task_prompt.md",
            "report_draft.md",
        ]:
            self.assertIn(allowed_link, evidence_source)

        for forbidden in [
            "safe-to-share",
            "confirmed vulnerability",
            "confirmed issue",
            "final CVSS",
            "raw_request",
            "raw_response",
            "cookie_value",
            "authorization_value",
            "Authorization: Bearer",
            "Cookie:",
            "C:\\coding\\",
            "C:\\Users\\",
            "start capture from dashboard",
            "raw preview/download action is approved",
        ]:
            self.assertNotIn(forbidden, evidence_source)
        self.assertIsNone(re.search(r"https?://", evidence_source))
        self.assertIsNone(re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", evidence_source))

    def test_live_capture_local_evidence_schema_is_planning_only_and_raw_free(self) -> None:
        schema_doc = LIVE_CAPTURE_LOCAL_EVIDENCE_SCHEMA_DOC.read_text(encoding="utf-8")
        fixture = json.loads(LIVE_CAPTURE_LOCAL_EVIDENCE_SCHEMA_FIXTURE.read_text(encoding="utf-8"))
        fixture_text = json.dumps(fixture, sort_keys=True)
        roadmap = (ROOT / "docs" / "ROADMAP_v0.5.md").read_text(encoding="utf-8")
        evidence_source = LIVE_CAPTURE_RUNTIME_EVIDENCE_SOURCE_DOC.read_text(encoding="utf-8")
        troubleshooting = V05_TROUBLESHOOTING_DOC.read_text(encoding="utf-8")

        for linked_text in [roadmap, evidence_source, troubleshooting]:
            self.assertIn("LIVE_CAPTURE_LOCAL_EVIDENCE_SCHEMA_v0.5.md", linked_text)

        self.assertEqual(fixture["schema_version"], "live-capture-local-evidence-v1")
        self.assertEqual(fixture["source_type"], "manual_runtime_smoke")
        self.assertEqual(fixture["evidence_source"], "local_only_smoke_evidence_file")
        self.assertEqual(fixture["extension_load_status"], "passed")
        self.assertEqual(fixture["local_receiver_status"], "passed")
        self.assertGreaterEqual(fixture["in_scope_handoff_count"], 1)
        self.assertGreaterEqual(fixture["out_of_scope_skip_count"], 1)
        self.assertEqual(fixture["raw_markers_in_extension_output"], 0)
        self.assertFalse(fixture["target_identifiers_recorded"])
        self.assertFalse(fixture["raw_traffic_recorded"])
        self.assertFalse(fixture["credential_values_recorded"])
        self.assertFalse(fixture["raw_data_included"])

        for required in [
            "planning document only",
            "does not add runtime behavior",
            "does not add file read behavior",
            "does not add upload or import behavior",
            "does not add POST action behavior",
            "does not add dashboard live capture integration",
            "Future Intake Requirements",
            "path traversal checks",
            "forbidden directory checks",
            "schema validation",
            "strict forbidden field checks",
            "raw-free error messages",
            "receiver output alias",
            "raw_data_included: false",
            "Findings remain candidates",
            "Risk remains draft",
            "Final severity and CVSS remain manual decisions",
            "not sharing approval",
        ]:
            self.assertIn(required, schema_doc)

        required_fields = [
            "schema_version",
            "source_type",
            "evidence_source",
            "extension_load_status",
            "local_receiver_status",
            "in_scope_handoff_count",
            "out_of_scope_skip_count",
            "missing_host_skipped",
            "invalid_host_skipped",
            "receiver_verify_status",
            "receiver_output_alias",
            "raw_markers_in_extension_output",
            "target_identifiers_recorded",
            "raw_traffic_recorded",
            "credential_values_recorded",
            "raw_data_included",
            "created_at_utc",
        ]
        self.assertEqual(set(required_fields), set(fixture))
        for field in required_fields:
            self.assertIn(field, schema_doc)

        combined = "\n".join([schema_doc, fixture_text])
        for forbidden in [
            "safe-to-share",
            "confirmed vulnerability",
            "confirmed issue",
            "final CVSS",
            "raw_request",
            "raw_response",
            "cookie_value",
            "authorization_value",
            "Authorization: Bearer",
            "Cookie:",
            "C:\\coding\\",
            "C:\\Users\\",
            "actual.local",
            "real_export_",
            "upload evidence",
            "submit evidence",
            "create evidence",
            "run capture",
            "start capture from dashboard",
            "raw preview/download action is approved",
            "external sharing clearance",
        ]:
            self.assertNotIn(forbidden, combined)
        self.assertIsNone(re.search(r"https?://", combined))
        self.assertIsNone(re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", combined))

    def test_v05_release_readiness_doc_is_scope_based_and_raw_free(self) -> None:
        readiness = V05_RELEASE_READINESS_DOC.read_text(encoding="utf-8")
        roadmap = (ROOT / "docs" / "ROADMAP_v0.5.md").read_text(encoding="utf-8")
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        troubleshooting = V05_TROUBLESHOOTING_DOC.read_text(encoding="utf-8")

        for linked_text in [roadmap, readme, troubleshooting]:
            self.assertIn("RELEASE_READINESS_v0.5.md", linked_text)

        for included in [
            "Upload Wizard",
            "Local dashboard",
            "/live-capture",
            "Receiver output alias evidence model",
            "Montoya collector safe host filter",
            "Receiver dry-run and skip summary helper",
            "Runtime smoke checklist",
            "Troubleshooting index",
            "Local evidence schema planning document",
            "analysis_packet.json",
            "chatgpt_prompt.md",
            "codex_task_prompt.md",
            "report_draft.md",
        ]:
            self.assertIn(included, readiness)

        for excluded in [
            "ChatGPT automatic handoff",
            "Raw preview or raw download",
            "Replay",
            "Active scan",
            "Local evidence file reader",
            "Upload or import evidence action",
            "Dashboard state-changing live capture orchestration",
            "HMAC secret UI",
            "File retention or delete policy changes",
            "Automatic final severity or CVSS decisions",
        ]:
            self.assertIn(excluded, readiness)

        for checklist_item in [
            "Python compileall",
            "Python unittest",
            "verify --input out",
            "Demo review and report generation",
            "Montoya Gradle build",
            "Browser smoke for `/upload`, `/live-capture`, `/safe-files`, and `/simple`",
            "Gitleaks directory scan",
            "Gitleaks git history scan",
            "Git safety check",
            "Git diff whitespace check",
            "Actual Burp runtime smoke raw-free evidence",
            "PR body hygiene",
            "Docs forbidden marker check",
            "No tag until explicit approval",
        ]:
            self.assertIn(checklist_item, readiness)

        for required_boundary in [
            "The local evidence reader does not exist yet",
            "Dashboard live capture orchestration does not exist yet",
            "Computer Use GUI automation is not a stable release gate",
            "Latest Montoya runtime smoke release evidence is recorded as raw-free manual evidence",
            "Candidate findings are not confirmed issues",
            "Risk remains draft",
            "Final severity and CVSS remain manual decisions",
            "Passing smoke evidence is readiness evidence only",
            "Passing smoke evidence is not sharing approval",
        ]:
            self.assertIn(required_boundary, readiness)

        combined = "\n".join([readiness, roadmap, troubleshooting])
        for forbidden in [
            "safe-to-share",
            "guaranteed safe",
            "confirmed vulnerability",
            "final CVSS",
            "raw_request",
            "raw_response",
            "cookie_value",
            "authorization_value",
            "Authorization:",
            "Cookie:",
            "C:\\coding\\",
            "C:\\Users\\",
            "real_export_",
        ]:
            self.assertNotIn(forbidden, combined)
        self.assertIsNone(re.search(r"https?://", readiness))
        self.assertIsNone(re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", readiness))

    def test_v05_rc_readiness_review_is_scope_based_and_raw_free(self) -> None:
        rc_readiness = V05_RC_READINESS_DOC.read_text(encoding="utf-8")
        readiness = V05_RELEASE_READINESS_DOC.read_text(encoding="utf-8")
        roadmap = (ROOT / "docs" / "ROADMAP_v0.5.md").read_text(encoding="utf-8")
        readme = (ROOT / "README.md").read_text(encoding="utf-8")

        for linked_text in [readiness, roadmap, readme]:
            self.assertIn("RC_READINESS_v0.5.md", linked_text)

        self.assertIn("RC possible with follow-up required", rc_readiness)
        self.assertIn("This document records whether the current `main` branch can be treated", rc_readiness)

        for included in [
            "Upload Wizard",
            "Local dashboard",
            "Home Korean quickstart landing",
            "/live-capture",
            "Receiver output alias evidence model",
            "Montoya collector safe host filter",
            "Receiver dry-run and skip summary helper",
            "Runtime smoke checklist",
            "Troubleshooting index",
            "Local evidence schema planning document",
            "MCP integration design",
            "Korean-first web UX plan",
            "analysis_packet.json",
            "chatgpt_prompt.md",
            "codex_task_prompt.md",
            "report_draft.md",
        ]:
            self.assertIn(included, rc_readiness)

        for excluded in [
            "ChatGPT automatic handoff",
            "MCP server implementation",
            "Raw preview or raw download",
            "Replay",
            "Active scan",
            "Local evidence file reader",
            "Upload or import evidence action",
            "Dashboard state-changing live capture orchestration",
            "HMAC secret UI",
            "File retention or delete policy changes",
            "Automatic final severity or CVSS decisions",
        ]:
            self.assertIn(excluded, rc_readiness)

        for checklist_item in [
            "compileall",
            "unittest",
            "verify --input out",
            "review/report demo",
            "Montoya gradle build",
            "Browser smoke for `/`, `/upload`, `/live-capture`, `/safe-files`, `/help`",
            "Montoya runtime smoke evidence",
            "Gitleaks dir",
            "Gitleaks git",
            "git_safety_check",
            "git diff --check",
            "PR body hygiene",
            "docs forbidden marker check",
            "no tag until explicit approval",
            "no GitHub Release until explicit approval",
        ]:
            self.assertIn(checklist_item, rc_readiness)

        for required_boundary in [
            "The local evidence reader does not exist yet",
            "Dashboard live capture orchestration does not exist yet",
            "MCP server is not implemented yet",
            "Computer Use GUI automation is not a stable release gate",
            "Latest Montoya runtime smoke release evidence is recorded as raw-free manual evidence",
            "Candidate findings are not confirmed issues",
            "Risk remains draft",
            "Final severity and CVSS remain manual decisions",
            "Passing smoke evidence is readiness evidence only",
            "Passing smoke evidence is not sharing approval",
            "A tag or GitHub Release must not be created without explicit approval",
        ]:
            self.assertIn(required_boundary, rc_readiness)

        for forbidden in [
            "safe-to-share",
            "guaranteed safe",
            "confirmed vulnerability",
            "final CVSS",
            "raw_request",
            "raw_response",
            "cookie_value",
            "authorization_value",
            "Authorization:",
            "Cookie:",
            "Bearer ",
            "JWT",
            "session=",
            "C:\\coding\\",
            "C:\\Users\\",
            "real_export_",
            "actual.local",
        ]:
            self.assertNotIn(forbidden, rc_readiness)
        self.assertIsNone(re.search(r"https?://", rc_readiness))
        self.assertIsNone(re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", rc_readiness))

    def test_v05_montoya_runtime_smoke_release_evidence_is_raw_free(self) -> None:
        evidence = V05_MONTOYA_RUNTIME_SMOKE_RELEASE_EVIDENCE_DOC.read_text(encoding="utf-8")
        rc_readiness = V05_RC_READINESS_DOC.read_text(encoding="utf-8")
        readiness = V05_RELEASE_READINESS_DOC.read_text(encoding="utf-8")
        roadmap = (ROOT / "docs" / "ROADMAP_v0.5.md").read_text(encoding="utf-8")
        readme = (ROOT / "README.md").read_text(encoding="utf-8")

        for linked_text in [rc_readiness, readiness, roadmap, readme]:
            self.assertIn("V05_MONTOYA_RUNTIME_SMOKE_RELEASE_EVIDENCE.md", linked_text)

        for required in [
            "v0.5 Montoya Runtime Smoke Release Evidence",
            "smoke date",
            "2026-06-17",
            "montoya-runtime-smoke-v0.5-release-evidence",
            "tested commit alias",
            "2e7503b",
            "extension load status",
            "local receiver status",
            "in_scope_handoff_count",
            "out_of_scope_skip_count",
            "missing_host_skipped",
            "invalid_host_skipped",
            "receiver_verify_status",
            "receiver_output_alias",
            "montoya_runtime_smoke",
            "raw_marker_count",
            "raw_data_included",
            "target_identifiers_recorded",
            "raw_traffic_recorded",
            "credential_values_recorded",
            "false",
            "No tag until explicit approval",
            "No GitHub Release until explicit approval",
            "Candidate findings are not confirmed issues",
            "Risk remains draft",
            "Final severity and CVSS remain manual decisions",
            "The tested runtime baseline is `2e7503b`",
            "changes only",
            "docs and tests",
            "does not change runtime behavior",
            "runtime-affecting code",
            "runtime baseline remains unchanged",
        ]:
            self.assertIn(required, evidence)

        for forbidden in [
            "release commit changes",
            "safe-to-share",
            "guaranteed safe",
            "confirmed vulnerability",
            "final CVSS",
            "raw_request",
            "raw_response",
            "cookie_value",
            "authorization_value",
            "Authorization:",
            "Cookie:",
            "Bearer ",
            "JWT",
            "session=",
            "C:\\coding\\",
            "C:\\Users\\",
            "local_only/",
            "real_export_",
            "actual.local",
            "example.com",
        ]:
            self.assertNotIn(forbidden, evidence)

        self.assertIsNone(re.search(r"https?://", evidence))
        self.assertIsNone(re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", evidence))

    def test_v06_roadmap_and_v05_hotfix_policy_are_planning_only_and_raw_free(self) -> None:
        roadmap_v06 = ROADMAP_V06_DOC.read_text(encoding="utf-8")
        hotfix_policy = V05_HOTFIX_POLICY_DOC.read_text(encoding="utf-8")
        roadmap_v05 = (ROOT / "docs" / "ROADMAP_v0.5.md").read_text(encoding="utf-8")
        readiness = V05_RELEASE_READINESS_DOC.read_text(encoding="utf-8")
        readme = (ROOT / "README.md").read_text(encoding="utf-8")

        for linked_text in [roadmap_v05, readiness, readme]:
            self.assertIn("ROADMAP_v0.6.md", linked_text)
            self.assertIn("V0.5_HOTFIX_POLICY.md", linked_text)

        for required in [
            "v0.6 Roadmap",
            "planning only",
            "Low-Risk UX Improvements",
            "Read-Only Integration",
            "Security-Sensitive Deferred Work",
            "Korean quickstart wording polish",
            "Safe files explanation cards",
            "Output alias selector",
            "Troubleshooting panel",
            "Demo and sample output guidance",
            "MCP read-only tool contract matrix",
            "MCP read-only prototype",
            "Release readiness status page",
            "Report and prompt readiness read-only endpoint",
            "Local evidence file reader",
            "Upload or import evidence action",
            "Dashboard live capture orchestration",
            "Replay",
            "Active scan",
            "Automatic ChatGPT handoff",
            "File retention or delete policy changes",
            "HMAC secret UI",
            "CSRF or state-changing action changes",
            "MCP server implementation",
            "New tag",
            "GitHub Release",
        ]:
            self.assertIn(required, roadmap_v06)

        for required in [
            "v0.5 Hotfix Policy",
            "policy only",
            "Release note typo",
            "Broken link fix",
            "Documentation correction",
            "Failing test fix",
            "Packaging or launch script bug",
            "Dashboard copy bug",
            "Non-behavioral safety wording correction",
            "MCP server implementation",
            "Local evidence reader",
            "New POST action",
            "Collector forwarding behavior change",
            "Receiver ingest behavior change",
            "Raw preview or raw download",
            "Replay or active scan",
            "ChatGPT auto-send",
            "File delete or retention policy change",
            "HMAC or CSRF behavior change",
        ]:
            self.assertIn(required, hotfix_policy)

        combined = "\n".join([roadmap_v06, hotfix_policy])
        for forbidden in [
            "safe-to-share",
            "guaranteed safe",
            "confirmed vulnerability",
            "final CVSS",
            "raw_request",
            "raw_response",
            "cookie_value",
            "authorization_value",
            "Authorization:",
            "Cookie:",
            "Bearer ",
            "JWT",
            "session=",
            "C:\\coding\\",
            "C:\\Users\\",
            "local_only/",
            "real_export_",
            "actual.local",
            "example.com",
        ]:
            self.assertNotIn(forbidden, combined)

        self.assertIsNone(re.search(r"https?://", combined))
        self.assertIsNone(re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", combined))

    def test_v06_fast_track_plan_is_planning_only_and_raw_free(self) -> None:
        plan = V06_FAST_TRACK_PLAN_DOC.read_text(encoding="utf-8")
        roadmap_v06 = ROADMAP_V06_DOC.read_text(encoding="utf-8")

        self.assertIn("V0.6_FAST_TRACK_PLAN.md", roadmap_v06)

        for required in [
            "v0.6 Fast-Track Plan",
            "planning only",
            "Fast-Track Slices",
            "Completed Read-Only UX Slice",
            "Two-Week Candidate Sequence",
            "Required Completion Criteria Per PR",
            "Work That Must Stay Separate",
            "Boundary Checklist",
            "Output alias selector follow-up UX",
            "Completed in the read-only dashboard UX bundle",
            "Troubleshooting panel read-only UX",
            "Release readiness status panel",
            "existing dashboard routes",
            'no `href="docs/`',
            "MCP registry adapter design",
            "Next candidate",
            "MCP read-only prototype skeleton plan",
            "MCP server implementation",
            "MCP transport implementation",
            "Tool handler implementation",
            "Local evidence reader",
            "Upload or import evidence action",
            "Dashboard POST action",
            "Raw preview or raw download",
            "Replay",
            "Active scan",
            "Automatic ChatGPT handoff",
            "File delete or retention behavior change",
            "HMAC behavior change",
            "CSRF behavior change",
            "Candidate findings are not treated as confirmed issues",
            "Draft risk values are not treated as final severity",
            "Severity and CVSS decisions remain manual",
            "Tags and GitHub Releases remain separate",
        ]:
            self.assertIn(required, plan)

        for forbidden in [
            "safe-to-share",
            "guaranteed safe",
            "confirmed vulnerability",
            "final CVSS",
            "raw_request",
            "raw_response",
            "cookie_value",
            "authorization_value",
            "Authorization:",
            "Cookie:",
            "Bearer ",
            "JWT",
            "session=",
            "C:\\coding\\",
            "C:\\Users\\",
            "local_only/",
            "real_export_",
            "actual.local",
            "example.com",
        ]:
            self.assertNotIn(forbidden, plan)

        self.assertIsNone(re.search(r"https?://", plan))
        self.assertIsNone(re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", plan))

    def test_v06_rc_readiness_checklist_is_gate_based_and_raw_free(self) -> None:
        checklist = V06_RC_READINESS_CHECKLIST_DOC.read_text(encoding="utf-8")
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        roadmap = ROADMAP_V06_DOC.read_text(encoding="utf-8")
        fast_track = V06_FAST_TRACK_PLAN_DOC.read_text(encoding="utf-8")
        quickstart_ko = USER_QUICKSTART_KO_V06_DOC.read_text(encoding="utf-8")
        output_guide_ko = OUTPUT_BUNDLE_GUIDE_KO_V06_DOC.read_text(encoding="utf-8")

        self.assertTrue(V06_RC_READINESS_CHECKLIST_DOC.exists())
        for linked_text in [readme, roadmap, fast_track, quickstart_ko, output_guide_ko]:
            self.assertIn("V0.6_RC_READINESS_CHECKLIST.md", linked_text)

        for section in [
            "## Purpose",
            "## Current Completed Baseline",
            "## RC Readiness Criteria",
            "## Required Smoke Evidence",
            "## Required Security Evidence",
            "## Required UX Evidence",
            "## Output Bundle Criteria",
            "## MCP Boundary Criteria",
            "## Release Blockers",
            "## Explicit Non-Goals",
            "## Tag And GitHub Release Decision",
            "## Deferred Work After v0.6",
        ]:
            self.assertIn(section, checklist)

        for completed in [
            "v0.5 release completed",
            "Local redaction, verify, review, and report flow",
            "Upload Wizard baseline",
            "Simple Dashboard copy-only UX",
            "Korean quickstart",
            "Output bundle guide",
            "Montoya collector build gate",
            "MCP contract matrix",
            "MCP registry, adapter design, adapter dry-run, and schema catalog",
            "MCP runtime boundary decision",
            "MCP server skeleton preflight",
            "MCP runtime boundary consumption",
            "MCP listener decision, acceptance criteria, and runtime-facing source-check",
        ]:
            self.assertIn(completed, checklist)

        for gate in [
            "python -m compileall burp_ai_redaction_gateway tests",
            "python -m unittest discover -s tests",
            "python -m burp_ai_redaction_gateway verify --input out",
            "python -m burp_ai_redaction_gateway review --input out\\demo",
            "python -m burp_ai_redaction_gateway report --input out\\demo --output out\\demo\\report_draft.md --profile conservative",
            "extensions\\montoya-collector\\gradlew.bat clean build",
            "gitleaks dir -v --redact=100 --config .gitleaks.toml .",
            "gitleaks git -v --redact=100 --config .gitleaks.toml .",
            "scripts\\git_safety_check.bat",
            "git diff --check",
            "git status --short --untracked-files=all",
        ]:
            self.assertIn(gate, checklist)

        for required in [
            "Output bundle 4 files remain unchanged",
            "Basic view: `report_draft.md`, `chatgpt_prompt.md`",
            "Advanced view: `analysis_packet.json`, `codex_task_prompt.md`",
            "Manual review required",
            "Candidate finding only",
            "Draft risk only",
            "Draft report only",
            "Severity/CVSS manual decision",
            "No automatic ChatGPT handoff",
            "No direct raw traffic handoff",
            "`analysis_packet.json`",
            "`chatgpt_prompt.md`",
            "`codex_task_prompt.md`",
            "`report_draft.md`",
            "MCP server listener remains not implemented",
            "MCP transport remains not implemented",
            "MCP protocol handler remains not implemented",
            "Executable tool registration remains not implemented",
            "Actual tool execution remains not implemented",
            "Local evidence reader remains not implemented",
            "Safe file body reader remains not implemented",
            "Tag or GitHub Release is created without explicit approval",
            "No tag until explicit approval",
            "No GitHub Release until explicit approval",
        ]:
            self.assertIn(required, checklist)

        for blocker in [
            "Full gate failure",
            "Gitleaks failure",
            "Git safety failure",
            "Raw request or raw response marker appears",
            "Actual target, domain, IP, credential, token, or session values appear",
            "Full local path appears",
            "Sharing guarantee wording appears",
            "Confirmed issue or CVSS certainty wording appears",
            "Automatic ChatGPT handoff is added",
            "Raw preview or raw download is added",
        ]:
            self.assertIn(blocker, checklist)

        for non_goal in [
            "MCP server listener implementation",
            "MCP transport implementation",
            "MCP protocol handler implementation",
            "Executable tool registration implementation",
            "Actual tool execution implementation",
            "Local evidence reader implementation",
            "Safe file body reader implementation",
            "Upload, import, or dashboard POST action implementation",
            "Collector forwarding behavior change",
            "Receiver ingest behavior change",
            "Raw preview or raw download implementation",
            "Replay or active scan implementation",
            "Automatic ChatGPT handoff implementation",
            "Output bundle four-file structure change",
            "New tag creation",
            "GitHub Release creation",
        ]:
            self.assertIn(non_goal, checklist)

        combined = "\n".join([checklist, roadmap, fast_track])
        for forbidden in [
            "safe-to-share",
            "safe to share",
            "guaranteed safe",
            "confirmed vulnerability",
            "final CVSS",
            "\"raw_request\"",
            "\"raw_response\"",
            "raw_request:",
            "raw_response:",
            "cookie_value",
            "authorization_value",
            "Authorization:",
            "Cookie:",
            "Bearer ",
            "JWT",
            "session=",
            "C:\\coding\\",
            "C:\\Users\\",
            "local_only/",
            "real_export_",
            "actual.local",
            "example.com",
        ]:
            self.assertNotIn(forbidden, combined)

        self.assertIsNone(re.search(r"https?://", checklist))
        self.assertIsNone(re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", checklist))

    def test_v06_quickstart_smoke_and_release_notes_draft_are_raw_free(self) -> None:
        quickstart_smoke = V06_QUICKSTART_SMOKE_DOC.read_text(encoding="utf-8")
        release_notes = V06_RELEASE_NOTES_DRAFT_DOC.read_text(encoding="utf-8")
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        checklist = V06_RC_READINESS_CHECKLIST_DOC.read_text(encoding="utf-8")
        roadmap = ROADMAP_V06_DOC.read_text(encoding="utf-8")
        quickstart_ko = USER_QUICKSTART_KO_V06_DOC.read_text(encoding="utf-8")
        output_guide_ko = OUTPUT_BUNDLE_GUIDE_KO_V06_DOC.read_text(encoding="utf-8")

        self.assertTrue(V06_QUICKSTART_SMOKE_DOC.exists())
        self.assertTrue(V06_RELEASE_NOTES_DRAFT_DOC.exists())
        for linked_text in [readme, checklist, roadmap, quickstart_ko, output_guide_ko]:
            self.assertIn("V0.6_QUICKSTART_SMOKE.md", linked_text)
            self.assertIn("V0.6_RELEASE_NOTES_DRAFT.md", linked_text)

        for section in [
            "## Purpose",
            "## Smoke Scope",
            "## Preconditions",
            "## Commands",
            "## Expected Output",
            "## Dashboard Simple Check",
            "## Output Bundle Check",
            "## Security Checks",
            "## Failure Handling",
            "## Non-Goals",
        ]:
            self.assertIn(section, quickstart_smoke)

        for section in [
            "## Purpose",
            "## Draft Release Summary",
            "## User-Visible Changes",
            "## Security And Privacy Boundaries",
            "## Output Bundle",
            "## Dashboard UX",
            "## MCP Status",
            "## Verification Evidence Required Before Release",
            "## Known Limitations",
            "## Explicit Non-Goals",
            "## Release Action Status",
        ]:
            self.assertIn(section, release_notes)

        combined = "\n".join([quickstart_smoke, release_notes])
        for required in [
            "generate",
            "verify",
            "review",
            "report",
            "/simple?project=quickstart_smoke",
            "Simple Dashboard",
            "analysis_packet.json",
            "chatgpt_prompt.md",
            "codex_task_prompt.md",
            "report_draft.md",
            "Basic view",
            "Advanced view",
            "Manual review required",
            "candidate finding",
            "draft risk",
            "draft report",
            "Severity/CVSS",
            "manual decision",
            "No automatic ChatGPT handoff",
            "release notes draft only",
            "No tag",
            "No GitHub Release",
            "MCP server listener",
            "MCP transport",
            "MCP protocol handler",
            "Executable tool registration",
            "Actual tool execution",
            "Local evidence reader",
            "Safe file body reader",
            "Raw preview or raw download",
            "Replay or active scan",
            "Automatic ChatGPT handoff",
        ]:
            self.assertIn(required, combined)

        for forbidden in [
            "safe-to-share",
            "safe to share",
            "guaranteed safe",
            "confirmed vulnerability",
            "confirmed issue count",
            "final CVSS",
            "\"raw_request\"",
            "\"raw_response\"",
            "raw_request:",
            "raw_response:",
            "Cookie:",
            "Authorization:",
            "Bearer ",
            "JWT ",
            "session=",
            "token=",
            "HMAC secret:",
            "CSRF token:",
            "C:\\coding\\",
            "C:\\Users\\",
            "local_only/",
            "real_export_",
            "actual.local",
            "example.com",
            "approved for external sharing",
            "ready to submit",
        ]:
            self.assertNotIn(forbidden, combined)

        self.assertIsNone(re.search(r"https?://", combined))
        self.assertIsNone(re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", combined))

    def test_v06_final_gate_and_release_approval_packet_are_raw_free(self) -> None:
        final_gate = V06_RC_FINAL_GATE_RUN_DOC.read_text(encoding="utf-8")
        approval_packet = V06_RELEASE_APPROVAL_PACKET_DOC.read_text(encoding="utf-8")
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        checklist = V06_RC_READINESS_CHECKLIST_DOC.read_text(encoding="utf-8")
        roadmap = ROADMAP_V06_DOC.read_text(encoding="utf-8")
        release_notes = V06_RELEASE_NOTES_DRAFT_DOC.read_text(encoding="utf-8")

        self.assertTrue(V06_RC_FINAL_GATE_RUN_DOC.exists())
        self.assertTrue(V06_RELEASE_APPROVAL_PACKET_DOC.exists())
        for linked_text in [readme, checklist, roadmap, release_notes]:
            self.assertIn("V0.6_RC_FINAL_GATE_RUN.md", linked_text)
            self.assertIn("V0.6_RELEASE_APPROVAL_PACKET.md", linked_text)

        for section in [
            "## Purpose",
            "## Run Label",
            "## Required Gate Commands",
            "## Gate Evidence Summary",
            "## Quickstart Smoke Evidence",
            "## Output Bundle Evidence",
            "## Release Blocker Check",
            "## MCP Boundary Check",
            "## Release Decision Status",
            "## Follow-Up",
        ]:
            self.assertIn(section, final_gate)

        for section in [
            "## Purpose",
            "## Current Candidate Summary",
            "## Required Inputs",
            "## Approval Criteria",
            "## Required Human Decision",
            "## Security And Privacy Boundary",
            "## MCP Status",
            "## Release Action Status",
            "## Blockers Before Release Action",
            "## Rollback Plan",
            "## Final Approval Status",
        ]:
            self.assertIn(section, approval_packet)

        combined = "\n".join([final_gate, approval_packet])
        for required in [
            "v0.6-rc-final-gate-docs-pr",
            "fa909f1",
            "python -m compileall burp_ai_redaction_gateway tests",
            "python -m unittest discover -s tests",
            "python -m burp_ai_redaction_gateway verify --input out",
            "python -m burp_ai_redaction_gateway review --input out\\demo",
            "python -m burp_ai_redaction_gateway report --input out\\demo --output out\\demo\\report_draft.md --profile conservative",
            "extensions\\montoya-collector\\gradlew.bat clean build",
            "gitleaks dir -v --redact=100 --config .gitleaks.toml .",
            "gitleaks git -v --redact=100 --config .gitleaks.toml .",
            "scripts\\git_safety_check.bat",
            "git diff --check",
            "git status --short --untracked-files=all",
            "Quickstart smoke",
            "Simple Dashboard",
            "analysis_packet.json",
            "chatgpt_prompt.md",
            "codex_task_prompt.md",
            "report_draft.md",
            "Manual review",
            "candidate finding",
            "draft risk",
            "draft report",
            "severity/CVSS",
            "MCP server listener remains not implemented",
            "MCP transport remains not implemented",
            "MCP protocol handler remains not implemented",
            "Actual tool execution remains not implemented",
            "Local evidence reader remains not implemented",
            "Tag action status: not created",
            "GitHub Release action status: not created",
            "Release approval status: pending",
            "requires separate explicit approval",
        ]:
            self.assertIn(required, combined)

        for forbidden in [
            "safe-to-share",
            "safe to share",
            "guaranteed safe",
            "confirmed vulnerability",
            "confirmed finding",
            "confirmed issue count",
            "final CVSS",
            "\"raw_request\"",
            "\"raw_response\"",
            "raw_request:",
            "raw_response:",
            "Cookie:",
            "Authorization:",
            "Bearer ",
            "JWT ",
            "session=",
            "token=",
            "HMAC secret:",
            "CSRF token:",
            "C:\\coding\\",
            "C:\\Users\\",
            "local_only/",
            "real_export_",
            "actual.local",
            "example.com",
            "approved for external sharing",
            "ready to submit",
        ]:
            self.assertNotIn(forbidden, combined)

        self.assertIsNone(re.search(r"https?://", combined))
        self.assertIsNone(re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", combined))

    def test_v061_hotfix_triage_is_patch_scoped_and_raw_free(self) -> None:
        hotfix_triage = V061_HOTFIX_TRIAGE_DOC.read_text(encoding="utf-8")
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        roadmap = ROADMAP_V06_DOC.read_text(encoding="utf-8")

        self.assertTrue(V061_HOTFIX_TRIAGE_DOC.exists())
        for linked_text in [readme, roadmap]:
            self.assertIn("V0.6.1_HOTFIX_TRIAGE.md", linked_text)

        for section in [
            "## Purpose",
            "## v0.6 Release Baseline",
            "## Hotfix Candidate Criteria",
            "## Not A Hotfix",
            "## Required Reproduction Evidence",
            "## Required Security Checks",
            "## Required Release Note Impact Check",
            "## Branch Naming Rule",
            "## PR Size Rule",
            "## Deferred Work",
            "## Explicit Non-Goals",
        ]:
            self.assertIn(section, hotfix_triage)

        for candidate in [
            "Reproducible error discovered after the `v0.6` release",
            "Error that blocks the redaction, verify, review, or report flow",
            "Simple Dashboard copy-only display error",
            "Regression in creating or displaying the four-file output bundle",
            "Broken release body wording, README link, or documentation link",
            "Documentation hygiene issue that affects Gitleaks or git safety results",
        ]:
            self.assertIn(candidate, hotfix_triage)

        for non_goal in [
            "MCP server listener implementation",
            "MCP transport implementation",
            "MCP protocol handler implementation",
            "Executable tool registration",
            "Actual tool execution",
            "Local evidence reader implementation",
            "Raw preview or raw download",
            "Replay or active scan",
            "Automatic ChatGPT handoff",
            "Output bundle four-file structure change",
            "Large refactor",
            "New UX feature",
            "v0.7 scope work",
        ]:
            self.assertIn(non_goal, hotfix_triage)

        for required in [
            "hotfix/v0.6.x-<short-topic>",
            "one reproducible bug",
            "one documentation correction",
            "Release version or tag",
            "Affected command, document, or read-only route alias",
            "Minimal reproduction step summary",
            "Expected result",
            "Actual result summary",
            "Candidate finding wording remains candidate-only",
            "Draft risk wording remains draft-only",
            "Draft report wording remains visible",
            "Severity and CVSS remain manual decisions",
            "Secret scanning remains part of the verification path",
            "No runtime MCP surface added",
            "No new dashboard state-changing action",
        ]:
            self.assertIn(required, hotfix_triage)

        for forbidden in [
            "safe-to-share",
            "safe to share",
            "guaranteed safe",
            "confirmed vulnerability",
            "confirmed finding",
            "confirmed issue count",
            "final CVSS",
            "\"raw_request\"",
            "\"raw_response\"",
            "raw_request:",
            "raw_response:",
            "Cookie:",
            "Authorization:",
            "Bearer ",
            "JWT ",
            "session=",
            "token=",
            "HMAC secret:",
            "CSRF token:",
            "C:\\coding\\",
            "C:\\Users\\",
            "local_only/",
            "real_export_",
            "actual.local",
            "example.com",
            "approved for external sharing",
            "ready to submit",
        ]:
            self.assertNotIn(forbidden, hotfix_triage)

        self.assertIsNone(re.search(r"https?://", hotfix_triage))
        self.assertIsNone(re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", hotfix_triage))

    def test_v07_scope_plan_is_planning_only_and_raw_free(self) -> None:
        scope_plan = V07_SCOPE_PLAN_DOC.read_text(encoding="utf-8")
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        roadmap = ROADMAP_V06_DOC.read_text(encoding="utf-8")
        hotfix_triage = V061_HOTFIX_TRIAGE_DOC.read_text(encoding="utf-8")

        self.assertTrue(V07_SCOPE_PLAN_DOC.exists())
        for linked_text in [readme, roadmap, hotfix_triage]:
            self.assertIn("V0.7_SCOPE_PLAN.md", linked_text)

        for section in [
            "## Purpose",
            "## v0.6 Completed Baseline",
            "## v0.6.1 Hotfix Boundary",
            "## v0.7 Candidate Goals",
            "## v0.7 Non-Goals",
            "## MCP Listener Path",
            "## UX Improvement Path",
            "## Local Evidence Reader Decision Boundary",
            "## PR Split Rules",
            "## Security Review Requirements",
            "## Test Requirements",
            "## Deferred Work",
            "## Explicitly Out of Scope",
        ]:
            self.assertIn(section, scope_plan)

        for required in [
            "Four-file AI input candidate output bundle",
            "findings as candidates",
            "risk values as drafts",
            "final severity and CVSS as manual decisions",
            "hotfix/v0.6.x-<short-topic>",
            "MCP listener skeleton planning",
            "UX Improvement Path",
            "Output bundle usability improvements",
            "Threat boundary decision for local evidence reader work",
            "Listener work must not imply transport, protocol handling, tool execution, or",
            "local evidence reading",
            "Each PR should state whether it changes runtime behavior",
            "Runtime work should include a clear negative test for blocked behavior",
        ]:
            self.assertIn(required, scope_plan)

        for non_goal in [
            "MCP server listener",
            "MCP transport",
            "MCP protocol handler",
            "Executable tool registration",
            "Actual tool execution",
            "Local evidence reader",
            "Safe file body reader",
            "Raw preview or raw download",
            "Replay or active scan",
            "Automatic ChatGPT handoff",
            "`v0.6` tag modification",
            "GitHub Release `v0.6` modification",
            "Output bundle four-file structure change",
            "Large refactor",
        ]:
            self.assertIn(non_goal, scope_plan)

        for split_rule in [
            "MCP listener skeleton",
            "Transport or protocol handler",
            "Executable tool registration",
            "Actual tool execution",
            "Local evidence reader",
            "Raw preview or raw download",
            "Dashboard state-changing action",
            "Upload or import action",
            "Automatic ChatGPT handoff",
            "Large refactor",
            "UX copy-only changes",
        ]:
            self.assertIn(split_rule, scope_plan)

        for forbidden in [
            "safe-to-share",
            "safe to share",
            "guaranteed safe",
            "confirmed vulnerability",
            "confirmed finding",
            "confirmed issue count",
            "final CVSS",
            "\"raw_request\"",
            "\"raw_response\"",
            "raw_request:",
            "raw_response:",
            "Cookie:",
            "Authorization:",
            "Bearer ",
            "JWT ",
            "session=",
            "token=",
            "HMAC secret:",
            "CSRF token:",
            "C:\\coding\\",
            "C:\\Users\\",
            "local_only/",
            "real_export_",
            "actual.local",
            "example.com",
            "approved for external sharing",
            "ready to submit",
        ]:
            self.assertNotIn(forbidden, scope_plan)

        self.assertIsNone(re.search(r"https?://", scope_plan))
        self.assertIsNone(re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", scope_plan))

    def test_v07_mcp_listener_skeleton_plan_is_source_check_only(self) -> None:
        plan = V07_MCP_LISTENER_SKELETON_PLAN_DOC.read_text(encoding="utf-8")
        fixture = json.loads(V07_MCP_LISTENER_SKELETON_PLAN_FIXTURE.read_text(encoding="utf-8"))
        fixture_text = json.dumps(fixture, sort_keys=True)
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        roadmap = ROADMAP_V06_DOC.read_text(encoding="utf-8")
        scope_plan = V07_SCOPE_PLAN_DOC.read_text(encoding="utf-8")

        self.assertTrue(V07_MCP_LISTENER_SKELETON_PLAN_DOC.exists())
        self.assertTrue(V07_MCP_LISTENER_SKELETON_PLAN_FIXTURE.exists())
        for linked_text in [readme, roadmap, scope_plan]:
            self.assertIn("V0.7_MCP_LISTENER_SKELETON_PLAN.md", linked_text)

        for section in [
            "## Purpose",
            "## v0.7 Scope Baseline",
            "## Listener Skeleton Goal",
            "## Non-goals",
            "## Source-check Scope",
            "## Forbidden Source Markers",
            "## Acceptance Criteria",
            "## Required Tests",
            "## PR Split Requirements",
            "## Security Review Checklist",
            "## Deferred Runtime Work",
            "## Explicitly Out of Scope",
        ]:
            self.assertIn(section, plan)

        for required_text in [
            "metadata-only\nmodule boundary",
            "not implementation approval",
            "metadata-only listener skeleton module",
            "No MCP server listener implementation",
            "No MCP transport implementation",
            "No MCP protocol handler implementation",
            "No executable tool registration implementation",
            "No actual tool execution implementation",
            "No local evidence reader implementation",
            "No safe file body reader implementation",
            "No raw preview or raw download implementation",
            "No replay or active scan implementation",
            "No automatic ChatGPT handoff implementation",
            "No v0.6 tag modification",
            "No GitHub Release v0.6 modification",
            "No output bundle four-file structure change",
            "future listener-facing file must be declared",
            "The declared metadata-only listener skeleton module exists",
            "Listener skeleton implementation",
            "Transport or protocol handler",
            "Executable tool registration",
            "Actual tool execution",
            "Local evidence reader",
            "Dashboard state-changing action",
            "Upload or import action",
            "Automatic ChatGPT handoff",
        ]:
            self.assertIn(required_text, plan)

        self.assertEqual(fixture["schema_version"], "v07_mcp_listener_skeleton_plan.v1")
        self.assertIs(fixture["planning_only"], True)
        self.assertIs(fixture["v07_scope_plan_consumed"], True)
        self.assertIs(fixture["source_check_scope_declared"], True)
        self.assertIs(fixture["future_listener_files_must_be_declared"], True)
        self.assertIs(fixture["metadata_only_skeleton_module_declared"], True)

        for blocked_flag in [
            "listener_skeleton_implemented",
            "mcp_server_listener_implemented",
            "transport_implemented",
            "protocol_handler_implemented",
            "executable_tool_registration_implemented",
            "actual_tool_execution_implemented",
            "local_evidence_reader_implemented",
            "safe_file_body_reader_implemented",
            "raw_preview_download_implemented",
            "replay_active_scan_implemented",
            "automatic_chatgpt_handoff_implemented",
            "v06_tag_modified",
            "v06_release_modified",
            "output_bundle_structure_changed",
            "raw_data_included",
        ]:
            self.assertIs(fixture[blocked_flag], False)

        scope = fixture["source_check_scope"]
        expected_helpers = [
            "burp_ai_redaction_gateway/mcp_adapter_dry_run.py",
            "burp_ai_redaction_gateway/mcp_tool_schema_catalog.py",
            "burp_ai_redaction_gateway/mcp_read_only_registry.py",
        ]
        self.assertEqual(scope["existing_pre_runtime_helpers"], expected_helpers)
        self.assertEqual(scope["planned_listener_skeleton_files"], ["burp_ai_redaction_gateway/mcp_listener_skeleton.py"])
        self.assertEqual(scope["existing_excluded_baseline_files"], ["burp_ai_redaction_gateway/mcp_server.py"])

        forbidden_markers = [
            "http.server",
            "socketserver",
            "http.client",
            "socket",
            "subprocess",
            "requests",
            "urllib",
            "bind(",
            "serve_forever",
            "listen(",
            "accept(",
            "run_server",
            "create_server",
            "register_tool",
            "dispatch_tool",
            "tool_execute",
            "execute_tool",
            "read_local_evidence",
            "read_file_body",
        ]
        self.assertEqual(fixture["forbidden_source_markers"], forbidden_markers)

        for source_path in scope["existing_pre_runtime_helpers"]:
            source_file = ROOT / source_path
            self.assertTrue(source_file.exists(), source_path)
            source_text = source_file.read_text(encoding="utf-8")
            for marker in forbidden_markers:
                self.assertNotIn(marker, source_text, f"{marker} found in {source_path}")

        for source_path in scope["planned_listener_skeleton_files"]:
            source_file = ROOT / source_path
            self.assertTrue(source_file.exists(), source_path)
            source_text = source_file.read_text(encoding="utf-8")
            for marker in forbidden_markers:
                self.assertNotIn(marker, source_text, f"{marker} found in {source_path}")

        for source_path in scope["existing_excluded_baseline_files"]:
            self.assertTrue((ROOT / source_path).exists(), source_path)

        combined = plan + "\n" + fixture_text
        for forbidden in [
            "safe-to-share",
            "safe to share",
            "guaranteed safe",
            "confirmed vulnerability",
            "confirmed finding",
            "confirmed issue count",
            "final CVSS",
            "\"raw_request\"",
            "\"raw_response\"",
            "raw_request:",
            "raw_response:",
            "Cookie:",
            "Authorization:",
            "Bearer ",
            "JWT ",
            "session=",
            "token=",
            "HMAC secret:",
            "CSRF token:",
            "C:\\coding\\",
            "C:\\Users\\",
            "local_only/",
            "real_export_",
            "actual.local",
            "example.com",
            "approved for external sharing",
            "ready to submit",
        ]:
            self.assertNotIn(forbidden, combined)

        self.assertIsNone(re.search(r"https?://", combined))
        self.assertIsNone(re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", combined))

    def test_v07_mcp_listener_skeleton_module_is_metadata_only(self) -> None:
        self.assertTrue(MCP_LISTENER_SKELETON_MODULE.exists())
        fixture = json.loads(V07_MCP_LISTENER_SKELETON_PLAN_FIXTURE.read_text(encoding="utf-8"))
        module_text = MCP_LISTENER_SKELETON_MODULE.read_text(encoding="utf-8")
        forbidden_markers = fixture["forbidden_source_markers"]
        for marker in forbidden_markers:
            self.assertNotIn(marker, module_text, f"{marker} found in mcp_listener_skeleton.py")

        metadata = build_listener_skeleton_metadata()
        self.assertEqual(metadata["schema_version"], "v07_mcp_listener_metadata_skeleton.v1")
        self.assertIs(metadata["metadata_only"], True)
        self.assertEqual(
            metadata["output_bundle_files"],
            [
                "analysis_packet.json",
                "chatgpt_prompt.md",
                "codex_task_prompt.md",
                "report_draft.md",
            ],
        )
        self.assertEqual(metadata["allowed_operations"], ["describe_boundary", "build_blocked_response"])
        self.assertEqual(
            metadata["blocked_surfaces"],
            [
                "listener",
                "transport",
                "protocol_handler",
                "tool_registration",
                "tool_execution",
                "local_evidence_reader",
                "raw_preview_download",
                "automatic_chatgpt_handoff",
            ],
        )
        for false_flag in [
            "listener_runtime_enabled",
            "transport_enabled",
            "protocol_handler_enabled",
            "executable_tool_registration_enabled",
            "actual_tool_execution_enabled",
            "local_evidence_reader_enabled",
            "safe_file_body_reader_enabled",
            "raw_preview_download_enabled",
            "automatic_chatgpt_handoff_enabled",
            "raw_data_included",
        ]:
            self.assertIs(metadata[false_flag], False)

        blocked = build_blocked_listener_response("tool_execution_blocked")
        self.assertEqual(
            blocked,
            {
                "status": "blocked",
                "reason_code": "tool_execution_blocked",
                "metadata_only": True,
                "raw_data_included": False,
                "manual_review_required": True,
            },
        )
        unknown = build_blocked_listener_response("unsafe user supplied reason")
        self.assertEqual(unknown["reason_code"], "unknown_blocked_surface")
        self.assertNotIn("unsafe user supplied reason", str(unknown))

        combined = module_text + "\n" + json.dumps(metadata, sort_keys=True) + "\n" + json.dumps(blocked, sort_keys=True)
        for forbidden in [
            "safe-to-share",
            "safe to share",
            "guaranteed safe",
            "confirmed vulnerability",
            "confirmed finding",
            "confirmed issue count",
            "final CVSS",
            "\"raw_request\"",
            "\"raw_response\"",
            "raw_request:",
            "raw_response:",
            "Cookie:",
            "Authorization:",
            "Bearer ",
            "JWT ",
            "session=",
            "token=",
            "HMAC secret:",
            "CSRF token:",
            "C:\\coding\\",
            "C:\\Users\\",
            "local_only/",
            "real_export_",
            "actual.local",
            "example.com",
            "approved for external sharing",
            "ready to submit",
        ]:
            self.assertNotIn(forbidden, combined)
        self.assertIsNone(re.search(r"https?://", combined))
        self.assertIsNone(re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", combined))

    def test_v07_listener_runtime_decision_preflight_is_planning_only(self) -> None:
        preflight = V07_LISTENER_RUNTIME_DECISION_PREFLIGHT_DOC.read_text(encoding="utf-8")
        fixture = json.loads(V07_LISTENER_RUNTIME_DECISION_PREFLIGHT_FIXTURE.read_text(encoding="utf-8"))
        fixture_text = json.dumps(fixture, sort_keys=True)
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        scope_plan = V07_SCOPE_PLAN_DOC.read_text(encoding="utf-8")
        skeleton_plan = V07_MCP_LISTENER_SKELETON_PLAN_DOC.read_text(encoding="utf-8")

        self.assertTrue(V07_LISTENER_RUNTIME_DECISION_PREFLIGHT_DOC.exists())
        self.assertTrue(V07_LISTENER_RUNTIME_DECISION_PREFLIGHT_FIXTURE.exists())
        for linked_text in [readme, scope_plan, skeleton_plan]:
            self.assertIn("V0.7_LISTENER_RUNTIME_DECISION_PREFLIGHT.md", linked_text)

        for section in [
            "## Purpose",
            "## Current Baseline",
            "## Decision Scope",
            "## Explicit Non-goals",
            "## Runtime Preflight Fixture",
            "## Allowed Future Listener Boundary",
            "## Forbidden Runtime Surfaces",
            "## Required Acceptance Criteria",
            "## Required Negative Tests",
            "## Source-check Requirements",
            "## PR Split Requirements",
            "## Deferred Work",
        ]:
            self.assertIn(section, preflight)

        for required_text in [
            "documentation, fixture, and source-check",
            "does not approve that runtime PR",
            "No listener runtime implementation",
            "No socket, bind, listen, or accept implementation",
            "No transport implementation",
            "No protocol handler implementation",
            "No executable tool registration implementation",
            "No actual tool execution implementation",
            "No local evidence reader implementation",
            "No safe file body reader implementation",
            "No raw preview or raw download implementation",
            "No replay or active scan implementation",
            "No automatic ChatGPT handoff implementation",
            "No `v0.6` tag modification",
            "No GitHub Release `v0.6` modification",
            "No output bundle four-file structure change",
            "Source-check is required before runtime",
            "Negative tests are required before runtime",
            "Listener runtime implementation",
            "Transport or protocol handler",
            "Executable tool registration",
            "Actual tool execution",
            "Local evidence reader",
            "Dashboard state-changing action",
            "Upload or import action",
            "Automatic ChatGPT handoff",
        ]:
            self.assertIn(required_text, preflight)

        self.assertEqual(fixture["schema_version"], "v07_listener_runtime_decision_preflight.v1")
        self.assertIs(fixture["planning_only"], True)
        self.assertIs(fixture["metadata_only_skeleton_consumed"], True)
        self.assertIs(fixture["v07_listener_skeleton_plan_consumed"], True)
        self.assertIs(fixture["source_check_required_before_runtime"], True)
        self.assertIs(fixture["negative_tests_required_before_runtime"], True)
        self.assertEqual(
            fixture["existing_metadata_only_files"],
            ["burp_ai_redaction_gateway/mcp_listener_skeleton.py"],
        )

        for blocked_flag in [
            "listener_runtime_approved",
            "listener_runtime_implemented",
            "socket_bind_implemented",
            "socket_listen_implemented",
            "transport_implemented",
            "protocol_handler_implemented",
            "executable_tool_registration_implemented",
            "actual_tool_execution_implemented",
            "local_evidence_reader_implemented",
            "safe_file_body_reader_implemented",
            "raw_preview_download_implemented",
            "replay_active_scan_implemented",
            "automatic_chatgpt_handoff_implemented",
            "v06_tag_modified",
            "v06_release_modified",
            "output_bundle_structure_changed",
            "raw_data_included",
        ]:
            self.assertIs(fixture[blocked_flag], False)

        forbidden_markers = [
            "http.server",
            "socketserver",
            "http.client",
            "socket",
            "subprocess",
            "requests",
            "urllib",
            "bind(",
            "listen(",
            "accept(",
            "serve_forever",
            "run_server",
            "create_server",
            "register_tool",
            "dispatch_tool",
            "tool_execute",
            "execute_tool",
            "read_local_evidence",
            "read_file_body",
        ]
        self.assertEqual(fixture["forbidden_source_markers"], forbidden_markers)

        for source_path in fixture["existing_metadata_only_files"]:
            source_file = ROOT / source_path
            self.assertTrue(source_file.exists(), source_path)
            source_text = source_file.read_text(encoding="utf-8")
            for marker in forbidden_markers:
                self.assertNotIn(marker, source_text, f"{marker} found in {source_path}")

        combined = preflight + "\n" + fixture_text
        for forbidden in [
            "safe-to-share",
            "safe to share",
            "guaranteed safe",
            "confirmed vulnerability",
            "confirmed finding",
            "confirmed issue count",
            "final CVSS",
            "\"raw_request\"",
            "\"raw_response\"",
            "raw_request:",
            "raw_response:",
            "Cookie:",
            "Authorization:",
            "Bearer ",
            "JWT ",
            "session=",
            "token=",
            "HMAC secret:",
            "CSRF token:",
            "C:\\coding\\",
            "C:\\Users\\",
            "local_only/",
            "real_export_",
            "actual.local",
            "example.com",
            "approved for external sharing",
            "ready to submit",
        ]:
            self.assertNotIn(forbidden, combined)
        self.assertIsNone(re.search(r"https?://", combined))
        self.assertIsNone(re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", combined))

    def test_v07_minimal_listener_runtime_approval_packet_is_approval_only(self) -> None:
        packet = V07_MINIMAL_LISTENER_RUNTIME_APPROVAL_PACKET_DOC.read_text(encoding="utf-8")
        fixture = json.loads(V07_MINIMAL_LISTENER_RUNTIME_APPROVAL_PACKET_FIXTURE.read_text(encoding="utf-8"))
        fixture_text = json.dumps(fixture, sort_keys=True)
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        scope_plan = V07_SCOPE_PLAN_DOC.read_text(encoding="utf-8")
        preflight = V07_LISTENER_RUNTIME_DECISION_PREFLIGHT_DOC.read_text(encoding="utf-8")
        skeleton_plan = V07_MCP_LISTENER_SKELETON_PLAN_DOC.read_text(encoding="utf-8")

        self.assertTrue(V07_MINIMAL_LISTENER_RUNTIME_APPROVAL_PACKET_DOC.exists())
        self.assertTrue(V07_MINIMAL_LISTENER_RUNTIME_APPROVAL_PACKET_FIXTURE.exists())
        for linked_text in [readme, scope_plan, preflight, skeleton_plan]:
            self.assertIn("V0.7_MINIMAL_LISTENER_RUNTIME_APPROVAL_PACKET.md", linked_text)

        for section in [
            "## Purpose",
            "## Current Baseline",
            "## Approval Scope",
            "## Explicit Non-goals",
            "## Allowed Future Minimal Listener Boundary",
            "## Required Runtime Constraints",
            "## Required Negative Tests",
            "## Source-check Requirements",
            "## Security Review Checklist",
            "## PR Split Requirements",
            "## Rollback and Disablement Expectations",
            "## Deferred Work",
        ]:
            self.assertIn(section, packet)

        for required_text in [
            "approval evidence required before a separate minimal",
            "does not implement listener",
            "This approval packet does not approve",
            "Listener runtime implementation",
            "Socket bind, listen, or accept implementation",
            "Transport implementation",
            "Protocol handler implementation",
            "Executable tool registration implementation",
            "Actual tool execution implementation",
            "Local evidence reader implementation",
            "Safe file body reader implementation",
            "Raw preview or raw download implementation",
            "Replay or active scan implementation",
            "Automatic ChatGPT handoff implementation",
            "`v0.6` tag modification",
            "GitHub Release `v0.6` modification",
            "Output bundle structure change",
            "Local-only or loopback-only",
            "Disabled by default",
            "protocol parsing beyond blocked placeholder metadata",
            "source-check declared file scope",
            "raw-free error responses",
            "remote_bind_blocked",
            "protocol_message_rejected",
            "tool_registration_absent",
            "tool_execution_absent",
            "local_evidence_read_absent",
            "raw_preview_absent",
            "automatic_handoff_absent",
            "disabled_by_default",
            "A documented disablement path",
        ]:
            self.assertIn(required_text, packet)

        self.assertEqual(fixture["schema_version"], "v07_minimal_listener_runtime_approval_packet.v1")
        self.assertIs(fixture["approval_packet_only"], True)
        for false_flag in [
            "runtime_implementation_approved",
            "listener_runtime_implemented",
            "socket_bind_implemented",
            "socket_listen_implemented",
            "socket_accept_implemented",
            "long_running_server_loop_implemented",
            "transport_implemented",
            "protocol_handler_implemented",
            "executable_tool_registration_implemented",
            "actual_tool_execution_implemented",
            "local_evidence_reader_implemented",
            "safe_file_body_reader_implemented",
            "raw_preview_download_implemented",
            "replay_active_scan_implemented",
            "automatic_chatgpt_handoff_implemented",
            "v06_tag_modified",
            "v06_release_modified",
            "output_bundle_structure_changed",
            "raw_data_included",
        ]:
            self.assertIs(fixture[false_flag], False)

        for true_flag in [
            "metadata_only_skeleton_consumed",
            "runtime_decision_preflight_consumed",
            "negative_tests_required_before_runtime",
            "source_check_required_before_runtime",
            "disabled_by_default_required",
            "local_only_required",
            "raw_free_error_required",
            "rollback_plan_required",
        ]:
            self.assertIs(fixture[true_flag], True)

        self.assertEqual(
            fixture["blocked_future_surfaces"],
            [
                "transport",
                "protocol_handler",
                "tool_registration",
                "tool_execution",
                "local_evidence_reader",
                "raw_preview_download",
                "replay_active_scan",
                "automatic_chatgpt_handoff",
            ],
        )
        self.assertEqual(
            fixture["required_negative_tests"],
            [
                "remote_bind_blocked",
                "protocol_message_rejected",
                "tool_registration_absent",
                "tool_execution_absent",
                "local_evidence_read_absent",
                "raw_preview_absent",
                "automatic_handoff_absent",
                "disabled_by_default",
            ],
        )

        combined = packet + "\n" + fixture_text
        for forbidden in [
            "safe-to-share",
            "safe to share",
            "guaranteed safe",
            "confirmed vulnerability",
            "confirmed finding",
            "confirmed issue count",
            "final CVSS",
            "\"raw_request\"",
            "\"raw_response\"",
            "raw_request:",
            "raw_response:",
            "Cookie:",
            "Authorization:",
            "Bearer ",
            "JWT ",
            "session=",
            "token=",
            "HMAC secret:",
            "CSRF token:",
            "C:\\coding\\",
            "C:\\Users\\",
            "local_only/",
            "real_export_",
            "actual.local",
            "example.com",
            "approved for external sharing",
            "ready to submit",
        ]:
            self.assertNotIn(forbidden, combined)
        self.assertIsNone(re.search(r"https?://", combined))
        self.assertIsNone(re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", combined))

    def test_v07_minimal_listener_runtime_design_is_design_only(self) -> None:
        design = V07_MINIMAL_LISTENER_RUNTIME_DESIGN_DOC.read_text(encoding="utf-8")
        fixture = json.loads(V07_MINIMAL_LISTENER_RUNTIME_DESIGN_FIXTURE.read_text(encoding="utf-8"))
        fixture_text = json.dumps(fixture, sort_keys=True)
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        scope_plan = V07_SCOPE_PLAN_DOC.read_text(encoding="utf-8")
        preflight = V07_LISTENER_RUNTIME_DECISION_PREFLIGHT_DOC.read_text(encoding="utf-8")
        approval = V07_MINIMAL_LISTENER_RUNTIME_APPROVAL_PACKET_DOC.read_text(encoding="utf-8")

        self.assertTrue(V07_MINIMAL_LISTENER_RUNTIME_DESIGN_DOC.exists())
        self.assertTrue(V07_MINIMAL_LISTENER_RUNTIME_DESIGN_FIXTURE.exists())
        for linked_text in [readme, scope_plan, preflight, approval]:
            self.assertIn("V0.7_MINIMAL_LISTENER_RUNTIME_DESIGN.md", linked_text)

        for section in [
            "## Purpose",
            "## Current Baseline",
            "## Design Scope",
            "## Explicit Non-goals",
            "## Allowed Future Listener Runtime Boundary",
            "## Local-only and Loopback-only Constraints",
            "## Disabled-by-default Requirement",
            "## Raw-free Error Behavior",
            "## Source-check Requirements",
            "## Required Negative Tests",
            "## Security Review Checklist",
            "## PR Split Requirements",
            "## Rollback and Disablement Expectations",
            "## Deferred Work",
        ]:
            self.assertIn(section, design)

        for required_text in [
            "documentation, fixture, and test scope only",
            "not implement listener runtime behavior",
            "This design records the constraints",
            "It does not approve that later",
            "No listener runtime implementation",
            "No socket bind, listen, or accept implementation",
            "No long-running server loop",
            "No MCP transport implementation",
            "No MCP protocol handler implementation",
            "No executable tool registration",
            "No actual tool execution",
            "No local evidence reader",
            "No safe file body reader",
            "No raw preview or raw download",
            "No replay or active scan",
            "No automatic ChatGPT handoff",
            "No dashboard start or stop control",
            "No upload or import action",
            "No `v0.6` tag modification",
            "No GitHub Release `v0.6` modification",
            "No new tag or GitHub Release creation",
            "No output bundle structure change",
            "Local-only",
            "Loopback-only",
            "Disabled by default",
            "raw-free blocked and error responses",
            "remote_bind_blocked",
            "disabled_by_default",
            "protocol_message_rejected",
            "transport_absent",
            "tool_registration_absent",
            "tool_execution_absent",
            "local_evidence_read_absent",
            "raw_preview_absent",
            "automatic_handoff_absent",
            "dashboard_control_absent",
        ]:
            self.assertIn(required_text, design)

        self.assertEqual(fixture["schema_version"], "v07_minimal_listener_runtime_design.v1")
        self.assertIs(fixture["design_only"], True)

        for false_flag in [
            "runtime_implementation_included",
            "listener_runtime_approved_for_next_pr",
            "socket_bind_implemented",
            "socket_listen_implemented",
            "socket_accept_implemented",
            "long_running_server_loop_implemented",
            "transport_implemented",
            "protocol_handler_implemented",
            "executable_tool_registration_implemented",
            "actual_tool_execution_implemented",
            "local_evidence_reader_implemented",
            "safe_file_body_reader_implemented",
            "raw_preview_download_implemented",
            "replay_active_scan_implemented",
            "automatic_chatgpt_handoff_implemented",
            "dashboard_state_changing_control_implemented",
            "upload_import_action_implemented",
            "v06_tag_modified",
            "v06_release_modified",
            "new_tag_or_release_created",
            "output_bundle_structure_changed",
        ]:
            self.assertIs(fixture[false_flag], False)

        for true_flag in [
            "local_only_required",
            "loopback_only_required",
            "disabled_by_default_required",
            "raw_free_error_required",
            "source_check_required",
            "negative_tests_required",
            "rollback_plan_required",
        ]:
            self.assertIs(fixture[true_flag], True)

        self.assertEqual(
            fixture["required_negative_tests"],
            [
                "remote_bind_blocked",
                "disabled_by_default",
                "protocol_message_rejected",
                "transport_absent",
                "tool_registration_absent",
                "tool_execution_absent",
                "local_evidence_read_absent",
                "raw_preview_absent",
                "automatic_handoff_absent",
                "dashboard_control_absent",
            ],
        )
        self.assertEqual(
            fixture["blocked_surfaces"],
            [
                "transport",
                "protocol_handler",
                "tool_registration",
                "tool_execution",
                "local_evidence_reader",
                "safe_file_body_reader",
                "raw_preview_download",
                "replay_active_scan",
                "automatic_chatgpt_handoff",
                "dashboard_state_changing_control",
                "upload_import_action",
            ],
        )

        combined = design + "\n" + fixture_text
        for forbidden in [
            "safe-to-share",
            "safe to share",
            "guaranteed safe",
            "confirmed vulnerability",
            "confirmed finding",
            "confirmed issue count",
            "final CVSS",
            "\"raw_request\"",
            "\"raw_response\"",
            "raw_request:",
            "raw_response:",
            "Cookie:",
            "Authorization:",
            "Bearer ",
            "JWT ",
            "session=",
            "token=",
            "HMAC secret:",
            "CSRF token:",
            "C:\\coding\\",
            "C:\\Users\\",
            "local_only/",
            "real_export_",
            "actual.local",
            "example.com",
            "approved for external sharing",
            "ready to submit",
        ]:
            self.assertNotIn(forbidden, combined)
        self.assertIsNone(re.search(r"https?://", combined))
        self.assertIsNone(re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", combined))

    def test_v07_runtime_source_check_consumption_blocks_drift(self) -> None:
        consumption_doc = V07_RUNTIME_SOURCE_CHECK_CONSUMPTION_DOC.read_text(encoding="utf-8")
        fixture = json.loads(V07_RUNTIME_SOURCE_CHECK_CONSUMPTION_FIXTURE.read_text(encoding="utf-8"))
        fixture_text = json.dumps(fixture, sort_keys=True)
        design_fixture = json.loads(V07_MINIMAL_LISTENER_RUNTIME_DESIGN_FIXTURE.read_text(encoding="utf-8"))
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        scope_plan = V07_SCOPE_PLAN_DOC.read_text(encoding="utf-8")
        design_doc = V07_MINIMAL_LISTENER_RUNTIME_DESIGN_DOC.read_text(encoding="utf-8")
        approval = V07_MINIMAL_LISTENER_RUNTIME_APPROVAL_PACKET_DOC.read_text(encoding="utf-8")
        implementation_doc = V07_MINIMAL_LISTENER_RUNTIME_IMPLEMENTATION_DOC.read_text(encoding="utf-8")

        self.assertTrue(V07_RUNTIME_SOURCE_CHECK_CONSUMPTION_DOC.exists())
        self.assertTrue(V07_RUNTIME_SOURCE_CHECK_CONSUMPTION_FIXTURE.exists())
        for linked_text in [readme, scope_plan, design_doc, approval, implementation_doc]:
            self.assertIn("V0.7_RUNTIME_SOURCE_CHECK_CONSUMPTION.md", linked_text)

        for section in [
            "## Purpose",
            "## Current Baseline",
            "## Consumed Fixtures",
            "## Runtime-facing Source Scope",
            "## Existing Allowed Metadata-only Files",
            "## Existing Excluded Baseline Files",
            "## Forbidden Source Markers",
            "## Required Consumption Checks",
            "## Negative Expectations",
            "## PR Split Requirements",
            "## Explicit Non-goals",
            "## Deferred Work",
        ]:
            self.assertIn(section, consumption_doc)

        for required_text in [
            "documentation, fixture, and test scope only",
            "cannot bypass the declared source-check",
            "v07_minimal_listener_runtime_design.json",
            "v07_minimal_listener_runtime_approval_packet.json",
            "v07_listener_runtime_decision_preflight.json",
            "v07_mcp_listener_skeleton_plan.json",
            "v07_runtime_source_check_consumption.json",
            "V0.7_MINIMAL_LISTENER_RUNTIME_IMPLEMENTATION.md",
            "burp_ai_redaction_gateway/mcp_listener_skeleton.py",
            "burp_ai_redaction_gateway/mcp_listener_runtime.py",
            "burp_ai_redaction_gateway/mcp_server.py",
            "Future runtime-facing files must be declared",
            "No socket bind, listen, or accept implementation",
            "No long-running server loop",
            "No transport implementation",
            "No protocol handler implementation",
            "No executable tool registration",
            "No actual tool execution",
            "No local evidence reader",
            "No safe file body reader",
            "No raw preview or raw download",
            "No replay or active scan",
            "No automatic ChatGPT handoff",
            "No dashboard state-changing control",
            "No upload or import action",
            "No `v0.6` tag modification",
            "No GitHub Release `v0.6` modification",
            "No new tag or GitHub Release creation",
            "Allowed metadata-only blocked-surface labels do not count as implementation",
        ]:
            self.assertIn(required_text, consumption_doc)

        self.assertEqual(fixture["schema_version"], "v07_runtime_source_check_consumption.v1")
        self.assertIs(fixture["consumption_guard_only"], True)

        for true_flag in [
            "design_fixture_consumed",
            "approval_packet_consumed",
            "runtime_decision_preflight_consumed",
            "metadata_only_skeleton_consumed",
            "source_check_required",
            "fail_on_undeclared_runtime_facing_file",
            "future_runtime_files_must_be_declared",
        ]:
            self.assertIs(fixture[true_flag], True)

        for false_flag in [
            "runtime_implementation_included",
            "listener_runtime_approved_for_next_pr",
            "socket_bind_implemented",
            "socket_listen_implemented",
            "socket_accept_implemented",
            "long_running_server_loop_implemented",
            "transport_implemented",
            "protocol_handler_implemented",
            "executable_tool_registration_implemented",
            "actual_tool_execution_implemented",
            "local_evidence_reader_implemented",
            "safe_file_body_reader_implemented",
            "raw_preview_download_implemented",
            "replay_active_scan_implemented",
            "automatic_chatgpt_handoff_implemented",
            "dashboard_state_changing_control_implemented",
            "upload_import_action_implemented",
            "v06_tag_modified",
            "v06_release_modified",
            "new_tag_or_release_created",
        ]:
            self.assertIs(fixture[false_flag], False)

        self.assertEqual(
            fixture["declared_runtime_facing_source_scope"],
            [
                "burp_ai_redaction_gateway/mcp_listener_skeleton.py",
                "burp_ai_redaction_gateway/mcp_listener_runtime.py",
                "burp_ai_redaction_gateway/mcp_minimal_skeleton.py",
                "burp_ai_redaction_gateway/mcp_protocol_parser.py",
                "burp_ai_redaction_gateway/mcp_runtime_contract.py",
            ],
        )
        self.assertEqual(fixture["planned_runtime_files"], ["burp_ai_redaction_gateway/mcp_listener_runtime.py"])
        self.assertEqual(
            fixture["existing_excluded_baseline_files"],
            ["burp_ai_redaction_gateway/mcp_server.py"],
        )
        self.assertEqual(
            fixture["runtime_facing_filename_markers"],
            [
                "mcp_listener",
                "listener_skeleton",
                "runtime_listener",
                "mcp_runtime",
                "mcp_transport",
                "mcp_protocol",
                "tool_registration",
                "tool_execution",
                "evidence_reader",
                "file_body_reader",
            ],
        )
        self.assertEqual(
            fixture["blocked_surfaces"],
            [
                "transport",
                "protocol_handler",
                "tool_registration",
                "tool_execution",
                "local_evidence_reader",
                "safe_file_body_reader",
                "raw_preview_download",
                "replay_active_scan",
                "automatic_chatgpt_handoff",
                "dashboard_state_changing_control",
                "upload_import_action",
            ],
        )
        self.assertTrue(set(design_fixture["blocked_surfaces"]).issubset(set(fixture["blocked_surfaces"])))
        self.assertEqual(
            fixture["allowed_metadata_only_marker_values"],
            [
                "raw_preview_download",
                "raw_preview_download_blocked",
                "raw_preview_download_enabled",
            ],
        )

        forbidden_markers = [
            "http.server",
            "socketserver",
            "http.client",
            "socket",
            "subprocess",
            "requests",
            "urllib",
            "bind(",
            "listen(",
            "accept(",
            "serve_forever",
            "run_server",
            "create_server",
            "register_tool",
            "dispatch_tool",
            "tool_execute",
            "execute_tool",
            "read_local_evidence",
            "read_file_body",
            "raw_preview",
            "replay",
            "active_scan",
        ]
        self.assertEqual(fixture["forbidden_source_markers"], forbidden_markers)

        declared_scope = set(fixture["declared_runtime_facing_source_scope"])
        excluded_scope = set(fixture["existing_excluded_baseline_files"])
        runtime_markers = fixture["runtime_facing_filename_markers"]
        undeclared_runtime_facing_files: list[str] = []
        for source_file in (ROOT / "burp_ai_redaction_gateway").rglob("*.py"):
            relative_source = source_file.relative_to(ROOT).as_posix()
            normalized_source = relative_source.lower()
            if relative_source in excluded_scope:
                continue
            if any(marker in normalized_source for marker in runtime_markers):
                if relative_source not in declared_scope:
                    undeclared_runtime_facing_files.append(relative_source)
                else:
                    source_text = source_file.read_text(encoding="utf-8")
                    source_text_for_scan = source_text
                    for allowed_marker in fixture["allowed_metadata_only_marker_values"]:
                        source_text_for_scan = source_text_for_scan.replace(allowed_marker, "")
                    for marker in forbidden_markers:
                        self.assertNotIn(marker, source_text_for_scan, f"{marker} found in {relative_source}")
        self.assertEqual(undeclared_runtime_facing_files, [])

        for source_path in declared_scope:
            self.assertTrue((ROOT / source_path).exists(), source_path)
        for source_path in excluded_scope:
            self.assertTrue((ROOT / source_path).exists(), source_path)

        combined = consumption_doc + "\n" + fixture_text
        for forbidden in [
            "safe-to-share",
            "safe to share",
            "guaranteed safe",
            "confirmed vulnerability",
            "confirmed finding",
            "confirmed issue count",
            "final CVSS",
            "\"raw_request\"",
            "\"raw_response\"",
            "raw_request:",
            "raw_response:",
            "Cookie:",
            "Authorization:",
            "Bearer ",
            "JWT ",
            "session=",
            "token=",
            "HMAC secret:",
            "CSRF token:",
            "C:\\coding\\",
            "C:\\Users\\",
            "local_only/",
            "real_export_",
            "actual.local",
            "example.com",
            "approved for external sharing",
            "ready to submit",
        ]:
            self.assertNotIn(forbidden, combined)
        self.assertIsNone(re.search(r"https?://", combined))
        self.assertIsNone(re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", combined))

    def test_v07_listener_negative_test_harness_design_is_design_only(self) -> None:
        harness_doc = V07_LISTENER_NEGATIVE_TEST_HARNESS_DESIGN_DOC.read_text(encoding="utf-8")
        fixture = json.loads(V07_LISTENER_NEGATIVE_TEST_HARNESS_DESIGN_FIXTURE.read_text(encoding="utf-8"))
        fixture_text = json.dumps(fixture, sort_keys=True)
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        scope_plan = V07_SCOPE_PLAN_DOC.read_text(encoding="utf-8")
        design_doc = V07_MINIMAL_LISTENER_RUNTIME_DESIGN_DOC.read_text(encoding="utf-8")
        consumption_doc = V07_RUNTIME_SOURCE_CHECK_CONSUMPTION_DOC.read_text(encoding="utf-8")
        consumption_fixture = json.loads(V07_RUNTIME_SOURCE_CHECK_CONSUMPTION_FIXTURE.read_text(encoding="utf-8"))

        self.assertTrue(V07_LISTENER_NEGATIVE_TEST_HARNESS_DESIGN_DOC.exists())
        self.assertTrue(V07_LISTENER_NEGATIVE_TEST_HARNESS_DESIGN_FIXTURE.exists())
        for linked_text in [readme, scope_plan, design_doc, consumption_doc]:
            self.assertIn("V0.7_LISTENER_NEGATIVE_TEST_HARNESS_DESIGN.md", linked_text)

        for section in [
            "## Purpose",
            "## Current Baseline",
            "## Harness Scope",
            "## Explicit Non-goals",
            "## Required Negative Tests",
            "## Expected Blocked Responses",
            "## Source-check Requirements",
            "## Security Review Checklist",
            "## PR Split Requirements",
            "## Rollback and Disablement Expectations",
            "## Deferred Work",
        ]:
            self.assertIn(section, harness_doc)

        for required_text in [
            "documentation, fixture, and test scope only",
            "does not implement listener runtime behavior",
            "raw-free blocked and disabled responses",
            "V0.7_RUNTIME_SOURCE_CHECK_CONSUMPTION.md",
            "No listener runtime implementation",
            "No socket bind, listen, or accept implementation",
            "No long-running server loop",
            "No MCP transport implementation",
            "No MCP protocol handler implementation",
            "No executable tool registration",
            "No actual tool execution",
            "No local evidence reader",
            "No safe file body reader",
            "No raw preview or raw download",
            "No replay or active scan",
            "No automatic ChatGPT handoff",
            "No dashboard start or stop control",
            "No upload or import action",
            "No `v0.6` tag modification",
            "No GitHub Release `v0.6` modification",
            "No new tag or GitHub Release creation",
            "No output bundle structure change",
        ]:
            self.assertIn(required_text, harness_doc)

        self.assertEqual(fixture["schema_version"], "v07_listener_negative_test_harness_design.v1")
        for true_flag in [
            "design_only",
            "negative_harness_only",
            "source_check_consumption_guard_consumed",
            "minimal_listener_runtime_design_consumed",
            "disabled_by_default_required",
            "local_only_required",
            "loopback_only_required",
            "raw_free_error_required",
            "negative_tests_required",
            "source_check_required",
            "rollback_plan_required",
        ]:
            self.assertIs(fixture[true_flag], True)

        for false_flag in [
            "runtime_implementation_included",
            "listener_runtime_approved_for_next_pr",
            "listener_runtime_implemented",
            "socket_bind_implemented",
            "socket_listen_implemented",
            "socket_accept_implemented",
            "long_running_server_loop_implemented",
            "transport_implemented",
            "protocol_handler_implemented",
            "executable_tool_registration_implemented",
            "actual_tool_execution_implemented",
            "local_evidence_reader_implemented",
            "safe_file_body_reader_implemented",
            "raw_preview_download_implemented",
            "replay_active_scan_implemented",
            "automatic_chatgpt_handoff_implemented",
            "dashboard_state_changing_control_implemented",
            "upload_import_action_implemented",
            "v06_tag_modified",
            "v06_release_modified",
            "new_tag_or_release_created",
            "output_bundle_structure_changed",
        ]:
            self.assertIs(fixture[false_flag], False)

        required_negative_tests = [
            "remote_bind_blocked",
            "non_loopback_host_rejected",
            "disabled_by_default",
            "protocol_message_rejected",
            "transport_absent",
            "tool_registration_absent",
            "tool_execution_absent",
            "local_evidence_read_absent",
            "safe_file_body_read_absent",
            "raw_preview_absent",
            "replay_active_scan_absent",
            "automatic_handoff_absent",
            "dashboard_control_absent",
            "upload_import_absent",
        ]
        self.assertEqual(fixture["required_negative_tests"], required_negative_tests)
        for test_name in required_negative_tests:
            self.assertIn(f"`{test_name}`", harness_doc)

        self.assertEqual(
            fixture["expected_blocked_response_fields"],
            [
                "status",
                "reason_code",
                "raw_data_included",
                "manual_review_required",
                "metadata_only",
            ],
        )
        self.assertIn("Use stable `blocked` or `disabled` status codes", harness_doc)
        self.assertIn("Set `raw_data_included` to `false`", harness_doc)
        self.assertIn("Set `manual_review_required` to `true`", harness_doc)

        self.assertEqual(
            fixture["forbidden_response_markers"],
            [
                "caller body echo",
                "target identifier",
                "url value",
                "ip address value",
                "credential value",
                "local path value",
                "stack trace body",
                "safe file body preview",
            ],
        )
        harness_doc_lower = harness_doc.lower()
        for marker in fixture["forbidden_response_markers"]:
            self.assertIn(marker, harness_doc_lower)

        self.assertEqual(
            fixture["blocked_surfaces"],
            [
                "remote_bind",
                "non_loopback_host",
                "protocol_message",
                "protocol_handler",
                "transport",
                "tool_registration",
                "tool_execution",
                "local_evidence_reader",
                "safe_file_body_reader",
                "raw_preview_download",
                "replay_active_scan",
                "automatic_chatgpt_handoff",
                "dashboard_state_changing_control",
                "upload_import_action",
            ],
        )
        self.assertTrue(set(consumption_fixture["blocked_surfaces"]).issubset(set(fixture["blocked_surfaces"])))

        combined = harness_doc + "\n" + fixture_text
        for forbidden in [
            "safe-to-share",
            "safe to share",
            "guaranteed safe",
            "confirmed vulnerability",
            "confirmed finding",
            "confirmed issue count",
            "final CVSS",
            "\"raw_request\"",
            "\"raw_response\"",
            "raw_request:",
            "raw_response:",
            "Cookie:",
            "Authorization:",
            "Bearer ",
            "JWT ",
            "session=",
            "token=",
            "HMAC secret:",
            "CSRF token:",
            "C:\\coding\\",
            "C:\\Users\\",
            "local_only/",
            "real_export_",
            "actual.local",
            "example.com",
            "approved for external sharing",
            "ready to submit",
        ]:
            self.assertNotIn(forbidden, combined)
        self.assertIsNone(re.search(r"https?://", combined))
        self.assertIsNone(re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", combined))

    def test_v07_minimal_listener_runtime_implementation_decision_is_decision_only(self) -> None:
        decision_doc = V07_MINIMAL_LISTENER_RUNTIME_IMPLEMENTATION_DECISION_DOC.read_text(encoding="utf-8")
        fixture = json.loads(V07_MINIMAL_LISTENER_RUNTIME_IMPLEMENTATION_DECISION_FIXTURE.read_text(encoding="utf-8"))
        fixture_text = json.dumps(fixture, sort_keys=True)
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        scope_plan = V07_SCOPE_PLAN_DOC.read_text(encoding="utf-8")
        design_doc = V07_MINIMAL_LISTENER_RUNTIME_DESIGN_DOC.read_text(encoding="utf-8")
        consumption_doc = V07_RUNTIME_SOURCE_CHECK_CONSUMPTION_DOC.read_text(encoding="utf-8")
        harness_doc = V07_LISTENER_NEGATIVE_TEST_HARNESS_DESIGN_DOC.read_text(encoding="utf-8")
        harness_fixture = json.loads(V07_LISTENER_NEGATIVE_TEST_HARNESS_DESIGN_FIXTURE.read_text(encoding="utf-8"))

        self.assertTrue(V07_MINIMAL_LISTENER_RUNTIME_IMPLEMENTATION_DECISION_DOC.exists())
        self.assertTrue(V07_MINIMAL_LISTENER_RUNTIME_IMPLEMENTATION_DECISION_FIXTURE.exists())
        for linked_text in [readme, scope_plan, design_doc, consumption_doc, harness_doc]:
            self.assertIn("V0.7_MINIMAL_LISTENER_RUNTIME_IMPLEMENTATION_DECISION.md", linked_text)

        for section in [
            "## Purpose",
            "## Current Baseline",
            "## Implementation Decision",
            "## Required Preconditions",
            "## Allowed Next PR Scope",
            "## Explicit Non-goals",
            "## Required Negative Tests for Implementation PR",
            "## Required Source-check Consumption",
            "## Required Security Review",
            "## Required Rollback and Disablement",
            "## PR Split Requirements",
            "## Deferred Work",
        ]:
            self.assertIn(section, decision_doc)

        for required_text in [
            "documentation, fixture, and test scope only",
            "does not implement listener runtime behavior",
            "`minimal_listener_runtime_may_be_proposed_next: true`",
            "This PR itself is not runtime implementation",
            "The next implementation PR must be local-only",
            "The next implementation PR must be loopback-only",
            "The next implementation PR must be disabled by default",
            "The next implementation PR must not include transport",
            "The next implementation PR must not include protocol handling",
            "The next implementation PR must not include executable tool registration",
            "The next implementation PR must not include actual tool execution",
            "The next implementation PR must not include local evidence reading",
            "V0.7_LISTENER_NEGATIVE_TEST_HARNESS_DESIGN.md",
            "V0.7_RUNTIME_SOURCE_CHECK_CONSUMPTION.md",
            "No listener runtime implementation",
            "No socket bind, listen, or accept implementation",
            "No long-running server loop",
            "No MCP transport implementation",
            "No MCP protocol handler implementation",
            "No executable tool registration",
            "No actual tool execution",
            "No local evidence reader",
            "No safe file body reader",
            "No raw preview or raw download",
            "No replay or active scan",
            "No automatic ChatGPT handoff",
            "No dashboard start or stop control",
            "No upload or import action",
            "No `v0.6` tag modification",
            "No GitHub Release `v0.6` modification",
            "No new tag or GitHub Release creation",
            "No output bundle structure change",
        ]:
            self.assertIn(required_text, decision_doc)

        self.assertEqual(fixture["schema_version"], "v07_minimal_listener_runtime_implementation_decision.v1")
        for true_flag in [
            "decision_only",
            "minimal_listener_runtime_may_be_proposed_next",
            "implementation_requires_explicit_followup_pr",
            "source_check_consumption_guard_consumed",
            "negative_harness_design_consumed",
            "minimal_listener_runtime_design_consumed",
            "approval_packet_consumed",
            "disabled_by_default_required",
            "local_only_required",
            "loopback_only_required",
            "raw_free_error_required",
            "source_check_required",
            "negative_tests_required",
            "rollback_plan_required",
        ]:
            self.assertIs(fixture[true_flag], True)

        for false_flag in [
            "runtime_implementation_included",
            "listener_runtime_implemented",
            "socket_bind_implemented",
            "socket_listen_implemented",
            "socket_accept_implemented",
            "long_running_server_loop_implemented",
            "transport_implemented",
            "protocol_handler_implemented",
            "executable_tool_registration_implemented",
            "actual_tool_execution_implemented",
            "local_evidence_reader_implemented",
            "safe_file_body_reader_implemented",
            "raw_preview_download_implemented",
            "replay_active_scan_implemented",
            "automatic_chatgpt_handoff_implemented",
            "dashboard_state_changing_control_implemented",
            "upload_import_action_implemented",
            "v06_tag_modified",
            "v06_release_modified",
            "new_tag_or_release_created",
            "output_bundle_structure_changed",
        ]:
            self.assertIs(fixture[false_flag], False)

        self.assertEqual(
            fixture["allowed_next_pr_scope"],
            [
                "minimal_listener_runtime_only",
                "local_loopback_binding_only",
                "disabled_by_default_only",
                "raw_free_blocked_response_only",
                "source_check_consumption_tests",
                "negative_tests_from_fixture",
                "local_smoke_only",
            ],
        )
        self.assertEqual(
            fixture["blocked_next_pr_scope"],
            [
                "remote_bind",
                "non_loopback_host",
                "protocol_message",
                "transport",
                "protocol_handler",
                "tool_registration",
                "tool_execution",
                "local_evidence_reader",
                "safe_file_body_reader",
                "raw_preview_download",
                "replay_active_scan",
                "automatic_chatgpt_handoff",
                "dashboard_state_changing_control",
                "upload_import_action",
                "output_bundle_structure_change",
                "tag_or_release_action",
            ],
        )
        self.assertTrue(set(harness_fixture["blocked_surfaces"]).issubset(set(fixture["blocked_next_pr_scope"])))
        for allowed in fixture["allowed_next_pr_scope"]:
            self.assertIn(allowed, decision_doc)
        for blocked in fixture["blocked_next_pr_scope"]:
            self.assertIn(blocked, fixture_text)

        for test_name in harness_fixture["required_negative_tests"]:
            self.assertIn(f"`{test_name}`", decision_doc)

        combined = decision_doc + "\n" + fixture_text
        for forbidden in [
            "safe-to-share",
            "safe to share",
            "guaranteed safe",
            "confirmed vulnerability",
            "confirmed finding",
            "confirmed issue count",
            "final CVSS",
            "\"raw_request\"",
            "\"raw_response\"",
            "raw_request:",
            "raw_response:",
            "Cookie:",
            "Authorization:",
            "Bearer ",
            "JWT ",
            "session=",
            "token=",
            "HMAC secret:",
            "CSRF token:",
            "C:\\coding\\",
            "C:\\Users\\",
            "local_only/",
            "real_export_",
            "actual.local",
            "example.com",
            "approved for external sharing",
            "ready to submit",
        ]:
            self.assertNotIn(forbidden, combined)
        self.assertIsNone(re.search(r"https?://", combined))
        self.assertIsNone(re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", combined))

    def test_v07_minimal_listener_runtime_implementation_is_guarded(self) -> None:
        implementation_doc = V07_MINIMAL_LISTENER_RUNTIME_IMPLEMENTATION_DOC.read_text(encoding="utf-8")
        fixture = json.loads(V07_MINIMAL_LISTENER_RUNTIME_IMPLEMENTATION_FIXTURE.read_text(encoding="utf-8"))
        fixture_text = json.dumps(fixture, sort_keys=True)
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        scope_plan = V07_SCOPE_PLAN_DOC.read_text(encoding="utf-8")
        decision_doc = V07_MINIMAL_LISTENER_RUNTIME_IMPLEMENTATION_DECISION_DOC.read_text(encoding="utf-8")
        source_check_doc = V07_RUNTIME_SOURCE_CHECK_CONSUMPTION_DOC.read_text(encoding="utf-8")
        harness_doc = V07_LISTENER_NEGATIVE_TEST_HARNESS_DESIGN_DOC.read_text(encoding="utf-8")
        source_check_fixture = json.loads(V07_RUNTIME_SOURCE_CHECK_CONSUMPTION_FIXTURE.read_text(encoding="utf-8"))
        harness_fixture = json.loads(V07_LISTENER_NEGATIVE_TEST_HARNESS_DESIGN_FIXTURE.read_text(encoding="utf-8"))

        self.assertTrue(V07_MINIMAL_LISTENER_RUNTIME_IMPLEMENTATION_DOC.exists())
        self.assertTrue(V07_MINIMAL_LISTENER_RUNTIME_IMPLEMENTATION_FIXTURE.exists())
        self.assertTrue(MCP_LISTENER_RUNTIME_MODULE.exists())
        for linked_text in [readme, scope_plan, decision_doc, source_check_doc, harness_doc]:
            self.assertIn("V0.7_MINIMAL_LISTENER_RUNTIME_IMPLEMENTATION.md", linked_text)

        for section in [
            "## Purpose",
            "## Implemented Boundary",
            "## Disabled-by-default Behavior",
            "## Loopback-only Behavior",
            "## Raw-free Response Contract",
            "## Source-check Consumption",
            "## Negative Tests",
            "## Explicit Non-goals",
            "## Local Smoke",
            "## Deferred Work",
        ]:
            self.assertIn(section, implementation_doc)

        for required_text in [
            "disabled-by-default",
            "loopback-only",
            "raw-free blocked or disabled response",
            "burp_ai_redaction_gateway/mcp_listener_runtime.py",
            "transport, protocol handling, executable tool registration, actual tool execution",
            "local evidence reading, safe file body reading",
            "dashboard state-changing control",
            "upload or import action",
            "automatic ChatGPT handoff",
            "No MCP transport implementation",
            "No MCP protocol handler implementation",
            "No JSON-RPC parser implementation",
            "No executable tool registration",
            "No actual tool execution",
            "No local evidence reader",
            "No safe file body reader",
            "No raw preview or raw download",
            "No replay or active scan",
            "No automatic ChatGPT handoff",
            "No dashboard start or stop control",
            "No upload or import action",
            "No arbitrary local file read",
            "No external network call",
            "No environment secret access",
            "No `v0.6` tag modification",
            "No GitHub Release `v0.6` modification",
            "No new tag or GitHub Release creation",
            "No output bundle structure change",
        ]:
            self.assertIn(required_text, implementation_doc)

        self.assertEqual(fixture["schema_version"], "v07_minimal_listener_runtime_implementation.v1")
        for true_flag in [
            "minimal_listener_runtime_implemented",
            "disabled_by_default",
            "local_only",
            "loopback_only",
            "raw_free_blocked_response",
            "source_check_consumed",
            "negative_harness_consumed",
            "implementation_decision_consumed",
            "disabled_first_input_handling",
            "all_interface_hosts_blocked",
            "status_allowlist_enforced",
        ]:
            self.assertIs(fixture[true_flag], True)

        for false_flag in [
            "listener_started_by_helper",
            "long_running_server_loop_implemented",
            "transport_implemented",
            "protocol_handler_implemented",
            "tool_registration_implemented",
            "tool_execution_implemented",
            "local_evidence_reader_implemented",
            "safe_file_body_reader_implemented",
            "raw_preview_download_implemented",
            "replay_active_scan_implemented",
            "automatic_chatgpt_handoff_implemented",
            "dashboard_state_changing_control_implemented",
            "upload_import_action_implemented",
            "external_network_call_implemented",
            "arbitrary_local_file_read_implemented",
            "environment_secret_access_implemented",
            "v06_tag_modified",
            "v06_release_modified",
            "new_tag_or_release_created",
            "output_bundle_structure_changed",
        ]:
            self.assertIs(fixture[false_flag], False)

        self.assertEqual(fixture["runtime_module"], "burp_ai_redaction_gateway/mcp_listener_runtime.py")
        self.assertIn(fixture["runtime_module"], source_check_fixture["declared_runtime_facing_source_scope"])
        self.assertIn(fixture["runtime_module"], source_check_fixture["planned_runtime_files"])
        self.assertEqual(fixture["required_negative_tests"], harness_fixture["required_negative_tests"])
        self.assertEqual(fixture["allowed_statuses"], ["disabled", "blocked", "ready"])

        default_config = build_default_listener_runtime_config()
        self.assertIs(default_config.enabled, False)
        self.assertEqual(default_config.host, "localhost")
        self.assertIs(is_loopback_host("localhost"), True)
        self.assertIs(is_loopback_host("::1"), True)
        self.assertIs(is_loopback_host("remote-host"), False)
        self.assertIs(is_all_interface_host(""), True)
        self.assertIs(is_all_interface_host("*"), True)
        self.assertIs(is_all_interface_host("0.0.0.0"), True)
        self.assertIs(is_all_interface_host("::"), True)
        self.assertIs(is_all_interface_host("[::]"), True)
        self.assertIs(is_all_interface_host("localhost"), False)

        metadata = build_listener_runtime_metadata()
        self.assertEqual(metadata["schema_version"], "v07_minimal_listener_runtime.v1")
        self.assertIs(metadata["minimal_listener_runtime_implemented"], True)
        self.assertIs(metadata["listener_started"], False)
        self.assertEqual(
            metadata["output_bundle_files"],
            [
                "analysis_packet.json",
                "chatgpt_prompt.md",
                "codex_task_prompt.md",
                "report_draft.md",
            ],
        )

        disabled_response = validate_minimal_listener_startup()
        self.assertEqual(disabled_response["status"], "disabled")
        self.assertEqual(disabled_response["reason_code"], "listener_disabled")
        self.assertIs(disabled_response["raw_data_included"], False)
        self.assertIs(disabled_response["manual_review_required"], True)
        self.assertIs(disabled_response["listener_started"], False)
        self.assertIs(disabled_response["startup_permitted"], False)

        local_response = validate_minimal_listener_startup(
            MinimalListenerRuntimeConfig(enabled=True, host="localhost")
        )
        self.assertEqual(local_response["status"], "ready")
        self.assertEqual(local_response["reason_code"], "local_loopback_validation_passed")
        self.assertIs(local_response["startup_permitted"], True)
        self.assertIs(local_response["listener_started"], False)

        remote_bind_response = validate_minimal_listener_startup(MinimalListenerRuntimeConfig(enabled=True, host="*"))
        self.assertEqual(remote_bind_response["status"], "blocked")
        self.assertEqual(remote_bind_response["reason_code"], "remote_bind_blocked")

        non_loopback_response = validate_minimal_listener_startup(
            MinimalListenerRuntimeConfig(enabled=True, host="remote-host")
        )
        self.assertEqual(non_loopback_response["status"], "blocked")
        self.assertEqual(non_loopback_response["reason_code"], "non_loopback_host_rejected")

        caller_body = {"jsonrpc": "2.0", "method": "caller_controlled_value"}
        disabled_protocol_response = validate_minimal_listener_startup(
            MinimalListenerRuntimeConfig(enabled=False, host="localhost"),
            input_body=caller_body,
        )
        self.assertEqual(disabled_protocol_response["status"], "disabled")
        self.assertEqual(disabled_protocol_response["reason_code"], "listener_disabled")

        protocol_response = validate_minimal_listener_startup(
            MinimalListenerRuntimeConfig(enabled=True, host="localhost"),
            input_body=caller_body,
        )
        self.assertEqual(protocol_response["status"], "blocked")
        self.assertEqual(protocol_response["reason_code"], "protocol_message_rejected")

        unsafe_status_response = build_listener_runtime_response(
            status="caller_controlled_value",
            reason_code="unknown",
            enabled=True,
            startup_permitted=False,
        )
        self.assertIn(unsafe_status_response["status"], {"disabled", "blocked", "ready"})
        self.assertEqual(unsafe_status_response["status"], "blocked")
        self.assertEqual(unsafe_status_response["reason_code"], "listener_disabled")
        self.assertIs(unsafe_status_response["startup_permitted"], False)

        all_interface_responses = []
        for all_interface_host in ["", "*", "0.0.0.0", "::", "[::]"]:
            all_interface_response = validate_minimal_listener_startup(
                MinimalListenerRuntimeConfig(enabled=True, host=all_interface_host)
            )
            self.assertEqual(all_interface_response["status"], "blocked")
            self.assertEqual(all_interface_response["reason_code"], "remote_bind_blocked")
            self.assertIs(all_interface_response["startup_permitted"], False)
            self.assertIs(all_interface_response["listener_started"], False)
            all_interface_response_text = json.dumps(all_interface_response, sort_keys=True)
            if all_interface_host:
                self.assertNotIn(all_interface_host, all_interface_response_text)
            all_interface_responses.append(all_interface_response)

        for response in [
            disabled_response,
            disabled_protocol_response,
            local_response,
            remote_bind_response,
            non_loopback_response,
            protocol_response,
            unsafe_status_response,
            *all_interface_responses,
        ]:
            self.assertIs(response["metadata_only"], True)
            self.assertIs(response["raw_data_included"], False)
            self.assertIs(response["manual_review_required"], True)
            self.assertIs(response["transport_enabled"], False)
            self.assertIs(response["protocol_handler_enabled"], False)
            self.assertIs(response["actual_tool_execution_enabled"], False)
            self.assertIs(response["local_evidence_reader_enabled"], False)
            response_text = json.dumps(response, sort_keys=True)
            self.assertNotIn("caller_controlled_value", response_text)
            self.assertNotIn("remote-host", response_text)
            self.assertNotIn("jsonrpc", response_text)
            self.assertNotIn("method", response_text)
            self.assertNotIn("Cookie", response_text)
            self.assertNotIn("Authorization", response_text)
            self.assertNotIn("token", response_text.lower())
            self.assertNotIn("session", response_text.lower())
            self.assertNotIn("safe body preview", response_text.lower())
            self.assertNotIn("stack", response_text.lower())

        smoke = build_minimal_listener_local_smoke_summary()
        self.assertIs(smoke["disabled_by_default"], True)
        self.assertIs(smoke["loopback_allowed"], True)
        self.assertIs(smoke["non_loopback_blocked"], True)
        self.assertIs(smoke["raw_data_included"], False)
        self.assertIs(smoke["listener_started"], False)

        module_text = MCP_LISTENER_RUNTIME_MODULE.read_text(encoding="utf-8")
        for marker in source_check_fixture["forbidden_source_markers"]:
            self.assertNotIn(marker, module_text, f"{marker} found in mcp_listener_runtime.py")
        for absent_name in [
            "register_tool",
            "execute_tool",
            "read_local_evidence",
            "read_file_body",
            "dashboard_start",
        ]:
            self.assertNotIn(absent_name, module_text)

        combined = implementation_doc + "\n" + fixture_text
        for forbidden in [
            "safe-to-share",
            "safe to share",
            "guaranteed safe",
            "confirmed vulnerability",
            "confirmed finding",
            "confirmed issue count",
            "final CVSS",
            "\"raw_request\"",
            "\"raw_response\"",
            "raw_request:",
            "raw_response:",
            "Cookie:",
            "Authorization:",
            "Bearer ",
            "JWT ",
            "session=",
            "token=",
            "HMAC secret:",
            "CSRF token:",
            "C:\\coding\\",
            "C:\\Users\\",
            "local_only/",
            "real_export_",
            "actual.local",
            "example.com",
            "approved for external sharing",
            "ready to submit",
        ]:
            self.assertNotIn(forbidden, combined)
        self.assertIsNone(re.search(r"https?://", combined))
        self.assertIsNone(re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", combined))

    def test_v07_listener_local_smoke_evidence_is_raw_free_and_boundary_only(self) -> None:
        evidence_doc = V07_LISTENER_LOCAL_SMOKE_EVIDENCE_DOC.read_text(encoding="utf-8")
        fixture = json.loads(V07_LISTENER_LOCAL_SMOKE_EVIDENCE_FIXTURE.read_text(encoding="utf-8"))
        fixture_text = json.dumps(fixture, sort_keys=True)
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        scope_plan = V07_SCOPE_PLAN_DOC.read_text(encoding="utf-8")
        implementation_doc = V07_MINIMAL_LISTENER_RUNTIME_IMPLEMENTATION_DOC.read_text(encoding="utf-8")
        decision_doc = V07_MINIMAL_LISTENER_RUNTIME_IMPLEMENTATION_DECISION_DOC.read_text(encoding="utf-8")

        self.assertTrue(V07_LISTENER_LOCAL_SMOKE_EVIDENCE_DOC.exists())
        self.assertTrue(V07_LISTENER_LOCAL_SMOKE_EVIDENCE_FIXTURE.exists())
        for linked_text in [readme, scope_plan, implementation_doc, decision_doc]:
            self.assertIn("V0.7_LISTENER_LOCAL_SMOKE_EVIDENCE.md", linked_text)

        for section in [
            "## Purpose",
            "## Current Baseline",
            "## Smoke Evidence Scope",
            "## Consumed Runtime Helper",
            "## Expected Smoke Results",
            "## Raw-free Response Checks",
            "## Explicit Non-goals",
            "## Release Readiness Use",
            "## Deferred Work",
        ]:
            self.assertIn(section, evidence_doc)

        for required_text in [
            "release-readiness evidence only",
            "does not start a listener",
            "disabled-by-default",
            "loopback-only",
            "all-interface bind rejection metadata",
            "raw-free blocked or disabled responses",
            "burp_ai_redaction_gateway/mcp_listener_runtime.py",
            "No MCP transport implementation",
            "No MCP protocol handler implementation",
            "No JSON-RPC parser implementation",
            "No executable tool registration",
            "No actual tool execution",
            "No local evidence reader",
            "No safe file body reader",
            "No raw preview or raw download",
            "No replay or active scan",
            "No automatic ChatGPT handoff",
            "No dashboard start or stop control",
            "No upload or import action",
            "No arbitrary local file read",
            "No external network call",
            "No environment secret access",
            "No `v0.6` tag modification",
            "No GitHub Release `v0.6` modification",
            "No `v0.7` tag creation",
            "No GitHub Release `v0.7` creation",
            "No output bundle structure change",
        ]:
            self.assertIn(required_text, evidence_doc)

        self.assertEqual(fixture["schema_version"], "v07_listener_local_smoke_evidence.v1")
        for true_flag in [
            "smoke_evidence_only",
            "runtime_helper_consumed",
            "minimal_listener_runtime_implemented",
        ]:
            self.assertIs(fixture[true_flag], True)

        for false_flag in [
            "actual_listener_startup_implemented",
            "socket_bind_implemented",
            "socket_listen_implemented",
            "socket_accept_implemented",
            "long_running_server_loop_implemented",
            "transport_implemented",
            "protocol_handler_implemented",
            "json_rpc_parser_implemented",
            "tool_registration_implemented",
            "tool_execution_implemented",
            "local_evidence_reader_implemented",
            "safe_file_body_reader_implemented",
            "raw_preview_download_implemented",
            "replay_active_scan_implemented",
            "automatic_chatgpt_handoff_implemented",
            "dashboard_state_changing_control_implemented",
            "upload_import_action_implemented",
            "v06_tag_modified",
            "v06_release_modified",
            "v07_tag_created",
            "v07_release_created",
            "output_bundle_structure_changed",
        ]:
            self.assertIs(fixture[false_flag], False)

        self.assertEqual(
            fixture["smoke_expectations"],
            [
                "default_disabled",
                "loopback_allowed",
                "non_loopback_blocked",
                "all_interface_blocked",
                "protocol_like_input_blocked_when_enabled",
                "protocol_like_input_not_interpreted_when_disabled",
                "status_allowlisted",
                "reason_code_allowlisted",
                "raw_data_included_false",
                "manual_review_required_true",
                "listener_started_false",
                "no_caller_body_echo",
                "no_host_value_echo",
                "no_credential_value_echo",
                "no_local_path_echo",
                "no_stack_trace_body",
                "no_safe_file_body_preview",
            ],
        )
        self.assertEqual(
            fixture["allowed_smoke_reason_codes"],
            [
                "listener_disabled",
                "local_loopback_validation_passed",
                "remote_bind_blocked",
                "non_loopback_host_rejected",
                "protocol_message_rejected",
            ],
        )
        self.assertEqual(fixture["allowed_statuses"], ["disabled", "blocked", "ready"])
        self.assertEqual(
            fixture["output_bundle_files"],
            [
                "analysis_packet.json",
                "chatgpt_prompt.md",
                "codex_task_prompt.md",
                "report_draft.md",
            ],
        )

        metadata = build_listener_runtime_metadata()
        smoke = build_minimal_listener_local_smoke_summary()
        self.assertIs(smoke["disabled_by_default"], True)
        self.assertIs(smoke["loopback_allowed"], True)
        self.assertIs(smoke["non_loopback_blocked"], True)
        self.assertIs(smoke["raw_data_included"], False)
        self.assertIs(smoke["listener_started"], False)
        self.assertIs(smoke["manual_review_required"], True)
        self.assertEqual(metadata["output_bundle_files"], fixture["output_bundle_files"])

        caller_body = {"jsonrpc": "2.0", "method": "caller_controlled_value"}
        disabled_protocol_response = validate_minimal_listener_startup(
            MinimalListenerRuntimeConfig(enabled=False, host="localhost"),
            input_body=caller_body,
        )
        self.assertEqual(disabled_protocol_response["status"], "disabled")
        self.assertEqual(disabled_protocol_response["reason_code"], "listener_disabled")

        enabled_protocol_response = validate_minimal_listener_startup(
            MinimalListenerRuntimeConfig(enabled=True, host="localhost"),
            input_body=caller_body,
        )
        self.assertEqual(enabled_protocol_response["status"], "blocked")
        self.assertEqual(enabled_protocol_response["reason_code"], "protocol_message_rejected")

        unsafe_response = build_listener_runtime_response(
            status="caller_controlled_value",
            reason_code="unknown",
            enabled=True,
            startup_permitted=False,
        )
        self.assertIn(unsafe_response["status"], fixture["allowed_statuses"])
        self.assertEqual(unsafe_response["status"], "blocked")
        self.assertIn(unsafe_response["reason_code"], fixture["allowed_smoke_reason_codes"])
        self.assertEqual(unsafe_response["reason_code"], "listener_disabled")

        all_interface_responses = []
        for all_interface_host in ["", "*", "0.0.0.0", "::", "[::]"]:
            self.assertIs(is_all_interface_host(all_interface_host), True)
            all_interface_response = validate_minimal_listener_startup(
                MinimalListenerRuntimeConfig(enabled=True, host=all_interface_host)
            )
            self.assertEqual(all_interface_response["status"], "blocked")
            self.assertEqual(all_interface_response["reason_code"], "remote_bind_blocked")
            self.assertIs(all_interface_response["startup_permitted"], False)
            self.assertIs(all_interface_response["listener_started"], False)
            all_interface_response_text = json.dumps(all_interface_response, sort_keys=True)
            if all_interface_host:
                self.assertNotIn(all_interface_host, all_interface_response_text)
            all_interface_responses.append(all_interface_response)

        non_loopback_response = validate_minimal_listener_startup(
            MinimalListenerRuntimeConfig(enabled=True, host="remote-host")
        )
        self.assertEqual(non_loopback_response["status"], "blocked")
        self.assertEqual(non_loopback_response["reason_code"], "non_loopback_host_rejected")

        for response in [
            disabled_protocol_response,
            enabled_protocol_response,
            unsafe_response,
            non_loopback_response,
            *all_interface_responses,
        ]:
            response_text = json.dumps(response, sort_keys=True)
            self.assertIs(response["raw_data_included"], False)
            self.assertIs(response["manual_review_required"], True)
            self.assertIs(response["listener_started"], False)
            self.assertIn(response["status"], fixture["allowed_statuses"])
            self.assertIn(response["reason_code"], fixture["allowed_smoke_reason_codes"])
            self.assertIs(response["transport_enabled"], False)
            self.assertIs(response["protocol_handler_enabled"], False)
            self.assertIs(response["actual_tool_execution_enabled"], False)
            self.assertIs(response["local_evidence_reader_enabled"], False)
            for forbidden_echo in [
                "caller_controlled_value",
                "jsonrpc",
                "method",
                "remote-host",
                "Cookie",
                "Authorization",
                "Bearer",
                "JWT",
                "session=",
                "token=",
                "safe file body",
                "stack trace",
            ]:
                self.assertNotIn(forbidden_echo, response_text)

        combined = evidence_doc + "\n" + fixture_text
        for forbidden in [
            "safe-to-share",
            "safe to share",
            "guaranteed safe",
            "confirmed vulnerability",
            "confirmed finding",
            "confirmed issue count",
            "final CVSS",
            "\"raw_request\"",
            "\"raw_response\"",
            "raw_request:",
            "raw_response:",
            "Cookie:",
            "Authorization:",
            "Bearer ",
            "JWT ",
            "session=",
            "token=",
            "HMAC secret:",
            "CSRF token:",
            "C:\\coding\\",
            "C:\\Users\\",
            "local_only/",
            "real_export_",
            "actual.local",
            "example.com",
            "approved for external sharing",
            "ready to submit",
        ]:
            self.assertNotIn(forbidden, combined)
        self.assertIsNone(re.search(r"https?://", combined))
        self.assertIsNone(re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", combined))

    def test_v07_rc_readiness_checklist_is_release_boundary_only(self) -> None:
        checklist = V07_RC_READINESS_CHECKLIST_DOC.read_text(encoding="utf-8")
        fixture = json.loads(V07_RC_READINESS_CHECKLIST_FIXTURE.read_text(encoding="utf-8"))
        fixture_text = json.dumps(fixture, sort_keys=True)
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        scope_plan = V07_SCOPE_PLAN_DOC.read_text(encoding="utf-8")
        smoke_evidence = V07_LISTENER_LOCAL_SMOKE_EVIDENCE_DOC.read_text(encoding="utf-8")
        implementation_doc = V07_MINIMAL_LISTENER_RUNTIME_IMPLEMENTATION_DOC.read_text(encoding="utf-8")

        self.assertTrue(V07_RC_READINESS_CHECKLIST_DOC.exists())
        self.assertTrue(V07_RC_READINESS_CHECKLIST_FIXTURE.exists())
        for linked_text in [readme, scope_plan, smoke_evidence, implementation_doc]:
            self.assertIn("V0.7_RC_READINESS_CHECKLIST.md", linked_text)

        for section in [
            "## Purpose",
            "## Current Baseline",
            "## Included v0.7 Scope",
            "## Explicitly Deferred Scope",
            "## Required Release Gates",
            "## Required Security Checks",
            "## Required Smoke Evidence",
            "## Required Documentation Checks",
            "## Tag and Release Approval Boundary",
            "## Failure Handling",
            "## Final Go/No-Go Checklist",
        ]:
            self.assertIn(section, checklist)

        for required_text in [
            "evidence checklist only",
            "does not approve a tag",
            "does not start a service",
            "CLI generate, verify, review, and report flows",
            "Upload Wizard browser smoke evidence",
            "Read-only dashboard copy and troubleshooting panels",
            "Minimal listener runtime helper metadata",
            "Listener local smoke evidence",
            "Four-file AI input candidate output bundle",
            "actual listener startup",
            "MCP transport",
            "MCP protocol handler",
            "JSON-RPC parser",
            "Executable tool registration",
            "Actual tool execution",
            "Local evidence reader",
            "Safe file body reader",
            "Raw preview or raw download",
            "Replay or active scan",
            "Automatic ChatGPT handoff",
            "Dashboard start or stop control",
            "Upload or import action",
            "tag or GitHub Release action without explicit approval",
            "final severity and CVSS remain manual decisions",
            "release body hygiene",
            "target commit",
        ]:
            self.assertIn(required_text, checklist)

        self.assertEqual(fixture["schema_version"], "v07_rc_readiness_checklist.v1")
        for true_flag in [
            "rc_readiness_only",
            "minimal_listener_runtime_helper_included",
            "listener_local_smoke_evidence_consumed",
            "upload_wizard_browser_smoke_consumed",
        ]:
            self.assertIs(fixture[true_flag], True)

        for false_flag in [
            "release_approval_included",
            "tag_created",
            "github_release_created",
            "v06_tag_modified",
            "v06_release_modified",
            "v07_tag_created",
            "v07_release_created",
            "output_bundle_structure_changed",
            "actual_listener_startup_implemented",
            "socket_bind_implemented",
            "socket_listen_implemented",
            "socket_accept_implemented",
            "long_running_server_loop_implemented",
            "transport_implemented",
            "protocol_handler_implemented",
            "json_rpc_parser_implemented",
            "tool_registration_implemented",
            "tool_execution_implemented",
            "local_evidence_reader_implemented",
            "safe_file_body_reader_implemented",
            "raw_preview_download_implemented",
            "replay_active_scan_implemented",
            "automatic_chatgpt_handoff_implemented",
            "dashboard_state_changing_control_implemented",
            "upload_import_action_implemented",
        ]:
            self.assertIs(fixture[false_flag], False)

        self.assertEqual(fixture["safe_files_count"], 4)
        self.assertEqual(
            fixture["required_gates"],
            [
                "compileall",
                "unittest",
                "verify_out",
                "review_demo",
                "report_demo",
                "montoya_gradle_build",
                "gitleaks_dir",
                "gitleaks_git",
                "git_safety_check",
                "git_diff_check",
                "git_status_clean",
                "pr_body_hygiene",
                "release_body_hygiene_before_release",
                "tag_target_verification_before_release",
            ],
        )
        self.assertEqual(
            fixture["required_smoke_evidence"],
            [
                "listener_local_smoke_evidence",
                "upload_wizard_browser_smoke",
                "safe_file_bundle_four_files",
                "raw_free_review_report",
            ],
        )

        for included in [
            "cli_generate_verify_review_report",
            "upload_wizard_browser_smoke_evidence",
            "read_only_dashboard_copy_and_troubleshooting",
            "minimal_listener_runtime_helper",
            "listener_local_smoke_evidence",
            "four_file_ai_candidate_output_bundle",
        ]:
            self.assertIn(included, fixture["included_scope"])

        for deferred in [
            "actual_listener_startup",
            "socket_bind_listen_accept",
            "mcp_transport",
            "mcp_protocol_handler",
            "json_rpc_parser",
            "executable_tool_registration",
            "actual_tool_execution",
            "local_evidence_reader",
            "safe_file_body_reader",
            "raw_preview_download",
            "replay_active_scan",
            "automatic_chatgpt_handoff",
            "dashboard_state_changing_control",
            "upload_import_action",
            "tag_or_github_release_action_without_explicit_approval",
        ]:
            self.assertIn(deferred, fixture["deferred_scope"])

        combined = checklist + "\n" + fixture_text
        for forbidden in [
            "safe-to-share",
            "safe to share",
            "guaranteed safe",
            "confirmed vulnerability",
            "confirmed finding",
            "confirmed issue count",
            "final CVSS",
            "\"raw_request\"",
            "\"raw_response\"",
            "raw_request:",
            "raw_response:",
            "Cookie:",
            "Authorization:",
            "Bearer ",
            "JWT ",
            "session=",
            "token=",
            "HMAC secret:",
            "CSRF token:",
            "C:\\coding\\",
            "C:\\Users\\",
            "local_only/",
            "real_export_",
            "actual.local",
            "example.com",
            "approved for external sharing",
            "ready to submit",
        ]:
            self.assertNotIn(forbidden, combined)
        self.assertIsNone(re.search(r"https?://", combined))
        self.assertIsNone(re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", combined))

    def test_v07_release_approval_packet_is_approval_only_and_raw_free(self) -> None:
        approval_packet = V07_RELEASE_APPROVAL_PACKET_DOC.read_text(encoding="utf-8")
        fixture = json.loads(V07_RELEASE_APPROVAL_PACKET_FIXTURE.read_text(encoding="utf-8"))
        fixture_text = json.dumps(fixture, sort_keys=True)
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        rc_checklist = V07_RC_READINESS_CHECKLIST_DOC.read_text(encoding="utf-8")
        scope_plan = V07_SCOPE_PLAN_DOC.read_text(encoding="utf-8")
        smoke_evidence = V07_LISTENER_LOCAL_SMOKE_EVIDENCE_DOC.read_text(encoding="utf-8")

        self.assertTrue(V07_RELEASE_APPROVAL_PACKET_DOC.exists())
        self.assertTrue(V07_RELEASE_APPROVAL_PACKET_FIXTURE.exists())
        for linked_text in [readme, rc_checklist, scope_plan, smoke_evidence]:
            self.assertIn("V0.7_RELEASE_APPROVAL_PACKET.md", linked_text)

        for section in [
            "## Purpose",
            "## Current Baseline",
            "## Approval Packet Scope",
            "## Proposed Release Target Rule",
            "## Required Final Gates",
            "## Required Release Body Hygiene",
            "## Required Tag Checks",
            "## Required GitHub Release Checks",
            "## Explicit Non-goals",
            "## Deferred Runtime Scope",
            "## Rollback Note",
            "## Human Approval Boundary",
            "## Final Release Execution Checklist",
        ]:
            self.assertIn(section, approval_packet)

        for required_text in [
            "release approval packet only",
            "does not create a tag",
            "does not create a GitHub Release",
            "approval_packet_merge_commit_or_later_explicit_main_head",
            "main HEAD must be checked again",
            "separate explicit human approval",
            "v0.6 tag and GitHub Release remain unchanged",
            "release body hygiene",
            "tag target verification",
            "Rollback Note",
            "Candidate findings only",
            "Draft risk only",
            "Manual review required",
            "actual listener startup",
            "MCP transport",
            "MCP protocol handler",
            "JSON-RPC parser",
            "Executable tool registration",
            "Actual tool execution",
            "Local evidence reader",
            "Safe file body reader",
            "Raw preview or raw download",
            "Replay or active scan",
            "Automatic ChatGPT handoff",
            "Dashboard start or stop control",
            "Upload or import action",
        ]:
            self.assertIn(required_text, approval_packet)

        self.assertEqual(fixture["schema_version"], "v07_release_approval_packet.v1")
        for true_flag in [
            "release_approval_packet_only",
            "requires_explicit_human_approval_before_release",
            "rc_readiness_checklist_consumed",
            "listener_local_smoke_evidence_consumed",
            "minimal_listener_runtime_helper_included",
            "upload_wizard_browser_smoke_consumed",
        ]:
            self.assertIs(fixture[true_flag], True)

        for false_flag in [
            "release_executed",
            "tag_created",
            "github_release_created",
            "v06_tag_modified",
            "v06_release_modified",
            "v07_tag_created",
            "v07_release_created",
            "output_bundle_structure_changed",
            "actual_listener_startup_implemented",
            "socket_bind_implemented",
            "socket_listen_implemented",
            "socket_accept_implemented",
            "long_running_server_loop_implemented",
            "transport_implemented",
            "protocol_handler_implemented",
            "json_rpc_parser_implemented",
            "tool_registration_implemented",
            "tool_execution_implemented",
            "local_evidence_reader_implemented",
            "safe_file_body_reader_implemented",
            "raw_preview_download_implemented",
            "replay_active_scan_implemented",
            "automatic_chatgpt_handoff_implemented",
            "dashboard_state_changing_control_implemented",
            "upload_import_action_implemented",
        ]:
            self.assertIs(fixture[false_flag], False)

        self.assertEqual(fixture["proposed_release_version"], "v0.7")
        self.assertEqual(
            fixture["proposed_release_target_rule"],
            "approval_packet_merge_commit_or_later_explicit_main_head",
        )
        self.assertEqual(fixture["safe_files_count"], 4)
        self.assertEqual(
            fixture["required_final_gates"],
            [
                "compileall",
                "unittest",
                "verify_out",
                "review_demo",
                "report_demo",
                "montoya_gradle_build",
                "gitleaks_dir",
                "gitleaks_git",
                "git_safety_check",
                "git_diff_check",
                "git_status_clean",
                "pr_body_hygiene",
                "release_body_hygiene",
                "tag_target_verification",
                "release_target_verification",
            ],
        )
        self.assertEqual(
            fixture["release_body_hygiene_rules"],
            [
                "no_raw_request_response",
                "no_target_identifier",
                "no_cookie_authorization_token_session",
                "no_hmac_secret",
                "no_csrf_token",
                "no_full_local_path",
                "no_safe_to_share_claim",
                "no_confirmed_vulnerability_claim",
                "no_final_cvss_claim",
                "candidate_findings_only",
                "draft_risk_only",
                "manual_review_required",
                "no_automatic_chatgpt_handoff_claim",
            ],
        )

        combined = approval_packet + "\n" + fixture_text
        for forbidden in [
            "safe-to-share",
            "safe to share",
            "guaranteed safe",
            "confirmed vulnerability",
            "confirmed finding",
            "confirmed issue count",
            "final CVSS",
            "\"raw_request\"",
            "\"raw_response\"",
            "raw_request:",
            "raw_response:",
            "Cookie:",
            "Authorization:",
            "Bearer ",
            "JWT ",
            "session=",
            "token=",
            "HMAC secret:",
            "CSRF token:",
            "C:\\coding\\",
            "C:\\Users\\",
            "local_only/",
            "real_export_",
            "actual.local",
            "example.com",
            "approved for external sharing",
            "ready to submit",
        ]:
            self.assertNotIn(forbidden, combined)
        self.assertIsNone(re.search(r"https?://", combined))
        self.assertIsNone(re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", combined))

    def test_v07_final_gate_execution_is_evidence_only_and_raw_free(self) -> None:
        final_gate = V07_FINAL_GATE_EXECUTION_DOC.read_text(encoding="utf-8")
        fixture = json.loads(V07_FINAL_GATE_EXECUTION_FIXTURE.read_text(encoding="utf-8"))
        fixture_text = json.dumps(fixture, sort_keys=True)
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        approval_packet = V07_RELEASE_APPROVAL_PACKET_DOC.read_text(encoding="utf-8")
        rc_checklist = V07_RC_READINESS_CHECKLIST_DOC.read_text(encoding="utf-8")
        scope_plan = V07_SCOPE_PLAN_DOC.read_text(encoding="utf-8")

        self.assertTrue(V07_FINAL_GATE_EXECUTION_DOC.exists())
        self.assertTrue(V07_FINAL_GATE_EXECUTION_FIXTURE.exists())
        for linked_text in [readme, approval_packet, rc_checklist, scope_plan]:
            self.assertIn("V0.7_FINAL_GATE_EXECUTION.md", linked_text)

        for section in [
            "## Purpose",
            "## Current target candidate",
            "## Final gate scope",
            "## Executed gates",
            "## Tag and release absence checks",
            "## Release body hygiene checks",
            "## Runtime and deferred scope checks",
            "## Go/hold decision input",
            "## Explicit non-goals",
            "## Next approval boundary",
        ]:
            self.assertIn(section, final_gate)

        for required_text in [
            "release-readiness evidence document only",
            "does not create a tag",
            "does not create a GitHub Release",
            "2c9829f6c21793e5b980add7bf1ecbeccc759a67",
            "approval_packet_merge_commit_or_later_explicit_main_head",
            "Target commit must be rechecked before release",
            "No local v0.7 tag",
            "No remote v0.7 tag",
            "No GitHub Release v0.7",
            "Existing v0.6 tag remains unchanged",
            "Existing GitHub Release v0.6 remains unchanged",
            "Candidate findings only",
            "Draft risk only",
            "Manual review required",
            "Actual listener startup",
            "MCP transport",
            "MCP protocol handler",
            "JSON-RPC parser",
            "Executable tool registration",
            "Actual tool execution",
            "Local evidence reader",
            "Safe file body reader",
            "Raw preview or raw download",
            "Replay or active scan",
            "Dashboard start or stop control",
            "Upload or import action",
            "Automatic ChatGPT handoff",
            "separate explicit human approval",
        ]:
            self.assertIn(required_text, final_gate)

        self.assertEqual(fixture["schema_version"], "v07_final_gate_execution.v1")
        for true_flag in [
            "final_gate_execution_only",
            "target_commit_must_be_rechecked_before_release",
            "approval_packet_consumed",
            "rc_readiness_checklist_consumed",
            "listener_local_smoke_evidence_consumed",
            "minimal_listener_runtime_helper_included",
        ]:
            self.assertIs(fixture[true_flag], True)

        for false_flag in [
            "release_executed",
            "tag_created",
            "github_release_created",
            "v06_tag_modified",
            "v06_release_modified",
            "v07_tag_created",
            "v07_release_created",
            "output_bundle_structure_changed",
            "actual_listener_startup_implemented",
            "socket_bind_implemented",
            "socket_listen_implemented",
            "socket_accept_implemented",
            "long_running_server_loop_implemented",
            "transport_implemented",
            "protocol_handler_implemented",
            "json_rpc_parser_implemented",
            "tool_registration_implemented",
            "tool_execution_implemented",
            "local_evidence_reader_implemented",
            "safe_file_body_reader_implemented",
            "raw_preview_download_implemented",
            "replay_active_scan_implemented",
            "automatic_chatgpt_handoff_implemented",
            "dashboard_state_changing_control_implemented",
            "upload_import_action_implemented",
        ]:
            self.assertIs(fixture[false_flag], False)

        self.assertEqual(fixture["target_commit_rule"], "approval_packet_merge_commit_or_later_explicit_main_head")
        self.assertEqual(
            fixture["pr118_merge_commit"],
            "2c9829f6c21793e5b980add7bf1ecbeccc759a67",
        )
        self.assertEqual(fixture["safe_files_count"], 4)
        self.assertEqual(
            fixture["required_final_gates"],
            [
                "compileall",
                "unittest",
                "verify_out",
                "review_demo",
                "report_demo",
                "montoya_gradle_build",
                "gitleaks_dir",
                "gitleaks_git",
                "git_safety_check",
                "git_diff_check",
                "git_status_clean",
                "release_body_hygiene",
                "tag_target_verification",
                "release_target_verification",
            ],
        )
        for expected_result in [
            "compileall_passed",
            "unittest_passed",
            "verify_out_passed",
            "review_demo_passed",
            "report_demo_passed",
            "montoya_gradle_build_passed",
            "gitleaks_dir_passed",
            "gitleaks_git_passed",
            "git_safety_check_passed",
            "git_diff_check_passed",
            "git_status_clean_passed",
            "v07_tag_absent",
            "v07_release_absent",
            "v06_tag_unchanged",
            "v06_release_unchanged",
        ]:
            self.assertIn(expected_result, fixture["expected_gate_results"])

        for hygiene_rule in [
            "no_raw_request_response",
            "no_target_identifier",
            "no_cookie_authorization_token_session",
            "no_hmac_secret",
            "no_csrf_token",
            "no_full_local_path",
            "no_safe_to_share_claim",
            "no_confirmed_vulnerability_claim",
            "no_final_cvss_claim",
            "candidate_findings_only",
            "draft_risk_only",
            "manual_review_required",
            "no_automatic_chatgpt_handoff_claim",
        ]:
            self.assertIn(hygiene_rule, fixture["release_body_hygiene_rules"])

        combined = final_gate + "\n" + fixture_text
        for forbidden in [
            "safe-to-share",
            "safe to share",
            "guaranteed safe",
            "confirmed vulnerability",
            "confirmed finding",
            "confirmed issue count",
            "final CVSS",
            "\"raw_request\"",
            "\"raw_response\"",
            "raw_request:",
            "raw_response:",
            "Cookie:",
            "Authorization:",
            "Bearer ",
            "JWT ",
            "session=",
            "token=",
            "HMAC secret:",
            "CSRF token:",
            "C:\\coding\\",
            "C:\\Users\\",
            "local_only/",
            "real_export_",
            "actual.local",
            "example.com",
            "approved for external sharing",
            "ready to submit",
        ]:
            self.assertNotIn(forbidden, combined)
        self.assertIsNone(re.search(r"https?://", combined))
        self.assertIsNone(re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", combined))

    def test_v07_release_notes_draft_is_review_only_and_raw_free(self) -> None:
        notes = V07_RELEASE_NOTES_DRAFT_DOC.read_text(encoding="utf-8")
        fixture = json.loads(V07_RELEASE_NOTES_DRAFT_FIXTURE.read_text(encoding="utf-8"))
        fixture_text = json.dumps(fixture, sort_keys=True)
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        final_gate = V07_FINAL_GATE_EXECUTION_DOC.read_text(encoding="utf-8")
        approval_packet = V07_RELEASE_APPROVAL_PACKET_DOC.read_text(encoding="utf-8")
        rc_checklist = V07_RC_READINESS_CHECKLIST_DOC.read_text(encoding="utf-8")

        self.assertTrue(V07_RELEASE_NOTES_DRAFT_DOC.exists())
        self.assertTrue(V07_RELEASE_NOTES_DRAFT_FIXTURE.exists())
        for linked_text in [readme, final_gate, approval_packet, rc_checklist]:
            self.assertIn("V0.7_RELEASE_NOTES_DRAFT.md", linked_text)

        for section in [
            "## Purpose",
            "## Release title draft",
            "## Release target rule",
            "## Summary",
            "## Included changes",
            "## Security and privacy boundaries",
            "## Deferred scope",
            "## Validation evidence",
            "## Manual review boundaries",
            "## Not a release execution",
            "## Final approval requirements",
        ]:
            self.assertIn(section, notes)

        for required_text in [
            "GitHub Release body draft",
            "does not create a tag",
            "does not create a GitHub Release",
            "`v0.7`",
            "approval_packet_merge_commit_or_later_explicit_main_head",
            "target commit must be rechecked before release",
            "redaction, verification, review, and report generation",
            "Upload Wizard",
            "RC readiness checklist",
            "minimal listener runtime helper",
            "disabled-first, loopback-only, and metadata-only",
            "Candidate findings only",
            "Draft risk only",
            "Manual review required",
            "four-file structure",
            "Actual listener startup",
            "MCP transport",
            "MCP protocol handler",
            "JSON-RPC parser",
            "Executable tool registration",
            "Actual tool execution",
            "Local evidence reader",
            "Raw preview or raw download",
            "Replay or active scan",
            "Automatic ChatGPT handoff",
            "separate explicit human approval",
        ]:
            self.assertIn(required_text, notes)

        self.assertEqual(fixture["schema_version"], "v07_release_notes_draft.v1")
        for true_flag in [
            "release_notes_draft_only",
            "target_commit_must_be_rechecked_before_release",
            "final_gate_execution_consumed",
            "release_approval_packet_consumed",
            "rc_readiness_checklist_consumed",
            "listener_local_smoke_evidence_consumed",
            "minimal_listener_runtime_helper_included",
        ]:
            self.assertIs(fixture[true_flag], True)

        for false_flag in [
            "release_executed",
            "tag_created",
            "github_release_created",
            "output_bundle_structure_changed",
            "actual_listener_startup_implemented",
            "socket_bind_implemented",
            "socket_listen_implemented",
            "socket_accept_implemented",
            "long_running_server_loop_implemented",
            "transport_implemented",
            "protocol_handler_implemented",
            "json_rpc_parser_implemented",
            "tool_registration_implemented",
            "tool_execution_implemented",
            "local_evidence_reader_implemented",
            "safe_file_body_reader_implemented",
            "raw_preview_download_implemented",
            "replay_active_scan_implemented",
            "automatic_chatgpt_handoff_implemented",
            "dashboard_state_changing_control_implemented",
            "upload_import_action_implemented",
        ]:
            self.assertIs(fixture[false_flag], False)

        self.assertEqual(fixture["proposed_release_version"], "v0.7")
        self.assertEqual(fixture["release_title_draft"], "v0.7")
        self.assertEqual(fixture["target_commit_rule"], "approval_packet_merge_commit_or_later_explicit_main_head")
        self.assertEqual(fixture["safe_files_count"], 4)

        for hygiene_rule in [
            "no_raw_request_response",
            "no_target_identifier",
            "no_cookie_authorization_token_session",
            "no_hmac_secret",
            "no_csrf_token",
            "no_full_local_path",
            "no_safe_to_share_claim",
            "no_confirmed_vulnerability_claim",
            "no_final_cvss_claim",
            "candidate_findings_only",
            "draft_risk_only",
            "manual_review_required",
            "no_automatic_chatgpt_handoff_claim",
        ]:
            self.assertIn(hygiene_rule, fixture["release_body_hygiene_rules"])

        combined = notes + "\n" + fixture_text
        for forbidden in [
            "safe-to-share",
            "safe to share",
            "guaranteed safe",
            "confirmed vulnerability",
            "confirmed finding",
            "confirmed issue count",
            "final CVSS",
            "\"raw_request\"",
            "\"raw_response\"",
            "raw_request:",
            "raw_response:",
            "Cookie:",
            "Authorization:",
            "Bearer ",
            "JWT ",
            "session=",
            "token=",
            "HMAC secret:",
            "CSRF token:",
            "C:\\coding\\",
            "C:\\Users\\",
            "local_only/",
            "real_export_",
            "actual.local",
            "example.com",
            "approved for external sharing",
            "ready to submit",
        ]:
            self.assertNotIn(forbidden, combined)
        self.assertIsNone(re.search(r"https?://", combined))
        self.assertIsNone(re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", combined))

    def test_v08_backlog_split_is_planning_only_and_raw_free(self) -> None:
        doc = V08_BACKLOG_SPLIT_DOC.read_text(encoding="utf-8")
        fixture = json.loads(V08_BACKLOG_SPLIT_FIXTURE.read_text(encoding="utf-8"))
        fixture_text = json.dumps(fixture, sort_keys=True)
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        release_notes = V07_RELEASE_NOTES_DRAFT_DOC.read_text(encoding="utf-8")
        final_gate = V07_FINAL_GATE_EXECUTION_DOC.read_text(encoding="utf-8")
        normalized_doc = " ".join(doc.split())

        self.assertTrue(V08_BACKLOG_SPLIT_DOC.exists())
        self.assertTrue(V08_BACKLOG_SPLIT_FIXTURE.exists())
        for linked_text in [readme, release_notes, final_gate]:
            self.assertIn("V0.8_BACKLOG_SPLIT.md", linked_text)

        for section in [
            "## Purpose",
            "## Current v0.7 baseline",
            "## v0.8 candidate surfaces",
            "## Risk ranking",
            "## Required PR split",
            "## Explicit non-goals",
            "## Security review requirements",
            "## Testing requirements",
            "## Recommended order",
            "## Deferred decisions",
        ]:
            self.assertIn(section, doc)

        for required_text in [
            "planning and review-boundary document only",
            "published v0.7 release",
            "post-release tag checkout smoke",
            "local-only operational smoke",
            "four-file candidate bundle",
            "MCP transport",
            "MCP protocol handler and JSON-RPC parser",
            "Executable tool registration",
            "Actual tool execution",
            "Local evidence reader",
            "Safe file body reader",
            "Raw preview or raw download",
            "Dashboard start or stop control",
            "Upload or import action",
            "Replay or active scan",
            "Automatic ChatGPT handoff",
            "Very high risk",
            "High risk",
            "Medium risk",
            "Transport design",
            "Protocol handler design",
            "Tool execution approval packet",
            "Local evidence reader threat model",
            "Dashboard state-changing control threat model",
            "Transport design only",
            "Protocol handler design only",
            "Actual implementation stays blocked",
        ]:
            self.assertIn(required_text, normalized_doc)

        self.assertEqual(fixture["schema_version"], "v08_backlog_split.v1")
        for true_flag in [
            "backlog_split_only",
            "v07_release_consumed",
            "v07_operational_smoke_consumed",
        ]:
            self.assertIs(fixture[true_flag], True)

        for false_flag in [
            "implementation_included",
            "transport_implemented",
            "protocol_handler_implemented",
            "json_rpc_parser_implemented",
            "tool_registration_implemented",
            "tool_execution_implemented",
            "local_evidence_reader_implemented",
            "safe_file_body_reader_implemented",
            "raw_preview_download_implemented",
            "dashboard_state_changing_control_implemented",
            "upload_import_action_implemented",
            "replay_active_scan_implemented",
            "automatic_chatgpt_handoff_implemented",
        ]:
            self.assertIs(fixture[false_flag], False)

        for surface in [
            "mcp_transport",
            "mcp_protocol_handler_json_rpc_parser",
            "executable_tool_registration",
            "actual_tool_execution",
            "local_evidence_reader",
            "safe_file_body_reader",
            "raw_preview_download",
            "dashboard_start_stop_control",
            "upload_import_action",
            "replay_active_scan",
            "automatic_chatgpt_handoff",
        ]:
            self.assertIn(surface, fixture["candidate_surfaces"])

        for very_high in [
            "actual_tool_execution",
            "local_evidence_reader",
            "safe_file_body_reader",
            "raw_preview_download",
            "automatic_chatgpt_handoff",
        ]:
            self.assertIn(very_high, fixture["very_high_risk_surfaces"])

        for high in [
            "mcp_transport",
            "mcp_protocol_handler_json_rpc_parser",
            "dashboard_start_stop_control",
            "upload_import_action",
            "replay_active_scan",
        ]:
            self.assertIn(high, fixture["high_risk_surfaces"])

        for split in [
            "transport_design",
            "protocol_handler_design",
            "tool_registration_design",
            "tool_execution_approval_packet",
            "local_evidence_reader_threat_model",
            "raw_preview_download_decision",
            "dashboard_state_changing_control_threat_model",
            "upload_import_action_threat_model",
            "replay_active_scan_decision",
            "automatic_chatgpt_handoff_decision",
        ]:
            self.assertIn(split, fixture["required_pr_splits"])

        self.assertEqual(
            fixture["recommended_order"][:2],
            ["transport_design_only", "protocol_handler_design_only"],
        )

        combined = doc + "\n" + fixture_text
        for forbidden in [
            "safe-to-share",
            "safe to share",
            "guaranteed safe",
            "confirmed vulnerability",
            "confirmed finding",
            "confirmed issue count",
            "final CVSS",
            "\"raw_request\"",
            "\"raw_response\"",
            "raw_request:",
            "raw_response:",
            "Cookie:",
            "Authorization:",
            "Bearer ",
            "JWT ",
            "session=",
            "token=",
            "HMAC secret:",
            "CSRF token:",
            "C:\\coding\\",
            "C:\\Users\\",
            "local_only/",
            "real_export_",
            "actual.local",
            "example.com",
            "approved for external sharing",
            "ready to submit",
        ]:
            self.assertNotIn(forbidden, combined)
        self.assertIsNone(re.search(r"https?://", combined))
        self.assertIsNone(re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", combined))

    def test_v08_transport_design_is_design_only_and_raw_free(self) -> None:
        doc = V08_TRANSPORT_DESIGN_DOC.read_text(encoding="utf-8")
        fixture = json.loads(V08_TRANSPORT_DESIGN_FIXTURE.read_text(encoding="utf-8"))
        fixture_text = json.dumps(fixture, sort_keys=True)
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        backlog = V08_BACKLOG_SPLIT_DOC.read_text(encoding="utf-8")
        normalized_doc = " ".join(doc.split())
        normalized_doc_lower = normalized_doc.lower()

        self.assertTrue(V08_TRANSPORT_DESIGN_DOC.exists())
        self.assertTrue(V08_TRANSPORT_DESIGN_FIXTURE.exists())
        for linked_text in [readme, backlog]:
            self.assertIn("V0.8_TRANSPORT_DESIGN.md", linked_text)

        for section in [
            "## Purpose",
            "## Current v0.7 baseline",
            "## Transport design scope",
            "## Explicit non-goals",
            "## Allowed future transport boundary",
            "## Forbidden transport behaviors",
            "## Required negative tests",
            "## Source-check requirements",
            "## Security review requirements",
            "## Rollback expectations",
            "## Deferred decisions",
        ]:
            self.assertIn(section, doc)

        for required_text in [
            "design-only and review-boundary document",
            "v0.8 backlog split",
            "Socket, bind, listen, or accept behavior",
            "Stdio transport runtime",
            "HTTP transport runtime",
            "MCP protocol handler",
            "JSON-RPC parser",
            "Executable tool registration",
            "Actual tool execution",
            "Local evidence reader",
            "Raw preview or raw download",
            "Replay or active scan",
            "Automatic ChatGPT handoff",
            "Dashboard start or stop control",
            "Upload or import action",
            "Source-check requirements",
            "Blocked and failure responses must remain raw-free",
            "Candidate findings remain candidates",
            "risk remains draft",
            "final severity or scoring remains manual",
        ]:
            self.assertIn(required_text.lower(), normalized_doc_lower)

        self.assertEqual(fixture["schema_version"], "v08_transport_design.v1")
        for true_flag in [
            "transport_design_only",
            "v08_backlog_split_consumed",
        ]:
            self.assertIs(fixture[true_flag], True)

        for false_flag in [
            "implementation_included",
            "transport_implemented",
            "socket_bind_implemented",
            "socket_listen_implemented",
            "socket_accept_implemented",
            "stdio_transport_runtime_implemented",
            "http_transport_runtime_implemented",
            "protocol_handler_implemented",
            "json_rpc_parser_implemented",
            "tool_registration_implemented",
            "tool_execution_implemented",
            "local_evidence_reader_implemented",
            "safe_file_body_reader_implemented",
            "raw_preview_download_implemented",
            "replay_active_scan_implemented",
            "automatic_chatgpt_handoff_implemented",
            "dashboard_state_changing_control_implemented",
            "upload_import_action_implemented",
        ]:
            self.assertIs(fixture[false_flag], False)

        for behavior in [
            "socket_bind_listen_accept",
            "stdio_transport_runtime",
            "http_transport_runtime",
            "mcp_protocol_handler",
            "json_rpc_parser",
            "executable_tool_registration",
            "actual_tool_execution",
            "local_evidence_reader",
            "safe_file_body_reader",
            "raw_preview_download",
            "dashboard_start_stop_control",
            "upload_import_action",
            "replay_active_scan",
            "automatic_chatgpt_handoff",
        ]:
            self.assertIn(behavior, fixture["forbidden_transport_behaviors"])

        for negative in [
            "socket_bind_listen_accept_marker_check",
            "stdio_http_runtime_marker_check",
            "protocol_json_rpc_parser_marker_check",
            "tool_registration_execution_marker_check",
            "local_evidence_file_body_reader_marker_check",
            "raw_preview_download_marker_check",
            "dashboard_state_change_marker_check",
            "upload_import_replay_active_scan_marker_check",
            "automatic_handoff_marker_check",
        ]:
            self.assertIn(negative, fixture["required_negative_tests"])

        for requirement in [
            "declare_transport_facing_files_before_runtime",
            "block_protocol_parser_markers",
            "block_tool_execution_markers",
            "block_local_evidence_reader_markers",
            "block_raw_preview_download_markers",
            "block_dashboard_state_change_markers",
            "block_upload_import_replay_active_scan_markers",
            "block_automatic_handoff_markers",
        ]:
            self.assertIn(requirement, fixture["source_check_requirements"])

        self.assertEqual(
            fixture["recommended_next_order"][:2],
            ["protocol_handler_design_only", "protocol_negative_test_harness"],
        )

        combined = doc + "\n" + fixture_text
        for forbidden in [
            "safe-to-share",
            "safe to share",
            "guaranteed safe",
            "confirmed vulnerability",
            "confirmed finding",
            "confirmed issue count",
            "final CVSS",
            "\"raw_request\"",
            "\"raw_response\"",
            "raw_request:",
            "raw_response:",
            "Cookie:",
            "Authorization:",
            "Bearer ",
            "JWT ",
            "session=",
            "token=",
            "HMAC secret:",
            "CSRF token:",
            "C:\\coding\\",
            "C:\\Users\\",
            "local_only/",
            "real_export_",
            "actual.local",
            "example.com",
            "approved for external sharing",
            "ready to submit",
        ]:
            self.assertNotIn(forbidden, combined)
        self.assertIsNone(re.search(r"https?://", combined))
        self.assertIsNone(re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", combined))

    def test_v08_protocol_handler_design_is_design_only_and_raw_free(self) -> None:
        doc = V08_PROTOCOL_HANDLER_DESIGN_DOC.read_text(encoding="utf-8")
        fixture = json.loads(V08_PROTOCOL_HANDLER_DESIGN_FIXTURE.read_text(encoding="utf-8"))
        fixture_text = json.dumps(fixture, sort_keys=True)
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        backlog = V08_BACKLOG_SPLIT_DOC.read_text(encoding="utf-8")
        transport = V08_TRANSPORT_DESIGN_DOC.read_text(encoding="utf-8")
        normalized_doc = " ".join(doc.split())
        normalized_doc_lower = normalized_doc.lower()

        self.assertTrue(V08_PROTOCOL_HANDLER_DESIGN_DOC.exists())
        self.assertTrue(V08_PROTOCOL_HANDLER_DESIGN_FIXTURE.exists())
        for linked_text in [readme, backlog, transport]:
            self.assertIn("V0.8_PROTOCOL_HANDLER_DESIGN.md", linked_text)

        for section in [
            "## Purpose",
            "## Current v0.8 baseline",
            "## Protocol design scope",
            "## Explicit non-goals",
            "## Allowed future protocol boundary",
            "## Forbidden protocol behaviors",
            "## Failure and blocked-response contract",
            "## Required negative tests",
            "## Source-check requirements",
            "## Security review requirements",
            "## Rollback expectations",
            "## Deferred decisions",
        ]:
            self.assertIn(section, doc)

        for required_text in [
            "design-only and review-boundary document",
            "v0.8 backlog split",
            "v0.8 transport design",
            "MCP protocol handler",
            "JSON-RPC parser",
            "Protocol message parser",
            "Schema validation runtime",
            "Request dispatcher",
            "Executable tool registration",
            "Actual tool execution",
            "Transport runtime",
            "Socket, bind, listen, or accept behavior",
            "Stdio transport runtime",
            "HTTP transport runtime",
            "Local evidence reader",
            "Raw preview or raw download",
            "Replay or active scan",
            "Automatic ChatGPT handoff",
            "Failure and blocked-response contract",
            "Malformed protocol input",
            "raw-free blocked or failure response",
            "no request body echo",
            "no credential, session, or token echo",
            "no local path echo",
            "no stack trace echo",
            "no target identifier echo",
            "Candidate findings remain candidates",
            "risk remains draft",
            "final severity or scoring remains manual",
        ]:
            self.assertIn(required_text.lower(), normalized_doc_lower)

        self.assertEqual(fixture["schema_version"], "v08_protocol_handler_design.v1")
        for true_flag in [
            "protocol_handler_design_only",
            "v08_backlog_split_consumed",
            "v08_transport_design_consumed",
        ]:
            self.assertIs(fixture[true_flag], True)

        for false_flag in [
            "implementation_included",
            "protocol_handler_implemented",
            "json_rpc_parser_implemented",
            "protocol_message_parser_implemented",
            "schema_validation_runtime_implemented",
            "request_dispatcher_implemented",
            "tool_registration_implemented",
            "tool_execution_implemented",
            "transport_runtime_implemented",
            "socket_bind_implemented",
            "socket_listen_implemented",
            "socket_accept_implemented",
            "stdio_transport_runtime_implemented",
            "http_transport_runtime_implemented",
            "local_evidence_reader_implemented",
            "safe_file_body_reader_implemented",
            "raw_preview_download_implemented",
            "replay_active_scan_implemented",
            "automatic_chatgpt_handoff_implemented",
            "dashboard_state_changing_control_implemented",
            "upload_import_action_implemented",
            "raw_data_included",
        ]:
            self.assertIs(fixture[false_flag], False)

        for behavior in [
            "mcp_protocol_handler",
            "json_rpc_parser",
            "protocol_message_parser",
            "schema_validation_runtime",
            "request_dispatcher",
            "executable_tool_registration",
            "actual_tool_execution",
            "transport_runtime",
            "socket_bind_listen_accept",
            "stdio_http_runtime",
            "local_evidence_reader",
            "safe_file_body_reader",
            "raw_preview_download",
            "dashboard_start_stop_control",
            "upload_import_action",
            "replay_active_scan",
            "automatic_chatgpt_handoff",
            "request_body_echo",
            "credential_session_token_echo",
            "stack_trace_echo",
            "target_identifier_echo",
            "external_handoff",
        ]:
            self.assertIn(behavior, fixture["forbidden_protocol_behaviors"])

        for negative in [
            "malformed_protocol_input_blocked_response_check",
            "protocol_json_rpc_parser_marker_check",
            "schema_validation_runtime_marker_check",
            "request_dispatcher_marker_check",
            "tool_registration_execution_marker_check",
            "transport_runtime_marker_check",
            "socket_bind_listen_accept_marker_check",
            "stdio_http_runtime_marker_check",
            "local_evidence_file_body_reader_marker_check",
            "raw_preview_download_marker_check",
            "dashboard_state_change_marker_check",
            "upload_import_replay_active_scan_marker_check",
            "automatic_handoff_marker_check",
            "request_body_echo_marker_check",
            "credential_session_token_echo_marker_check",
            "local_path_stack_trace_target_echo_marker_check",
        ]:
            self.assertIn(negative, fixture["required_negative_tests"])

        for contract in [
            "raw_free_blocked_or_failure_response_only",
            "no_request_body_echo",
            "no_credential_session_token_echo",
            "no_local_path_echo",
            "no_stack_trace_echo",
            "no_target_identifier_echo",
            "no_final_vulnerability_severity_cvss_claim",
            "no_tool_dispatch",
            "no_external_handoff",
        ]:
            self.assertIn(contract, fixture["failure_response_contract"])

        for requirement in [
            "declare_protocol_facing_files_before_runtime",
            "block_transport_runtime_markers",
            "block_protocol_parser_runtime_markers",
            "block_request_dispatcher_markers",
            "block_tool_execution_markers",
            "block_local_evidence_reader_markers",
            "block_raw_preview_download_markers",
            "block_dashboard_state_change_markers",
            "block_upload_import_replay_active_scan_markers",
            "block_automatic_handoff_markers",
            "block_sensitive_input_echo_markers",
        ]:
            self.assertIn(requirement, fixture["source_check_requirements"])

        self.assertEqual(
            fixture["recommended_next_order"][:2],
            ["protocol_negative_test_harness", "transport_protocol_minimal_skeleton_planning"],
        )

        combined = doc + "\n" + fixture_text
        for forbidden in [
            "safe-to-share",
            "safe to share",
            "guaranteed safe",
            "confirmed vulnerability",
            "confirmed finding",
            "confirmed issue count",
            "final CVSS",
            "\"raw_request\"",
            "\"raw_response\"",
            "raw_request:",
            "raw_response:",
            "Cookie:",
            "Authorization:",
            "Bearer ",
            "JWT ",
            "session=",
            "token=",
            "HMAC secret:",
            "CSRF token:",
            "C:\\coding\\",
            "C:\\Users\\",
            "local_only/",
            "real_export_",
            "actual.local",
            "example.com",
            "approved for external sharing",
            "ready to submit",
        ]:
            self.assertNotIn(forbidden, combined)
        self.assertIsNone(re.search(r"https?://", combined))
        self.assertIsNone(re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", combined))

    def test_v08_protocol_negative_harness_is_planning_only_and_raw_free(self) -> None:
        doc = V08_PROTOCOL_NEGATIVE_HARNESS_DOC.read_text(encoding="utf-8")
        fixture = json.loads(V08_PROTOCOL_NEGATIVE_HARNESS_FIXTURE.read_text(encoding="utf-8"))
        fixture_text = json.dumps(fixture, sort_keys=True)
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        backlog = V08_BACKLOG_SPLIT_DOC.read_text(encoding="utf-8")
        protocol_design = V08_PROTOCOL_HANDLER_DESIGN_DOC.read_text(encoding="utf-8")
        normalized_doc = " ".join(doc.split())
        normalized_doc_lower = normalized_doc.lower()

        self.assertTrue(V08_PROTOCOL_NEGATIVE_HARNESS_DOC.exists())
        self.assertTrue(V08_PROTOCOL_NEGATIVE_HARNESS_FIXTURE.exists())
        for linked_text in [readme, backlog, protocol_design]:
            self.assertIn("V0.8_PROTOCOL_NEGATIVE_TEST_HARNESS.md", linked_text)

        for section in [
            "## Purpose",
            "## Current v0.8 baseline",
            "## Negative harness scope",
            "## Explicit non-goals",
            "## Malformed input categories",
            "## Echo-forbidden contract",
            "## Forbidden source markers",
            "## Blocked-response requirements",
            "## Source-check requirements",
            "## Security review requirements",
            "## Rollback expectations",
            "## Deferred decisions",
        ]:
            self.assertIn(section, doc)

        for required_text in [
            "planning and test-boundary document",
            "v0.8 backlog split",
            "v0.8 transport design",
            "v0.8 protocol handler design",
            "Malformed input categories",
            "malformed JSON",
            "missing JSON-RPC version",
            "invalid method shape",
            "tool-call-like payload",
            "local-path-like payload",
            "Echo-forbidden contract",
            "request body",
            "credential value",
            "session value",
            "token value",
            "local path",
            "stack trace",
            "actual target identifier",
            "Forbidden source markers",
            "protocol parser implementation marker",
            "JSON-RPC parser implementation marker",
            "request dispatcher marker",
            "tool registration marker",
            "tool execution marker",
            "local evidence reader marker",
            "raw preview or raw download marker",
            "external handoff marker",
            "Blocked-response requirements",
            "raw-free blocked response only",
            "raw data included false",
            "no request body echo",
            "no credential, session, or token echo",
            "no local path echo",
            "no stack trace echo",
            "no target identifier echo",
            "Candidate findings remain candidates",
            "risk remains draft",
            "final severity or scoring remains manual",
        ]:
            self.assertIn(required_text.lower(), normalized_doc_lower)

        self.assertEqual(fixture["schema_version"], "v08_protocol_negative_harness.v1")
        for true_flag in [
            "protocol_negative_harness_only",
            "v08_backlog_split_consumed",
            "v08_transport_design_consumed",
            "v08_protocol_handler_design_consumed",
        ]:
            self.assertIs(fixture[true_flag], True)

        for false_flag in [
            "implementation_included",
            "protocol_handler_implemented",
            "json_rpc_parser_implemented",
            "protocol_message_parser_implemented",
            "schema_validation_runtime_implemented",
            "request_dispatcher_implemented",
            "tool_registration_implemented",
            "tool_execution_implemented",
            "transport_runtime_implemented",
            "socket_bind_implemented",
            "socket_listen_implemented",
            "socket_accept_implemented",
            "stdio_transport_runtime_implemented",
            "http_transport_runtime_implemented",
            "local_evidence_reader_implemented",
            "safe_file_body_reader_implemented",
            "raw_preview_download_implemented",
            "replay_active_scan_implemented",
            "automatic_chatgpt_handoff_implemented",
            "dashboard_state_changing_control_implemented",
            "upload_import_action_implemented",
            "raw_data_included",
        ]:
            self.assertIs(fixture[false_flag], False)

        for category in [
            "malformed_json",
            "missing_jsonrpc_version",
            "invalid_method_shape",
            "tool_call_like_payload",
            "local_path_like_payload",
            "raw_request_like_payload",
            "credential_like_payload",
        ]:
            self.assertIn(category, fixture["malformed_input_categories"])

        for echo_forbidden in [
            "request_body",
            "credential_value",
            "session_value",
            "token_value",
            "local_path",
            "stack_trace",
            "actual_target_identifier",
            "raw_request_response",
            "hmac_secret",
            "csrf_token",
        ]:
            self.assertIn(echo_forbidden, fixture["echo_forbidden_values"])

        for marker in [
            "protocol_parser_implementation_marker",
            "json_rpc_parser_implementation_marker",
            "request_dispatcher_marker",
            "tool_registration_marker",
            "tool_execution_marker",
            "local_evidence_reader_marker",
            "raw_preview_download_marker",
            "external_handoff_marker",
        ]:
            self.assertIn(marker, fixture["forbidden_source_markers"])

        for negative in [
            "malformed_json_blocked_response_check",
            "missing_jsonrpc_version_blocked_response_check",
            "invalid_method_shape_blocked_response_check",
            "tool_call_like_payload_blocked_response_check",
            "local_path_like_payload_no_echo_check",
            "raw_request_like_payload_no_echo_check",
            "credential_like_payload_no_echo_check",
            "parser_dispatcher_source_marker_check",
            "tool_registration_execution_source_marker_check",
            "local_evidence_raw_preview_source_marker_check",
            "external_handoff_source_marker_check",
        ]:
            self.assertIn(negative, fixture["required_negative_tests"])

        for contract in [
            "raw_free_blocked_response_only",
            "raw_data_included_false",
            "no_request_body_echo",
            "no_credential_session_token_echo",
            "no_local_path_echo",
            "no_stack_trace_echo",
            "no_target_identifier_echo",
            "no_raw_request_response_echo",
            "no_hmac_secret_echo",
            "no_csrf_token_echo",
            "no_tool_dispatch",
            "no_external_handoff",
        ]:
            self.assertIn(contract, fixture["blocked_response_contract"])

        for requirement in [
            "declare_protocol_facing_files_before_runtime",
            "block_protocol_parser_markers",
            "block_json_rpc_parser_markers",
            "block_request_dispatcher_markers",
            "block_tool_registration_markers",
            "block_tool_execution_markers",
            "block_local_evidence_reader_markers",
            "block_raw_preview_download_markers",
            "block_external_handoff_markers",
            "block_sensitive_echo_markers",
        ]:
            self.assertIn(requirement, fixture["source_check_requirements"])

        self.assertEqual(
            fixture["recommended_next_order"][:2],
            ["tool_registration_design_only", "transport_protocol_minimal_skeleton_planning"],
        )

        combined = doc + "\n" + fixture_text
        for forbidden in [
            "safe-to-share",
            "safe to share",
            "guaranteed safe",
            "confirmed vulnerability",
            "confirmed finding",
            "confirmed issue count",
            "final CVSS",
            "\"raw_request\"",
            "\"raw_response\"",
            "raw_request:",
            "raw_response:",
            "Cookie:",
            "Authorization:",
            "Bearer ",
            "JWT ",
            "session=",
            "token=",
            "HMAC secret:",
            "CSRF token:",
            "C:\\coding\\",
            "C:\\Users\\",
            "local_only/",
            "real_export_",
            "actual.local",
            "example.com",
            "approved for external sharing",
            "ready to submit",
        ]:
            self.assertNotIn(forbidden, combined)
        self.assertIsNone(re.search(r"https?://", combined))
        self.assertIsNone(re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", combined))

    def test_v08_tool_registration_design_is_design_only_and_raw_free(self) -> None:
        doc = V08_TOOL_REGISTRATION_DESIGN_DOC.read_text(encoding="utf-8")
        fixture = json.loads(V08_TOOL_REGISTRATION_DESIGN_FIXTURE.read_text(encoding="utf-8"))
        fixture_text = json.dumps(fixture, sort_keys=True)
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        backlog = V08_BACKLOG_SPLIT_DOC.read_text(encoding="utf-8")
        negative_harness = V08_PROTOCOL_NEGATIVE_HARNESS_DOC.read_text(encoding="utf-8")
        normalized_doc = " ".join(doc.split())
        normalized_doc_lower = normalized_doc.lower()

        self.assertTrue(V08_TOOL_REGISTRATION_DESIGN_DOC.exists())
        self.assertTrue(V08_TOOL_REGISTRATION_DESIGN_FIXTURE.exists())
        for linked_text in [readme, backlog, negative_harness]:
            self.assertIn("V0.8_TOOL_REGISTRATION_DESIGN.md", linked_text)

        for section in [
            "## Purpose",
            "## Current v0.8 baseline",
            "## Tool registration design scope",
            "## Explicit non-goals",
            "## Allowed future registration boundary",
            "## Forbidden registration behaviors",
            "## Tool execution separation",
            "## Required approval conditions",
            "## Required negative tests",
            "## Source-check requirements",
            "## Security review requirements",
            "## Rollback expectations",
            "## Deferred decisions",
        ]:
            self.assertIn(section, doc)

        for required_text in [
            "design-only and review-boundary document",
            "v0.8 backlog split",
            "v0.8 transport design",
            "v0.8 protocol handler design",
            "v0.8 protocol negative test harness",
            "Executable tool registration",
            "Tool registry runtime",
            "Tool discovery runtime",
            "Actual tool execution",
            "Request dispatcher",
            "Protocol parser",
            "JSON-RPC parser",
            "Transport runtime",
            "Local evidence reader",
            "Safe file body reader",
            "Raw preview or raw download",
            "Replay or active scan",
            "Automatic ChatGPT handoff",
            "Dashboard start or stop control",
            "Upload or import action",
            "Tool registration and actual tool execution must remain separate PRs",
            "Registration metadata is future design data only",
            "not runtime callable surface",
            "Tool call dispatch",
            "Local file read behavior",
            "Safe file body read behavior",
            "raw-free",
            "Candidate findings remain candidates",
            "risk remains draft",
            "final severity or scoring remains manual",
        ]:
            self.assertIn(required_text.lower(), normalized_doc_lower)

        self.assertEqual(fixture["schema_version"], "v08_tool_registration_design.v1")
        for true_flag in [
            "tool_registration_design_only",
            "v08_backlog_split_consumed",
            "v08_transport_design_consumed",
            "v08_protocol_handler_design_consumed",
            "v08_protocol_negative_harness_consumed",
        ]:
            self.assertIs(fixture[true_flag], True)

        for false_flag in [
            "implementation_included",
            "tool_registration_implemented",
            "tool_registry_runtime_implemented",
            "tool_discovery_runtime_implemented",
            "tool_execution_implemented",
            "request_dispatcher_implemented",
            "protocol_handler_implemented",
            "json_rpc_parser_implemented",
            "protocol_message_parser_implemented",
            "schema_validation_runtime_implemented",
            "transport_runtime_implemented",
            "socket_bind_implemented",
            "socket_listen_implemented",
            "socket_accept_implemented",
            "stdio_transport_runtime_implemented",
            "http_transport_runtime_implemented",
            "local_evidence_reader_implemented",
            "safe_file_body_reader_implemented",
            "raw_preview_download_implemented",
            "replay_active_scan_implemented",
            "automatic_chatgpt_handoff_implemented",
            "dashboard_state_changing_control_implemented",
            "upload_import_action_implemented",
            "raw_data_included",
        ]:
            self.assertIs(fixture[false_flag], False)

        for behavior in [
            "executable_tool_registration",
            "runtime_tool_registry",
            "runtime_tool_discovery",
            "request_dispatcher",
            "actual_tool_execution",
            "local_evidence_reader_tool",
            "safe_file_body_reader_tool",
            "raw_preview_download_tool",
            "replay_active_scan_tool",
            "external_handoff_tool",
            "dashboard_state_changing_tool",
            "upload_import_tool",
        ]:
            self.assertIn(behavior, fixture["forbidden_tool_registration_behaviors"])

        for contract in [
            "tool_registration_and_execution_are_separate_prs",
            "registration_metadata_is_future_design_data_only",
            "registration_metadata_is_not_runtime_callable_surface",
            "tool_call_dispatch_is_out_of_scope",
            "local_file_read_is_out_of_scope",
            "safe_file_body_read_is_out_of_scope",
            "raw_preview_is_out_of_scope",
            "replay_active_scan_is_out_of_scope",
            "external_handoff_tool_is_forbidden",
            "candidate_findings_remain_candidates",
            "risk_remains_draft",
            "final_severity_or_scoring_remains_manual",
        ]:
            self.assertIn(contract, fixture["tool_execution_separation_contract"])

        for negative in [
            "tool_registration_marker_check",
            "tool_registry_runtime_marker_check",
            "tool_discovery_runtime_marker_check",
            "tool_execution_marker_check",
            "dispatcher_marker_check",
            "local_evidence_reader_tool_marker_check",
            "raw_preview_download_tool_marker_check",
            "replay_active_scan_tool_marker_check",
            "external_handoff_tool_marker_check",
            "dashboard_state_changing_tool_marker_check",
        ]:
            self.assertIn(negative, fixture["required_negative_tests"])

        for requirement in [
            "declare_tool_registration_facing_files_before_runtime",
            "block_executable_tool_registration_markers",
            "block_runtime_tool_registry_markers",
            "block_runtime_tool_discovery_markers",
            "block_request_dispatcher_markers",
            "block_tool_execution_markers",
            "block_local_evidence_reader_tool_markers",
            "block_safe_file_body_reader_tool_markers",
            "block_raw_preview_download_tool_markers",
            "block_replay_active_scan_tool_markers",
            "block_external_handoff_tool_markers",
            "block_dashboard_state_changing_tool_markers",
            "block_upload_import_tool_markers",
            "block_protocol_parser_markers",
            "block_transport_runtime_markers",
        ]:
            self.assertIn(requirement, fixture["source_check_requirements"])

        self.assertEqual(
            fixture["recommended_next_order"][:2],
            ["read_only_tool_contract_v08", "transport_protocol_minimal_skeleton_planning"],
        )

        combined = doc + "\n" + fixture_text
        for forbidden in [
            "safe-to-share",
            "safe to share",
            "guaranteed safe",
            "confirmed vulnerability",
            "confirmed finding",
            "confirmed issue count",
            "final CVSS",
            "\"raw_request\"",
            "\"raw_response\"",
            "raw_request:",
            "raw_response:",
            "Cookie:",
            "Authorization:",
            "Bearer ",
            "JWT ",
            "session=",
            "token=",
            "HMAC secret:",
            "CSRF token:",
            "C:\\coding\\",
            "C:\\Users\\",
            "local_only/",
            "real_export_",
            "actual.local",
            "example.com",
            "approved for external sharing",
            "ready to submit",
        ]:
            self.assertNotIn(forbidden, combined)
        self.assertIsNone(re.search(r"https?://", combined))
        self.assertIsNone(re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", combined))

    def test_v08_read_only_tool_contract_is_planning_only_and_raw_free(self) -> None:
        doc = V08_READ_ONLY_TOOL_CONTRACT_DOC.read_text(encoding="utf-8")
        fixture = json.loads(V08_READ_ONLY_TOOL_CONTRACT_FIXTURE.read_text(encoding="utf-8"))
        fixture_text = json.dumps(fixture, sort_keys=True)
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        backlog = V08_BACKLOG_SPLIT_DOC.read_text(encoding="utf-8")
        registration = V08_TOOL_REGISTRATION_DESIGN_DOC.read_text(encoding="utf-8")
        normalized_doc = " ".join(doc.split())
        normalized_doc_lower = normalized_doc.lower()

        self.assertTrue(V08_READ_ONLY_TOOL_CONTRACT_DOC.exists())
        self.assertTrue(V08_READ_ONLY_TOOL_CONTRACT_FIXTURE.exists())
        for linked_text in [readme, backlog, registration]:
            self.assertIn("V0.8_READ_ONLY_TOOL_CONTRACT.md", linked_text)

        for section in [
            "## Purpose",
            "## Current v0.8 baseline",
            "## Read-only tool contract scope",
            "## Explicit non-goals",
            "## Allowed future read-only metadata tools",
            "## Forbidden tool surfaces",
            "## Raw-free response contract",
            "## Candidate-only finding contract",
            "## Required negative tests",
            "## Source-check requirements",
            "## Security review requirements",
            "## Rollback expectations",
            "## Deferred decisions",
        ]:
            self.assertIn(section, doc)

        for required_text in [
            "planning and review-boundary document",
            "v0.8 backlog split",
            "v0.8 transport design",
            "v0.8 protocol handler design",
            "v0.8 protocol negative test harness",
            "v0.8 tool registration design",
            "metadata-only future read-only tool candidates",
            "gateway_status",
            "verified_output_aliases",
            "safe_file_inventory",
            "prompt_readiness",
            "report_readiness",
            "triage_summary_metadata",
            "workflow_status",
            "troubleshooting_categories",
            "release_readiness_metadata",
            "raw_exchange_lookup",
            "local_evidence_reader",
            "safe_file_body_reader",
            "arbitrary_file_reader",
            "replay_request",
            "active_scan",
            "external_handoff",
            "automatic_chatgpt_handoff",
            "dashboard_start_stop_control",
            "upload_import_action",
            "tag_or_release_action",
            "no raw request or response",
            "no credential value",
            "no session value",
            "no token value",
            "no full local path",
            "no actual target identifier",
            "no file body",
            "candidate findings only",
            "risk draft only",
            "final severity is manual",
            "final scoring is manual",
        ]:
            self.assertIn(required_text.lower(), normalized_doc_lower)

        self.assertEqual(fixture["schema_version"], "v08_read_only_tool_contract.v1")
        for true_flag in [
            "read_only_tool_contract_only",
            "v08_backlog_split_consumed",
            "v08_transport_design_consumed",
            "v08_protocol_handler_design_consumed",
            "v08_protocol_negative_harness_consumed",
            "v08_tool_registration_design_consumed",
        ]:
            self.assertIs(fixture[true_flag], True)

        for false_flag in [
            "implementation_included",
            "tool_implementation_included",
            "tool_registration_runtime_implemented",
            "tool_discovery_runtime_implemented",
            "tool_execution_implemented",
            "request_dispatcher_implemented",
            "protocol_handler_implemented",
            "json_rpc_parser_implemented",
            "transport_runtime_implemented",
            "local_evidence_reader_implemented",
            "safe_file_body_reader_implemented",
            "raw_preview_download_implemented",
            "replay_active_scan_implemented",
            "automatic_chatgpt_handoff_implemented",
            "dashboard_state_changing_control_implemented",
            "upload_import_action_implemented",
            "raw_data_included",
        ]:
            self.assertIs(fixture[false_flag], False)

        for candidate in [
            "gateway_status",
            "verified_output_aliases",
            "safe_file_inventory",
            "prompt_readiness",
            "report_readiness",
        ]:
            self.assertIn(candidate, fixture["allowed_metadata_tool_candidates"])

        for surface in [
            "raw_exchange_lookup",
            "raw_request_response_reader",
            "local_evidence_reader",
            "safe_file_body_reader",
            "arbitrary_file_reader",
            "replay_request",
            "active_scan",
            "external_handoff",
            "automatic_chatgpt_handoff",
            "dashboard_start_stop_control",
            "upload_import_action",
            "tag_or_release_action",
        ]:
            self.assertIn(surface, fixture["forbidden_tool_surfaces"])

        for contract in [
            "no_raw_request_response",
            "no_credential_value",
            "no_session_value",
            "no_token_value",
            "no_hmac_secret",
            "no_csrf_token_value",
            "no_full_local_path",
            "no_actual_target_identifier",
            "no_stack_trace",
            "no_file_body",
            "no_external_handoff",
            "candidate_findings_only",
            "risk_draft_only",
            "final_severity_manual",
            "final_cvss_manual",
        ]:
            self.assertIn(contract, fixture["raw_free_response_contract"])

        for negative in [
            "raw_exchange_lookup_tool_marker_check",
            "local_evidence_reader_tool_marker_check",
            "safe_file_body_reader_tool_marker_check",
            "arbitrary_file_reader_tool_marker_check",
            "file_write_delete_edit_tool_marker_check",
            "replay_active_scan_tool_marker_check",
            "external_handoff_tool_marker_check",
            "automatic_chatgpt_handoff_marker_check",
            "dashboard_state_changing_tool_marker_check",
            "upload_import_tool_marker_check",
            "tag_release_action_marker_check",
        ]:
            self.assertIn(negative, fixture["required_negative_tests"])

        for requirement in [
            "declare_tool_facing_files_before_implementation",
            "block_raw_exchange_lookup_tool_markers",
            "block_local_evidence_reader_tool_markers",
            "block_safe_file_body_reader_tool_markers",
            "block_arbitrary_file_reader_tool_markers",
            "block_file_write_delete_edit_tool_markers",
            "block_replay_active_scan_tool_markers",
            "block_external_handoff_tool_markers",
            "block_automatic_chatgpt_handoff_markers",
            "block_dashboard_state_changing_tool_markers",
            "block_upload_import_tool_markers",
            "block_tag_release_action_markers",
            "block_request_dispatcher_markers",
            "block_executable_tool_registration_markers",
            "block_actual_tool_execution_markers",
        ]:
            self.assertIn(requirement, fixture["source_check_requirements"])

        self.assertEqual(
            fixture["recommended_next_order"][:2],
            ["transport_protocol_minimal_skeleton_planning", "disabled_by_default_skeleton_approval_packet"],
        )

    def test_v08_minimal_skeleton_planning_is_planning_only_and_raw_free(self) -> None:
        doc = V08_MINIMAL_SKELETON_PLANNING_DOC.read_text(encoding="utf-8")
        fixture = json.loads(V08_MINIMAL_SKELETON_PLANNING_FIXTURE.read_text(encoding="utf-8"))
        fixture_text = json.dumps(fixture, sort_keys=True)
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        backlog = V08_BACKLOG_SPLIT_DOC.read_text(encoding="utf-8")
        contract = V08_READ_ONLY_TOOL_CONTRACT_DOC.read_text(encoding="utf-8")
        normalized_doc = " ".join(doc.split())
        normalized_doc_lower = normalized_doc.lower()

        self.assertTrue(V08_MINIMAL_SKELETON_PLANNING_DOC.exists())
        self.assertTrue(V08_MINIMAL_SKELETON_PLANNING_FIXTURE.exists())
        for linked_text in [readme, backlog, contract]:
            self.assertIn("V0.8_MINIMAL_SKELETON_PLANNING.md", linked_text)

        for section in [
            "## Purpose",
            "## Current v0.8 baseline",
            "## Minimal skeleton planning scope",
            "## Explicit non-goals",
            "## Disabled-by-default requirements",
            "## Transport/protocol separation",
            "## Contract consumption requirements",
            "## Forbidden runtime behaviors",
            "## Required negative tests",
            "## Source-check requirements",
            "## Security review requirements",
            "## Rollback expectations",
            "## Deferred decisions",
        ]:
            self.assertIn(section, doc)

        for required_text in [
            "planning and review-boundary document",
            "v0.8 backlog split",
            "v0.8 transport design",
            "v0.8 protocol handler design",
            "v0.8 protocol negative test harness",
            "v0.8 tool registration design",
            "v0.8 read-only tool contract",
            "disabled by default",
            "loopback-only if any runtime is later approved",
            "does not parse protocol messages",
            "does not dispatch tools",
            "does not read local evidence",
            "does not return file bodies",
            "raw-free blocked or disabled responses",
            "manual review",
            "four-file safe candidate boundary",
            "socket bind, listen, or accept",
            "stdio runtime",
            "http runtime",
            "protocol parser",
            "json-rpc parser",
            "request dispatcher",
            "executable tool registration",
            "actual tool execution",
            "local evidence reader",
            "safe file body reader",
            "raw preview",
            "replay or active scan",
            "automatic chatgpt handoff",
            "dashboard state-changing control",
            "upload or import action",
        ]:
            self.assertIn(required_text.lower(), normalized_doc_lower)

        self.assertEqual(fixture["schema_version"], "v08_minimal_skeleton_planning.v1")
        for true_flag in [
            "minimal_skeleton_planning_only",
            "v08_backlog_split_consumed",
            "v08_transport_design_consumed",
            "v08_protocol_handler_design_consumed",
            "v08_protocol_negative_harness_consumed",
            "v08_tool_registration_design_consumed",
            "v08_read_only_tool_contract_consumed",
        ]:
            self.assertIs(fixture[true_flag], True)

        for false_flag in [
            "implementation_included",
            "skeleton_runtime_implemented",
            "socket_bind_implemented",
            "socket_listen_implemented",
            "socket_accept_implemented",
            "stdio_transport_runtime_implemented",
            "http_transport_runtime_implemented",
            "protocol_parser_implemented",
            "json_rpc_parser_implemented",
            "request_dispatcher_implemented",
            "tool_registration_runtime_implemented",
            "tool_discovery_runtime_implemented",
            "tool_execution_implemented",
            "local_evidence_reader_implemented",
            "safe_file_body_reader_implemented",
            "raw_preview_download_implemented",
            "replay_active_scan_implemented",
            "automatic_chatgpt_handoff_implemented",
            "dashboard_state_changing_control_implemented",
            "upload_import_action_implemented",
            "tag_github_release_modified",
            "output_bundle_structure_changed",
        ]:
            self.assertIs(fixture[false_flag], False)

        for requirement in [
            "disabled_by_default",
            "loopback_only_if_approved",
            "no_protocol_parser_same_pr",
            "no_request_dispatcher",
            "no_tool_dispatch",
            "no_local_evidence_reader",
            "no_file_body_response",
            "raw_free_blocked_or_disabled_response",
            "manual_review_required",
            "preserve_four_file_safe_candidate_boundary",
        ]:
            self.assertIn(requirement, fixture["disabled_by_default_requirements"])

        for consumed in [
            "v08_backlog_split",
            "v08_transport_design",
            "v08_protocol_handler_design",
            "v08_protocol_negative_harness",
            "v08_tool_registration_design",
            "v08_read_only_tool_contract",
        ]:
            self.assertIn(consumed, fixture["contract_consumption_requirements"])

        for behavior in [
            "skeleton_runtime_startup",
            "socket_bind_listen_accept",
            "stdio_runtime",
            "http_runtime",
            "protocol_parser",
            "json_rpc_parser",
            "request_dispatcher",
            "executable_tool_registration",
            "tool_registry_runtime",
            "tool_discovery_runtime",
            "actual_tool_execution",
            "local_evidence_reader",
            "safe_file_body_reader",
            "raw_preview_download",
            "replay_active_scan",
            "automatic_chatgpt_handoff",
            "dashboard_state_changing_control",
            "upload_import_action",
        ]:
            self.assertIn(behavior, fixture["forbidden_runtime_behaviors"])

        for negative in [
            "skeleton_runtime_marker_check",
            "socket_bind_listen_accept_marker_check",
            "stdio_http_runtime_marker_check",
            "protocol_parser_marker_check",
            "json_rpc_parser_marker_check",
            "request_dispatcher_marker_check",
            "tool_registration_runtime_marker_check",
            "tool_execution_marker_check",
            "local_evidence_reader_marker_check",
            "safe_file_body_reader_marker_check",
            "raw_preview_download_marker_check",
            "replay_active_scan_marker_check",
            "automatic_handoff_marker_check",
            "dashboard_state_changing_marker_check",
            "upload_import_marker_check",
        ]:
            self.assertIn(negative, fixture["required_negative_tests"])

        for requirement in [
            "declare_runtime_facing_files_before_implementation",
            "block_skeleton_runtime_markers",
            "block_socket_bind_listen_accept_markers",
            "block_stdio_http_runtime_markers",
            "block_protocol_parser_markers",
            "block_json_rpc_parser_markers",
            "block_request_dispatcher_markers",
            "block_executable_tool_registration_markers",
            "block_actual_tool_execution_markers",
            "block_local_evidence_reader_markers",
            "block_safe_file_body_reader_markers",
            "block_raw_preview_download_markers",
            "block_replay_active_scan_markers",
            "block_automatic_handoff_markers",
            "block_dashboard_state_changing_markers",
            "block_upload_import_markers",
            "block_tag_release_action_markers",
        ]:
            self.assertIn(requirement, fixture["source_check_requirements"])

        self.assertEqual(
            fixture["recommended_next_order"][:2],
            ["disabled_by_default_skeleton_approval_packet", "runtime_facing_source_check_consumption_guard"],
        )

        combined = "\n".join([doc, fixture_text])
        for forbidden in [
            "\ufeff",
            "\ufffd",
            "??",
            "safe-to-share",
            "safe to share",
            "guaranteed safe",
            "confirmed vulnerability",
            "confirmed finding",
            "confirmed issue count",
            "final CVSS",
            "\"raw_request\"",
            "\"raw_response\"",
            "raw_request:",
            "raw_response:",
            "Cookie:",
            "Authorization:",
            "Bearer ",
            "JWT ",
            "session=",
            "token=",
            "HMAC secret:",
            "CSRF token:",
            "C:\\coding\\",
            "C:\\Users\\",
            "local_only/",
            "real_export_",
            "actual.local",
            "example.com",
            "approved for external sharing",
            "ready to submit",
        ]:
            self.assertNotIn(forbidden, combined)
        self.assertIsNone(re.search(r"https?://", combined))
        self.assertIsNone(re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", combined))

        combined = doc + "\n" + fixture_text
        for forbidden in [
            "safe-to-share",
            "safe to share",
            "guaranteed safe",
            "confirmed vulnerability",
            "confirmed finding",
            "confirmed issue count",
            "final CVSS",
            "\"raw_request\"",
            "\"raw_response\"",
            "raw_request:",
            "raw_response:",
            "Cookie:",
            "Authorization:",
            "Bearer ",
            "JWT ",
            "session=",
            "token=",
            "HMAC secret:",
            "CSRF token:",
            "C:\\coding\\",
            "C:\\Users\\",
            "local_only/",
            "real_export_",
            "actual.local",
            "example.com",
            "approved for external sharing",
            "ready to submit",
        ]:
            self.assertNotIn(forbidden, combined)
        self.assertIsNone(re.search(r"https?://", combined))
        self.assertIsNone(re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", combined))

    def test_burp_mcp_compatibility_doc_is_boundary_only_and_raw_free(self) -> None:
        compatibility = BURP_MCP_COMPATIBILITY_DOC.read_text(encoding="utf-8")
        mcp_design = MCP_INTEGRATION_DESIGN_DOC.read_text(encoding="utf-8")
        roadmap = (ROOT / "docs" / "ROADMAP_v0.5.md").read_text(encoding="utf-8")
        readiness = V05_RELEASE_READINESS_DOC.read_text(encoding="utf-8")
        readme = (ROOT / "README.md").read_text(encoding="utf-8")

        for linked_text in [mcp_design, roadmap, readiness, readme]:
            self.assertIn("BURP_MCP_COMPATIBILITY_v0.5.md", linked_text)

        for required in [
            "Burp MCP does not replace this gateway",
            "upstream tool",
            "downstream safety gateway",
            "redacts and verifies",
            "manual AI input or future read-only MCP gateway",
            "direct Burp MCP access",
            "not approved for",
            "analysis_packet.json",
            "chatgpt_prompt.md",
            "codex_task_prompt.md",
            "report_draft.md",
            "read-only first",
            "Deny by default",
            "Allowlist tools only",
            "No raw traffic",
            "No credential, session, or token values",
            "No local path exposure",
            "No automatic external handoff",
            "Candidate finding only",
            "Risk draft only",
            "Final severity and CVSS are manual decisions",
            "Tag and GitHub Release actions need separate approval",
            "AI directly reading Burp-side raw traffic through Burp MCP",
            "AI sending or replaying requests through Burp MCP",
            "Automatic active scan execution",
            "Automatic ChatGPT handoff",
            "Raw preview or raw download",
            "HMAC secret or CSRF token exposure",
            "Confirm no tag or GitHub Release is created",
        ]:
            self.assertIn(required, compatibility)

        for forbidden in [
            "safe-to-share",
            "guaranteed safe",
            "confirmed vulnerability",
            "final CVSS",
            "raw_request",
            "raw_response",
            "cookie_value",
            "authorization_value",
            "Authorization:",
            "Cookie:",
            "Bearer ",
            "JWT",
            "session=",
            "C:\\coding\\",
            "C:\\Users\\",
            "local_only/",
            "real_export_",
            "actual.local",
            "example.com",
        ]:
            self.assertNotIn(forbidden, compatibility)
        self.assertIsNone(re.search(r"https?://", compatibility))
        self.assertIsNone(re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", compatibility))

    def test_mcp_read_only_tool_contract_matrix_v06_is_planning_only_and_raw_free(self) -> None:
        contract = MCP_READ_ONLY_TOOL_CONTRACT_MATRIX_V06_DOC.read_text(encoding="utf-8")
        fixture = json.loads(
            MCP_READ_ONLY_TOOL_CONTRACT_MATRIX_V06_FIXTURE.read_text(encoding="utf-8")
        )
        roadmap_v06 = ROADMAP_V06_DOC.read_text(encoding="utf-8")
        mcp_design = MCP_INTEGRATION_DESIGN_DOC.read_text(encoding="utf-8")
        compatibility = BURP_MCP_COMPATIBILITY_DOC.read_text(encoding="utf-8")
        readme = (ROOT / "README.md").read_text(encoding="utf-8")

        for linked_text in [roadmap_v06, mcp_design, compatibility, readme]:
            self.assertIn("MCP_READ_ONLY_TOOL_CONTRACT_MATRIX_v0.6.md", linked_text)

        allowed_tools = [
            "get_gateway_status",
            "list_verified_outputs",
            "get_live_capture_status",
            "get_safe_file_inventory",
            "get_report_readiness",
            "get_prompt_readiness",
            "get_troubleshooting_categories",
            "get_release_readiness",
        ]
        blocked_tools = [
            "get_raw_request",
            "get_raw_response",
            "read_local_only_file",
            "read_raw_vault",
            "replay_request",
            "active_scan",
            "send_to_chatgpt",
            "delete_files",
            "show_hmac_secret",
            "show_csrf_token",
            "modify_burp_config",
            "collaborator_payload_send",
        ]
        blocked_codes = [
            "not_verified",
            "not_allowlisted",
            "raw_access_blocked",
            "state_change_blocked",
            "local_path_blocked",
            "secret_access_blocked",
        ]

        self.assertEqual(fixture["allowed_candidate_tools"], allowed_tools)
        self.assertEqual(fixture["forbidden_tool_concepts"], blocked_tools)
        self.assertEqual(fixture["blocked_response_codes"], blocked_codes)
        self.assertTrue(fixture["planning_only"])
        self.assertFalse(fixture["runtime_registry_implemented"])
        self.assertTrue(fixture["read_only_first"])
        self.assertTrue(fixture["allowlist_tools_only"])
        self.assertTrue(fixture["verify_first_requirement"])
        self.assertFalse(fixture["raw_data_included"])

        for required in [
            "contract matrix only",
            "does not implement an MCP server",
            "register MCP tools",
            "read-only first",
            "allowlist tools only",
            "verify-first",
            "No automatic ChatGPT handoff",
            "Candidate finding",
            "risk language draft-only",
            "severity and CVSS as manual decisions",
            "not return raw traffic",
            "Blocked Response Contract",
            "raw_data_included: false",
        ]:
            self.assertIn(required, contract)
        for tool in allowed_tools + blocked_tools:
            self.assertIn(tool, contract)
        for code in blocked_codes:
            self.assertIn(code, contract)
        for safe_file in [
            "analysis_packet.json",
            "chatgpt_prompt.md",
            "codex_task_prompt.md",
            "report_draft.md",
        ]:
            self.assertIn(safe_file, contract)
            self.assertIn(safe_file, json.dumps(fixture))

        serialized_fixture = json.dumps(fixture)
        self.assertIn("no_raw_traffic", serialized_fixture)
        self.assertIn("no_automatic_chatgpt_handoff", serialized_fixture)
        self.assertIn("candidate_finding_only", serialized_fixture)
        self.assertIn("risk_draft_only", serialized_fixture)
        self.assertIn("final_severity_cvss_manual_decision", serialized_fixture)

        combined = contract + "\n" + serialized_fixture
        for forbidden in [
            "safe-to-share",
            "guaranteed safe",
            "confirmed vulnerability",
            "final CVSS",
            "\"raw_request\"",
            "\"raw_response\"",
            "raw_request:",
            "raw_response:",
            "cookie_value",
            "authorization_value",
            "Authorization:",
            "Cookie:",
            "Bearer ",
            "JWT",
            "session=",
            "C:\\coding\\",
            "C:\\Users\\",
            "real_export_",
            "actual.local",
            "example.com",
        ]:
            self.assertNotIn(forbidden, combined)
        self.assertIsNone(re.search(r"https?://", combined))
        self.assertIsNone(re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", combined))

    def test_mcp_read_only_prototype_preflight_v06_is_planning_only_and_raw_free(self) -> None:
        preflight = MCP_READ_ONLY_PROTOTYPE_PREFLIGHT_V06_DOC.read_text(encoding="utf-8")
        fixture = json.loads(
            MCP_READ_ONLY_PROTOTYPE_PREFLIGHT_V06_FIXTURE.read_text(encoding="utf-8")
        )
        roadmap_v06 = ROADMAP_V06_DOC.read_text(encoding="utf-8")
        contract = MCP_READ_ONLY_TOOL_CONTRACT_MATRIX_V06_DOC.read_text(encoding="utf-8")
        mcp_design = MCP_INTEGRATION_DESIGN_DOC.read_text(encoding="utf-8")
        readme = (ROOT / "README.md").read_text(encoding="utf-8")

        for linked_text in [roadmap_v06, contract, mcp_design, readme]:
            self.assertIn("MCP_READ_ONLY_PROTOTYPE_PREFLIGHT_v0.6.md", linked_text)

        allowed_tools = [
            "get_gateway_status",
            "list_verified_outputs",
            "get_live_capture_status",
            "get_safe_file_inventory",
            "get_report_readiness",
            "get_prompt_readiness",
            "get_troubleshooting_categories",
            "get_release_readiness",
        ]
        forbidden_tools = [
            "get_raw_request",
            "get_raw_response",
            "read_local_only_file",
            "read_raw_vault",
            "replay_request",
            "active_scan",
            "send_to_chatgpt",
            "delete_files",
            "show_hmac_secret",
            "show_csrf_token",
            "modify_burp_config",
            "collaborator_payload_send",
        ]
        blocked_codes = [
            "not_verified",
            "not_allowlisted",
            "raw_access_blocked",
            "state_change_blocked",
            "local_path_blocked",
            "secret_access_blocked",
        ]
        safe_files = [
            "analysis_packet.json",
            "chatgpt_prompt.md",
            "codex_task_prompt.md",
            "report_draft.md",
        ]

        self.assertEqual(fixture["allowed_tools"], allowed_tools)
        self.assertEqual(fixture["forbidden_tools"], forbidden_tools)
        self.assertEqual(fixture["blocked_response_codes"], blocked_codes)
        self.assertEqual(fixture["safe_files"], safe_files)
        self.assertTrue(fixture["planning_only"])
        self.assertFalse(fixture["runtime_registry_implemented"])
        self.assertFalse(fixture["mcp_server_implemented"])
        self.assertFalse(fixture["mcp_tool_handler_implemented"])
        self.assertFalse(fixture["raw_data_included"])
        self.assertFalse(fixture["local_paths_included"])
        self.assertFalse(fixture["credential_values_included"])
        self.assertFalse(fixture["target_identifiers_included"])

        for required in [
            "planning and test-design document only",
            "does not implement an MCP server",
            "implement an MCP runtime registry",
            "add MCP tool handlers",
            "Purpose",
            "Non-goals",
            "Allowed Runtime Registry Candidates",
            "Forbidden Runtime Registry Concepts",
            "Registry Drift Prevention",
            "Blocked Response Schema",
            "Verify-First Behavior",
            "Safe File Allowlist",
            "Acceptance Evidence For Later Implementation PR",
            "no raw traffic",
            "No automatic ChatGPT handoff",
            "Candidate finding only",
            "Risk draft only",
            "Final severity/CVSS manual decision",
        ]:
            self.assertIn(required, preflight)
        for item in allowed_tools + forbidden_tools + blocked_codes + safe_files:
            self.assertIn(item, preflight)
            self.assertIn(item, json.dumps(fixture))
        for field in ["ok", "code", "safe_reason", "output_alias", "remediation_hint"]:
            self.assertIn(field, preflight)
            self.assertIn(field, json.dumps(fixture))

        serialized_fixture = json.dumps(fixture)
        for required in [
            "allowlist_registry_test_required",
            "forbidden_concept_absence_test_required",
            "blocked_response_schema_test_required",
            "verify_first_behavior_required",
            "no_raw_traffic",
            "no_automatic_chatgpt_handoff",
            "candidate_finding_only",
            "risk_draft_only",
            "final_severity_cvss_manual_decision",
        ]:
            self.assertIn(required, serialized_fixture)

        combined = preflight + "\n" + serialized_fixture
        for forbidden in [
            "safe-to-share",
            "guaranteed safe",
            "confirmed vulnerability",
            "final CVSS",
            "\"raw_request\"",
            "\"raw_response\"",
            "raw_request:",
            "raw_response:",
            "cookie_value",
            "authorization_value",
            "Authorization:",
            "Cookie:",
            "Bearer ",
            "JWT",
            "session=",
            "C:\\coding\\",
            "C:\\Users\\",
            "real_export_",
            "actual.local",
            "example.com",
        ]:
            self.assertNotIn(forbidden, combined)
        self.assertIsNone(re.search(r"https?://", combined))
        self.assertIsNone(re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", combined))

    def test_mcp_registry_adapter_design_v06_is_design_only_and_raw_free(self) -> None:
        adapter = MCP_REGISTRY_ADAPTER_DESIGN_V06_DOC.read_text(encoding="utf-8")
        roadmap_v06 = ROADMAP_V06_DOC.read_text(encoding="utf-8")
        fast_track = V06_FAST_TRACK_PLAN_DOC.read_text(encoding="utf-8")
        contract = MCP_READ_ONLY_TOOL_CONTRACT_MATRIX_V06_DOC.read_text(encoding="utf-8")
        preflight = MCP_READ_ONLY_PROTOTYPE_PREFLIGHT_V06_DOC.read_text(encoding="utf-8")
        readme = (ROOT / "README.md").read_text(encoding="utf-8")

        for linked_text in [roadmap_v06, fast_track, contract, preflight, readme]:
            self.assertIn("MCP_REGISTRY_ADAPTER_DESIGN_v0.6.md", linked_text)

        for required in [
            "design document only",
            "does not implement an MCP server",
            "No MCP transport implementation",
            "No protocol handler implementation",
            "No tool handler implementation",
            "No local evidence reader",
            "No automatic ChatGPT handoff",
            "Purpose",
            "Non-goals",
            "Adapter Boundary",
            "Registry Consumption Flow",
            "Verify-First Behavior",
            "Blocked Response Handling",
            "Forbidden Actions",
            "Safe Metadata Boundary",
            "Fixture Consistency Requirements",
            "Acceptance Evidence For Later Implementation",
            "mcp_read_only_registry.py",
            "build_read_only_tool_registry()",
            "build_blocked_response()",
            "second independent allowlist",
            "verified output alias",
            "raw_data_included: false",
            "four AI input candidate file names",
            "Candidate finding only check",
            "Risk draft only check",
            "Final severity/CVSS manual decision check",
        ]:
            self.assertIn(required, adapter)

        for safe_file in [
            "analysis_packet.json",
            "chatgpt_prompt.md",
            "codex_task_prompt.md",
            "report_draft.md",
        ]:
            self.assertIn(safe_file, adapter)

        for forbidden in [
            "safe-to-share",
            "guaranteed safe",
            "confirmed vulnerability",
            "final CVSS",
            "\"raw_request\"",
            "\"raw_response\"",
            "raw_request:",
            "raw_response:",
            "cookie_value",
            "authorization_value",
            "Authorization:",
            "Cookie:",
            "Bearer ",
            "JWT",
            "session=",
            "token=",
            "C:\\coding\\",
            "C:\\Users\\",
            "real_export_",
            "actual.local",
            "example.com",
        ]:
            self.assertNotIn(forbidden, adapter)
        self.assertIsNone(re.search(r"https?://", adapter))
        self.assertIsNone(re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", adapter))

    def test_mcp_registry_adapter_fixture_plan_v06_matches_registry_and_is_raw_free(self) -> None:
        fixture_plan = MCP_REGISTRY_ADAPTER_FIXTURE_PLAN_V06_DOC.read_text(encoding="utf-8")
        fixture = json.loads(
            MCP_REGISTRY_ADAPTER_EXPECTED_BEHAVIOR_V06_FIXTURE.read_text(encoding="utf-8")
        )
        adapter = MCP_REGISTRY_ADAPTER_DESIGN_V06_DOC.read_text(encoding="utf-8")
        roadmap_v06 = ROADMAP_V06_DOC.read_text(encoding="utf-8")
        fast_track = V06_FAST_TRACK_PLAN_DOC.read_text(encoding="utf-8")
        contract = MCP_READ_ONLY_TOOL_CONTRACT_MATRIX_V06_DOC.read_text(encoding="utf-8")
        preflight = MCP_READ_ONLY_PROTOTYPE_PREFLIGHT_V06_DOC.read_text(encoding="utf-8")
        readme = (ROOT / "README.md").read_text(encoding="utf-8")

        for linked_text in [adapter, roadmap_v06, fast_track, contract, preflight, readme]:
            self.assertIn("MCP_REGISTRY_ADAPTER_FIXTURE_PLAN_v0.6.md", linked_text)
        self.assertIn(
            "synthetic_mcp_registry_adapter_expected_behavior_v0.6.json",
            fixture_plan,
        )
        self.assertIn(
            "synthetic_mcp_registry_adapter_expected_behavior_v0.6.json",
            adapter,
        )

        self.assertEqual(fixture["schema_version"], "mcp_registry_adapter_expected_behavior.v0.6")
        self.assertTrue(fixture["planning_only"])
        self.assertFalse(fixture["mcp_server_implemented"])
        self.assertFalse(fixture["mcp_transport_implemented"])
        self.assertFalse(fixture["mcp_protocol_handler_implemented"])
        self.assertFalse(fixture["mcp_tool_execution_implemented"])
        self.assertFalse(fixture["local_evidence_reader_implemented"])
        self.assertFalse(fixture["raw_data_included"])
        non_goal_flags = [
            "upload_import_action_implemented",
            "dashboard_post_action_implemented",
            "collector_forwarding_changed",
            "receiver_ingest_changed",
            "raw_preview_download_implemented",
            "replay_active_scan_implemented",
            "automatic_chatgpt_handoff_implemented",
            "tag_created",
            "github_release_created",
        ]
        for flag in non_goal_flags:
            self.assertIn(flag, fixture)
            self.assertFalse(fixture[flag])
        self.assertEqual(tuple(fixture["allowed_tools"]), ALLOWED_TOOL_NAMES)
        self.assertEqual(tuple(fixture["forbidden_tools"]), FORBIDDEN_TOOL_CONCEPTS)
        self.assertEqual(tuple(fixture["blocked_response_codes"]), BLOCKED_RESPONSE_CODES)
        self.assertEqual(tuple(fixture["blocked_response_allowed_fields"]), BLOCKED_RESPONSE_ALLOWED_FIELDS)
        self.assertEqual(tuple(fixture["safe_files"]), SAFE_FILE_ALLOWLIST)

        expected_case_codes = {
            "allowed_global_status_tool": None,
            "allowed_verified_output_specific_tool": None,
            "unverified_output_alias_blocked": "not_verified",
            "unknown_tool_blocked": "not_allowlisted",
            "forbidden_concept_blocked": "not_allowlisted",
            "raw_access_request_blocked": "raw_access_blocked",
            "state_changing_request_blocked": "state_change_blocked",
            "local_path_request_blocked": "local_path_blocked",
            "secret_request_blocked": "secret_access_blocked",
            "safe_file_inventory_metadata_only": None,
            "no_automatic_chatgpt_handoff": "state_change_blocked",
        }
        cases = fixture["adapter_cases"]
        self.assertEqual({case["name"] for case in cases}, set(expected_case_codes))
        for case in cases:
            self.assertEqual(case["expected_code"], expected_case_codes[case["name"]])
            self.assertIs(case["raw_data_included"], False)
            self.assertIs(case["local_path_included"], False)
            self.assertIs(case["credential_values_included"], False)
            self.assertIs(case["target_identifiers_included"], False)
            self.assertIs(case["state_change_performed"], False)
            self.assertIsInstance(case["expected_fields"], list)
            self.assertTrue(case["expected_fields"])
            if case["expected_code"] is None:
                self.assertTrue(case["expected_ok"])
                self.assertFalse(case["state_change_performed"])
            else:
                self.assertFalse(case["expected_ok"])
                self.assertIn(case["expected_code"], BLOCKED_RESPONSE_CODES)
                self.assertLessEqual(set(case["expected_fields"]), set(BLOCKED_RESPONSE_ALLOWED_FIELDS))

        for required in [
            "planning and fixture document only",
            "No MCP server implementation",
            "No MCP transport implementation",
            "No protocol handler implementation",
            "No actual tool execution",
            "No local evidence reader",
            "No dashboard POST action",
            "No raw preview or raw download",
            "No replay or active scan",
            "No automatic ChatGPT handoff",
            "No tag or GitHub Release",
            "does not approve adapter implementation",
            "machine-readable non-goal flags",
            "runtime boundary drift",
            "Cases with `expected_ok: true` are fixture expectations only",
            "implementation approval",
            "Purpose",
            "Non-goals",
            "Fixture Scope",
            "Adapter Expected Behavior Cases",
            "Blocked Response Case Matrix",
            "Drift Prevention",
            "Acceptance Evidence For Later Implementation",
            "Deferred Runtime Decisions",
            "raw_data_included: false",
            "state_change_performed: false",
        ]:
            self.assertIn(required, fixture_plan)
        for flag in non_goal_flags:
            self.assertIn(flag, fixture_plan)

        combined = fixture_plan + "\n" + json.dumps(fixture, sort_keys=True)
        normalized = (
            combined.replace("get_raw_request", "")
            .replace("get_raw_response", "")
            .replace("show_csrf_token", "")
        )
        for forbidden in [
            "safe-to-share",
            "guaranteed safe",
            "confirmed vulnerability",
            "final CVSS",
            "\"raw_request\"",
            "\"raw_response\"",
            "raw_request:",
            "raw_response:",
            "cookie_value",
            "authorization_value",
            "Authorization:",
            "Cookie:",
            "Bearer ",
            "JWT",
            "session=",
            "token=",
            "HMAC secret value",
            "CSRF token value",
            "C:\\coding\\",
            "C:\\Users\\",
            "real_export_",
            "actual.local",
            "example.com",
        ]:
            self.assertNotIn(forbidden, normalized)
        self.assertIsNone(re.search(r"https?://", normalized))
        self.assertIsNone(re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", normalized))

    def test_mcp_implementation_gate_design_v06_is_planning_only_and_raw_free(self) -> None:
        gate_doc = MCP_IMPLEMENTATION_GATE_DESIGN_V06_DOC.read_text(encoding="utf-8")
        fixture = json.loads(MCP_IMPLEMENTATION_GATE_V06_FIXTURE.read_text(encoding="utf-8"))
        roadmap_v06 = ROADMAP_V06_DOC.read_text(encoding="utf-8")
        fast_track = V06_FAST_TRACK_PLAN_DOC.read_text(encoding="utf-8")
        contract = MCP_READ_ONLY_TOOL_CONTRACT_MATRIX_V06_DOC.read_text(encoding="utf-8")
        preflight = MCP_READ_ONLY_PROTOTYPE_PREFLIGHT_V06_DOC.read_text(encoding="utf-8")
        adapter = MCP_REGISTRY_ADAPTER_DESIGN_V06_DOC.read_text(encoding="utf-8")
        fixture_plan = MCP_REGISTRY_ADAPTER_FIXTURE_PLAN_V06_DOC.read_text(encoding="utf-8")
        readme = (ROOT / "README.md").read_text(encoding="utf-8")

        for linked_text in [
            roadmap_v06,
            fast_track,
            contract,
            preflight,
            adapter,
            fixture_plan,
            readme,
        ]:
            self.assertIn("MCP_IMPLEMENTATION_GATE_DESIGN_v0.6.md", linked_text)
        self.assertIn("synthetic_mcp_implementation_gate_v0.6.json", gate_doc)

        for required in [
            "design and gate document only",
            "does not implement an MCP server",
            "MCP transport",
            "protocol handler",
            "actual tool execution",
            "No local evidence reader",
            "No upload or import action",
            "No dashboard POST action",
            "No raw preview or raw download",
            "No replay or active scan",
            "No automatic ChatGPT handoff",
            "No tag or GitHub Release",
            "No implementation approval",
            "Purpose",
            "Non-goals",
            "Required Preconditions",
            "Required Implementation Gates",
            "Required Blocked Cases",
            "Required Review Evidence",
            "Runtime Work That Remains Forbidden",
            "Approval Checklist",
            "Deferred Decisions",
            "registry helper",
            "adapter expected behavior fixture",
            "blocked response helper",
            "Verify-first behavior",
            "If any required gate is missing, runtime implementation remains blocked",
            "Candidate findings remain candidates",
            "Risk values remain drafts",
            "Severity and CVSS remain manual decisions",
            "No tag or GitHub Release was created",
        ]:
            self.assertIn(required, gate_doc)

        self.assertEqual(fixture["schema_version"], "mcp_implementation_gate.v0.6")
        self.assertTrue(fixture["planning_only"])
        self.assertFalse(fixture["implementation_approved"])
        self.assertFalse(fixture["raw_data_included"])
        runtime_flags = [
            "mcp_server_implemented",
            "mcp_transport_implemented",
            "mcp_protocol_handler_implemented",
            "mcp_tool_execution_implemented",
            "local_evidence_reader_implemented",
            "upload_import_action_implemented",
            "dashboard_post_action_implemented",
            "collector_forwarding_changed",
            "receiver_ingest_changed",
            "raw_preview_download_implemented",
            "replay_active_scan_implemented",
            "automatic_chatgpt_handoff_implemented",
            "tag_created",
            "github_release_created",
        ]
        for flag in runtime_flags:
            self.assertIn(flag, fixture)
            self.assertIs(fixture[flag], False)

        required_gate_names = {
            "registry_helper_consumed",
            "adapter_expected_behavior_fixture_consumed",
            "allowed_tools_match_registry",
            "forbidden_tools_absent",
            "blocked_response_helper_used",
            "blocked_response_fields_match_fixture",
            "verify_first_for_output_specific_tools",
            "unverified_alias_blocked",
            "unknown_tool_blocked",
            "forbidden_concept_blocked",
            "raw_access_blocked",
            "state_change_blocked",
            "local_path_blocked",
            "secret_access_blocked",
            "no_automatic_chatgpt_handoff",
            "no_local_evidence_reader",
            "no_raw_file_body",
            "no_target_identifier",
            "no_credential_or_session_value",
            "candidate_findings_only",
            "risk_draft_only",
            "severity_cvss_manual_decision",
        }
        gate_requirements = fixture["gate_requirements"]
        self.assertEqual({gate["name"] for gate in gate_requirements}, required_gate_names)
        for gate in gate_requirements:
            self.assertIs(gate["required"], True)
            self.assertIsInstance(gate["evidence_type"], str)
            self.assertTrue(gate["evidence_type"])
            self.assertIs(gate["blocks_runtime_if_missing"], True)
            self.assertIs(gate["raw_data_included"], False)
            self.assertIs(gate["state_change_performed"], False)

        combined = gate_doc + "\n" + json.dumps(fixture, sort_keys=True)
        for forbidden in [
            "safe-to-share",
            "guaranteed safe",
            "confirmed vulnerability",
            "final CVSS",
            "\"raw_request\"",
            "\"raw_response\"",
            "raw_request:",
            "raw_response:",
            "cookie_value",
            "authorization_value",
            "Authorization:",
            "Cookie:",
            "Bearer ",
            "JWT",
            "session=",
            "token=",
            "HMAC secret value",
            "CSRF token value",
            "C:\\coding\\",
            "C:\\Users\\",
            "real_export_",
            "actual.local",
            "example.com",
        ]:
            self.assertNotIn(forbidden, combined)
        self.assertIsNone(re.search(r"https?://", combined))
        self.assertIsNone(re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", combined))

    def test_mcp_adapter_dry_run_v06_consumes_fixtures_without_runtime_boundary_changes(self) -> None:
        adapter_fixture = json.loads(
            MCP_REGISTRY_ADAPTER_EXPECTED_BEHAVIOR_V06_FIXTURE.read_text(encoding="utf-8")
        )
        gate_fixture = json.loads(MCP_IMPLEMENTATION_GATE_V06_FIXTURE.read_text(encoding="utf-8"))
        module_source = MCP_ADAPTER_DRY_RUN_MODULE.read_text(encoding="utf-8")
        gate_doc = MCP_IMPLEMENTATION_GATE_DESIGN_V06_DOC.read_text(encoding="utf-8")
        fixture_plan = MCP_REGISTRY_ADAPTER_FIXTURE_PLAN_V06_DOC.read_text(encoding="utf-8")
        roadmap_v06 = ROADMAP_V06_DOC.read_text(encoding="utf-8")
        fast_track = V06_FAST_TRACK_PLAN_DOC.read_text(encoding="utf-8")
        readme = (ROOT / "README.md").read_text(encoding="utf-8")

        for linked_text in [gate_doc, fixture_plan, roadmap_v06, fast_track, readme]:
            self.assertIn("mcp_adapter_dry_run.py", linked_text)
        for required in [
            "local-only adapter dry-run skeleton",
            "not an MCP server",
            "not MCP transport",
            "not a protocol handler",
            "not actual tool execution",
            "not a local evidence reader",
            "not runtime MCP exposure",
            "gate and fixture consumption",
        ]:
            self.assertIn(required, gate_doc + "\n" + fixture_plan)

        self.assertIn("build_read_only_tool_registry", module_source)
        self.assertIn("build_blocked_response", module_source)
        self.assertNotIn("ALLOWED_TOOL_NAMES =", module_source)
        self.assertNotIn("FORBIDDEN_TOOL_CONCEPTS =", module_source)
        self.assertNotIn("http.server", module_source)
        self.assertNotIn("socketserver", module_source)
        self.assertNotIn("subprocess", module_source)

        plan = build_adapter_dry_run_plan(adapter_fixture, gate_fixture)
        self.assertEqual(
            plan,
            {
                "ok": True,
                "case_count": len(adapter_fixture["adapter_cases"]),
                "gate_requirement_count": len(gate_fixture["gate_requirements"]),
                "registry_tool_count": len(ALLOWED_TOOL_NAMES),
                "implementation_approved": False,
                "mcp_runtime_implemented": False,
                "raw_data_included": False,
                "local_path_included": False,
                "credential_values_included": False,
                "target_identifiers_included": False,
                "state_change_performed": False,
            },
        )

        evaluated = evaluate_adapter_dry_run_fixture(adapter_fixture, gate_fixture)
        self.assertTrue(evaluated["ok"])
        self.assertEqual(evaluated["case_count"], len(adapter_fixture["adapter_cases"]))
        self.assertEqual(evaluated["gate_requirement_count"], len(gate_fixture["gate_requirements"]))
        self.assertFalse(evaluated["raw_data_included"])
        self.assertFalse(evaluated["local_path_included"])
        self.assertFalse(evaluated["credential_values_included"])
        self.assertFalse(evaluated["target_identifiers_included"])
        self.assertFalse(evaluated["state_change_performed"])

        expected_case_codes = {
            "allowed_global_status_tool": None,
            "allowed_verified_output_specific_tool": None,
            "unverified_output_alias_blocked": "not_verified",
            "unknown_tool_blocked": "not_allowlisted",
            "forbidden_concept_blocked": "not_allowlisted",
            "raw_access_request_blocked": "raw_access_blocked",
            "state_changing_request_blocked": "state_change_blocked",
            "local_path_request_blocked": "local_path_blocked",
            "secret_request_blocked": "secret_access_blocked",
            "safe_file_inventory_metadata_only": None,
            "no_automatic_chatgpt_handoff": "state_change_blocked",
        }
        self.assertEqual(
            {result["case_name"]: result["observed_code"] for result in evaluated["case_results"]},
            expected_case_codes,
        )
        for result in evaluated["case_results"]:
            self.assertTrue(result["gate_passed"])
            self.assertFalse(result["raw_data_included"])
            self.assertFalse(result["local_path_included"])
            self.assertFalse(result["credential_values_included"])
            self.assertFalse(result["target_identifiers_included"])
            self.assertFalse(result["state_change_performed"])

        for case in adapter_fixture["adapter_cases"]:
            result = evaluate_adapter_dry_run_case(case)
            self.assertEqual(result["observed_code"], expected_case_codes[case["name"]])
            if case["expected_code"] is None:
                with self.assertRaises(McpAdapterDryRunError):
                    build_adapter_blocked_response_for_case(case)
            else:
                blocked = build_adapter_blocked_response_for_case(case)
                self.assertLessEqual(set(blocked), set(BLOCKED_RESPONSE_ALLOWED_FIELDS))
                self.assertFalse(blocked["ok"])
                self.assertEqual(blocked["code"], case["expected_code"])

        changed_gate_fixture = deepcopy(gate_fixture)
        changed_gate_fixture["implementation_approved"] = True
        with self.assertRaises(McpAdapterDryRunError):
            evaluate_adapter_dry_run_fixture(adapter_fixture, changed_gate_fixture)

        changed_adapter_fixture = deepcopy(adapter_fixture)
        changed_adapter_fixture["mcp_server_implemented"] = True
        with self.assertRaises(McpAdapterDryRunError):
            evaluate_adapter_dry_run_fixture(changed_adapter_fixture, gate_fixture)

        changed_adapter_fixture = deepcopy(adapter_fixture)
        changed_adapter_fixture["raw_data_included"] = True
        with self.assertRaises(McpAdapterDryRunError):
            evaluate_adapter_dry_run_fixture(changed_adapter_fixture, gate_fixture)

        changed_gate_fixture = deepcopy(gate_fixture)
        changed_gate_fixture["raw_data_included"] = True
        with self.assertRaises(McpAdapterDryRunError):
            evaluate_adapter_dry_run_fixture(adapter_fixture, changed_gate_fixture)

        changed_adapter_fixture = deepcopy(adapter_fixture)
        changed_adapter_fixture["blocked_response_codes"] = ["not_verified"]
        with self.assertRaises(McpAdapterDryRunError):
            evaluate_adapter_dry_run_fixture(changed_adapter_fixture, gate_fixture)

        changed_adapter_fixture = deepcopy(adapter_fixture)
        changed_adapter_fixture["adapter_cases"][2]["expected_fields"].append("raw_body")
        with self.assertRaises(McpAdapterDryRunError):
            evaluate_adapter_dry_run_fixture(changed_adapter_fixture, gate_fixture)

        changed_adapter_fixture = deepcopy(adapter_fixture)
        changed_adapter_fixture["adapter_cases"][2]["expected_fields"].remove("remediation_hint")
        with self.assertRaises(McpAdapterDryRunError):
            evaluate_adapter_dry_run_fixture(changed_adapter_fixture, gate_fixture)

        changed_adapter_fixture = deepcopy(adapter_fixture)
        changed_adapter_fixture["adapter_cases"][0]["expected_ok"] = "true"
        with self.assertRaises(McpAdapterDryRunError):
            evaluate_adapter_dry_run_fixture(changed_adapter_fixture, gate_fixture)

        combined = (
            module_source
            + "\n"
            + json.dumps(plan, sort_keys=True)
            + "\n"
            + json.dumps(evaluated, sort_keys=True)
        )
        normalized = (
            combined.replace("raw_access_request_blocked", "")
            .replace("raw_access_blocked", "")
            .replace("local_path_request_blocked", "")
            .replace("local_path_blocked", "")
            .replace("secret_request_blocked", "")
            .replace("secret_access_blocked", "")
        )
        for forbidden in [
            "safe-to-share",
            "guaranteed safe",
            "confirmed vulnerability",
            "final CVSS",
            "\"raw_request\"",
            "\"raw_response\"",
            "raw_request:",
            "raw_response:",
            "cookie_value",
            "authorization_value",
            "Authorization:",
            "Cookie:",
            "Bearer ",
            "JWT",
            "session=",
            "token=",
            "HMAC secret value",
            "CSRF token value",
            "C:\\coding\\",
            "C:\\Users\\",
            "real_export_",
            "actual.local",
            "example.com",
        ]:
            self.assertNotIn(forbidden, normalized)
        self.assertIsNone(re.search(r"https?://", normalized))
        self.assertIsNone(re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", normalized))

    def test_mcp_local_only_tool_schema_catalog_v06_stays_registry_based_and_raw_free(self) -> None:
        adapter_fixture = json.loads(
            MCP_REGISTRY_ADAPTER_EXPECTED_BEHAVIOR_V06_FIXTURE.read_text(encoding="utf-8")
        )
        gate_fixture = json.loads(MCP_IMPLEMENTATION_GATE_V06_FIXTURE.read_text(encoding="utf-8"))
        module_source = MCP_TOOL_SCHEMA_CATALOG_MODULE.read_text(encoding="utf-8")
        catalog_doc = MCP_TOOL_SCHEMA_CATALOG_DOC.read_text(encoding="utf-8")
        registry = build_read_only_tool_registry()

        self.assertIn("build_read_only_tool_registry", module_source)
        self.assertIn("evaluate_adapter_dry_run_fixture", module_source)
        self.assertNotIn("ALLOWED_TOOL_NAMES =", module_source)
        for forbidden_import in [
            "http.server",
            "socketserver",
            "http.client",
            "socket",
            "subprocess",
            "requests",
            "urllib",
        ]:
            self.assertNotIn(forbidden_import, module_source)

        catalog = build_local_only_tool_schema_catalog()
        validation = validate_tool_schema_catalog_against_registry(catalog)
        fixture_validation = validate_tool_schema_catalog_against_fixtures(
            adapter_fixture,
            gate_fixture,
            catalog,
        )
        self.assertEqual(
            validation,
            {
                "ok": True,
                "tool_count": len(ALLOWED_TOOL_NAMES),
                "read_only": True,
                "raw_data_included": False,
            },
        )
        self.assertEqual(fixture_validation["tool_count"], len(ALLOWED_TOOL_NAMES))
        self.assertEqual(fixture_validation["adapter_case_count"], len(adapter_fixture["adapter_cases"]))
        self.assertEqual(fixture_validation["gate_requirement_count"], len(gate_fixture["gate_requirements"]))
        self.assertFalse(fixture_validation["raw_data_included"])

        self.assertEqual(tuple(tool["name"] for tool in catalog["tools"]), ALLOWED_TOOL_NAMES)
        self.assertEqual(tuple(adapter_fixture["allowed_tools"]), ALLOWED_TOOL_NAMES)
        self.assertTrue(catalog["planning_only"])
        self.assertFalse(catalog["implementation_approved"])
        self.assertFalse(catalog["mcp_runtime_implemented"])
        self.assertFalse(catalog["raw_data_included"])
        self.assertFalse(catalog["local_path_included"])
        self.assertFalse(catalog["credential_values_included"])
        self.assertFalse(catalog["target_identifiers_included"])
        self.assertFalse(catalog["state_change_performed"])

        global_metadata_tools = {"get_gateway_status", "get_release_readiness"}
        unsafe_field_markers = [
            "raw",
            "request",
            "response",
            "body",
            "path",
            "url",
            "domain",
            "cookie",
            "authorization",
            "credential",
            "token",
            "session",
            "secret",
            "hmac",
            "csrf",
            "target",
        ]
        for descriptor in catalog["tools"]:
            name = descriptor["name"]
            entry = registry[name]
            self.assertEqual(
                set(descriptor),
                {
                    "name",
                    "description",
                    "read_only",
                    "verify_first",
                    "safe_input_fields",
                    "safe_output_fields",
                    "raw_data_included",
                    "local_path_included",
                    "credential_values_included",
                    "target_identifiers_included",
                    "state_change_performed",
                },
            )
            self.assertEqual(descriptor["description"], entry.description)
            self.assertTrue(descriptor["read_only"])
            self.assertEqual(descriptor["verify_first"], entry.verify_first)
            if name in global_metadata_tools:
                self.assertFalse(descriptor["verify_first"])
            else:
                self.assertTrue(descriptor["verify_first"])
            self.assertEqual(tuple(descriptor["safe_output_fields"]), entry.safe_output_fields)
            self.assertFalse(descriptor["raw_data_included"])
            self.assertFalse(descriptor["local_path_included"])
            self.assertFalse(descriptor["credential_values_included"])
            self.assertFalse(descriptor["target_identifiers_included"])
            self.assertFalse(descriptor["state_change_performed"])
            for field in descriptor["safe_input_fields"] + descriptor["safe_output_fields"]:
                field_lower = field.lower()
                self.assertFalse(any(marker in field_lower for marker in unsafe_field_markers), field)

        assert_tool_schema_catalog_raw_free(catalog)
        combined = json.dumps(catalog, sort_keys=True) + "\n" + catalog_doc
        normalized = combined.replace("raw-free", "metadata-only").replace("read-only", "readonly")
        for forbidden in [
            "safe-to-share",
            "guaranteed safe",
            "confirmed vulnerability",
            "final CVSS",
            "\"raw_request\"",
            "\"raw_response\"",
            "raw_request:",
            "raw_response:",
            "cookie_value",
            "authorization_value",
            "Authorization:",
            "Cookie:",
            "Bearer ",
            "JWT",
            "session=",
            "token=",
            "HMAC secret value",
            "CSRF token value",
            "C:\\coding\\",
            "C:\\Users\\",
            "real_export_",
            "actual.local",
            "example.com",
        ]:
            self.assertNotIn(forbidden, normalized)
        self.assertIsNone(re.search(r"https?://", normalized))
        self.assertIsNone(re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", normalized))

        changed_catalog = deepcopy(catalog)
        changed_catalog["tools"][0]["safe_output_fields"].append("raw_body")
        with self.assertRaises(McpToolSchemaCatalogError):
            assert_tool_schema_catalog_raw_free(changed_catalog)

        changed_catalog = deepcopy(catalog)
        changed_catalog["tools"][0]["raw_data_included"] = True
        with self.assertRaises(McpToolSchemaCatalogError):
            validate_tool_schema_catalog_against_registry(changed_catalog)

        changed_adapter_fixture = deepcopy(adapter_fixture)
        changed_adapter_fixture["allowed_tools"] = list(reversed(changed_adapter_fixture["allowed_tools"]))
        with self.assertRaises(McpToolSchemaCatalogError):
            validate_tool_schema_catalog_against_fixtures(changed_adapter_fixture, gate_fixture, catalog)

    def test_mcp_runtime_boundary_decision_v06_documents_split_before_server_work(self) -> None:
        decision = MCP_RUNTIME_BOUNDARY_DECISION_V06_DOC.read_text(encoding="utf-8")
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        roadmap = ROADMAP_V06_DOC.read_text(encoding="utf-8")
        fast_track = V06_FAST_TRACK_PLAN_DOC.read_text(encoding="utf-8")
        gate_doc = MCP_IMPLEMENTATION_GATE_DESIGN_V06_DOC.read_text(encoding="utf-8")
        catalog_doc = MCP_TOOL_SCHEMA_CATALOG_DOC.read_text(encoding="utf-8")
        fixture_plan = MCP_REGISTRY_ADAPTER_FIXTURE_PLAN_V06_DOC.read_text(encoding="utf-8")

        self.assertTrue(MCP_RUNTIME_BOUNDARY_DECISION_V06_DOC.exists())
        for linked_text in [readme, roadmap, fast_track, gate_doc, catalog_doc, fixture_plan]:
            self.assertIn("MCP_RUNTIME_BOUNDARY_DECISION_v0.6.md", linked_text)

        for section in [
            "## Purpose",
            "## Current Completed MCP Preparation",
            "## Non-goals",
            "## Runtime Boundary Decision",
            "## Allowed Next Slice",
            "## Forbidden Work",
            "## Required Acceptance Criteria Before Server Work",
            "## Required Test Evidence",
            "## Split Plan For Later Runtime Work",
            "## Deferred Decisions",
        ]:
            self.assertIn(section, decision)

        for completed in [
            "MCP contract matrix",
            "MCP prototype preflight",
            "Read-only registry skeleton",
            "Registry adapter design",
            "Adapter expected behavior fixture",
            "Implementation gate fixture",
            "Local-only adapter dry-run",
            "Local-only tool schema catalog",
        ]:
            self.assertIn(completed, decision)

        for non_goal in [
            "It is a design and decision document only",
            "No MCP server implementation",
            "No MCP transport implementation",
            "No protocol handler implementation",
            "No actual tool execution",
            "No local evidence reader implementation",
            "No upload or import action",
            "No dashboard POST action",
            "No raw preview or raw download",
            "No replay or active scan",
            "No automatic ChatGPT handoff",
            "No tag or GitHub Release",
            "No runtime implementation approval",
        ]:
            self.assertIn(non_goal, decision)

        for allowed_or_forbidden in [
            "Server-free local-only runtime boundary skeleton",
            "Server skeleton preflight",
            "must not create a listener",
            "External transport",
            "Protocol handling",
            "Actual tool execution",
            "Local evidence reader",
        ]:
            self.assertIn(allowed_or_forbidden, decision)

        for gate in [
            "Registry helper consumed",
            "Dry-run helper consumed",
            "Tool schema catalog consumed",
            "Implementation gate fixture consumed",
            "Adapter expected behavior fixture consumed",
            "Allowed tools match registry",
            "Forbidden concepts absent",
            "Blocked response helper used",
            "Verify-first behavior tested",
            "Raw-free metadata only",
            "Local path absent",
            "Credential, session, and token values absent",
            "Target identifier absent",
            "No automatic ChatGPT handoff",
            "No local evidence reader",
            "No state-changing action",
            "Candidate finding only",
            "Risk draft only",
            "Severity and CVSS manual decision",
        ]:
            self.assertIn(gate, decision)

        for split in [
            "Server listener skeleton",
            "Transport and protocol handler",
            "Tool registration",
            "Tool execution",
            "Local evidence reader",
            "Dashboard POST action",
            "Upload or import action",
            "Raw preview or raw download",
            "Automatic ChatGPT handoff",
            "Release or tag work",
        ]:
            self.assertIn(split, decision)

        combined = "\n".join([decision, roadmap, fast_track, gate_doc, catalog_doc, fixture_plan])
        for forbidden in [
            "safe-to-share",
            "guaranteed safe",
            "confirmed vulnerability",
            "final CVSS",
            "\"raw_request\"",
            "\"raw_response\"",
            "raw_request:",
            "raw_response:",
            "Cookie:",
            "Authorization:",
            "Bearer ",
            "JWT",
            "session=",
            "token=",
            "HMAC secret value",
            "CSRF token value",
            "C:\\coding\\",
            "C:\\Users\\",
            "real_export_",
            "actual.local",
            "example.com",
        ]:
            self.assertNotIn(forbidden, combined)
        self.assertIsNone(re.search(r"https?://", combined))
        self.assertIsNone(re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", combined))

    def test_mcp_server_skeleton_preflight_v06_consumes_boundary_without_runtime_surface(self) -> None:
        preflight = MCP_SERVER_SKELETON_PREFLIGHT_V06_DOC.read_text(encoding="utf-8")
        fixture = json.loads(MCP_SERVER_SKELETON_PREFLIGHT_V06_FIXTURE.read_text(encoding="utf-8"))
        fixture_text = json.dumps(fixture, sort_keys=True)
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        roadmap = ROADMAP_V06_DOC.read_text(encoding="utf-8")
        fast_track = V06_FAST_TRACK_PLAN_DOC.read_text(encoding="utf-8")
        decision = MCP_RUNTIME_BOUNDARY_DECISION_V06_DOC.read_text(encoding="utf-8")

        self.assertTrue(MCP_SERVER_SKELETON_PREFLIGHT_V06_DOC.exists())
        self.assertTrue(MCP_SERVER_SKELETON_PREFLIGHT_V06_FIXTURE.exists())
        for linked_text in [readme, roadmap, fast_track, decision]:
            self.assertIn("MCP_SERVER_SKELETON_PREFLIGHT_v0.6.md", linked_text)
        self.assertIn("MCP_RUNTIME_BOUNDARY_DECISION_v0.6.md", preflight)

        for section in [
            "## Purpose",
            "## Required Input Baseline",
            "## Acceptance Inputs",
            "## Allowed Preflight Work",
            "## Forbidden Work",
            "## Fixture Contract",
            "## Required Test Evidence",
            "## Later Runtime Split",
            "## Deferred Decisions",
        ]:
            self.assertIn(section, preflight)

        for consumed in [
            "MCP contract matrix",
            "MCP prototype preflight",
            "Read-only registry skeleton",
            "Registry adapter design",
            "Adapter expected behavior fixture",
            "Implementation gate fixture",
            "Local-only adapter dry-run",
            "Local-only tool schema catalog",
            "Runtime boundary decision",
            "Registry helper",
            "Dry-run helper",
            "Tool schema catalog",
            "Blocked response contract",
            "Verify-first behavior",
        ]:
            self.assertIn(consumed, preflight)

        for forbidden in [
            "Server listener",
            "Socket bind",
            "Stdio transport",
            "HTTP transport",
            "JSON-RPC protocol handler",
            "MCP protocol message parser",
            "Executable tool registration",
            "Actual tool execution",
            "Local evidence reader",
            "Safe file body reader",
            "Upload or import action",
            "Dashboard POST action",
            "Collector forwarding change",
            "Receiver ingest change",
            "Raw preview or download",
            "Replay or active scan",
            "Automatic ChatGPT handoff",
            "Tag or GitHub Release",
        ]:
            self.assertIn(forbidden, preflight)

        self.assertEqual(fixture["schema_version"], "mcp_server_skeleton_preflight.v0.6")
        for consumed_field in [
            "consumes_registry_helper",
            "consumes_dry_run_helper",
            "consumes_tool_schema_catalog",
            "consumes_implementation_gate_fixture",
            "consumes_adapter_expected_behavior_fixture",
            "consumes_runtime_boundary_decision",
            "consumes_blocked_response_contract",
            "consumes_verify_first_behavior",
        ]:
            self.assertIs(fixture[consumed_field], True)

        for blocked_field in [
            "server_listener_allowed",
            "socket_bind_allowed",
            "stdio_transport_allowed",
            "http_transport_allowed",
            "transport_allowed",
            "json_rpc_protocol_handler_allowed",
            "protocol_handler_allowed",
            "mcp_protocol_message_parser_allowed",
            "executable_tool_registration_allowed",
            "tool_execution_allowed",
            "local_evidence_reader_allowed",
            "safe_file_body_reader_allowed",
            "upload_import_action_allowed",
            "dashboard_post_action_allowed",
            "collector_forwarding_change_allowed",
            "receiver_ingest_change_allowed",
            "raw_preview_download_allowed",
            "replay_active_scan_allowed",
            "automatic_chatgpt_handoff_allowed",
            "tag_allowed",
            "github_release_allowed",
            "raw_data_included",
            "target_identifiers_included",
            "local_path_details_included",
            "credential_values_included",
            "external_sharing_approval_included",
        ]:
            self.assertIs(fixture[blocked_field], False)

        for required_item in [
            "registry_helper",
            "dry_run_helper",
            "tool_schema_catalog",
            "implementation_gate_fixture",
            "adapter_expected_behavior_fixture",
            "runtime_boundary_decision",
            "blocked_response_contract",
            "verify_first_behavior",
        ]:
            self.assertIn(required_item, fixture["preflight_acceptance_inputs"])

        for forbidden_surface in [
            "server_listener",
            "socket_bind",
            "stdio_transport",
            "http_transport",
            "json_rpc_protocol_handler",
            "mcp_protocol_message_parser",
            "executable_tool_registration",
            "actual_tool_execution",
            "local_evidence_reader",
            "safe_file_body_reader",
            "upload_import_action",
            "dashboard_post_action",
            "collector_forwarding_change",
            "receiver_ingest_change",
            "raw_preview_download",
            "replay_active_scan",
            "automatic_chatgpt_handoff",
            "tag_or_github_release",
        ]:
            self.assertIn(forbidden_surface, fixture["forbidden_runtime_surfaces"])

        combined = preflight + "\n" + fixture_text
        for forbidden_marker in [
            "safe-to-share",
            "guaranteed safe",
            "confirmed vulnerability",
            "final CVSS",
            "\"raw_request\"",
            "\"raw_response\"",
            "raw_request:",
            "raw_response:",
            "Cookie",
            "Authorization",
            "Bearer ",
            "JWT",
            "session",
            "token",
            "HMAC secret value",
            "CSRF token value",
            "C:\\coding\\",
            "C:\\Users\\",
            "real_export_",
            "actual.local",
            "example.com",
        ]:
            self.assertNotIn(forbidden_marker, combined)
        self.assertIsNone(re.search(r"https?://", combined))
        self.assertIsNone(re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", combined))

    def test_mcp_runtime_boundary_consumption_v06_blocks_runtime_source_drift(self) -> None:
        consumption_doc = MCP_RUNTIME_BOUNDARY_CONSUMPTION_V06_DOC.read_text(encoding="utf-8")
        fixture = json.loads(MCP_RUNTIME_BOUNDARY_CONSUMPTION_V06_FIXTURE.read_text(encoding="utf-8"))
        fixture_text = json.dumps(fixture, sort_keys=True)
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        roadmap = ROADMAP_V06_DOC.read_text(encoding="utf-8")
        fast_track = V06_FAST_TRACK_PLAN_DOC.read_text(encoding="utf-8")
        decision = MCP_RUNTIME_BOUNDARY_DECISION_V06_DOC.read_text(encoding="utf-8")
        preflight = MCP_SERVER_SKELETON_PREFLIGHT_V06_DOC.read_text(encoding="utf-8")
        gate_doc = MCP_IMPLEMENTATION_GATE_DESIGN_V06_DOC.read_text(encoding="utf-8")
        catalog_doc = MCP_TOOL_SCHEMA_CATALOG_DOC.read_text(encoding="utf-8")

        self.assertTrue(MCP_RUNTIME_BOUNDARY_CONSUMPTION_V06_DOC.exists())
        self.assertTrue(MCP_RUNTIME_BOUNDARY_CONSUMPTION_V06_FIXTURE.exists())
        for linked_text in [readme, roadmap, fast_track, decision, preflight, gate_doc, catalog_doc]:
            self.assertIn("MCP_RUNTIME_BOUNDARY_CONSUMPTION_v0.6.md", linked_text)

        for section in [
            "## Purpose",
            "## Non-goals",
            "## Consumption Fixture Scope",
            "## Required Consumed Artifacts",
            "## Source Check Scope",
            "## Forbidden Source Markers",
            "## Boundary Flags",
            "## Acceptance Evidence",
            "## Deferred Runtime Work",
        ]:
            self.assertIn(section, consumption_doc)

        for non_goal in [
            "fixture, test, source-check, and documentation boundary only",
            "No MCP server listener implementation",
            "No MCP transport implementation",
            "No protocol handler implementation",
            "No executable tool registration",
            "No actual tool execution",
            "No local evidence reader implementation",
            "No safe file body reader implementation",
            "No upload or import action",
            "No dashboard POST action",
            "No raw preview or raw download",
            "No replay or active scan",
            "No automatic ChatGPT handoff",
            "No tag or GitHub Release",
            "No runtime implementation approval",
        ]:
            self.assertIn(non_goal, consumption_doc)

        self.assertEqual(fixture["schema_version"], "mcp_runtime_boundary_consumption.v0.6")
        self.assertIs(fixture["planning_only"], True)
        for consumed_flag in [
            "runtime_boundary_decision_consumed",
            "server_skeleton_preflight_consumed",
            "implementation_gate_consumed",
            "adapter_fixture_consumed",
            "dry_run_consumed",
            "tool_schema_catalog_consumed",
            "registry_helper_consumed",
        ]:
            self.assertIs(fixture[consumed_flag], True)

        for blocked_flag in [
            "mcp_server_listener_implemented",
            "mcp_transport_implemented",
            "mcp_protocol_handler_implemented",
            "executable_tool_registration_implemented",
            "actual_tool_execution_implemented",
            "local_evidence_reader_implemented",
            "dashboard_post_action_implemented",
            "upload_import_action_implemented",
            "raw_preview_download_implemented",
            "replay_active_scan_implemented",
            "automatic_chatgpt_handoff_implemented",
            "tag_created",
            "github_release_created",
            "raw_data_included",
        ]:
            self.assertIs(fixture[blocked_flag], False)

        expected_scope = [
            "burp_ai_redaction_gateway/mcp_adapter_dry_run.py",
            "burp_ai_redaction_gateway/mcp_tool_schema_catalog.py",
            "burp_ai_redaction_gateway/mcp_read_only_registry.py",
        ]
        self.assertEqual(fixture["source_check_scope"], expected_scope)
        self.assertEqual(
            fixture["forbidden_source_markers"],
            [
                "http.server",
                "socketserver",
                "http.client",
                "socket",
                "subprocess",
                "requests",
                "urllib",
                "bind(",
                "serve_forever",
                "listen(",
                "accept(",
                "run_server",
                "create_server",
            ],
        )

        for source_path in fixture["source_check_scope"]:
            source_file = ROOT / source_path
            self.assertTrue(source_file.exists(), source_path)
            source_text = source_file.read_text(encoding="utf-8")
            for marker in fixture["forbidden_source_markers"]:
                self.assertNotIn(marker, source_text, f"{marker} found in {source_path}")

        for required_doc in fixture["required_documents"]:
            self.assertTrue((ROOT / required_doc).exists(), required_doc)

        combined = consumption_doc + "\n" + fixture_text
        for forbidden_marker in [
            "safe-to-share",
            "guaranteed safe",
            "confirmed vulnerability",
            "final CVSS",
            "\"raw_request\"",
            "\"raw_response\"",
            "raw_request:",
            "raw_response:",
            "Cookie",
            "Authorization",
            "Bearer ",
            "JWT",
            "session",
            "token",
            "HMAC secret value",
            "CSRF token value",
            "C:\\coding\\",
            "C:\\Users\\",
            "real_export_",
            "actual.local",
            "example.com",
        ]:
            self.assertNotIn(forbidden_marker, combined)
        self.assertIsNone(re.search(r"https?://", combined))
        self.assertIsNone(re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", combined))

    def test_mcp_listener_skeleton_decision_v06_stays_design_only(self) -> None:
        listener_decision = MCP_LISTENER_SKELETON_DECISION_V06_DOC.read_text(encoding="utf-8")
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        roadmap = ROADMAP_V06_DOC.read_text(encoding="utf-8")
        fast_track = V06_FAST_TRACK_PLAN_DOC.read_text(encoding="utf-8")
        runtime_decision = MCP_RUNTIME_BOUNDARY_DECISION_V06_DOC.read_text(encoding="utf-8")
        consumption_doc = MCP_RUNTIME_BOUNDARY_CONSUMPTION_V06_DOC.read_text(encoding="utf-8")
        preflight = MCP_SERVER_SKELETON_PREFLIGHT_V06_DOC.read_text(encoding="utf-8")

        self.assertTrue(MCP_LISTENER_SKELETON_DECISION_V06_DOC.exists())
        for linked_text in [
            readme,
            roadmap,
            fast_track,
            runtime_decision,
            consumption_doc,
            preflight,
        ]:
            self.assertIn("MCP_LISTENER_SKELETON_DECISION_v0.6.md", linked_text)

        for section in [
            "## Purpose",
            "## Current Baseline",
            "## Non-goals",
            "## Listener Skeleton Decision",
            "## Allowed Next Slice",
            "## Forbidden Work",
            "## Source-check Scope Expansion Rule",
            "## Required Acceptance Criteria",
            "## Required Test Evidence",
            "## Split Plan",
            "## Deferred Decisions",
        ]:
            self.assertIn(section, listener_decision)

        for baseline in [
            "Runtime boundary decision",
            "Server skeleton preflight",
            "Runtime boundary consumption fixture",
            "Implementation gate",
            "Local-only tool schema catalog",
            "Local-only adapter dry-run",
            "Registry helper",
            "Adapter expected behavior fixture",
        ]:
            self.assertIn(baseline, listener_decision)

        for required_text in [
            "design and acceptance criteria document only",
            "not listener implementation approval",
            "No MCP server listener implementation",
            "No MCP transport implementation",
            "No protocol handler implementation",
            "No executable tool registration",
            "No actual tool execution",
            "No local evidence reader implementation",
            "No upload or import action",
            "No dashboard POST action",
            "No raw preview or raw download",
            "No replay or active scan",
            "No automatic ChatGPT handoff",
            "No tag or GitHub Release",
            "source-check scope must expand",
            "Runtime boundary consumption fixture consumed",
            "Server skeleton preflight consumed",
            "Implementation gate fixture consumed",
            "Tool schema catalog consumed",
            "Dry-run helper consumed",
            "Registry helper consumed",
            "Source-check scope expanded for any new runtime file",
            "No transport",
            "No protocol handler",
            "No executable tool registration",
            "No actual tool execution",
            "No local evidence reader",
            "No raw file body",
            "No state-changing action",
            "No automatic ChatGPT handoff",
            "Candidate finding only",
            "Risk draft only",
            "Severity and CVSS require manual decision",
        ]:
            self.assertIn(required_text, listener_decision)

        for split_item in [
            "Listener skeleton decision",
            "Listener skeleton acceptance criteria",
            "Listener source-check scope extension",
            "Listener runtime skeleton",
            "Transport selection and implementation",
            "Protocol message representation",
            "Executable tool registration",
            "Tool execution",
            "Local evidence reader",
            "Dashboard or upload state-changing action",
        ]:
            self.assertIn(split_item, listener_decision)

        for forbidden_marker in [
            "safe-to-share",
            "guaranteed safe",
            "confirmed vulnerability",
            "final CVSS",
            "\"raw_request\"",
            "\"raw_response\"",
            "raw_request:",
            "raw_response:",
            "Cookie",
            "Authorization",
            "Bearer ",
            "JWT",
            "session",
            "token",
            "HMAC secret value",
            "CSRF token value",
            "actual.local",
            "example.com",
        ]:
            self.assertNotIn(forbidden_marker, listener_decision)
        self.assertIsNone(re.search(r"https?://", listener_decision))
        self.assertIsNone(re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", listener_decision))

    def test_mcp_listener_skeleton_acceptance_v06_blocks_runtime_scope_drift(self) -> None:
        acceptance_doc = MCP_LISTENER_SKELETON_ACCEPTANCE_V06_DOC.read_text(encoding="utf-8")
        fixture = json.loads(MCP_LISTENER_SKELETON_ACCEPTANCE_V06_FIXTURE.read_text(encoding="utf-8"))
        fixture_text = json.dumps(fixture, sort_keys=True)
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        roadmap = ROADMAP_V06_DOC.read_text(encoding="utf-8")
        fast_track = V06_FAST_TRACK_PLAN_DOC.read_text(encoding="utf-8")
        decision = MCP_LISTENER_SKELETON_DECISION_V06_DOC.read_text(encoding="utf-8")
        consumption = MCP_RUNTIME_BOUNDARY_CONSUMPTION_V06_DOC.read_text(encoding="utf-8")
        preflight = MCP_SERVER_SKELETON_PREFLIGHT_V06_DOC.read_text(encoding="utf-8")

        self.assertTrue(MCP_LISTENER_SKELETON_ACCEPTANCE_V06_DOC.exists())
        self.assertTrue(MCP_LISTENER_SKELETON_ACCEPTANCE_V06_FIXTURE.exists())
        for linked_text in [readme, roadmap, fast_track, decision, consumption, preflight]:
            self.assertIn("MCP_LISTENER_SKELETON_ACCEPTANCE_v0.6.md", linked_text)

        for section in [
            "## Purpose",
            "## Non-goals",
            "## Acceptance Fixture Scope",
            "## Required Consumed Artifacts",
            "## Source-check Scope Expansion",
            "## Forbidden Source Markers",
            "## Listener Skeleton Boundaries",
            "## Required Acceptance Criteria",
            "## Required Test Evidence",
            "## Deferred Runtime Work",
        ]:
            self.assertIn(section, acceptance_doc)

        for required_text in [
            "acceptance criteria, fixture, and source-check planning document only",
            "not listener implementation approval",
            "No MCP server listener implementation",
            "No MCP transport implementation",
            "No protocol handler implementation",
            "No executable tool registration",
            "No actual tool execution",
            "No local evidence reader implementation",
            "No safe file body reader implementation",
            "No upload or import action",
            "No dashboard POST action",
            "No raw preview or raw download",
            "No replay or active scan",
            "No automatic ChatGPT handoff",
            "No tag or GitHub Release",
            "Future runtime-facing files must be added to source-check scope",
            "Listener skeleton file allowed only after acceptance",
            "Existing `mcp_server.py` excluded from this scope",
            "Candidate finding only",
            "Risk draft only",
            "Severity and CVSS require manual decision",
        ]:
            self.assertIn(required_text, acceptance_doc)

        self.assertEqual(fixture["schema_version"], "mcp_listener_skeleton_acceptance.v0.6")
        self.assertIs(fixture["planning_only"], True)
        for consumed_flag in [
            "listener_skeleton_decision_consumed",
            "runtime_boundary_consumption_consumed",
            "server_skeleton_preflight_consumed",
            "implementation_gate_consumed",
            "tool_schema_catalog_consumed",
            "dry_run_consumed",
            "registry_helper_consumed",
        ]:
            self.assertIs(fixture[consumed_flag], True)

        for blocked_flag in [
            "mcp_server_listener_implemented",
            "mcp_transport_implemented",
            "mcp_protocol_handler_implemented",
            "executable_tool_registration_implemented",
            "actual_tool_execution_implemented",
            "local_evidence_reader_implemented",
            "safe_file_body_reader_implemented",
            "dashboard_post_action_implemented",
            "upload_import_action_implemented",
            "raw_preview_download_implemented",
            "replay_active_scan_implemented",
            "automatic_chatgpt_handoff_implemented",
            "tag_created",
            "github_release_created",
            "raw_data_included",
        ]:
            self.assertIs(fixture[blocked_flag], False)

        policy = fixture["source_check_scope_policy"]
        expected_helpers = [
            "burp_ai_redaction_gateway/mcp_adapter_dry_run.py",
            "burp_ai_redaction_gateway/mcp_tool_schema_catalog.py",
            "burp_ai_redaction_gateway/mcp_read_only_registry.py",
        ]
        self.assertEqual(policy["existing_pre_runtime_helpers"], expected_helpers)
        self.assertIs(policy["future_runtime_facing_files_must_be_added"], True)
        self.assertIs(policy["listener_skeleton_file_allowed_only_after_acceptance"], True)
        self.assertIs(policy["existing_mcp_server_py_excluded_from_this_scope"], True)

        self.assertEqual(
            fixture["forbidden_source_markers"],
            [
                "http.server",
                "socketserver",
                "http.client",
                "socket",
                "subprocess",
                "requests",
                "urllib",
                "bind(",
                "serve_forever",
                "listen(",
                "accept(",
                "run_server",
                "create_server",
                "tool_execute",
                "execute_tool",
                "read_local_evidence",
                "read_file_body",
            ],
        )

        for source_path in policy["existing_pre_runtime_helpers"]:
            source_file = ROOT / source_path
            self.assertTrue(source_file.exists(), source_path)
            source_text = source_file.read_text(encoding="utf-8")
            for marker in fixture["forbidden_source_markers"]:
                self.assertNotIn(marker, source_text, f"{marker} found in {source_path}")

        combined = acceptance_doc + "\n" + fixture_text
        for forbidden_marker in [
            "safe-to-share",
            "guaranteed safe",
            "confirmed vulnerability",
            "final CVSS",
            "\"raw_request\"",
            "\"raw_response\"",
            "raw_request:",
            "raw_response:",
            "Cookie",
            "Authorization",
            "Bearer ",
            "JWT",
            "session",
            "token",
            "HMAC secret value",
            "CSRF token value",
            "C:\\coding\\",
            "C:\\Users\\",
            "real_export_",
            "actual.local",
            "example.com",
        ]:
            self.assertNotIn(forbidden_marker, combined)
        self.assertIsNone(re.search(r"https?://", combined))
        self.assertIsNone(re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", combined))

    def test_mcp_listener_runtime_source_check_v06_requires_declared_runtime_scope(self) -> None:
        source_check_doc = MCP_LISTENER_RUNTIME_SOURCE_CHECK_V06_DOC.read_text(encoding="utf-8")
        fixture = json.loads(MCP_LISTENER_RUNTIME_SOURCE_CHECK_V06_FIXTURE.read_text(encoding="utf-8"))
        fixture_text = json.dumps(fixture, sort_keys=True)
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        roadmap = ROADMAP_V06_DOC.read_text(encoding="utf-8")
        fast_track = V06_FAST_TRACK_PLAN_DOC.read_text(encoding="utf-8")
        acceptance = MCP_LISTENER_SKELETON_ACCEPTANCE_V06_DOC.read_text(encoding="utf-8")
        decision = MCP_LISTENER_SKELETON_DECISION_V06_DOC.read_text(encoding="utf-8")
        consumption = MCP_RUNTIME_BOUNDARY_CONSUMPTION_V06_DOC.read_text(encoding="utf-8")

        self.assertTrue(MCP_LISTENER_RUNTIME_SOURCE_CHECK_V06_DOC.exists())
        self.assertTrue(MCP_LISTENER_RUNTIME_SOURCE_CHECK_V06_FIXTURE.exists())
        for linked_text in [readme, roadmap, fast_track, acceptance, decision, consumption]:
            self.assertIn("MCP_LISTENER_RUNTIME_SOURCE_CHECK_v0.6.md", linked_text)

        for section in [
            "## Purpose",
            "## Non-goals",
            "## Runtime-facing Source Check Fixture",
            "## Required Consumed Artifacts",
            "## Existing Baseline Scope",
            "## Runtime-facing File Detection Rule",
            "## Declared Source-check Scope",
            "## Forbidden Source Markers",
            "## Required Acceptance Criteria",
            "## Required Test Evidence",
            "## Deferred Runtime Work",
        ]:
            self.assertIn(section, source_check_doc)

        for required_text in [
            "source-check guard, fixture, and test planning document only",
            "not listener implementation approval",
            "No MCP server listener implementation",
            "No MCP transport implementation",
            "No protocol handler implementation",
            "No executable tool registration",
            "No actual tool execution",
            "No local evidence reader implementation",
            "No safe file body reader implementation",
            "No upload or import action",
            "No dashboard POST action",
            "No raw preview or raw download",
            "No replay or active scan",
            "No automatic ChatGPT handoff",
            "No tag or GitHub Release",
            "does not approve excluding future runtime-facing files",
            "must be listed in `declared_runtime_facing_source_scope`",
            "metadata-only listener skeleton helper",
            "Candidate finding only",
            "Risk draft only",
            "Severity and CVSS require manual decision",
        ]:
            self.assertIn(required_text, source_check_doc)

        self.assertEqual(fixture["schema_version"], "mcp_listener_runtime_source_check.v0.6")
        self.assertIs(fixture["planning_only"], True)
        for consumed_flag in [
            "listener_skeleton_acceptance_consumed",
            "listener_skeleton_decision_consumed",
            "runtime_boundary_consumption_consumed",
            "server_skeleton_preflight_consumed",
            "implementation_gate_consumed",
            "tool_schema_catalog_consumed",
            "dry_run_consumed",
            "registry_helper_consumed",
        ]:
            self.assertIs(fixture[consumed_flag], True)

        for blocked_flag in [
            "mcp_server_listener_implemented",
            "mcp_transport_implemented",
            "mcp_protocol_handler_implemented",
            "executable_tool_registration_implemented",
            "actual_tool_execution_implemented",
            "local_evidence_reader_implemented",
            "safe_file_body_reader_implemented",
            "dashboard_post_action_implemented",
            "upload_import_action_implemented",
            "raw_preview_download_implemented",
            "replay_active_scan_implemented",
            "automatic_chatgpt_handoff_implemented",
            "tag_created",
            "github_release_created",
            "raw_data_included",
        ]:
            self.assertIs(fixture[blocked_flag], False)

        policy = fixture["source_check_policy"]
        expected_helpers = [
            "burp_ai_redaction_gateway/mcp_adapter_dry_run.py",
            "burp_ai_redaction_gateway/mcp_tool_schema_catalog.py",
            "burp_ai_redaction_gateway/mcp_read_only_registry.py",
        ]
        self.assertEqual(policy["existing_pre_runtime_helpers"], expected_helpers)
        self.assertEqual(policy["existing_excluded_baseline_files"], ["burp_ai_redaction_gateway/mcp_server.py"])
        self.assertIs(policy["runtime_facing_file_detection_enabled"], True)
        self.assertIs(policy["future_runtime_facing_files_must_be_declared"], True)
        self.assertEqual(
            policy["declared_runtime_facing_source_scope"],
            [
                "burp_ai_redaction_gateway/mcp_listener_skeleton.py",
                "burp_ai_redaction_gateway/mcp_listener_runtime.py",
                "burp_ai_redaction_gateway/mcp_minimal_skeleton.py",
                "burp_ai_redaction_gateway/mcp_protocol_parser.py",
                "burp_ai_redaction_gateway/mcp_runtime_contract.py",
            ],
        )
        self.assertIs(policy["fail_on_undeclared_runtime_facing_file"], True)

        runtime_markers = [
            "mcp_listener",
            "listener_skeleton",
            "runtime_listener",
            "mcp_runtime",
            "mcp_transport",
            "mcp_protocol",
            "tool_registration",
            "tool_execution",
            "evidence_reader",
            "file_body_reader",
        ]
        self.assertEqual(fixture["runtime_facing_filename_markers"], runtime_markers)

        forbidden_markers = [
            "http.server",
            "socketserver",
            "http.client",
            "socket",
            "subprocess",
            "requests",
            "urllib",
            "bind(",
            "serve_forever",
            "listen(",
            "accept(",
            "run_server",
            "create_server",
            "tool_execute",
            "execute_tool",
            "read_local_evidence",
            "read_file_body",
            "register_tool",
            "dispatch_tool",
        ]
        self.assertEqual(fixture["forbidden_source_markers"], forbidden_markers)

        for source_path in policy["existing_pre_runtime_helpers"]:
            source_file = ROOT / source_path
            self.assertTrue(source_file.exists(), source_path)
            source_text = source_file.read_text(encoding="utf-8")
            for marker in forbidden_markers:
                self.assertNotIn(marker, source_text, f"{marker} found in {source_path}")

        for source_path in policy["existing_excluded_baseline_files"]:
            source_file = ROOT / source_path
            self.assertTrue(source_file.exists(), source_path)
        self.assertIn("current baseline exception", source_check_doc)

        declared_scope = set(policy["declared_runtime_facing_source_scope"])
        excluded_scope = set(policy["existing_excluded_baseline_files"])
        undeclared_runtime_facing_files: list[str] = []
        for source_file in (ROOT / "burp_ai_redaction_gateway").rglob("*.py"):
            relative_source = source_file.relative_to(ROOT).as_posix()
            normalized_source = relative_source.lower()
            if relative_source in excluded_scope:
                continue
            if any(marker in normalized_source for marker in runtime_markers):
                if relative_source not in declared_scope:
                    undeclared_runtime_facing_files.append(relative_source)
                else:
                    source_text = source_file.read_text(encoding="utf-8")
                    for marker in forbidden_markers:
                        self.assertNotIn(marker, source_text, f"{marker} found in {relative_source}")
        self.assertEqual(undeclared_runtime_facing_files, [])

        combined = source_check_doc + "\n" + fixture_text
        for forbidden_marker in [
            "safe-to-share",
            "guaranteed safe",
            "confirmed vulnerability",
            "final CVSS",
            "\"raw_request\"",
            "\"raw_response\"",
            "raw_request:",
            "raw_response:",
            "Cookie",
            "Authorization",
            "Bearer ",
            "JWT",
            "session",
            "token",
            "HMAC secret value",
            "CSRF token value",
            "C:\\coding\\",
            "C:\\Users\\",
            "real_export_",
            "actual.local",
            "example.com",
        ]:
            self.assertNotIn(forbidden_marker, combined)
        self.assertIsNone(re.search(r"https?://", combined))
        self.assertIsNone(re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", combined))

    def test_mcp_read_only_registry_skeleton_v06_matches_fixtures_and_blocks_unsafe_metadata(self) -> None:
        contract_fixture = json.loads(
            MCP_READ_ONLY_TOOL_CONTRACT_MATRIX_V06_FIXTURE.read_text(encoding="utf-8")
        )
        preflight_fixture = json.loads(
            MCP_READ_ONLY_PROTOTYPE_PREFLIGHT_V06_FIXTURE.read_text(encoding="utf-8")
        )
        registry = build_read_only_tool_registry()

        self.assertEqual(tuple(registry), ALLOWED_TOOL_NAMES)
        self.assertEqual(tuple(contract_fixture["allowed_candidate_tools"]), ALLOWED_TOOL_NAMES)
        self.assertEqual(tuple(preflight_fixture["allowed_tools"]), ALLOWED_TOOL_NAMES)
        self.assertEqual(tuple(contract_fixture["forbidden_tool_concepts"]), FORBIDDEN_TOOL_CONCEPTS)
        self.assertEqual(tuple(preflight_fixture["forbidden_tools"]), FORBIDDEN_TOOL_CONCEPTS)
        self.assertEqual(tuple(contract_fixture["blocked_response_codes"]), BLOCKED_RESPONSE_CODES)
        self.assertEqual(tuple(preflight_fixture["blocked_response_codes"]), BLOCKED_RESPONSE_CODES)
        self.assertEqual(tuple(contract_fixture["safe_file_allowlist"]), SAFE_FILE_ALLOWLIST)
        self.assertEqual(tuple(preflight_fixture["safe_files"]), SAFE_FILE_ALLOWLIST)
        self.assertEqual(
            tuple(preflight_fixture["blocked_response_allowed_fields"]),
            BLOCKED_RESPONSE_ALLOWED_FIELDS,
        )
        self.assertFalse(preflight_fixture["runtime_registry_implemented"])
        self.assertFalse(preflight_fixture["mcp_server_implemented"])
        self.assertFalse(preflight_fixture["mcp_tool_handler_implemented"])

        for forbidden in FORBIDDEN_TOOL_CONCEPTS:
            self.assertNotIn(forbidden, registry)
        for entry in registry.values():
            self.assertIsInstance(entry, ReadOnlyRegistryEntry)
            self.assertTrue(entry.read_only)
            self.assertIsInstance(entry.verify_first, bool)
            serialized = json.dumps(entry.to_safe_metadata(), sort_keys=True)
            self.assertIn("raw_data_included", serialized)
            for forbidden in [
                "raw request",
                "raw response",
                "raw_request",
                "raw_response",
                "Cookie:",
                "Authorization:",
                "Bearer ",
                "JWT",
                "session=",
                "token=",
                "C:\\coding\\",
                "C:\\Users\\",
            ]:
                self.assertNotIn(forbidden, serialized)
            self.assertIsNone(re.search(r"https?://", serialized))
            self.assertIsNone(re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", serialized))

        validation = validate_registry_against_contract_fixtures(contract_fixture, preflight_fixture)
        self.assertEqual(
            validation,
            {
                "ok": True,
                "tool_count": 8,
                "read_only": True,
                "raw_data_included": False,
            },
        )

        blocked = build_blocked_response(
            "not_verified",
            "verification required",
            output_alias="verified-output-alias",
            remediation_hint="run verify before reading metadata",
        )
        self.assertEqual(set(blocked), set(BLOCKED_RESPONSE_ALLOWED_FIELDS))
        self.assertFalse(blocked["ok"])
        self.assertEqual(blocked["code"], "not_verified")
        self.assertEqual(blocked["output_alias"], "verified-output-alias")
        serialized_blocked = json.dumps(blocked, sort_keys=True)
        for forbidden in [
            "raw request",
            "raw response",
            "raw_request",
            "raw_response",
            "Cookie:",
            "Authorization:",
            "Bearer ",
            "JWT",
            "session=",
            "token=",
            "C:\\coding\\",
            "C:\\Users\\",
        ]:
            self.assertNotIn(forbidden, serialized_blocked)
        self.assertIsNone(re.search(r"https?://", serialized_blocked))
        self.assertIsNone(re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", serialized_blocked))

        with self.assertRaisesRegex(McpReadOnlyRegistryError, "unknown_blocked_response_code"):
            build_blocked_response("unknown_code", "blocked")
        with self.assertRaisesRegex(McpReadOnlyRegistryError, "unsafe_metadata_marker"):
            build_blocked_response("raw_access_blocked", "raw request body blocked")
        with self.assertRaisesRegex(McpReadOnlyRegistryError, "unsafe_output_alias"):
            build_blocked_response("not_verified", "blocked", output_alias="..\\raw")
        with self.assertRaisesRegex(McpReadOnlyRegistryError, "unsafe_output_alias"):
            build_blocked_response("not_verified", "blocked", output_alias="safe/output")

    def test_mcp_and_web_ux_plan_docs_are_planning_only_and_raw_free(self) -> None:
        mcp_design = MCP_INTEGRATION_DESIGN_DOC.read_text(encoding="utf-8")
        web_ux = WEB_UX_KO_PLAN_DOC.read_text(encoding="utf-8")
        roadmap = (ROOT / "docs" / "ROADMAP_v0.5.md").read_text(encoding="utf-8")
        readiness = V05_RELEASE_READINESS_DOC.read_text(encoding="utf-8")
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        local_dashboard = (ROOT / "docs" / "LOCAL_DASHBOARD.md").read_text(encoding="utf-8")

        for linked_text in [roadmap, readiness, readme, local_dashboard]:
            self.assertIn("MCP_INTEGRATION_DESIGN_v0.5.md", linked_text)
            self.assertIn("WEB_UX_KO_PLAN_v0.5.md", linked_text)

        for required in [
            "planning document only",
            "does not implement a new MCP server",
            "read-only first",
            "Allowlist tools only",
            "No raw traffic",
            "No automatic ChatGPT handoff",
            "Findings remain candidates",
            "Risk remains draft",
            "Final severity and CVSS remain manual decisions",
            "get_gateway_status",
            "list_verified_outputs",
            "get_live_capture_status",
            "get_safe_file_inventory",
            "get_report_readiness",
            "get_prompt_readiness",
            "get_troubleshooting_categories",
            "get_release_readiness",
            "get_raw_request",
            "get_raw_response",
            "read_local_only_file",
            "read_raw_vault",
            "replay_request",
            "active_scan",
            "send_to_chatgpt",
            "delete_files",
            "show_hmac_secret",
            "show_csrf_token",
        ]:
            self.assertIn(required, mcp_design)

        for required in [
            "planning document only",
            "Korean-first",
            "처음 시작하기",
            "파일 업로드",
            "Live Capture 상태 확인",
            "AI에 넣을 수 있는 후보 파일 확인",
            "analysis_packet.json",
            "chatgpt_prompt.md",
            "codex_task_prompt.md",
            "report_draft.md",
            "First-run wizard",
            "Korean quickstart landing",
            "Safe files explanation cards",
            "Copy prompt button",
            "MCP read-only server design",
            "MCP read-only prototype",
            "Local evidence reader",
            "Dashboard orchestration",
            "Replay or active scan",
            "ChatGPT auto-send",
        ]:
            self.assertIn(required, web_ux)

        combined = "\n".join([mcp_design, web_ux])
        for forbidden in [
            "safe-to-share",
            "guaranteed safe",
            "confirmed vulnerability",
            "confirmed issue",
            "final CVSS",
            "\"raw_request\"",
            "\"raw_response\"",
            "raw_request:",
            "raw_response:",
            "cookie_value",
            "authorization_value",
            "Authorization:",
            "Cookie:",
            "C:\\coding\\",
            "C:\\Users\\",
            "real_export_",
            "actual.local",
            "external sharing clearance",
            "implementation approved",
        ]:
            self.assertNotIn(forbidden, combined)
        self.assertIsNone(re.search(r"https?://", combined))
        self.assertIsNone(re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", combined))

    def test_live_capture_receiver_output_evidence_model_is_alias_based_and_raw_free(self) -> None:
        empty_evidence = _build_live_capture_receiver_output_evidence(None)
        self.assertEqual(empty_evidence.evidence_source, "receiver_output_alias")
        self.assertEqual(empty_evidence.receiver_output_alias, "not selected")
        self.assertEqual(empty_evidence.receiver_verify_status, "not selected")
        self.assertEqual(empty_evidence.safe_file_existence_status, "hidden until verify passes")
        self.assertEqual(empty_evidence.candidate_count, 0)
        self.assertFalse(empty_evidence.raw_data_included)
        self.assertFalse(empty_evidence.safe_navigation_available)

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir) / "out"
            output = root / "generated"
            main(["generate", "--input", str(SAMPLE), "--output", str(output), "--project", "client_alias_demo"])
            dashboard_output = _verified_output(root, load_policy(None), "generated")

            evidence = _build_live_capture_receiver_output_evidence(dashboard_output)
            self.assertEqual(evidence.evidence_source, "receiver_output_alias")
            self.assertEqual(evidence.receiver_output_alias, "generated")
            self.assertEqual(evidence.receiver_verify_status, "passed")
            self.assertEqual(evidence.safe_file_existence_status, "available")
            self.assertEqual(evidence.candidate_count, 22)
            self.assertFalse(evidence.raw_data_included)
            self.assertTrue(evidence.safe_navigation_available)

            serialized = json.dumps(evidence.__dict__, sort_keys=True)
            for forbidden in [
                "raw_request",
                "raw_response",
                "DUMMY_COOKIE_VALUE",
                "DUMMY_BEARER_TOKEN",
                "Cookie:",
                "Authorization:",
                str(root),
            ]:
                self.assertNotIn(forbidden, serialized)

    def test_dashboard_live_capture_read_only_status_panel_hides_actions_and_raw_values(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir) / "out"
            output = root / "generated"
            main(["generate", "--input", str(SAMPLE), "--output", str(output), "--project", "client_alias_demo"])
            secret_value = "DUMMY_LIVE_CAPTURE_SECRET_1234567890"

            with patch.dict("os.environ", {"BURP_AI_AUDIT_HMAC_KEY": secret_value}, clear=False):
                server = create_dashboard_server("127.0.0.1", 0, DashboardConfig(root=root))
                thread = threading.Thread(target=server.serve_forever, daemon=True)
                thread.start()
                try:
                    port = server.server_address[1]

                    def get(path: str) -> str:
                        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                        connection.request("GET", path)
                        response = connection.getresponse()
                        body = response.read().decode("utf-8")
                        connection.close()
                        self.assertEqual(response.status, 200)
                        return body

                    body = get("/live-capture")
                    self.assertIn("Live Capture read-only status", body)
                    self.assertIn("Runtime smoke status panel", body)
                    self.assertIn("extension load status", body)
                    self.assertIn("local receiver status", body)
                    self.assertIn("in-scope handoff count", body)
                    self.assertIn("out-of-scope skip count", body)
                    self.assertIn("missing_host_skipped", body)
                    self.assertIn("invalid_host_skipped", body)
                    self.assertIn("receiver verify status", body)
                    self.assertIn("receiver output alias", body)
                    self.assertIn("not selected", body)
                    self.assertIn("hidden until verify passes", body)
                    self.assertIn("evidence source", body)
                    self.assertIn("receiver_output_alias", body)
                    self.assertIn("candidate count", body)
                    self.assertIn("raw_data_included", body)
                    self.assertIn("false", body)
                    self.assertIn("Findings remain candidates", body)
                    self.assertIn("Risk remains draft", body)
                    self.assertIn("Final severity and CVSS remain manual decisions", body)
                    self.assertIn("docs/LIVE_CAPTURE_DASHBOARD_INTEGRATION_PLAN_v0.5.md", body)
                    self.assertIn("docs/LIVE_CAPTURE_RUNTIME_SMOKE_CHECKLIST_v0.5.md", body)
                    self.assertIn("docs/TROUBLESHOOTING_v0.5.md", body)
                    self.assertIn("검증된 output 산출물 선택", body)
                    self.assertIn("/safe-files?project=generated", body)

                    linked_body = get("/live-capture?project=generated")
                    self.assertIn("Verified receiver output navigation", linked_body)
                    self.assertIn("검증된 output 산출물 선택", linked_body)
                    self.assertIn("receiver output alias", linked_body)
                    self.assertIn("generated", linked_body)
                    self.assertIn("receiver verify status", linked_body)
                    self.assertIn("passed", linked_body)
                    self.assertIn("evidence source", linked_body)
                    self.assertIn("receiver_output_alias", linked_body)
                    self.assertIn("safe file existence status", linked_body)
                    self.assertIn("candidate count", linked_body)
                    self.assertIn(">22<", linked_body)
                    self.assertIn("/simple?project=generated", linked_body)
                    self.assertIn("/safe-files?project=generated", linked_body)
                    self.assertIn("/triage?project=generated", linked_body)
                    self.assertIn("/report-readiness?project=generated", linked_body)
                    self.assertIn("/workflow?project=generated", linked_body)

                    for rendered in [body, linked_body]:
                        for forbidden in [
                            "<form",
                            "<button",
                            'method="post"',
                            'name="csrf_token"',
                            'action="/live-capture/start"',
                            'action="/live-capture/stop"',
                            "/download?",
                            "/preview?",
                            "raw_request",
                            "raw_response",
                            "DUMMY_COOKIE_VALUE",
                            "DUMMY_BEARER_TOKEN",
                            secret_value,
                            "BURP_AI_AUDIT_HMAC_KEY",
                            "Cookie:",
                            "Authorization:",
                            "HMAC secret",
                            "CSRF token",
                            "safe to share",
                            "guaranteed safe",
                            "severity confirmed",
                            "ready to submit",
                            str(root),
                        ]:
                            self.assertNotIn(forbidden, rendered)
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
                connection.request("GET", "/simple?project=..%2Flocal_only")
                response = connection.getresponse()
                simple_traversal = response.read().decode("utf-8")
                self.assertEqual(response.status, 403)
                self.assertIn("forbidden_directory", simple_traversal)
                self.assertNotIn("rawBearerToken", simple_traversal)
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

                connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                connection.request("GET", "/prompt-readiness?project=..%2Flocal_only")
                response = connection.getresponse()
                prompt_traversal = response.read().decode("utf-8")
                self.assertEqual(response.status, 403)
                self.assertIn("forbidden_directory", prompt_traversal)
                self.assertNotIn("rawBearerToken", prompt_traversal)
                connection.close()

                connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                connection.request("GET", "/evidence-boundary?project=..%2Flocal_only")
                response = connection.getresponse()
                evidence_traversal = response.read().decode("utf-8")
                self.assertEqual(response.status, 403)
                self.assertIn("forbidden_directory", evidence_traversal)
                self.assertNotIn("rawBearerToken", evidence_traversal)
                connection.close()

                connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                connection.request("GET", "/operator-runbook?project=..%2Flocal_only")
                response = connection.getresponse()
                operator_traversal = response.read().decode("utf-8")
                self.assertEqual(response.status, 403)
                self.assertIn("forbidden_directory", operator_traversal)
                self.assertNotIn("rawBearerToken", operator_traversal)
                connection.close()

                connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                connection.request("GET", "/safe-files?project=..%2Flocal_only")
                response = connection.getresponse()
                safe_files_traversal = response.read().decode("utf-8")
                self.assertEqual(response.status, 403)
                self.assertIn("forbidden_directory", safe_files_traversal)
                self.assertNotIn("rawBearerToken", safe_files_traversal)
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

    def test_web_upload_wizard_browser_smoke_fixture_matches_route_and_safe_failures(self) -> None:
        fixture = json.loads(WEB_UPLOAD_WIZARD_BROWSER_SMOKE_V07_FIXTURE.read_text(encoding="utf-8"))
        fixture_text = json.dumps(fixture, sort_keys=True)
        self.assertEqual(fixture["schema_version"], "web_upload_wizard_browser_smoke.v0.7")
        self.assertIs(fixture["browser_smoke_only"], True)
        self.assertEqual(fixture["route"], "/upload")
        self.assertEqual(fixture["method"], "GET")
        self.assertEqual(fixture["expected_status"], 200)
        self.assertEqual(
            fixture["expected_form_counts"],
            {"form_count": 1, "post_form_count": 1, "file_input_count": 1},
        )
        self.assertEqual(
            {case["case"] for case in fixture["invalid_post_cases"]},
            {"missing_csrf", "invalid_alias"},
        )
        for false_flag in [
            "new_post_action_added",
            "upload_processing_logic_changed",
            "storage_policy_changed",
            "retention_delete_policy_changed",
            "raw_preview_download_implemented",
            "replay_active_scan_implemented",
            "automatic_chatgpt_handoff_implemented",
            "mcp_listener_runtime_implemented",
            "mcp_transport_implemented",
            "mcp_protocol_handler_implemented",
            "mcp_tool_execution_implemented",
            "local_evidence_reader_implemented",
            "raw_data_included",
            "actual_target_identifiers_included",
            "credential_values_included",
            "full_local_paths_included",
        ]:
            self.assertIn(false_flag, fixture)
            self.assertIs(fixture[false_flag], False)
        for unsafe_value in [
            "http://",
            "https://",
            "Cookie: value",
            "Authorization: Bearer",
            "secret=",
            "safe-to-share",
            "confirmed vulnerability",
            "final CVSS",
        ]:
            self.assertNotIn(unsafe_value, fixture_text)
        self.assertIsNone(re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", fixture_text))

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir) / "out"
            root.mkdir()
            server = create_dashboard_server("127.0.0.1", 0, DashboardConfig(root=root))
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                port = server.server_address[1]
                connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                connection.request("GET", fixture["route"])
                response = connection.getresponse()
                upload_page = response.read().decode("utf-8")
                self.assertEqual(response.status, fixture["expected_status"])
                self.assertEqual(upload_page.count("<form "), fixture["expected_form_counts"]["form_count"])
                self.assertEqual(upload_page.count('method="post"'), fixture["expected_form_counts"]["post_form_count"])
                self.assertEqual(upload_page.count('type="file"'), fixture["expected_form_counts"]["file_input_count"])
                for marker in fixture["required_page_markers"]:
                    self.assertIn(marker, upload_page)
                for marker in [
                    "raw_request",
                    "raw_response",
                    "dashboard_upload_",
                    "browser-smoke-missing-csrf.xml",
                    "browser-smoke-invalid-alias.xml",
                    "local_only/dashboard_uploads",
                    "Traceback",
                    "stack trace",
                ]:
                    self.assertNotIn(marker, upload_page)
                self.assertNotIn(str(root), upload_page)
                self.assertNotIn(str(Path(temp_dir)), upload_page)
                token_match = re.search(r'name="csrf_token" value="([0-9a-f]{32})"', upload_page)
                self.assertIsNotNone(token_match)
                csrf_token = token_match.group(1)
                connection.close()

                for case in fixture["invalid_post_cases"]:
                    fields = {"project": case["project_alias"]}
                    if case["case"] != "missing_csrf":
                        fields["csrf_token"] = csrf_token
                    body, content_type = self.multipart_form(
                        fields,
                        "burp_export",
                        case["file_name"],
                        BURP_XML.read_bytes(),
                        content_type="application/xml",
                    )
                    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                    connection.request("POST", "/upload", body=body, headers={"Content-Type": content_type})
                    response = connection.getresponse()
                    result = response.read().decode("utf-8")
                    self.assertEqual(response.status, case["expected_status"])
                    self.assertIn(case["expected_error"], result)
                    self.assertNotIn(case["file_name"], result)
                    self.assertNotIn(csrf_token, result)
                    self.assertNotIn(str(root), result)
                    self.assertNotIn(str(Path(temp_dir)), result)
                    for marker in fixture["forbidden_response_markers"]:
                        self.assertNotIn(marker, result)
                    for link in fixture["failure_safe_links_forbidden"]:
                        self.assertNotIn(link, result)
                    connection.close()
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)

    def test_dashboard_upload_wizard_runs_safe_pipeline_and_hides_raw_values(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir) / "out"
            root.mkdir()
            server = create_dashboard_server("127.0.0.1", 0, DashboardConfig(root=root))
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                port = server.server_address[1]
                connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                connection.request("GET", "/upload")
                response = connection.getresponse()
                upload_page = response.read().decode("utf-8")
                self.assertEqual(response.status, 200)
                self.assertIn("업로드 마법사", upload_page)
                self.assertIn('enctype="multipart/form-data"', upload_page)
                self.assertIn("마스킹 및 검증 시작", upload_page)
                self.assertIn("local-only workflow", upload_page)
                self.assertIn("verify 통과 전에는 AI 후보 파일을 사용하지 마세요", upload_page)
                self.assertIn("Web Operator Guide: docs/WEB_OPERATOR_GUIDE_KO_v0.7.md", upload_page)
                self.assertIn("raw preview/download 없음", upload_page)
                self.assertIn("replay/active scan 없음", upload_page)
                self.assertIn("automatic ChatGPT handoff 없음", upload_page)
                self.assertIn("MCP listener runtime", upload_page)
                self.assertIn("analysis_packet.json", upload_page)
                self.assertIn("chatgpt_prompt.md", upload_page)
                self.assertIn("codex_task_prompt.md", upload_page)
                self.assertIn("report_draft.md", upload_page)
                self.assertNotIn("raw_request", upload_page)
                self.assertNotIn("raw_response", upload_page)
                self.assertNotIn("HMAC secret", upload_page)
                self.assertNotIn("CSRF token", upload_page)
                self.assertNotIn(str(root), upload_page)
                token_match = re.search(r'name="csrf_token" value="([0-9a-f]{32})"', upload_page)
                self.assertIsNotNone(token_match)
                csrf_token = token_match.group(1)
                connection.close()

                body, content_type = self.multipart_form(
                    {"project": "upload_alias_demo", "csrf_token": csrf_token},
                    "burp_export",
                    "synthetic-upload.xml",
                    BURP_XML.read_bytes(),
                    content_type="application/xml",
                )
                connection = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
                connection.request("POST", "/upload", body=body, headers={"Content-Type": content_type})
                response = connection.getresponse()
                result = response.read().decode("utf-8")
                self.assertEqual(response.status, 200)
                self.assertIn("업로드 처리 완료", result)
                self.assertIn("raw_data_included=false", result)
                self.assertIn("upload_alias_demo", result)
                self.assertIn("safe files 4개는 AI 입력 후보일 뿐이며 사람이 직접 확인해야 합니다", result)
                self.assertIn("Simple Dashboard에서 전체 상태를 확인합니다", result)
                self.assertIn("Report Readiness에서 draft report 경계를 확인합니다", result)
                self.assertIn("필요한 범위만 사람이 복사합니다", result)
                self.assertIn("Simple Dashboard", result)
                self.assertIn("/simple?project=upload_alias_demo", result)
                self.assertIn("/safe-files?project=upload_alias_demo", result)
                self.assertIn("/triage?project=upload_alias_demo", result)
                self.assertIn("/report-readiness?project=upload_alias_demo", result)
                for name in ["analysis_packet.json", "chatgpt_prompt.md", "codex_task_prompt.md", "report_draft.md"]:
                    self.assertIn(name, result)
                    self.assertTrue((root / "upload_alias_demo" / name).is_file())
                self.assertNotIn("synthetic-upload.xml", result)
                self.assertNotIn("dashboard_upload_", result)
                self.assertNotIn(str(root), result)
                self.assertNotIn(str(Path(temp_dir)), result)
                self.assertNotIn(csrf_token, result)
                self.assertNotIn("raw_request", result)
                self.assertNotIn("raw_response", result)
                self.assertNotIn("Cookie:", result)
                self.assertNotIn("Authorization:", result)
                connection.close()

                connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                connection.request("GET", "/simple?project=upload_alias_demo")
                response = connection.getresponse()
                simple = response.read().decode("utf-8")
                self.assertEqual(response.status, 200)
                self.assertIn("간단 대시보드", simple)
                self.assertIn("upload_alias_demo", simple)
                self.assertIn("/upload", simple)
                self.assertNotIn("synthetic-upload.xml", simple)
                self.assertNotIn(str(root), simple)
                connection.close()

                connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                connection.request("GET", "/safe-files?project=upload_alias_demo")
                response = connection.getresponse()
                safe_files = response.read().decode("utf-8")
                self.assertEqual(response.status, 200)
                self.assertIn("Safe file inventory", safe_files)
                self.assertNotIn("synthetic-upload.xml", safe_files)
                self.assertNotIn("raw_request", safe_files)
                self.assertNotIn("raw_response", safe_files)
                connection.close()

                upload_storage = Path(temp_dir) / "local_only" / "dashboard_uploads"
                self.assertTrue(upload_storage.is_dir())
                self.assertEqual(len(list(upload_storage.iterdir())), 1)

                audit_path = root / ".audit" / "mcp_audit.jsonl"
                audit_text = audit_path.read_text(encoding="utf-8")
                audit_events = [json.loads(line) for line in audit_text.splitlines() if line.strip()]
                self.assertEqual(len(audit_events), 1)
                self.assert_audit_hash_chain(audit_events)
                self.assertEqual(audit_events[0]["action_name"], "upload")
                self.assertEqual(audit_events[0]["result_status"], "success")
                self.assertEqual(audit_events[0]["output_id"], "upload_alias_demo")
                self.assertFalse(audit_events[0]["raw_data_included"])
                self.assertNotIn(csrf_token, audit_text)
                self.assertNotIn("csrf_token", audit_text)
                self.assertNotIn("synthetic-upload.xml", audit_text)
                self.assertNotIn("dashboard_upload_", audit_text)
                self.assertNotIn(str(root), audit_text)
                self.assertNotIn("raw_request", audit_text)
                self.assertNotIn("raw_response", audit_text)
                audit_review = review_audit_path(audit_path)
                self.assertTrue(audit_review.passed, audit_review.findings)
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)

    def test_dashboard_upload_wizard_blocks_invalid_posts_without_raw_values(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir) / "out"
            root.mkdir()
            server = create_dashboard_server("127.0.0.1", 0, DashboardConfig(root=root))
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                port = server.server_address[1]
                connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                connection.request("GET", "/upload")
                response = connection.getresponse()
                upload_page = response.read().decode("utf-8")
                token_match = re.search(r'name="csrf_token" value="([0-9a-f]{32})"', upload_page)
                self.assertIsNotNone(token_match)
                csrf_token = token_match.group(1)
                connection.close()

                invalid_posts = [
                    (
                        {"project": "upload_missing_csrf"},
                        "missing-csrf.xml",
                        BURP_XML.read_bytes(),
                        400,
                        "csrf_token_missing",
                    ),
                    (
                        {"project": "upload_bad_csrf", "csrf_token": "invalid"},
                        "bad-csrf.xml",
                        BURP_XML.read_bytes(),
                        403,
                        "csrf_token_invalid",
                    ),
                    (
                        {"project": "upload_bad_type", "csrf_token": csrf_token},
                        "bad-type.txt",
                        b"not used",
                        400,
                        "unsupported_file_type",
                    ),
                    (
                        {"project": "../local_only", "csrf_token": csrf_token},
                        "bad-alias.xml",
                        BURP_XML.read_bytes(),
                        400,
                        "invalid_project_alias",
                    ),
                ]
                for fields, file_name, file_bytes, expected_status, expected_error in invalid_posts:
                    body, content_type = self.multipart_form(fields, "burp_export", file_name, file_bytes)
                    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                    connection.request("POST", "/upload", body=body, headers={"Content-Type": content_type})
                    response = connection.getresponse()
                    result = response.read().decode("utf-8")
                    self.assertEqual(response.status, expected_status)
                    self.assertIn(expected_error, result)
                    self.assertNotIn(file_name, result)
                    self.assertNotIn(str(root), result)
                    self.assertNotIn(csrf_token, result)
                    self.assertNotIn("raw_request", result)
                    self.assertNotIn("raw_response", result)
                    connection.close()

                audit_path = root / ".audit" / "mcp_audit.jsonl"
                audit_text = audit_path.read_text(encoding="utf-8")
                audit_events = [json.loads(line) for line in audit_text.splitlines() if line.strip()]
                self.assertEqual(len(audit_events), 4)
                self.assert_audit_hash_chain(audit_events)
                self.assertTrue(all(event["action_name"] == "upload" for event in audit_events))
                self.assertTrue(all(event["result_status"] == "blocked" for event in audit_events))
                self.assertEqual(audit_events[0]["blocked_reason"], "csrf_missing")
                self.assertEqual(audit_events[1]["blocked_reason"], "csrf_invalid")
                self.assertEqual(audit_events[2]["blocked_reason"], "unsupported_file_type")
                self.assertEqual(audit_events[3]["blocked_reason"], "invalid_project_alias")
                self.assertNotIn(csrf_token, audit_text)
                self.assertNotIn("csrf_token", audit_text)
                self.assertNotIn("missing-csrf.xml", audit_text)
                self.assertNotIn("bad-csrf.xml", audit_text)
                self.assertNotIn("bad-type.txt", audit_text)
                self.assertNotIn("bad-alias.xml", audit_text)
                self.assertNotIn(str(root), audit_text)
                self.assertNotIn("raw_request", audit_text)
                self.assertNotIn("raw_response", audit_text)
                self.assertFalse((Path(temp_dir) / "local_only").exists())
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)

    def test_dashboard_upload_wizard_hides_safe_links_when_verify_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir) / "out"
            root.mkdir()
            server = create_dashboard_server("127.0.0.1", 0, DashboardConfig(root=root))
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                port = server.server_address[1]
                connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                connection.request("GET", "/upload")
                response = connection.getresponse()
                upload_page = response.read().decode("utf-8")
                token_match = re.search(r'name="csrf_token" value="([0-9a-f]{32})"', upload_page)
                self.assertIsNotNone(token_match)
                csrf_token = token_match.group(1)
                connection.close()

                body, content_type = self.multipart_form(
                    {"project": "upload_verify_fail", "csrf_token": csrf_token},
                    "burp_export",
                    "verify-fail.xml",
                    BURP_XML.read_bytes(),
                    content_type="application/xml",
                )
                with patch(
                    "burp_ai_redaction_gateway.dashboard.verify_path",
                    return_value=VerificationResult(files_checked=3, findings=[object()]),
                ):
                    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
                    connection.request("POST", "/upload", body=body, headers={"Content-Type": content_type})
                    response = connection.getresponse()
                    result = response.read().decode("utf-8")
                    self.assertEqual(response.status, 200)
                    self.assertIn("검증 실패", result)
                    self.assertIn("verify failed safely", result)
                    self.assertIn("safe files are hidden", result)
                    self.assertIn("review/report/safe file link를 제공하지 않습니다", result)
                    self.assertIn("verify 통과 전 output은 AI 입력 후보가 아닙니다", result)
                    self.assertNotIn("/safe-files?project=upload_verify_fail", result)
                    self.assertNotIn("/simple?project=upload_verify_fail", result)
                    self.assertNotIn("verify-fail.xml", result)
                    self.assertNotIn(str(root), result)
                    self.assertNotIn(csrf_token, result)
                    self.assertNotIn("raw_request", result)
                    self.assertNotIn("raw_response", result)
                    connection.close()

                audit_path = root / ".audit" / "mcp_audit.jsonl"
                audit_text = audit_path.read_text(encoding="utf-8")
                audit_events = [json.loads(line) for line in audit_text.splitlines() if line.strip()]
                self.assertEqual(len(audit_events), 1)
                self.assertEqual(audit_events[0]["action_name"], "upload")
                self.assertEqual(audit_events[0]["result_status"], "blocked")
                self.assertEqual(audit_events[0]["blocked_reason"], "verify_failed")
                self.assertNotIn("verify-fail.xml", audit_text)
                self.assertNotIn(csrf_token, audit_text)
                self.assertNotIn("raw_request", audit_text)
                self.assertNotIn("raw_response", audit_text)
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
                        self.assertIn("압축 archive", body)
                        self.assertIn("압축 archive 검증", body)
                        self.assertIn("압축 archive HMAC manifest", body)
                        self.assertIn("압축 archive HMAC 검증", body)
                        self.assertIn("있음", body)
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
        self.assertTrue((ROOT / "scripts" / "run_local_real_export_smoke.ps1").is_file())
        self.assertTrue((ROOT / "scripts" / "run_local_real_export_smoke.bat").is_file())
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
        self.assertIn("compatibility testing을 대체하지 않습니다", readme)
        self.assertIn("Safe Real-Like Smoke Test", real_testing)
        self.assertIn("not a real Burp export compatibility test", real_testing)

    def test_real_burp_export_validation_docs_are_raw_free(self) -> None:
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        release_checklist = (ROOT / "docs" / "RELEASE_CHECKLIST_v0.4.md").read_text(encoding="utf-8")
        real_testing = (ROOT / "docs" / "REAL_BURP_EXPORT_TESTING.md").read_text(encoding="utf-8")
        validation = (ROOT / "docs" / "REAL_BURP_EXPORT_VALIDATION.md").read_text(encoding="utf-8")
        template = (ROOT / "docs" / "templates" / "REAL_BURP_EXPORT_VALIDATION_TEMPLATE.md").read_text(
            encoding="utf-8"
        )

        for text in [readme, release_checklist, real_testing]:
            self.assertIn("REAL_BURP_EXPORT_VALIDATION.md", text)
        self.assertIn("REAL_BURP_EXPORT_VALIDATION_TEMPLATE.md", readme)
        self.assertIn("REAL_BURP_EXPORT_VALIDATION_TEMPLATE.md", release_checklist)

        required = [
            "local_only/",
            "authorized_burp_export.xml",
            "real_export_validation",
            "real_export_alias",
            "generate",
            "verify",
            "review",
            "report",
            "Dashboard smoke",
            "/safe-files?project=real_export_validation",
            "analysis_packet.json",
            "chatgpt_prompt.md",
            "codex_task_prompt.md",
            "report_draft.md",
            "raw_data_included: false",
            "candidate",
            "risk rating은 draft",
            "실제 export 파일명 또는 원본 경로",
            "synthetic fixture",
        ]
        for item in required:
            self.assertIn(item, validation)

        template_required = [
            "validation date",
            "operator alias",
            "source type alias",
            "project alias",
            "raw_data_included",
            "generate",
            "verify",
            "review",
            "report",
            "Dashboard smoke 결과",
            "Safe file inventory",
            "analysis_packet.json",
            "chatgpt_prompt.md",
            "codex_task_prompt.md",
            "report_draft.md",
            "finding은 candidate",
            "risk rating은 draft",
            "AI 입력 후보는 safe files 4개",
        ]
        for item in template_required:
            self.assertIn(item, template)

        forbidden = [
            "raw_request",
            "raw_response",
            "DUMMY_COOKIE_VALUE",
            "DUMMY_BEARER_TOKEN",
            "Authorization: Bearer",
            "Cookie:",
            "https://",
            "http://",
            "C:\\",
            "safe to share",
            "approved",
            "guaranteed safe",
            "severity confirmed",
            "ready to submit",
            "confirmed CVSS",
            "final severity",
            "제출 가능",
            "승인 완료",
            "안전 보장",
        ]
        for text in [validation, template]:
            for item in forbidden:
                self.assertNotIn(item, text)

    def test_local_real_export_smoke_harness_is_local_only_and_raw_free(self) -> None:
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        release_checklist = (ROOT / "docs" / "RELEASE_CHECKLIST_v0.4.md").read_text(encoding="utf-8")
        validation = (ROOT / "docs" / "REAL_BURP_EXPORT_VALIDATION.md").read_text(encoding="utf-8")
        guide = (ROOT / "docs" / "LOCAL_REAL_EXPORT_SMOKE_HARNESS.md").read_text(encoding="utf-8")
        ps1 = (ROOT / "scripts" / "run_local_real_export_smoke.ps1").read_text(encoding="utf-8")
        bat = (ROOT / "scripts" / "run_local_real_export_smoke.bat").read_text(encoding="utf-8")
        gitignore = (ROOT / ".gitignore").read_text(encoding="utf-8")

        for text in [readme, release_checklist, validation]:
            self.assertIn("LOCAL_REAL_EXPORT_SMOKE_HARNESS.md", text)
        for text in [guide, ps1]:
            self.assertIn("local_only", text)
            self.assertIn("raw_data_included=false", text)
            self.assertIn("generate", text)
            self.assertIn("verify", text)
            self.assertIn("review", text)
            self.assertIn("report", text)
            self.assertIn("dashboard", text.lower())
        self.assertIn("input_must_be_under_local_only", ps1)
        self.assertIn("output_alias_must_be_direct_child_of_out", ps1)
        self.assertIn("Start-Process", ps1)
        self.assertIn("-WindowStyle Hidden", ps1)
        self.assertIn("run_local_real_export_smoke.ps1", bat)
        self.assertIn("local_only/", gitignore)
        self.assertIn("out/", gitignore)

        forbidden = [
            "raw_request",
            "raw_response",
            "DUMMY_COOKIE_VALUE",
            "DUMMY_BEARER_TOKEN",
            "Authorization: Bearer",
            "Cookie:",
            "C:\\",
            "safe to share",
            "approved",
            "guaranteed safe",
            "confirmed CVSS",
            "final severity",
        ]
        for text in [guide, ps1, bat]:
            for item in forbidden:
                self.assertNotIn(item, text)

        tracked = subprocess.run(
            ["git", "ls-files"],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        if tracked.returncode == 0:
            tracked_paths = tracked.stdout.splitlines()
            blocked_prefixes = ("local_only/", "raw/", "raw_vault/", "out/")
            for path in tracked_paths:
                self.assertFalse(path.startswith(blocked_prefixes), path)
                self.assertFalse(path.lower().endswith((".burp", ".har")), path)

    def test_v04_rc1_readiness_docs_are_raw_free_and_cautious(self) -> None:
        docs = [
            ROOT / "README.md",
            ROOT / "docs" / "RELEASE_CHECKLIST_v0.4.md",
            ROOT / "docs" / "RELEASE_NOTES_v0.4.md",
            ROOT / "docs" / "REAL_BURP_EXPORT_VALIDATION.md",
            ROOT / "docs" / "LOCAL_REAL_EXPORT_SMOKE_HARNESS.md",
        ]
        text = "\n".join(path.read_text(encoding="utf-8") for path in docs)

        required = [
            "v0.4.30-local-real-export-smoke-harness",
            "v0.4.31-rc1",
            "actual_export_smoke=passed",
            "generate=passed",
            "verify=passed",
            "review=passed",
            "report=passed",
            "dashboard_smoke=passed",
            "browser_smoke=passed",
            "candidate_count=60",
            "safe_files_present=4",
            "forbidden_value_hits=0",
            "raw-free metadata",
            "candidate",
            "draft",
        ]
        for item in required:
            self.assertIn(item, text)

        forbidden = [
            "real_export_01.xml",
            "real_export_validation_run_01.md",
            "raw_request",
            "raw_response",
            "DUMMY_COOKIE_VALUE",
            "DUMMY_BEARER_TOKEN",
            "Authorization: Bearer",
            "Cookie:",
            "C:\\",
            "safe to share",
            "approved",
            "safe-to-share guaranteed",
            "guaranteed safe",
            "severity confirmed",
            "ready to submit",
            "confirmed CVSS",
            "final severity",
        ]
        for item in forbidden:
            self.assertNotIn(item, text)

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
        self.assertIn("requestResponse != null", source)
        self.assertIn("CollectorSafeHostMetadata.evaluate(item)", source)
        self.assertIn("request.isInScope()", source)
        self.assertIn("request.httpService().host()", source)
        self.assertIn("toLowerCase(Locale.ROOT)", source)
        self.assertIn("value.trim()", source)
        self.assertIn("IPV4_LITERAL", source)
        self.assertIn("host.equals(\"localhost\")", source)
        self.assertIn("host.endsWith(\".localhost\")", source)
        self.assertIn("host.contains(\"/\")", source)
        self.assertIn("host.contains(\":\")", source)
        self.assertIn("request_metadata", source)
        self.assertIn("\\\"host\\\"", source)
        self.assertIn("collector_scope_out_of_burp_scope", source)
        self.assertIn("collector_scope_missing_host", source)
        self.assertIn("collector_scope_invalid_host", source)
        self.assertIn("out_of_scope_skipped", source)
        self.assertIn("missing_host_skipped", source)
        self.assertIn("invalid_host_skipped", source)
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
            "logToOutput(decision.host",
            "logToError(decision.host",
            "logToOutput(requestHost",
            "logToError(requestHost",
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
        self.assertIn("LIVE_CAPTURE_SCOPE_DRIFT_MATRIX_v0.5.md", doc)
        self.assertIn("synthetic_live_capture_scope_drift_matrix.json", doc)

        fixture = json.loads(MONTOYA_SCOPE_FIXTURE.read_text(encoding="utf-8"))
        self.assertEqual(fixture["schema_version"], "montoya-scope-inventory-v1")
        self.assertTrue(any(item["in_scope"] for item in fixture["items"]))
        self.assertTrue(any(not item["in_scope"] for item in fixture["items"]))
        self.assertTrue(all(item["raw_values_included"] is False for item in fixture["items"]))
        self.assertTrue(all(item["request_values"] == "omitted" for item in fixture["items"]))
        self.assertTrue(all(item["response_values"] == "omitted" for item in fixture["items"]))
        self.assertTrue(all(item["safe_host_metadata_key"] == "request_metadata.host" for item in fixture["items"]))
        self.assertIn(
            "collector_scope_out_of_burp_scope",
            {item["collector_decision_reason"] for item in fixture["items"]},
        )
        self.assertIn("out_of_scope_skipped", json.dumps(fixture))
        self.assertIn("missing_host_skipped", json.dumps(fixture))
        self.assertIn("invalid_host_skipped", json.dumps(fixture))
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
            self.assertIn("GUI_UPLOAD_WIZARD.md", text)
            self.assertIn("GUI_SIMPLE_DASHBOARD.md", text)
            self.assertIn("GUI_AI_SAFE_PREFLIGHT.md", text)
            self.assertIn("GUI_AI_HANDOFF_INDEX.md", text)
            self.assertIn("GUI_PROMPT_READINESS_INDEX.md", text)
            self.assertIn("GUI_EVIDENCE_BOUNDARY_INDEX.md", text)
            self.assertIn("GUI_OPERATOR_RUNBOOK_INDEX.md", text)
            self.assertIn("GUI_SAFE_FILE_INVENTORY_INDEX.md", text)
            self.assertIn("GUI_FINDING_TRIAGE_INDEX.md", text)
            self.assertIn("GUI_REPORT_READINESS_INDEX.md", text)
            self.assertIn("GUI_WORKFLOW_STATUS_INDEX.md", text)
        for text in [readme, local_dashboard, user_flow]:
            self.assertIn("LIVE_CAPTURE_WIZARD_DESIGN_v0.5.md", text)

        required = [
            "start receiver and dashboard",
            "send scoped Burp history",
            "upload Burp export at /upload",
            "open /live-capture",
            "check live capture read-only status",
            "check receiver output alias",
            "verify the selected output",
            "check simple dashboard summary",
            "review candidate findings",
            "check finding triage index",
            "generate report_draft.md",
            "check report readiness index",
            "check workflow status index",
            "check AI-safe preflight",
            "check AI handoff index",
            "check prompt readiness index",
            "check evidence boundary index",
            "check operator runbook index",
            "check safe file inventory index",
            "export safe files",
            "send only verified safe files to AI",
            "http://127.0.0.1:8766/",
            "/upload",
            "/live-capture",
            "/simple?project=<alias>",
            "/dashboard-simple?project=<alias>",
            "/triage?project=<alias>",
            "/report-readiness?project=<alias>",
            "/workflow?project=<alias>",
            "/prompt-readiness?project=<alias>",
            "/evidence-boundary?project=<alias>",
            "/operator-runbook?project=<alias>",
            "/safe-files?project=<alias>",
            "/preflight?project=<alias>",
            "/handoff?project=<alias>",
            "/help",
            "/operations",
            "/settings",
            "Verify",
            "Upload Wizard",
            "Live Capture",
            "Simple Dashboard",
            "Review",
            "Report",
            "Finding triage index",
            "Report readiness index",
            "Workflow status index",
            "Prompt readiness index",
            "Operator runbook index",
            "Safe file inventory index",
            "AI-safe preflight",
            "AI handoff index",
            "Export",
            "analysis_packet.json",
            "chatgpt_prompt.md",
            "codex_task_prompt.md",
            "report_draft.md",
            "evidence confidence이며 severity가 아닙니다",
            "risk_rating_draft",
            "severity 결정은 권한 있는 재현",
            "CVSS는 별도 산정 범위",
        ]
        for item in required:
            self.assertIn(item, user_flow)

        blocked_items = [
            "raw request 또는 raw response 데이터",
            "Cookie, Authorization, token, JWT, session 값",
            "실제 domain, 고객명, 내부 IP, 개인정보",
            "HMAC secret, CSRF 값, 로컬 secret file",
            "raw viewer",
            "replay 또는 active scan",
            "archive 또는 HMAC 실행 버튼",
            "finding triage 실행 버튼",
            "report readiness 실행 버튼",
            "workflow status 실행 버튼",
            "prompt readiness 실행 버튼",
            "operator runbook 실행 버튼",
            "safe file inventory 실행 버튼",
            "AI-safe preflight 실행 버튼",
            "AI handoff 실행 버튼",
            "risk profile 변경 버튼",
            "delete 또는 edit action",
            "settings-write action",
        ]
        for item in blocked_items:
            self.assertIn(item, user_flow)

        self.assertNotIn("raw_request", user_flow)
        self.assertNotIn("raw_response", user_flow)
        self.assertNotIn("DUMMY_COOKIE_VALUE", user_flow)
        self.assertNotIn("DUMMY_BEARER_TOKEN", user_flow)
        self.assertNotIn("This guide explains", user_flow)
        self.assertNotIn("safe to share", user_flow)
        self.assertNotIn("approved", user_flow)
        self.assertNotIn("guaranteed safe", user_flow)
        self.assertNotIn("severity confirmed", user_flow)
        self.assertNotIn("ready to submit", user_flow)
        self.assertNotIn("제출 가능", user_flow)
        self.assertNotIn("승인 완료", user_flow)
        self.assertNotIn("안전 보장", user_flow)

    def test_gui_live_capture_readiness_guide_documents_read_only_boundary(self) -> None:
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        local_dashboard = (ROOT / "docs" / "LOCAL_DASHBOARD.md").read_text(encoding="utf-8")
        user_flow = (ROOT / "docs" / "GUI_USER_FLOW.md").read_text(encoding="utf-8")
        design = (ROOT / "docs" / "LIVE_CAPTURE_WIZARD_DESIGN_v0.5.md").read_text(encoding="utf-8")
        roadmap = (ROOT / "docs" / "ROADMAP_v0.5.md").read_text(encoding="utf-8")

        for text in [readme, local_dashboard, user_flow, design, roadmap]:
            self.assertIn("/live-capture", text)
            self.assertIn("Live Capture", text)
        for text in [readme, local_dashboard, user_flow, design]:
            self.assertIn("session", text)
            self.assertIn("read-only", text)
            self.assertIn("separate PR", text)
            self.assertIn("AI", text)
        for text in [local_dashboard, user_flow, design]:
            self.assertIn("receiver output alias", text)
            self.assertIn("collector/receiver", text)

        required = [
            "GET /live-capture",
            "read-only status",
            "runtime smoke status labels",
            "receiver output alias",
            "automatic AI handoff status as false",
            "safe files 4",
            "analysis_packet.json",
            "chatgpt_prompt.md",
            "codex_task_prompt.md",
            "report_draft.md",
            "finding = candidate",
            "risk = draft",
            "final severity = manual decision",
            "CVSS = separate manual calculation",
            "raw_data_included=false",
        ]
        for item in required:
            self.assertIn(item, design)

        forbidden = [
            "raw_request",
            "raw_response",
            "DUMMY_COOKIE_VALUE",
            "DUMMY_BEARER_TOKEN",
            "Authorization: Bearer",
            "Cookie:",
            "real_export_",
            "C:\\",
            "safe to share",
            "guaranteed safe",
            "severity confirmed",
            "ready to submit",
            "confirmed CVSS",
        ]
        for text in [readme, local_dashboard, user_flow, design, roadmap]:
            for item in forbidden:
                self.assertNotIn(item, text)

    def test_gui_upload_wizard_guide_documents_state_changing_boundary(self) -> None:
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        quickstart = (ROOT / "docs" / "USER_QUICKSTART.md").read_text(encoding="utf-8")
        local_dashboard = (ROOT / "docs" / "LOCAL_DASHBOARD.md").read_text(encoding="utf-8")
        user_flow = (ROOT / "docs" / "GUI_USER_FLOW.md").read_text(encoding="utf-8")
        guide = (ROOT / "docs" / "GUI_UPLOAD_WIZARD.md").read_text(encoding="utf-8")
        roadmap = (ROOT / "docs" / "ROADMAP_v0.5.md").read_text(encoding="utf-8")

        for text in [readme, quickstart, local_dashboard, user_flow]:
            self.assertIn("GUI_UPLOAD_WIZARD.md", text)
        for text in [quickstart, local_dashboard, user_flow, roadmap, guide]:
            self.assertIn("/upload", text)

        required = [
            "GET /upload",
            "POST /upload",
            ".xml",
            ".json",
            "upload validation",
            "redaction/generate",
            "verify",
            "review",
            "report draft",
            "/simple?project=<alias>",
            "/safe-files?project=<alias>",
            "/triage?project=<alias>",
            "/report-readiness?project=<alias>",
            "analysis_packet.json",
            "chatgpt_prompt.md",
            "codex_task_prompt.md",
            "report_draft.md",
            "raw_data_included: false",
            "finding means candidate",
            "risk means draft",
            "final severity is a manual decision",
            "CVSS is a separate manual calculation",
        ]
        for item in required:
            self.assertIn(item, guide)

        blocked_items = [
            "original request or response bodies",
            "Cookie values",
            "Authorization values",
            "token, JWT, or session values",
            "real URL, domain, IP",
            "personal data",
            "integrity secrets",
            "request-forgery protection values",
            "full local paths",
            "actual local-only filenames",
            "raw upload previews",
            "report body previews",
            "prompt body previews",
        ]
        for item in blocked_items:
            self.assertIn(item, guide)

        forbidden = [
            "raw_request",
            "raw_response",
            "DUMMY_COOKIE_VALUE",
            "DUMMY_BEARER_TOKEN",
            "Authorization: Bearer",
            "Cookie:",
            "real_export_",
            "C:\\",
            "safe to share",
            "approved",
            "guaranteed safe",
            "severity confirmed",
            "ready to submit",
            "confirmed CVSS",
        ]
        for item in forbidden:
            self.assertNotIn(item, guide)

    def test_gui_simple_dashboard_guide_documents_read_only_boundary(self) -> None:
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        quickstart = (ROOT / "docs" / "USER_QUICKSTART.md").read_text(encoding="utf-8")
        local_dashboard = (ROOT / "docs" / "LOCAL_DASHBOARD.md").read_text(encoding="utf-8")
        user_flow = (ROOT / "docs" / "GUI_USER_FLOW.md").read_text(encoding="utf-8")
        guide = (ROOT / "docs" / "GUI_SIMPLE_DASHBOARD.md").read_text(encoding="utf-8")

        for text in [readme, local_dashboard, user_flow]:
            self.assertIn("GUI_SIMPLE_DASHBOARD.md", text)
        for text in [readme, quickstart, local_dashboard, user_flow, guide]:
            self.assertIn("/simple?project=<alias>", text)
            self.assertIn("read-only", text)
            self.assertIn("analysis_packet.json", text)
            self.assertIn("chatgpt_prompt.md", text)
            self.assertIn("codex_task_prompt.md", text)
            self.assertIn("report_draft.md", text)

        required = [
            "GUI Simple Dashboard",
            "/dashboard-simple?project=<alias>",
            "read-only 간단 체크 화면",
            "현재 상태",
            "기본 보기와 고급 산출물",
            "다음 행동",
            "project alias",
            "verify 결과",
            "후보 finding count",
            "safe files 4개",
            "exists",
            "missing",
            "/safe-files",
            "/preflight",
            "/triage",
            "/report-readiness",
            "/workflow",
            "실행 버튼",
            "POST form",
            "download",
            "preview",
            "raw viewer",
            "raw request/response",
            "Cookie, Authorization, token/JWT/session",
            "HMAC secret, CSRF token",
            "full local path",
            "local_only",
            "raw_vault",
            "out/.audit",
            "replay",
            "active scan",
            "파일 삭제",
            "retention 정책 변경",
            "수동 검토",
        ]
        for item in required:
            self.assertIn(item, guide)

        forbidden = [
            "raw_request",
            "raw_response",
            "DUMMY_COOKIE_VALUE",
            "DUMMY_BEARER_TOKEN",
            "Authorization: Bearer",
            "Cookie:",
            "safe to share",
            "approved",
            "guaranteed safe",
            "severity confirmed",
            "ready to submit",
            "C:\\",
        ]
        for item in forbidden:
            self.assertNotIn(item, guide)

    def test_gui_ai_safe_preflight_guide_documents_read_only_boundary(self) -> None:
        guide = (ROOT / "docs" / "GUI_AI_SAFE_PREFLIGHT.md").read_text(encoding="utf-8")
        required = [
            "조회 전용 체크리스트",
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
            "먼저 `verify`를 통과해야 하며",
            "사람이 수동으로 검토해야 합니다",
            "raw request 또는 raw response 데이터",
            "Cookie 또는 Authorization 값",
            "token, JWT, session 값",
            "실제 domain, URL, IP 값",
            "개인정보",
            "HMAC secret 또는 CSRF token 값",
            "candidate",
            "risk_rating_draft",
            "확정 심각도가 아닙니다",
            "CVSS는 별도 산정 범위",
            "POST action",
            "상태 변경 버튼",
            "raw viewer",
            "replay 또는 active scan",
        ]
        for item in required:
            self.assertIn(item, guide)

        self.assertNotIn("raw_request", guide)
        self.assertNotIn("raw_response", guide)
        self.assertNotIn("DUMMY_COOKIE_VALUE", guide)
        self.assertNotIn("DUMMY_BEARER_TOKEN", guide)
        self.assertNotIn("This guide explains", guide)
        self.assertNotIn("safe to share", guide)
        self.assertNotIn("approved", guide)
        self.assertNotIn("guaranteed safe", guide)
        self.assertNotIn("severity confirmed", guide)
        self.assertNotIn("ready to submit", guide)
        self.assertNotIn("제출 가능", guide)
        self.assertNotIn("승인 완료", guide)
        self.assertNotIn("안전 보장", guide)

    def test_gui_finding_triage_index_guide_documents_read_only_boundary(self) -> None:
        guide = (ROOT / "docs" / "GUI_FINDING_TRIAGE_INDEX.md").read_text(encoding="utf-8")
        required = [
            "조회 전용 triage 체크리스트",
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
            "draft risk는 운영자 보조 정보",
            "심각도 결정은 권한 있는 재현",
            "CVSS는 별도 산정 범위",
            "raw request 또는 raw response 데이터",
            "Cookie 또는 Authorization 값",
            "token, JWT, session 값",
            "실제 domain, URL, IP 값",
            "개인정보",
            "HMAC secret 또는 CSRF token 값",
            "full local path",
            "POST action",
            "상태 변경 버튼",
            "finding body preview",
            "request preview",
            "response preview",
            "raw viewer",
            "replay 또는 active scan",
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
        self.assertNotIn("제출 가능", guide)
        self.assertNotIn("승인 완료", guide)
        self.assertNotIn("안전 보장", guide)
        self.assertNotIn("This guide explains", guide)

    def test_gui_report_readiness_index_guide_documents_read_only_boundary(self) -> None:
        guide = (ROOT / "docs" / "GUI_REPORT_READINESS_INDEX.md").read_text(encoding="utf-8")
        required = [
            "보고서 초안 조회 전용 체크리스트",
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
            "prompt readiness link",
            "export/review/report flow link",
            "존재 여부",
            "크기(bytes)",
            "수정 시각(UTC)",
            "SHA-256 파일 fingerprint",
            "HMAC이 아닙니다",
            "scope 확인",
            "affected endpoint 확인",
            "evidence quality 확인",
            "false positive 가능성",
            "impact statement 검토",
            "remediation wording 검토",
            "severity 수동 결정",
            "고객 제출 전 민감정보 검토",
            "finding candidate입니다",
            "Risk는 draft",
            "Evidence confidence는 severity가 아닙니다",
            "`report_draft.md`는 보고서 초안",
            "심각도는 reviewer validation 뒤 사람이 수동으로 결정합니다",
            "raw request 또는 raw response 데이터",
            "raw audit row 본문",
            "Cookie 또는 Authorization 값",
            "token, JWT, session 값",
            "실제 domain, URL, IP 값",
            "개인정보",
            "HMAC secret 또는 CSRF token 값",
            "full local path",
            "form 또는 POST action",
            "상태 변경 버튼",
            "report body preview",
            "request preview",
            "response preview",
            "새 download action",
            "raw viewer",
            "replay 또는 active scan",
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
        self.assertNotIn("제출 가능", guide)
        self.assertNotIn("승인 완료", guide)
        self.assertNotIn("안전 보장", guide)
        self.assertNotIn("This guide explains", guide)

    def test_gui_workflow_status_index_guide_documents_read_only_boundary(self) -> None:
        guide = (ROOT / "docs" / "GUI_WORKFLOW_STATUS_INDEX.md").read_text(encoding="utf-8")
        required = [
            "조회 전용 workflow 체크리스트",
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
            "prompt-readiness",
            "evidence-boundary",
            "operator-runbook",
            "triage",
            "report-readiness",
            "review/report/export flow",
            "safe file status",
            "evidence-boundary",
            "candidate available",
            "draft available",
            "manual review required",
            "finding은 수동 검증이 끝날 때까지 candidate",
            "risk는 draft",
            "심각도는 사람이 수동으로 결정",
            "`report_draft.md`는 보고서 초안",
            "raw request 또는 raw response 데이터",
            "raw audit row 본문",
            "Cookie 또는 Authorization 값",
            "token, JWT, session 값",
            "실제 domain, URL, IP 값",
            "개인정보",
            "HMAC secret 또는 CSRF token 값",
            "full local path",
            "form 또는 POST action",
            "상태 변경 버튼",
            "새 download action",
            "raw viewer",
            "replay 또는 active scan",
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
        self.assertNotIn("제출 가능", guide)
        self.assertNotIn("승인 완료", guide)
        self.assertNotIn("안전 보장", guide)
        self.assertNotIn("This guide explains", guide)

    def test_gui_prompt_readiness_index_guide_documents_read_only_boundary(self) -> None:
        guide = (ROOT / "docs" / "GUI_PROMPT_READINESS_INDEX.md").read_text(encoding="utf-8")
        required = [
            "조회 전용 체크리스트",
            "/prompt-readiness?project=<alias>",
            "chatgpt_prompt.md",
            "codex_task_prompt.md",
            "analysis_packet.json",
            "report_draft.md",
            "safe files 4개",
            "prompt 목적",
            "크기(bytes)",
            "수정 시각(UTC)",
            "SHA-256 fingerprint",
            "HMAC이 아닌 일반 파일 fingerprint",
            "safe files 4개 언급 여부",
            "forbidden data warning",
            "verify-first warning",
            "candidate/draft/manual review boundary",
            "최종 심각도 수동 결정 경고",
            "raw data prohibition warning",
            "Codex prompt",
            "ChatGPT prompt",
            "AI-safe preflight",
            "AI handoff index",
            "workflow status index",
            "evidence boundary index",
            "finding triage index",
            "report readiness index",
            "finding은 수동 검증이 끝날 때까지 candidate",
            "risk는 draft",
            "evidence confidence는 severity가 아닙니다",
            "최종 심각도는 Burp 재현",
            "prompt 파일도 사람이 수동 검토",
            "raw request 또는 raw response 데이터",
            "raw audit row 본문",
            "Cookie 또는 Authorization 값",
            "token, JWT, session 값",
            "실제 domain, URL, IP 값",
            "개인정보",
            "HMAC secret 또는 CSRF token 값",
            "full local path",
            "form 또는 POST action",
            "상태 변경 버튼",
            "prompt body preview",
            "report body preview",
            "request preview",
            "response preview",
            "새 download action",
            "raw viewer",
            "replay 또는 active scan",
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
        self.assertNotIn("제출 가능", guide)
        self.assertNotIn("승인 완료", guide)
        self.assertNotIn("안전 보장", guide)
        self.assertNotIn("This guide explains", guide)

    def test_gui_evidence_boundary_index_guide_documents_read_only_boundary(self) -> None:
        guide = (ROOT / "docs" / "GUI_EVIDENCE_BOUNDARY_INDEX.md").read_text(encoding="utf-8")
        required = [
            "조회 전용 체크리스트",
            "/evidence-boundary?project=<alias>",
            "sanitized evidence",
            "finding candidate",
            "candidate count",
            "analysis_packet.json",
            "report_draft.md",
            "chatgpt_prompt.md",
            "codex_task_prompt.md",
            "safe files 4개",
            "파일 크기(bytes)",
            "수정 시각(UTC)",
            "SHA-256 fingerprint",
            "HMAC이 아닌 일반 파일 fingerprint",
            "허용되는 evidence 범위",
            "금지되는 raw evidence 범위",
            "/preflight?project=<alias>",
            "/handoff?project=<alias>",
            "/prompt-readiness?project=<alias>",
            "/triage?project=<alias>",
            "/report-readiness?project=<alias>",
            "/workflow?project=<alias>",
            "/operator-runbook?project=<alias>",
            "finding은 수동 검증이 끝날 때까지 candidate",
            "risk는 draft",
            "evidence confidence는 severity가 아닙니다",
            "최종 심각도는 Burp 재현",
            "CVSS는 별도 산정 범위",
            "raw request 또는 raw response body",
            "raw audit row 전문",
            "Cookie 또는 Authorization 값",
            "token, JWT, session 값",
            "실제 domain, URL, IP 값",
            "개인정보",
            "HMAC secret 또는 CSRF token 값",
            "full local path",
            "form 또는 POST action",
            "상태 변경 버튼",
            "raw body preview",
            "raw audit row preview",
            "download action",
            "archive 또는 HMAC 생성/검증 실행 버튼",
            "replay 또는 active scan",
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
        self.assertNotIn("제출 가능", guide)
        self.assertNotIn("승인 완료", guide)
        self.assertNotIn("안전 보장", guide)
        self.assertNotIn("This guide explains", guide)

    def test_gui_operator_runbook_index_guide_documents_read_only_boundary(self) -> None:
        guide = (ROOT / "docs" / "GUI_OPERATOR_RUNBOOK_INDEX.md").read_text(encoding="utf-8")
        required = [
            "조회 전용 operator runbook checklist",
            "/operator-runbook?project=<alias>",
            "Burp HTTP history 수집",
            "localhost receiver 저장",
            "redaction/verify",
            "review candidate findings",
            "report_draft.md 생성",
            "preflight",
            "handoff",
            "triage",
            "report-readiness",
            "prompt-readiness",
            "evidence-boundary",
            "workflow status recap",
            "analysis_packet.json",
            "chatgpt_prompt.md",
            "codex_task_prompt.md",
            "report_draft.md",
            "safe files 4개",
            "AI 후보 입력 범위",
            "금지 데이터 경계",
            "finding은 수동 검증이 끝날 때까지 candidate",
            "risk rating은 draft",
            "evidence confidence는 severity가 아닙니다",
            "최종 심각도는 Burp 재현",
            "report_draft.md는 최종 보고서가 아니라 초안",
            "prompt/evidence/report",
            "/preflight?project=<alias>",
            "/handoff?project=<alias>",
            "/triage?project=<alias>",
            "/report-readiness?project=<alias>",
            "/prompt-readiness?project=<alias>",
            "/evidence-boundary?project=<alias>",
            "/safe-files?project=<alias>",
            "/workflow?project=<alias>",
            "raw request/response body",
            "raw audit row 전문",
            "Cookie 값",
            "Authorization 값",
            "token/JWT/session 값",
            "실제 domain, URL, IP 값",
            "개인정보",
            "HMAC secret 또는 CSRF token 값",
            "full local path",
            "form 또는 POST action",
            "상태 변경 버튼",
            "파일 내려받기",
            "raw viewer",
            "replay 또는 active scan",
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
        self.assertNotIn("제출 가능", guide)
        self.assertNotIn("승인 완료", guide)
        self.assertNotIn("안전 보장", guide)
        self.assertNotIn("This guide explains", guide)

    def test_gui_safe_file_inventory_index_guide_documents_read_only_boundary(self) -> None:
        guide = (ROOT / "docs" / "GUI_SAFE_FILE_INVENTORY_INDEX.md").read_text(encoding="utf-8")
        required = [
            "조회 전용 safe file inventory checklist",
            "/safe-files?project=<alias>",
            "analysis_packet.json",
            "chatgpt_prompt.md",
            "codex_task_prompt.md",
            "report_draft.md",
            "exists / missing",
            "파일 목적",
            "권장 사용 위치",
            "verify 선행 필요",
            "file size",
            "modified UTC",
            "SHA-256 fingerprint",
            "HMAC이 아니며",
            "/preflight?project=<alias>",
            "/handoff?project=<alias>",
            "/prompt-readiness?project=<alias>",
            "/evidence-boundary?project=<alias>",
            "/triage?project=<alias>",
            "/report-readiness?project=<alias>",
            "/workflow?project=<alias>",
            "/operator-runbook?project=<alias>",
            "finding은 수동 검증이 끝날 때까지 candidate",
            "risk rating은 draft",
            "evidence confidence는 severity가 아닙니다",
            "final severity는 Burp 재현",
            "`report_draft.md`는 final report가 아니라",
            "raw request/response body",
            "request body 또는 response body preview",
            "prompt/report/evidence body preview",
            "Cookie 값",
            "Authorization 값",
            "token/JWT/session 값",
            "실제 domain, URL, IP 값",
            "개인정보",
            "HMAC secret 또는 CSRF token 값",
            "full local path",
            "form 또는 POST action",
            "상태 변경 버튼",
            "파일 다운로드",
            "파일 본문 preview",
            "raw viewer",
            "replay 또는 active scan",
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
        self.assertNotIn("This guide explains", guide)

    def test_gui_ai_handoff_index_guide_documents_read_only_boundary(self) -> None:
        guide = (ROOT / "docs" / "GUI_AI_HANDOFF_INDEX.md").read_text(encoding="utf-8")
        required = [
            "조회 전용 체크리스트",
            "/handoff?project=<alias>",
            "analysis_packet.json",
            "chatgpt_prompt.md",
            "codex_task_prompt.md",
            "report_draft.md",
            "권장 순서",
            "존재 여부",
            "크기(bytes)",
            "수정 시각(UTC)",
            "SHA-256 파일 fingerprint",
            "HMAC이 아니며",
            "verify first",
            "check prompt readiness index",
            "수동 검토가 필요합니다",
            "candidate finding",
            "draft risk",
            "최종 심각도 수동 결정",
            "raw request 또는 raw response 데이터",
            "Cookie 또는 Authorization 값",
            "token, JWT, session 값",
            "실제 domain, URL, IP 값",
            "개인정보",
            "HMAC secret 또는 CSRF token 값",
            "POST action",
            "상태 변경 버튼",
            "새 download action",
            "안전 파일 본문 preview",
            "raw viewer",
            "replay 또는 active scan",
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
        self.assertNotIn("제출 가능", guide)
        self.assertNotIn("승인 완료", guide)
        self.assertNotIn("안전 보장", guide)
        self.assertNotIn("This guide explains", guide)

    def test_ko_quickstart_and_output_bundle_v06_are_raw_free_and_operator_focused(self) -> None:
        quickstart = USER_QUICKSTART_KO_V06_DOC.read_text(encoding="utf-8")
        output_guide = OUTPUT_BUNDLE_GUIDE_KO_V06_DOC.read_text(encoding="utf-8")
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        dashboard = (ROOT / "burp_ai_redaction_gateway" / "dashboard.py").read_text(
            encoding="utf-8"
        )

        self.assertIn("USER_QUICKSTART_KO_v0.6.md", readme)
        self.assertIn("OUTPUT_BUNDLE_GUIDE_KO_v0.6.md", readme)
        self.assertIn("기본 보기: 보고서 초안", dashboard)
        self.assertIn("기본 보기: ChatGPT용 프롬프트", dashboard)
        self.assertIn("고급 산출물: 구조화된 분석 packet", dashboard)
        self.assertIn("고급 산출물: Codex 작업 프롬프트", dashboard)
        self.assertIn("자동 전송 없음", dashboard)

        for required in [
            "사용자 빠른 시작 가이드 v0.6",
            "1단계: Burp export 또는 collector 결과 준비",
            "2단계: 로컬 redaction 실행",
            "3단계: verify 실행",
            "4단계: review 실행",
            "5단계: report 생성",
            "6단계: 사람이 결과 확인",
            "7단계: 필요한 파일만 수동 복사",
            "자동 ChatGPT 전송은 없습니다",
            "AI 투입 전 사람이 최종 확인합니다",
            "finding은 candidate finding입니다",
            "risk는 draft risk입니다",
            "report는 draft report입니다",
            "severity/CVSS는 사람이 수동 판단합니다",
        ]:
            self.assertIn(required, quickstart)

        for required in [
            "산출물 묶음 안내 v0.6",
            "기본 보기",
            "고급 보기",
            "보고서 초안",
            "ChatGPT용 프롬프트",
            "고급 산출물",
            "원문 포함 여부",
            "자동 전송 없음",
            "수동 검토",
            "analysis_packet.json",
            "chatgpt_prompt.md",
            "codex_task_prompt.md",
            "report_draft.md",
        ]:
            self.assertIn(required, output_guide)

        combined = "\n".join([quickstart, output_guide])
        for safe_file in [
            "analysis_packet.json",
            "chatgpt_prompt.md",
            "codex_task_prompt.md",
            "report_draft.md",
        ]:
            self.assertIn(safe_file, combined)

        for forbidden in [
            "safe-to-share",
            "safe to share",
            "confirmed vulnerability",
            "final CVSS",
            "raw_request",
            "raw_response",
            "Cookie:",
            "Authorization:",
            "Bearer ",
            "JWT ",
            "session=",
            "token=",
            "C:\\coding\\",
            "C:\\Users\\",
            "real_export_",
            "actual.local",
            "example.com",
            "ready to submit",
            "approved for external sharing",
            "guaranteed safe",
        ]:
            self.assertNotIn(forbidden, combined)

        self.assertIsNone(re.search(r"https?://", combined))
        self.assertIsNone(re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", combined))

    def test_web_operator_guide_ko_v07_is_raw_free_and_scope_clear(self) -> None:
        guide = WEB_OPERATOR_GUIDE_KO_V07_DOC.read_text(encoding="utf-8")
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        quickstart = USER_QUICKSTART_KO_V06_DOC.read_text(encoding="utf-8")

        self.assertTrue(WEB_OPERATOR_GUIDE_KO_V07_DOC.exists())
        for linked_text in [readme, quickstart]:
            self.assertIn("WEB_OPERATOR_GUIDE_KO_v0.7.md", linked_text)

        for section in [
            "## 목적",
            "## 현재 웹에서 가능한 작업",
            "## 현재 웹에서 불가능한 작업",
            "## Local Dashboard 시작 방법",
            "## Upload Wizard 사용 흐름",
            "## safe files 4개 확인 방법",
            "## triage/report readiness 화면의 의미",
            "## Windows launcher 사용 범위",
            "## localhost receiver 사용 범위",
            "## read-only MCP stdio server와 dashboard의 차이",
            "## v0.7 MCP listener runtime 경계",
            "## 보안 경계",
            "## 실패 처리",
            "## 운영자 체크리스트",
            "## 다음 단계",
        ]:
            self.assertIn(section, guide)

        for required in [
            "Local Dashboard",
            "Upload Wizard",
            "safe files 4개",
            "triage/report readiness",
            "Windows launcher",
            "localhost receiver",
            "read-only MCP stdio server",
            "GET /upload",
            "POST /upload",
            "upload validation",
            "local-only storage",
            "generate",
            "verify",
            "review",
            "report draft",
            "safe file status",
            "verify`가 실패하면 Wizard는 안전하게 중단합니다",
            "review, report, safe file link를 제공하지 않습니다",
            "analysis_packet.json",
            "chatgpt_prompt.md",
            "codex_task_prompt.md",
            "report_draft.md",
            "finding은 candidate",
            "risk는 draft",
            "final severity와 CVSS는 사람이 별도로 결정",
            "v0.7 MCP listener runtime은 아직 사용할 수 없습니다",
            "socket, bind, listen 기반 endpoint",
            "MCP transport 또는 protocol handler",
            "executable tool registration",
            "actual tool execution",
            "local evidence reader",
            "raw preview/download",
            "replay/active scan",
            "automatic ChatGPT handoff",
        ]:
            self.assertIn(required, guide)

        for forbidden in [
            "safe-to-share",
            "safe to share",
            "guaranteed safe",
            "confirmed vulnerability",
            "confirmed finding",
            "final CVSS confirmed",
            "raw_request",
            "raw_response",
            "Cookie:",
            "Authorization:",
            "Bearer ",
            "JWT ",
            "session=",
            "token=",
            "HMAC secret:",
            "CSRF token:",
            "C:\\coding\\",
            "C:\\Users\\",
            "real_export_",
            "actual.local",
            "example.com",
            "ready to submit",
            "approved for external sharing",
        ]:
            self.assertNotIn(forbidden, guide)

        self.assertIsNone(re.search(r"https?://", guide))
        self.assertIsNone(re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", guide))

    def test_web_operator_smoke_checklist_ko_v07_is_raw_free_and_scope_clear(self) -> None:
        checklist = WEB_OPERATOR_SMOKE_CHECKLIST_KO_V07_DOC.read_text(encoding="utf-8")
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        web_operator_guide = WEB_OPERATOR_GUIDE_KO_V07_DOC.read_text(encoding="utf-8")
        upload_wizard = (ROOT / "docs" / "GUI_UPLOAD_WIZARD.md").read_text(encoding="utf-8")

        self.assertTrue(WEB_OPERATOR_SMOKE_CHECKLIST_KO_V07_DOC.exists())
        for linked_text in [readme, web_operator_guide, upload_wizard]:
            self.assertIn("WEB_OPERATOR_SMOKE_CHECKLIST_KO_v0.7.md", linked_text)

        for section in [
            "## 목적",
            "## 전제 조건",
            "## 금지 범위",
            "## Dashboard 시작 확인",
            "## Upload Wizard 접근 확인",
            "## invalid upload 실패 확인",
            "## safe sample upload 확인",
            "## verify-first 경계 확인",
            "## safe files 4개 확인",
            "## triage 화면 확인",
            "## report readiness 화면 확인",
            "## 실패 화면 확인",
            "## raw-free 확인 항목",
            "## no automatic handoff 확인 항목",
            "## browser smoke 기록 양식",
            "## 운영자 최종 체크리스트",
            "## 다음 단계",
        ]:
            self.assertIn(section, checklist)

        for required in [
            "manual smoke checklist",
            "Local Dashboard",
            "Upload Wizard",
            "Dashboard 시작",
            "safe files 4개",
            "triage",
            "report readiness",
            "failure screen",
            "local-only workflow",
            "verify 통과 전 output은 AI 입력 후보가 아닙니다",
            "analysis_packet.json",
            "chatgpt_prompt.md",
            "codex_task_prompt.md",
            "report_draft.md",
            "finding은 candidate",
            "report는 draft",
            "risk는 draft",
            "severity와 CVSS는 수동 결정",
            "raw preview/download",
            "replay/active scan",
            "automatic ChatGPT handoff",
            "MCP listener runtime",
            "socket/bind/listen endpoint",
            "transport/protocol handler",
            "tool registration/tool execution",
            "local evidence reader",
            "`favicon.ico` 404는 현재 blocker가 아닙니다",
            "favicon 404 blocker: no",
            "actual target identifiers recorded: no",
            "raw traffic recorded: no",
            "credential values recorded: no",
            "full local path recorded: no",
        ]:
            self.assertIn(required, checklist)

        for forbidden in [
            "safe-to-share",
            "safe to share",
            "guaranteed safe",
            "confirmed vulnerability",
            "confirmed finding",
            "final CVSS confirmed",
            "raw_request",
            "raw_response",
            "Cookie:",
            "Authorization:",
            "Bearer ",
            "JWT ",
            "session=",
            "token=",
            "HMAC secret:",
            "CSRF token:",
            "C:\\coding\\",
            "C:\\Users\\",
            "real_export_",
            "actual.local",
            "example.com",
            "ready to submit",
            "approved for external sharing",
        ]:
            self.assertNotIn(forbidden, checklist)

        self.assertIsNone(re.search(r"https?://", checklist))
        self.assertIsNone(re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", checklist))

    def test_release_checklist_v04_documents_hardening_flow(self) -> None:
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        quickstart = (ROOT / "docs" / "USER_QUICKSTART.md").read_text(encoding="utf-8")
        local_dashboard = (ROOT / "docs" / "LOCAL_DASHBOARD.md").read_text(encoding="utf-8")
        release_notes = (ROOT / "docs" / "RELEASE_NOTES_v0.4.md").read_text(encoding="utf-8")
        checklist = (ROOT / "docs" / "RELEASE_CHECKLIST_v0.4.md").read_text(encoding="utf-8")

        for text in [readme, quickstart, local_dashboard, release_notes]:
            self.assertIn("RELEASE_CHECKLIST_v0.4.md", text)

        required = [
            "v0.4 Release Checklist",
            "python -m compileall burp_ai_redaction_gateway tests",
            "python -m unittest discover -s tests",
            "python -m burp_ai_redaction_gateway verify --input out",
            "python -m burp_ai_redaction_gateway review --input out\\demo",
            "python -m burp_ai_redaction_gateway report --input out\\demo --output out\\demo\\report_draft.md --profile conservative",
            "gitleaks dir -v --redact=100 --config .gitleaks.toml .",
            "gitleaks git -v --redact=100 --config .gitleaks.toml .",
            "scripts\\git_safety_check.bat",
            "git diff --check",
            "git status --short --untracked-files=all",
            "/help",
            "/operations",
            "/settings",
            "/output?project=<alias>",
            "/simple?project=<alias>",
            "/dashboard-simple?project=<alias>",
            "/preflight?project=<alias>",
            "/handoff?project=<alias>",
            "/triage?project=<alias>",
            "/report-readiness?project=<alias>",
            "/workflow?project=<alias>",
            "/prompt-readiness?project=<alias>",
            "/evidence-boundary?project=<alias>",
            "/operator-runbook?project=<alias>",
            "/safe-files?project=<alias>",
            "formCount=0",
            "postFormCount=0",
            "buttonCount=0",
            "downloadLinkCount=0",
            "lang=\"ko\"",
            "analysis_packet.json",
            "chatgpt_prompt.md",
            "codex_task_prompt.md",
            "report_draft.md",
            "local_only/",
            "raw/",
            "raw_vault/",
            "out/.audit/",
            "candidate",
            "risk_rating_draft",
            "최종 심각도",
            "실제 Burp export",
            "Tag 기준",
            "Rollback 기준",
        ]
        for item in required:
            self.assertIn(item, checklist)

        forbidden = [
            "raw_request",
            "raw_response",
            "DUMMY_COOKIE_VALUE",
            "DUMMY_BEARER_TOKEN",
            "Authorization: Bearer",
            "Cookie:",
            "safe to share",
            "approved",
            "guaranteed safe",
            "confirmed CVSS",
            "final severity",
            "severity confirmed",
            "ready to submit",
            "제출 가능",
            "승인 완료",
            "안전 보장",
            "C:\\coding\\",
            "C:\\Users\\",
        ]
        for item in forbidden:
            self.assertNotIn(item, checklist)


if __name__ == "__main__":
    unittest.main()
