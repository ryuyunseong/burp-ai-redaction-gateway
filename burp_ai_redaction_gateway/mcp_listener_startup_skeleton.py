from __future__ import annotations

from types import MappingProxyType
from typing import Any


SCHEMA_VERSION = "v10_listener_startup_skeleton.v1"

OUTPUT_BUNDLE_FILES = (
    "analysis_packet.json",
    "chatgpt_prompt.md",
    "codex_task_prompt.md",
    "report_draft.md",
)

APPROVED_SCOPE = (
    "disabled_by_default_metadata_skeleton",
    "static_config_metadata_only",
    "loopback_requirement_metadata_only",
    "implementation_decision_consumed",
    "negative_fixture_consumed",
    "transport_listener_approval_packet_consumed",
)

BLOCKED_SCOPE = (
    "listener_runtime",
    "transport_runtime",
    "socket_startup",
    "protocol_handler",
    "protocol_message_parsing",
    "executable_tool_registration",
    "actual_tool_execution",
    "local_evidence_reader",
    "safe_file_body_reader",
    "raw_preview_download",
    "replay_active_scan",
    "dashboard_state_changing_action",
    "upload_import_action",
    "automatic_chatgpt_handoff",
)

CONSUMED_BASELINES = (
    "docs/V0.10_TRANSPORT_LISTENER_APPROVAL_PACKET.md",
    "docs/V0.10_LISTENER_STARTUP_IMPLEMENTATION_DECISION.md",
    "tests/fixtures/v10_listener_startup_negative_cases.json",
    "tests/fixtures/v10_listener_startup_implementation_decision.json",
)

RUNTIME_FLAGS = MappingProxyType(
    {
        "listener_runtime_enabled": False,
        "transport_runtime_enabled": False,
        "socket_bind_enabled": False,
        "socket_listen_enabled": False,
        "socket_accept_enabled": False,
        "server_startup_enabled": False,
        "protocol_message_handling_enabled": False,
        "executable_tool_registration_enabled": False,
        "actual_tool_execution_enabled": False,
        "tool_execution_enabled": False,
        "local_evidence_access_enabled": False,
        "safe_file_body_reader_enabled": False,
        "raw_preview_enabled": False,
        "raw_preview_download_enabled": False,
        "replay_active_scan_enabled": False,
        "dashboard_state_changing_action_enabled": False,
        "upload_import_action_enabled": False,
        "automatic_chatgpt_handoff_enabled": False,
    }
)


def build_listener_startup_skeleton_metadata() -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "skeleton_only": True,
        "disabled_by_default": True,
        "implementation_decision_consumed": True,
        "listener_startup_negative_fixture_consumed": True,
        "transport_listener_approval_packet_consumed": True,
        "listener_startup_skeleton_present": True,
        **dict(RUNTIME_FLAGS),
        "manual_review_required": True,
        "raw_data_included": False,
        "approved_next_step_consumed": "listener_startup_skeleton_only",
        "output_bundle_files": list(OUTPUT_BUNDLE_FILES),
        "approved_scope": list(APPROVED_SCOPE),
        "blocked_scope": list(BLOCKED_SCOPE),
        "consumed_baselines": list(CONSUMED_BASELINES),
    }
