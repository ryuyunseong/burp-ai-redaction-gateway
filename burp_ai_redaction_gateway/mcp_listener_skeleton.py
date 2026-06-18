from __future__ import annotations

from types import MappingProxyType
from typing import Any


SCHEMA_VERSION = "v07_mcp_listener_metadata_skeleton.v1"

OUTPUT_BUNDLE_FILES = (
    "analysis_packet.json",
    "chatgpt_prompt.md",
    "codex_task_prompt.md",
    "report_draft.md",
)

ALLOWED_OPERATIONS = (
    "describe_boundary",
    "build_blocked_response",
)

BLOCKED_SURFACES = (
    "listener",
    "transport",
    "protocol_handler",
    "tool_registration",
    "tool_execution",
    "local_evidence_reader",
    "raw_preview_download",
    "automatic_chatgpt_handoff",
)

ALLOWED_BLOCK_REASON_CODES = frozenset(
    {
        "listener_runtime_blocked",
        "transport_blocked",
        "protocol_handler_blocked",
        "tool_registration_blocked",
        "tool_execution_blocked",
        "local_evidence_reader_blocked",
        "raw_preview_download_blocked",
        "automatic_chatgpt_handoff_blocked",
    }
)

RUNTIME_FLAGS = MappingProxyType(
    {
        "listener_runtime_enabled": False,
        "transport_enabled": False,
        "protocol_handler_enabled": False,
        "executable_tool_registration_enabled": False,
        "actual_tool_execution_enabled": False,
        "local_evidence_reader_enabled": False,
        "safe_file_body_reader_enabled": False,
        "raw_preview_download_enabled": False,
        "automatic_chatgpt_handoff_enabled": False,
    }
)


def build_listener_skeleton_metadata() -> dict[str, Any]:
    metadata: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "metadata_only": True,
        **dict(RUNTIME_FLAGS),
        "output_bundle_files": list(OUTPUT_BUNDLE_FILES),
        "allowed_operations": list(ALLOWED_OPERATIONS),
        "blocked_surfaces": list(BLOCKED_SURFACES),
        "raw_data_included": False,
    }
    return metadata


def build_blocked_listener_response(reason_code: str) -> dict[str, Any]:
    safe_reason_code = (
        reason_code
        if isinstance(reason_code, str) and reason_code in ALLOWED_BLOCK_REASON_CODES
        else "unknown_blocked_surface"
    )
    return {
        "status": "blocked",
        "reason_code": safe_reason_code,
        "metadata_only": True,
        "raw_data_included": False,
        "manual_review_required": True,
    }
