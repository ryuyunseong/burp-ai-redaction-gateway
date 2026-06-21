from __future__ import annotations

from typing import Any

from burp_ai_redaction_gateway.mcp_runtime_contract import (
    CONSUMED_GUARDS,
    OUTPUT_BUNDLE_FILES,
    SCHEMA_VERSION as CONTRACT_SCHEMA_VERSION,
    build_disabled_runtime_response,
    build_runtime_contract_metadata,
    evaluate_minimal_skeleton_runtime_request,
    validate_loopback_host_candidate,
)


SCHEMA_VERSION = "v08_disabled_minimal_skeleton.v1"

ALLOWED_OPERATIONS = (
    "describe_boundary",
    "build_disabled_response",
    "validate_loopback_candidate",
)

BLOCKED_SURFACES = (
    "transport",
    "protocol_handler",
    "request_dispatcher",
    "tool_registration",
    "tool_execution",
    "local_evidence_reader",
    "safe_file_body_reader",
    "raw_preview_download",
    "dashboard_state_changing_control",
    "upload_import_action",
    "automatic_chatgpt_handoff",
)


def build_minimal_skeleton_metadata() -> dict[str, Any]:
    metadata = build_runtime_contract_metadata()
    metadata.update(
        {
            "schema_version": SCHEMA_VERSION,
            "contract_schema_version": CONTRACT_SCHEMA_VERSION,
            "minimal_skeleton_runtime_file_added": True,
            "source_check_guard_consumed": True,
            "approval_packet_consumed": True,
            "allowed_operations": list(ALLOWED_OPERATIONS),
            "blocked_surfaces": list(BLOCKED_SURFACES),
            "consumed_guards": list(CONSUMED_GUARDS),
            "output_bundle_files": list(OUTPUT_BUNDLE_FILES),
        }
    )
    return metadata


def build_minimal_skeleton_disabled_response(
    reason_code: str = "runtime_disabled_by_default",
    *,
    enabled: bool = False,
    host: str = "localhost",
) -> dict[str, Any]:
    if enabled:
        response = evaluate_minimal_skeleton_runtime_request(enabled=True, host=host)
    else:
        response = build_disabled_runtime_response(reason_code)
    response.update(
        {
            "schema_version": SCHEMA_VERSION,
            "contract_schema_version": CONTRACT_SCHEMA_VERSION,
            "source_check_guard_consumed": True,
            "approval_packet_consumed": True,
        }
    )
    return response


__all__ = [
    "ALLOWED_OPERATIONS",
    "BLOCKED_SURFACES",
    "OUTPUT_BUNDLE_FILES",
    "build_minimal_skeleton_disabled_response",
    "build_minimal_skeleton_metadata",
    "validate_loopback_host_candidate",
]
