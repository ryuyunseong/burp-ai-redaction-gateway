from __future__ import annotations

from ipaddress import AddressValueError, ip_address
from types import MappingProxyType
from typing import Any


SCHEMA_VERSION = "v08_minimal_skeleton_runtime_contract.v1"
EXPECTED_BASE_COMMIT = "5de5f499c1fe5b7bb1705d3d99f533d6cde4ea32"

OUTPUT_BUNDLE_FILES = (
    "analysis_packet.json",
    "chatgpt_prompt.md",
    "codex_task_prompt.md",
    "report_draft.md",
)

CONSUMED_GUARDS = (
    "v08_skeleton_approval_packet",
    "v08_runtime_source_check_consumption_guard",
)

ALLOWED_DISABLED_REASON_CODES = frozenset(
    {
        "runtime_disabled_by_default",
        "runtime_start_blocked",
        "loopback_host_allowed",
        "all_interface_host_blocked",
        "non_loopback_host_blocked",
        "invalid_host_blocked",
    }
)

RUNTIME_BOUNDARY_FLAGS = MappingProxyType(
    {
        "explicit_human_approval_recorded": True,
        "disabled_by_default": True,
        "runtime_enabled": False,
        "listener_started": False,
        "startup_permitted": False,
        "loopback_only_if_runtime_approved": True,
        "transport_enabled": False,
        "protocol_handler_enabled": False,
        "executable_tool_registration_enabled": False,
        "tool_registry_runtime_enabled": False,
        "tool_discovery_runtime_enabled": False,
        "actual_tool_execution_enabled": False,
        "local_evidence_reader_enabled": False,
        "safe_file_body_reader_enabled": False,
        "raw_preview_download_enabled": False,
        "dashboard_state_changing_control_enabled": False,
        "upload_import_action_enabled": False,
        "automatic_chatgpt_handoff_enabled": False,
        "tag_github_release_mutation_enabled": False,
        "output_bundle_structure_changed": False,
    }
)


def _normalize_host_candidate(host: str) -> str:
    return host.strip().lower().removeprefix("[").removesuffix("]")


def is_loopback_host_candidate(host: str) -> bool:
    normalized_host = _normalize_host_candidate(host)
    if normalized_host == "localhost":
        return True
    try:
        return ip_address(normalized_host).is_loopback
    except (AddressValueError, ValueError):
        return False


def is_all_interface_host_candidate(host: str) -> bool:
    normalized_host = _normalize_host_candidate(host)
    if normalized_host in {"", "*"}:
        return True
    try:
        return ip_address(normalized_host).is_unspecified
    except (AddressValueError, ValueError):
        return False


def normalize_disabled_reason_code(reason_code: str) -> str:
    if isinstance(reason_code, str) and reason_code in ALLOWED_DISABLED_REASON_CODES:
        return reason_code
    return "unknown_disabled_surface"


def build_runtime_contract_metadata() -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "expected_base_commit": EXPECTED_BASE_COMMIT,
        "minimal_skeleton_runtime_contract": True,
        "metadata_only": True,
        "raw_data_included": False,
        "manual_review_required": True,
        "candidate_findings_only": True,
        "risk_draft_only": True,
        "final_severity_manual": True,
        "final_cvss_manual": True,
        "output_bundle_files": list(OUTPUT_BUNDLE_FILES),
        "consumed_guards": list(CONSUMED_GUARDS),
        **dict(RUNTIME_BOUNDARY_FLAGS),
    }


def validate_loopback_host_candidate(host: str) -> dict[str, Any]:
    if is_all_interface_host_candidate(host):
        reason_code = "all_interface_host_blocked"
        allowed = False
    elif is_loopback_host_candidate(host):
        reason_code = "loopback_host_allowed"
        allowed = True
    elif _normalize_host_candidate(host):
        reason_code = "non_loopback_host_blocked"
        allowed = False
    else:
        reason_code = "invalid_host_blocked"
        allowed = False

    return {
        "schema_version": SCHEMA_VERSION,
        "status": "allowed" if allowed else "blocked",
        "reason_code": reason_code,
        "host_value_included": False,
        "loopback_candidate_allowed": allowed,
        "raw_data_included": False,
        "manual_review_required": True,
    }


def build_disabled_runtime_response(reason_code: str = "runtime_disabled_by_default") -> dict[str, Any]:
    safe_reason_code = normalize_disabled_reason_code(reason_code)
    return {
        "schema_version": SCHEMA_VERSION,
        "status": "disabled" if safe_reason_code == "runtime_disabled_by_default" else "blocked",
        "reason_code": safe_reason_code,
        "metadata_only": True,
        "raw_data_included": False,
        "manual_review_required": True,
        "host_value_included": False,
        "credential_values_included": False,
        "file_body_included": False,
        **dict(RUNTIME_BOUNDARY_FLAGS),
    }


def evaluate_minimal_skeleton_runtime_request(
    *, enabled: bool = False, host: str = "localhost"
) -> dict[str, Any]:
    if not enabled:
        return build_disabled_runtime_response()

    host_validation = validate_loopback_host_candidate(host)
    response = build_disabled_runtime_response("runtime_start_blocked")
    response.update(
        {
            "requested_runtime_enablement": True,
            "host_validation_status": host_validation["status"],
            "host_validation_reason_code": host_validation["reason_code"],
            "loopback_candidate_allowed": host_validation["loopback_candidate_allowed"],
            "startup_permitted": False,
            "listener_started": False,
            "runtime_enabled": False,
        }
    )
    return response
