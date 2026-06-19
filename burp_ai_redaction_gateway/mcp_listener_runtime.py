from __future__ import annotations

from dataclasses import dataclass
from ipaddress import AddressValueError, ip_address
from types import MappingProxyType
from typing import Any, Mapping


SCHEMA_VERSION = "v07_minimal_listener_runtime.v1"

OUTPUT_BUNDLE_FILES = (
    "analysis_packet.json",
    "chatgpt_prompt.md",
    "codex_task_prompt.md",
    "report_draft.md",
)

ALLOWED_REASON_CODES = frozenset(
    {
        "listener_disabled",
        "local_loopback_validation_passed",
        "remote_bind_blocked",
        "non_loopback_host_rejected",
        "protocol_message_rejected",
    }
)

ALLOWED_STATUSES = frozenset({"disabled", "blocked", "ready"})

PROTOCOL_MESSAGE_KEYS = frozenset({"jsonrpc", "method", "params", "id"})

RUNTIME_BOUNDARY_FLAGS = MappingProxyType(
    {
        "local_only": True,
        "loopback_only": True,
        "disabled_by_default": True,
        "raw_free_blocked_response": True,
        "transport_enabled": False,
        "protocol_handler_enabled": False,
        "executable_tool_registration_enabled": False,
        "actual_tool_execution_enabled": False,
        "local_evidence_reader_enabled": False,
        "safe_file_body_reader_enabled": False,
        "dashboard_state_changing_control_enabled": False,
        "upload_import_action_enabled": False,
        "automatic_chatgpt_handoff_enabled": False,
    }
)


@dataclass(frozen=True)
class MinimalListenerRuntimeConfig:
    enabled: bool = False
    host: str = "localhost"


def build_default_listener_runtime_config() -> MinimalListenerRuntimeConfig:
    return MinimalListenerRuntimeConfig()


def is_loopback_host(host: str) -> bool:
    normalized_host = host.strip().lower().removeprefix("[").removesuffix("]")
    if normalized_host == "localhost":
        return True
    try:
        return ip_address(normalized_host).is_loopback
    except (AddressValueError, ValueError):
        return False


def is_all_interface_host(host: str) -> bool:
    normalized_host = host.strip().lower().removeprefix("[").removesuffix("]")
    if normalized_host in {"", "*"}:
        return True
    try:
        return ip_address(normalized_host).is_unspecified
    except (AddressValueError, ValueError):
        return False


def is_protocol_message(value: Any) -> bool:
    if isinstance(value, Mapping):
        return bool(PROTOCOL_MESSAGE_KEYS.intersection(str(key).lower() for key in value.keys()))
    if isinstance(value, str):
        lowered = value.lower()
        return "jsonrpc" in lowered or '"method"' in lowered
    return False


def build_listener_runtime_metadata() -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "minimal_listener_runtime_implemented": True,
        "listener_started": False,
        "output_bundle_files": list(OUTPUT_BUNDLE_FILES),
        "raw_data_included": False,
        **dict(RUNTIME_BOUNDARY_FLAGS),
    }


def build_listener_runtime_response(
    *,
    status: str,
    reason_code: str,
    enabled: bool = False,
    startup_permitted: bool = False,
) -> dict[str, Any]:
    safe_reason_code = reason_code if reason_code in ALLOWED_REASON_CODES else "listener_disabled"
    safe_status = status if status in ALLOWED_STATUSES else "blocked"
    return {
        "schema_version": SCHEMA_VERSION,
        "status": safe_status,
        "reason_code": safe_reason_code,
        "metadata_only": True,
        "raw_data_included": False,
        "manual_review_required": True,
        "listener_runtime_enabled": enabled,
        "listener_started": False,
        "startup_permitted": startup_permitted,
        **dict(RUNTIME_BOUNDARY_FLAGS),
    }


def build_disabled_listener_runtime_response() -> dict[str, Any]:
    return build_listener_runtime_response(
        status="disabled",
        reason_code="listener_disabled",
        enabled=False,
        startup_permitted=False,
    )


def validate_minimal_listener_startup(
    config: MinimalListenerRuntimeConfig | None = None,
    *,
    input_body: Any = None,
) -> dict[str, Any]:
    runtime_config = config or build_default_listener_runtime_config()
    if not runtime_config.enabled:
        return build_disabled_listener_runtime_response()
    if is_protocol_message(input_body):
        return build_listener_runtime_response(
            status="blocked",
            reason_code="protocol_message_rejected",
            enabled=runtime_config.enabled,
            startup_permitted=False,
        )
    if is_all_interface_host(runtime_config.host):
        return build_listener_runtime_response(
            status="blocked",
            reason_code="remote_bind_blocked",
            enabled=True,
            startup_permitted=False,
        )
    if not is_loopback_host(runtime_config.host):
        return build_listener_runtime_response(
            status="blocked",
            reason_code="non_loopback_host_rejected",
            enabled=True,
            startup_permitted=False,
        )
    return build_listener_runtime_response(
        status="ready",
        reason_code="local_loopback_validation_passed",
        enabled=True,
        startup_permitted=True,
    )


def build_minimal_listener_local_smoke_summary() -> dict[str, Any]:
    disabled_response = validate_minimal_listener_startup()
    local_response = validate_minimal_listener_startup(MinimalListenerRuntimeConfig(enabled=True, host="localhost"))
    blocked_response = validate_minimal_listener_startup(MinimalListenerRuntimeConfig(enabled=True, host="remote-host"))
    return {
        "schema_version": SCHEMA_VERSION,
        "disabled_by_default": disabled_response["status"] == "disabled",
        "loopback_allowed": local_response["status"] == "ready",
        "non_loopback_blocked": blocked_response["status"] == "blocked",
        "raw_data_included": False,
        "listener_started": False,
        "manual_review_required": True,
    }
