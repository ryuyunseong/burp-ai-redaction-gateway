from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Mapping


ALLOWED_TOOL_NAMES = (
    "get_gateway_status",
    "list_verified_outputs",
    "get_live_capture_status",
    "get_safe_file_inventory",
    "get_report_readiness",
    "get_prompt_readiness",
    "get_troubleshooting_categories",
    "get_release_readiness",
)

FORBIDDEN_TOOL_CONCEPTS = (
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
)

BLOCKED_RESPONSE_CODES = (
    "not_verified",
    "not_allowlisted",
    "raw_access_blocked",
    "state_change_blocked",
    "local_path_blocked",
    "secret_access_blocked",
)

BLOCKED_RESPONSE_ALLOWED_FIELDS = (
    "ok",
    "code",
    "safe_reason",
    "output_alias",
    "remediation_hint",
)

SAFE_FILE_ALLOWLIST = (
    "analysis_packet.json",
    "chatgpt_prompt.md",
    "codex_task_prompt.md",
    "report_draft.md",
)

_UNSAFE_METADATA_MARKERS = (
    "raw request",
    "raw response",
    "raw_request",
    "raw_response",
    "cookie:",
    "authorization:",
    "bearer ",
    "jwt",
    "session=",
    "token=",
    "hmac secret",
    "csrf token",
)
_IP_LITERAL_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")


class McpReadOnlyRegistryError(ValueError):
    def __init__(self, error_type: str) -> None:
        super().__init__(error_type)
        self.error_type = error_type


@dataclass(frozen=True)
class ReadOnlyRegistryEntry:
    name: str
    read_only: bool
    verify_first: bool
    safe_output_fields: tuple[str, ...]
    description: str

    def to_safe_metadata(self) -> dict[str, Any]:
        metadata = {
            "name": self.name,
            "read_only": self.read_only,
            "verify_first": self.verify_first,
            "safe_output_fields": list(self.safe_output_fields),
            "description": self.description,
            "raw_data_included": False,
        }
        _assert_raw_free_metadata(metadata)
        return metadata


def build_read_only_tool_registry() -> dict[str, ReadOnlyRegistryEntry]:
    entries = [
        ReadOnlyRegistryEntry(
            name="get_gateway_status",
            read_only=True,
            verify_first=False,
            safe_output_fields=("tool_name", "status", "gateway_version", "root_alias", "verify_mode"),
            description="Global gateway status metadata only.",
        ),
        ReadOnlyRegistryEntry(
            name="list_verified_outputs",
            read_only=True,
            verify_first=True,
            safe_output_fields=("tool_name", "output_aliases", "verify_status", "safe_file_status"),
            description="Verified output alias inventory metadata only.",
        ),
        ReadOnlyRegistryEntry(
            name="get_live_capture_status",
            read_only=True,
            verify_first=True,
            safe_output_fields=("tool_name", "capture_status", "receiver_alias", "handoff_count", "skip_count"),
            description="Live Capture count and status metadata only.",
        ),
        ReadOnlyRegistryEntry(
            name="get_safe_file_inventory",
            read_only=True,
            verify_first=True,
            safe_output_fields=("tool_name", "safe_files", "exists", "size_bytes", "modified_at_utc", "fingerprint"),
            description="Four-file candidate inventory metadata only.",
        ),
        ReadOnlyRegistryEntry(
            name="get_report_readiness",
            read_only=True,
            verify_first=True,
            safe_output_fields=(
                "tool_name",
                "report_exists",
                "candidate_count",
                "manual_review_required",
                "risk_is_draft",
            ),
            description="Report readiness labels and counts only.",
        ),
        ReadOnlyRegistryEntry(
            name="get_prompt_readiness",
            read_only=True,
            verify_first=True,
            safe_output_fields=("tool_name", "prompt_files", "verify_passed", "manual_review_required"),
            description="Prompt candidate readiness metadata only.",
        ),
        ReadOnlyRegistryEntry(
            name="get_troubleshooting_categories",
            read_only=True,
            verify_first=True,
            safe_output_fields=("tool_name", "categories", "safe_next_steps"),
            description="Troubleshooting category labels only.",
        ),
        ReadOnlyRegistryEntry(
            name="get_release_readiness",
            read_only=True,
            verify_first=False,
            safe_output_fields=("tool_name", "readiness_status", "gate_summary", "manual_approval_required"),
            description="Release readiness metadata only; no release action.",
        ),
    ]
    registry = {entry.name: entry for entry in entries}
    _assert_registry_shape(registry)
    return registry


def build_blocked_response(
    code: str,
    safe_reason: str,
    *,
    output_alias: str | None = None,
    remediation_hint: str | None = None,
) -> dict[str, Any]:
    if code not in BLOCKED_RESPONSE_CODES:
        raise McpReadOnlyRegistryError("unknown_blocked_response_code")
    response: dict[str, Any] = {
        "ok": False,
        "code": code,
        "safe_reason": _safe_metadata_text(safe_reason, "blocked"),
    }
    if output_alias is not None:
        response["output_alias"] = _safe_output_alias(output_alias)
    if remediation_hint is not None:
        response["remediation_hint"] = _safe_metadata_text(remediation_hint, "check_required")
    _assert_blocked_response_shape(response)
    _assert_raw_free_metadata(response)
    return response


def validate_registry_against_contract_fixtures(
    contract_fixture: Mapping[str, Any],
    preflight_fixture: Mapping[str, Any],
) -> dict[str, Any]:
    registry = build_read_only_tool_registry()
    _require_sequence("contract_allowed_tools", contract_fixture.get("allowed_candidate_tools"), ALLOWED_TOOL_NAMES)
    _require_sequence("preflight_allowed_tools", preflight_fixture.get("allowed_tools"), ALLOWED_TOOL_NAMES)
    _require_sequence(
        "contract_forbidden_tools",
        contract_fixture.get("forbidden_tool_concepts"),
        FORBIDDEN_TOOL_CONCEPTS,
    )
    _require_sequence("preflight_forbidden_tools", preflight_fixture.get("forbidden_tools"), FORBIDDEN_TOOL_CONCEPTS)
    _require_sequence("contract_blocked_codes", contract_fixture.get("blocked_response_codes"), BLOCKED_RESPONSE_CODES)
    _require_sequence("preflight_blocked_codes", preflight_fixture.get("blocked_response_codes"), BLOCKED_RESPONSE_CODES)
    _require_sequence("contract_safe_files", contract_fixture.get("safe_file_allowlist"), SAFE_FILE_ALLOWLIST)
    _require_sequence("preflight_safe_files", preflight_fixture.get("safe_files"), SAFE_FILE_ALLOWLIST)
    _require_sequence(
        "preflight_blocked_response_fields",
        preflight_fixture.get("blocked_response_allowed_fields"),
        BLOCKED_RESPONSE_ALLOWED_FIELDS,
    )
    if preflight_fixture.get("runtime_registry_implemented") is not False:
        raise McpReadOnlyRegistryError("preflight_runtime_registry_flag_changed")
    if preflight_fixture.get("mcp_server_implemented") is not False:
        raise McpReadOnlyRegistryError("preflight_server_flag_changed")
    if preflight_fixture.get("mcp_tool_handler_implemented") is not False:
        raise McpReadOnlyRegistryError("preflight_tool_handler_flag_changed")
    _assert_registry_shape(registry)
    return {
        "ok": True,
        "tool_count": len(registry),
        "read_only": all(entry.read_only for entry in registry.values()),
        "raw_data_included": False,
    }


def _assert_registry_shape(registry: Mapping[str, ReadOnlyRegistryEntry]) -> None:
    if tuple(registry) != ALLOWED_TOOL_NAMES:
        raise McpReadOnlyRegistryError("registry_allowed_tool_drift")
    for forbidden in FORBIDDEN_TOOL_CONCEPTS:
        if forbidden in registry:
            raise McpReadOnlyRegistryError("forbidden_tool_registered")
    for entry in registry.values():
        if not entry.read_only:
            raise McpReadOnlyRegistryError("non_read_only_tool")
        _assert_raw_free_metadata(entry.to_safe_metadata())


def _assert_blocked_response_shape(response: Mapping[str, Any]) -> None:
    if any(field not in BLOCKED_RESPONSE_ALLOWED_FIELDS for field in response):
        raise McpReadOnlyRegistryError("blocked_response_field_drift")
    if response.get("ok") is not False:
        raise McpReadOnlyRegistryError("blocked_response_ok_drift")
    if response.get("code") not in BLOCKED_RESPONSE_CODES:
        raise McpReadOnlyRegistryError("blocked_response_code_drift")


def _require_sequence(name: str, actual: Any, expected: tuple[str, ...]) -> None:
    if tuple(actual or ()) != expected:
        raise McpReadOnlyRegistryError(f"{name}_drift")


def _safe_output_alias(value: str) -> str:
    text = _safe_metadata_text(value, "output")
    if "\\" in text or ":" in text or ".." in text or text.startswith("/") or "://" in text:
        raise McpReadOnlyRegistryError("unsafe_output_alias")
    return text


def _safe_metadata_text(value: str, fallback: str) -> str:
    text = str(value).replace("\r", " ").replace("\n", " ").strip()
    if not text:
        text = fallback
    text = " ".join(text.split())[:160]
    _assert_raw_free_text(text)
    return text


def _assert_raw_free_metadata(value: Any) -> None:
    _assert_raw_free_text(str(value))


def _assert_raw_free_text(text: str) -> None:
    lowered = text.lower()
    if any(marker in lowered for marker in _UNSAFE_METADATA_MARKERS):
        raise McpReadOnlyRegistryError("unsafe_metadata_marker")
    if "://" in lowered or _IP_LITERAL_RE.search(text):
        raise McpReadOnlyRegistryError("unsafe_metadata_locator")
