from __future__ import annotations

from typing import Any, Mapping

from .mcp_read_only_registry import (
    BLOCKED_RESPONSE_ALLOWED_FIELDS,
    BLOCKED_RESPONSE_CODES,
    FORBIDDEN_TOOL_CONCEPTS,
    SAFE_FILE_ALLOWLIST,
    McpReadOnlyRegistryError,
    build_blocked_response,
    build_read_only_tool_registry,
)


RUNTIME_FLAG_FIELDS = (
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
)

UNSAFE_EXPECTED_FIELD_MARKERS = (
    "raw",
    "request",
    "response",
    "body",
    "path",
    "url",
    "domain",
    "ip",
    "cookie",
    "authorization",
    "credential",
    "token",
    "session",
    "secret",
    "hmac",
    "csrf",
    "target",
)


class McpAdapterDryRunError(ValueError):
    def __init__(self, error_type: str) -> None:
        super().__init__(error_type)
        self.error_type = error_type


def build_adapter_dry_run_plan(
    adapter_fixture: Mapping[str, Any],
    implementation_gate_fixture: Mapping[str, Any],
) -> dict[str, Any]:
    registry = build_read_only_tool_registry()
    _validate_adapter_fixture_boundary(adapter_fixture, registry)
    _validate_implementation_gate_fixture(implementation_gate_fixture)
    evaluated = evaluate_adapter_dry_run_fixture(adapter_fixture, implementation_gate_fixture)
    return {
        "ok": evaluated["ok"],
        "case_count": evaluated["case_count"],
        "gate_requirement_count": evaluated["gate_requirement_count"],
        "registry_tool_count": len(registry),
        "implementation_approved": False,
        "mcp_runtime_implemented": False,
        "raw_data_included": False,
        "local_path_included": False,
        "credential_values_included": False,
        "target_identifiers_included": False,
        "state_change_performed": False,
    }


def evaluate_adapter_dry_run_fixture(
    adapter_fixture: Mapping[str, Any],
    implementation_gate_fixture: Mapping[str, Any],
) -> dict[str, Any]:
    registry = build_read_only_tool_registry()
    _validate_adapter_fixture_boundary(adapter_fixture, registry)
    _validate_implementation_gate_fixture(implementation_gate_fixture)
    case_results = [
        evaluate_adapter_dry_run_case(case, registry=registry)
        for case in _required_list(adapter_fixture, "adapter_cases")
    ]
    return {
        "ok": all(result["gate_passed"] for result in case_results),
        "case_count": len(case_results),
        "gate_requirement_count": len(_required_list(implementation_gate_fixture, "gate_requirements")),
        "case_results": case_results,
        "raw_data_included": False,
        "local_path_included": False,
        "credential_values_included": False,
        "target_identifiers_included": False,
        "state_change_performed": False,
    }


def evaluate_adapter_dry_run_case(
    case: Mapping[str, Any],
    *,
    registry: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    registry = registry or build_read_only_tool_registry()
    name = _required_text(case, "name")
    expected_code = case.get("expected_code")
    expected_ok = case.get("expected_ok")
    expected_fields = set(_required_list(case, "expected_fields"))
    if not isinstance(expected_ok, bool):
        raise McpAdapterDryRunError("case_expected_ok_not_bool")
    _assert_expected_fields_safe(expected_fields)
    if expected_ok is True:
        observed_code = None
        gate_passed = expected_code is None and _allowed_case_matches_registry(name, registry)
        remediation_hint = "metadata case stays read-only"
    else:
        blocked = build_adapter_blocked_response_for_case(case)
        observed_code = blocked["code"]
        if set(blocked) != expected_fields:
            raise McpAdapterDryRunError("blocked_response_expected_field_drift")
        gate_passed = observed_code == expected_code
        remediation_hint = blocked.get("remediation_hint", "blocked by dry-run gate")
    _assert_case_safe_flags(case)
    return {
        "ok": bool(gate_passed and expected_ok is True),
        "case_name": name,
        "expected_code": expected_code,
        "observed_code": observed_code,
        "raw_data_included": False,
        "local_path_included": False,
        "credential_values_included": False,
        "target_identifiers_included": False,
        "state_change_performed": False,
        "gate_passed": bool(gate_passed),
        "remediation_hint": remediation_hint,
    }


def build_adapter_blocked_response_for_case(case: Mapping[str, Any]) -> dict[str, Any]:
    expected_code = case.get("expected_code")
    if not isinstance(expected_code, str):
        raise McpAdapterDryRunError("case_is_not_blocked")
    name = _required_text(case, "name")
    kwargs: dict[str, str] = {
        "remediation_hint": "use verified metadata-only tool flow",
    }
    if expected_code == "not_verified":
        kwargs["output_alias"] = "verified-output-alias"
    try:
        return build_blocked_response(
            expected_code,
            f"{name} blocked by local dry-run gate",
            **kwargs,
        )
    except McpReadOnlyRegistryError as exc:
        raise McpAdapterDryRunError(exc.error_type) from exc


def _validate_adapter_fixture_boundary(
    adapter_fixture: Mapping[str, Any],
    registry: Mapping[str, Any],
) -> None:
    if adapter_fixture.get("planning_only") is not True:
        raise McpAdapterDryRunError("adapter_fixture_not_planning_only")
    if adapter_fixture.get("raw_data_included") is not False:
        raise McpAdapterDryRunError("adapter_fixture_raw_data_changed")
    for flag in RUNTIME_FLAG_FIELDS:
        if adapter_fixture.get(flag) is not False:
            raise McpAdapterDryRunError(f"adapter_fixture_{flag}_changed")
    if tuple(_required_list(adapter_fixture, "allowed_tools")) != tuple(registry):
        raise McpAdapterDryRunError("adapter_fixture_allowed_tool_drift")
    if tuple(_required_list(adapter_fixture, "forbidden_tools")) != FORBIDDEN_TOOL_CONCEPTS:
        raise McpAdapterDryRunError("adapter_fixture_forbidden_tool_drift")
    if tuple(_required_list(adapter_fixture, "blocked_response_codes")) != BLOCKED_RESPONSE_CODES:
        raise McpAdapterDryRunError("adapter_fixture_blocked_code_drift")
    if tuple(_required_list(adapter_fixture, "blocked_response_allowed_fields")) != BLOCKED_RESPONSE_ALLOWED_FIELDS:
        raise McpAdapterDryRunError("adapter_fixture_blocked_field_drift")
    if tuple(_required_list(adapter_fixture, "safe_files")) != SAFE_FILE_ALLOWLIST:
        raise McpAdapterDryRunError("adapter_fixture_safe_file_drift")


def _validate_implementation_gate_fixture(implementation_gate_fixture: Mapping[str, Any]) -> None:
    if implementation_gate_fixture.get("planning_only") is not True:
        raise McpAdapterDryRunError("implementation_gate_not_planning_only")
    if implementation_gate_fixture.get("implementation_approved") is not False:
        raise McpAdapterDryRunError("implementation_gate_approval_changed")
    if implementation_gate_fixture.get("raw_data_included") is not False:
        raise McpAdapterDryRunError("implementation_gate_raw_data_changed")
    for flag in RUNTIME_FLAG_FIELDS:
        if implementation_gate_fixture.get(flag) is not False:
            raise McpAdapterDryRunError(f"implementation_gate_{flag}_changed")
    for requirement in _required_list(implementation_gate_fixture, "gate_requirements"):
        if requirement.get("required") is not True:
            raise McpAdapterDryRunError("implementation_gate_requirement_not_required")
        if requirement.get("blocks_runtime_if_missing") is not True:
            raise McpAdapterDryRunError("implementation_gate_requirement_does_not_block")
        if requirement.get("raw_data_included") is not False:
            raise McpAdapterDryRunError("implementation_gate_requirement_raw_data_changed")
        if requirement.get("state_change_performed") is not False:
            raise McpAdapterDryRunError("implementation_gate_requirement_state_changed")


def _allowed_case_matches_registry(name: str, registry: Mapping[str, Any]) -> bool:
    if name == "allowed_global_status_tool":
        return any(
            not entry.verify_first
            and {"gateway_version", "root_alias", "verify_mode"}.issubset(set(entry.safe_output_fields))
            for entry in registry.values()
        )
    if name == "allowed_verified_output_specific_tool":
        return any(
            entry.verify_first and "verify_status" in entry.safe_output_fields
            for entry in registry.values()
        )
    if name == "safe_file_inventory_metadata_only":
        return any(
            entry.verify_first and "safe_files" in entry.safe_output_fields
            for entry in registry.values()
        )
    return False


def _assert_case_safe_flags(case: Mapping[str, Any]) -> None:
    for flag in (
        "raw_data_included",
        "local_path_included",
        "credential_values_included",
        "target_identifiers_included",
        "state_change_performed",
    ):
        if case.get(flag) is not False:
            raise McpAdapterDryRunError(f"case_{flag}_changed")


def _assert_expected_fields_safe(fields: set[Any]) -> None:
    for field in fields:
        if not isinstance(field, str) or not field:
            raise McpAdapterDryRunError("unsafe_expected_field")
        if field == "raw_data_included":
            continue
        normalized = field.lower()
        if any(marker in normalized for marker in UNSAFE_EXPECTED_FIELD_MARKERS):
            raise McpAdapterDryRunError("unsafe_expected_field")


def _required_list(value: Mapping[str, Any], field: str) -> list[Any]:
    item = value.get(field)
    if not isinstance(item, list) or not item:
        raise McpAdapterDryRunError(f"missing_{field}")
    return item


def _required_text(value: Mapping[str, Any], field: str) -> str:
    item = value.get(field)
    if not isinstance(item, str) or not item:
        raise McpAdapterDryRunError(f"missing_{field}")
    return item
