from __future__ import annotations

import re
from typing import Any, Mapping

from .mcp_adapter_dry_run import (
    McpAdapterDryRunError,
    build_adapter_dry_run_plan,
    evaluate_adapter_dry_run_fixture,
)
from .mcp_read_only_registry import (
    ALLOWED_TOOL_NAMES,
    FORBIDDEN_TOOL_CONCEPTS,
    ReadOnlyRegistryEntry,
    build_read_only_tool_registry,
)


SCHEMA_VERSION = "mcp_local_only_tool_schema_catalog.v0.6"

GLOBAL_METADATA_TOOL_NAMES = frozenset(
    {
        "get_gateway_status",
        "get_release_readiness",
    }
)

SAFE_DESCRIPTOR_FLAG_FIELDS = frozenset(
    {
        "raw_data_included",
        "local_path_included",
        "credential_values_included",
        "target_identifiers_included",
        "state_change_performed",
        "implementation_approved",
        "mcp_runtime_implemented",
    }
)

UNSAFE_SCHEMA_TEXT_MARKERS = (
    "raw request",
    "raw response",
    "raw_request",
    "raw_response",
    "file body",
    "local path",
    "actual target",
    "target identifier",
    "url",
    "domain",
    "ip address",
    "cookie",
    "authorization",
    "bearer",
    "jwt",
    "session",
    "credential",
    "token",
    "hmac secret",
    "csrf token",
    "stack trace",
    "audit row",
    "archive content",
    "safe-to-share",
    "guaranteed safe",
    "confirmed vulnerability",
    "final cvss",
)

UNSAFE_SCHEMA_FIELD_MARKERS = (
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
)

_IP_LITERAL_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")


class McpToolSchemaCatalogError(ValueError):
    def __init__(self, error_type: str) -> None:
        super().__init__(error_type)
        self.error_type = error_type


def build_local_only_tool_schema_catalog() -> dict[str, Any]:
    registry = build_read_only_tool_registry()
    tools = [_build_descriptor(entry) for entry in registry.values()]
    catalog: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "planning_only": True,
        "implementation_approved": False,
        "mcp_runtime_implemented": False,
        "tool_count": len(tools),
        "tools": tools,
        "raw_data_included": False,
        "local_path_included": False,
        "credential_values_included": False,
        "target_identifiers_included": False,
        "state_change_performed": False,
    }
    validate_tool_schema_catalog_against_registry(catalog)
    assert_tool_schema_catalog_raw_free(catalog)
    return catalog


def validate_tool_schema_catalog_against_registry(catalog: Mapping[str, Any] | None = None) -> dict[str, Any]:
    registry = build_read_only_tool_registry()
    catalog = catalog or build_local_only_tool_schema_catalog()
    tools = _required_tool_list(catalog)
    if tuple(tool.get("name") for tool in tools) != tuple(registry):
        raise McpToolSchemaCatalogError("tool_schema_catalog_name_drift")
    if catalog.get("planning_only") is not True:
        raise McpToolSchemaCatalogError("tool_schema_catalog_not_planning_only")
    if catalog.get("implementation_approved") is not False:
        raise McpToolSchemaCatalogError("tool_schema_catalog_approval_changed")
    if catalog.get("mcp_runtime_implemented") is not False:
        raise McpToolSchemaCatalogError("tool_schema_catalog_runtime_changed")
    if catalog.get("tool_count") != len(registry):
        raise McpToolSchemaCatalogError("tool_schema_catalog_count_drift")
    _assert_false_boundary_flags(catalog, "tool_schema_catalog")

    for tool in tools:
        name = _required_text(tool, "name", "tool_schema_descriptor")
        entry = registry.get(name)
        if entry is None:
            raise McpToolSchemaCatalogError("tool_schema_catalog_unknown_tool")
        _validate_descriptor_against_entry(tool, entry)

    if any(forbidden in str(catalog) for forbidden in FORBIDDEN_TOOL_CONCEPTS):
        raise McpToolSchemaCatalogError("tool_schema_catalog_forbidden_concept")
    assert_tool_schema_catalog_raw_free(catalog)
    return {
        "ok": True,
        "tool_count": len(tools),
        "read_only": all(tool.get("read_only") is True for tool in tools),
        "raw_data_included": False,
    }


def validate_tool_schema_catalog_against_fixtures(
    adapter_fixture: Mapping[str, Any],
    implementation_gate_fixture: Mapping[str, Any],
    catalog: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    catalog = catalog or build_local_only_tool_schema_catalog()
    registry_result = validate_tool_schema_catalog_against_registry(catalog)
    try:
        adapter_plan = build_adapter_dry_run_plan(adapter_fixture, implementation_gate_fixture)
        evaluated = evaluate_adapter_dry_run_fixture(adapter_fixture, implementation_gate_fixture)
    except McpAdapterDryRunError as exc:
        raise McpToolSchemaCatalogError(exc.error_type) from exc
    tool_names = tuple(tool["name"] for tool in _required_tool_list(catalog))
    if tuple(adapter_fixture.get("allowed_tools") or ()) != tool_names:
        raise McpToolSchemaCatalogError("tool_schema_fixture_allowed_tool_drift")
    if adapter_plan.get("registry_tool_count") != len(tool_names):
        raise McpToolSchemaCatalogError("tool_schema_fixture_registry_count_drift")
    if evaluated.get("ok") is not True:
        raise McpToolSchemaCatalogError("tool_schema_fixture_dry_run_failed")
    _assert_false_boundary_flags(adapter_fixture, "adapter_fixture")
    _assert_false_boundary_flags(implementation_gate_fixture, "implementation_gate")
    assert_tool_schema_catalog_raw_free(catalog)
    return {
        "ok": True,
        "tool_count": registry_result["tool_count"],
        "adapter_case_count": adapter_plan["case_count"],
        "gate_requirement_count": adapter_plan["gate_requirement_count"],
        "raw_data_included": False,
    }


def assert_tool_schema_catalog_raw_free(catalog: Mapping[str, Any]) -> None:
    for key, value in _walk_metadata(catalog):
        if key not in SAFE_DESCRIPTOR_FLAG_FIELDS:
            _assert_safe_field_name(key)
        if isinstance(value, str):
            _assert_safe_schema_text(value)
    for tool in _required_tool_list(catalog):
        for field_name in ("safe_input_fields", "safe_output_fields"):
            fields = tool.get(field_name)
            if not isinstance(fields, list) or not fields:
                raise McpToolSchemaCatalogError(f"missing_{field_name}")
            for field in fields:
                if not isinstance(field, str) or not field:
                    raise McpToolSchemaCatalogError("unsafe_schema_field")
                _assert_safe_field_name(field)


def _build_descriptor(entry: ReadOnlyRegistryEntry) -> dict[str, Any]:
    safe_input_fields = _safe_input_fields_for_entry(entry)
    descriptor: dict[str, Any] = {
        "name": entry.name,
        "description": entry.description,
        "read_only": entry.read_only,
        "verify_first": entry.verify_first,
        "safe_input_fields": list(safe_input_fields),
        "safe_output_fields": list(entry.safe_output_fields),
        "raw_data_included": False,
        "local_path_included": False,
        "credential_values_included": False,
        "target_identifiers_included": False,
        "state_change_performed": False,
    }
    _validate_descriptor_against_entry(descriptor, entry)
    return descriptor


def _safe_input_fields_for_entry(entry: ReadOnlyRegistryEntry) -> tuple[str, ...]:
    if entry.name in GLOBAL_METADATA_TOOL_NAMES:
        return ("status_alias", "manual_review_status")
    if entry.verify_first:
        return ("output_alias", "verify_status")
    raise McpToolSchemaCatalogError("unexpected_non_verify_first_tool")


def _validate_descriptor_against_entry(descriptor: Mapping[str, Any], entry: ReadOnlyRegistryEntry) -> None:
    if descriptor.get("description") != entry.description:
        raise McpToolSchemaCatalogError("tool_schema_descriptor_description_drift")
    if descriptor.get("read_only") is not True:
        raise McpToolSchemaCatalogError("tool_schema_descriptor_not_read_only")
    if descriptor.get("verify_first") is not entry.verify_first:
        raise McpToolSchemaCatalogError("tool_schema_descriptor_verify_drift")
    if tuple(descriptor.get("safe_input_fields") or ()) != _safe_input_fields_for_entry(entry):
        raise McpToolSchemaCatalogError("tool_schema_descriptor_input_drift")
    if tuple(descriptor.get("safe_output_fields") or ()) != entry.safe_output_fields:
        raise McpToolSchemaCatalogError("tool_schema_descriptor_output_drift")
    if entry.name in GLOBAL_METADATA_TOOL_NAMES:
        if descriptor.get("verify_first") is not False:
            raise McpToolSchemaCatalogError("tool_schema_global_verify_drift")
    elif descriptor.get("verify_first") is not True:
        raise McpToolSchemaCatalogError("tool_schema_output_verify_drift")
    _assert_false_boundary_flags(descriptor, "tool_schema_descriptor")


def _assert_false_boundary_flags(value: Mapping[str, Any], label: str) -> None:
    for flag in SAFE_DESCRIPTOR_FLAG_FIELDS:
        if flag in value and value.get(flag) is not False:
            raise McpToolSchemaCatalogError(f"{label}_{flag}_changed")


def _required_tool_list(catalog: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    tools = catalog.get("tools")
    if not isinstance(tools, list) or not tools:
        raise McpToolSchemaCatalogError("missing_tool_schema_descriptors")
    return tools


def _required_text(value: Mapping[str, Any], field: str, label: str) -> str:
    item = value.get(field)
    if not isinstance(item, str) or not item:
        raise McpToolSchemaCatalogError(f"{label}_missing_{field}")
    return item


def _walk_metadata(value: Any, key: str = "") -> list[tuple[str, Any]]:
    if isinstance(value, Mapping):
        items: list[tuple[str, Any]] = []
        for nested_key, nested_value in value.items():
            items.append((str(nested_key), nested_value))
            items.extend(_walk_metadata(nested_value, str(nested_key)))
        return items
    if isinstance(value, list):
        items = []
        for item in value:
            items.extend(_walk_metadata(item, key))
        return items
    return [(key, value)] if key else []


def _assert_safe_field_name(field: str) -> None:
    normalized = field.lower()
    if any(marker in normalized for marker in UNSAFE_SCHEMA_FIELD_MARKERS):
        raise McpToolSchemaCatalogError("unsafe_schema_field")


def _assert_safe_schema_text(text: str) -> None:
    normalized = " ".join(text.replace("_", " ").replace("-", " ").lower().split())
    if any(marker in normalized for marker in UNSAFE_SCHEMA_TEXT_MARKERS):
        raise McpToolSchemaCatalogError("unsafe_schema_text")
    if "://" in text or "\\" in text or _IP_LITERAL_RE.search(text):
        raise McpToolSchemaCatalogError("unsafe_schema_text")
