from __future__ import annotations

import re
from collections.abc import Mapping
from types import MappingProxyType
from typing import Any


SCHEMA_VERSION = "v09_minimal_dispatcher_decision_helper.v1"

DISPATCHER_RESPONSE_ALLOWED_FIELDS = (
    "status",
    "reason_code",
    "dispatcher_approved",
    "dispatcher_invocation_allowed",
    "tool_execution_allowed",
    "raw_data_included",
    "manual_review_required",
    "safe_message",
)

FALLBACK_REASON_CODE = "dispatcher_invocation_blocked"
SAFE_DISPATCHER_MESSAGE = "Dispatcher request blocked. Manual review required."
_SAFE_MESSAGE_ALLOWLIST = frozenset({SAFE_DISPATCHER_MESSAGE})
_REASON_CODE_RE = re.compile(r"^[a-z][a-z0-9_]{0,79}$")
_IP_LITERAL_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")

_UNSAFE_REASON_VALUES = frozenset(
    {
        "authorization",
        "bearer",
        "cookie",
        "csrf",
        "csrf_token",
        "hmac",
        "hmac_secret",
        "jwt",
        "raw_request",
        "raw_response",
        "session",
        "token",
    }
)

_UNSAFE_TEXT_MARKERS = (
    "authorization:",
    "bearer ",
    "cookie:",
    "csrf token",
    "hmac secret",
    "jwt",
    "raw request",
    "raw response",
    "raw_request",
    "raw_response",
    "session=",
    "token=",
)

RUNTIME_FLAGS = MappingProxyType(
    {
        "dispatcher_invocation_allowed": False,
        "executable_tool_registration_implemented": False,
        "actual_tool_execution_implemented": False,
        "local_evidence_reader_implemented": False,
        "safe_file_body_reader_implemented": False,
        "listener_startup_implemented": False,
        "transport_runtime_implemented": False,
    }
)


class McpDispatcherError(ValueError):
    def __init__(self, error_type: str) -> None:
        super().__init__(error_type)
        self.error_type = error_type


def build_minimal_dispatcher_metadata() -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "minimal_dispatcher_decision_helper": True,
        "dispatcher_approval_packet_consumed": True,
        "dispatcher_negative_fixture_consumed": True,
        "dispatcher_implementation_decision_consumed": True,
        "registry_dispatcher_boundary_consumed": True,
        "allowed_dispatcher_output_fields": list(DISPATCHER_RESPONSE_ALLOWED_FIELDS),
        "raw_data_included": False,
        "manual_review_required": True,
        **dict(RUNTIME_FLAGS),
    }


def build_blocked_dispatcher_response(
    reason_code: str,
    safe_message: str | None = None,
) -> dict[str, Any]:
    response = {
        "status": "blocked",
        "reason_code": _safe_reason_code(reason_code),
        "dispatcher_approved": False,
        "dispatcher_invocation_allowed": False,
        "tool_execution_allowed": False,
        "raw_data_included": False,
        "manual_review_required": True,
        "safe_message": _safe_message(safe_message),
    }
    _assert_dispatcher_response_shape(response)
    _assert_raw_free_text(str(response))
    return response


def classify_dispatcher_metadata(metadata: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(metadata, Mapping):
        return build_blocked_dispatcher_response(FALLBACK_REASON_CODE)
    return build_blocked_dispatcher_response(_metadata_reason_code(metadata))


def _metadata_reason_code(metadata: Mapping[str, Any]) -> str:
    for key in ("expected_reason_code", "category", "reason_code"):
        value = metadata.get(key)
        if isinstance(value, str) and value.strip():
            return value
    return FALLBACK_REASON_CODE


def _safe_reason_code(reason_code: str) -> str:
    text = str(reason_code).strip().lower()
    if not _REASON_CODE_RE.fullmatch(text):
        return FALLBACK_REASON_CODE
    if text in _UNSAFE_REASON_VALUES:
        return FALLBACK_REASON_CODE
    if "://" in text or "/" in text or "\\" in text or _IP_LITERAL_RE.search(text):
        return FALLBACK_REASON_CODE
    return text


def _safe_message(safe_message: str | None) -> str:
    if safe_message in _SAFE_MESSAGE_ALLOWLIST:
        return safe_message
    return SAFE_DISPATCHER_MESSAGE


def _assert_dispatcher_response_shape(response: Mapping[str, Any]) -> None:
    if tuple(response) != DISPATCHER_RESPONSE_ALLOWED_FIELDS:
        raise McpDispatcherError("dispatcher_response_field_drift")
    if response.get("status") != "blocked":
        raise McpDispatcherError("dispatcher_response_status_drift")
    if response.get("dispatcher_approved") is not False:
        raise McpDispatcherError("dispatcher_approval_drift")
    if response.get("dispatcher_invocation_allowed") is not False:
        raise McpDispatcherError("dispatcher_invocation_drift")
    if response.get("tool_execution_allowed") is not False:
        raise McpDispatcherError("tool_execution_drift")
    if response.get("raw_data_included") is not False:
        raise McpDispatcherError("raw_data_flag_drift")
    if response.get("manual_review_required") is not True:
        raise McpDispatcherError("manual_review_drift")
    if response.get("safe_message") not in _SAFE_MESSAGE_ALLOWLIST:
        raise McpDispatcherError("safe_message_drift")


def _assert_raw_free_text(text: str) -> None:
    lowered = text.lower()
    if any(marker in lowered for marker in _UNSAFE_TEXT_MARKERS):
        raise McpDispatcherError("unsafe_dispatcher_response_marker")
    if "://" in lowered or _IP_LITERAL_RE.search(text):
        raise McpDispatcherError("unsafe_dispatcher_response_locator")
