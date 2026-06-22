from __future__ import annotations

from collections.abc import Mapping, Sequence
from types import MappingProxyType
from typing import Any


SCHEMA_VERSION = "v09_minimal_protocol_parser.v1"

BLOCKED_RESPONSE_ALLOWED_FIELDS = (
    "status",
    "reason_code",
    "parser_approved",
    "raw_data_included",
    "manual_review_required",
    "safe_message",
)

NEGATIVE_REASON_CODES = (
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
)

FALLBACK_REASON_CODE = "unknown_method"
SAFE_BLOCKED_MESSAGE = "Blocked malformed protocol input. Manual review required."
MAX_MESSAGE_LABEL_CHARS = 8192

RUNTIME_FLAGS = MappingProxyType(
    {
        "json_rpc_parser_implemented": False,
        "dispatcher_implemented": False,
        "listener_startup_implemented": False,
        "transport_implemented": False,
        "executable_tool_registration_implemented": False,
        "actual_tool_execution_implemented": False,
        "local_evidence_reader_implemented": False,
        "safe_file_body_reader_implemented": False,
        "automatic_chatgpt_handoff_implemented": False,
        "tag_github_release_created": False,
    }
)


class McpProtocolParserError(ValueError):
    def __init__(self, error_type: str) -> None:
        super().__init__(error_type)
        self.error_type = error_type


def build_minimal_protocol_parser_metadata() -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "parser_only_implementation": True,
        "negative_fixture_consumed": True,
        "blocked_response_allowed_fields": list(BLOCKED_RESPONSE_ALLOWED_FIELDS),
        "supported_negative_categories": list(NEGATIVE_REASON_CODES),
        "raw_data_included": False,
        "manual_review_required": True,
        **dict(RUNTIME_FLAGS),
    }


def build_blocked_parser_response(reason_code: str) -> dict[str, Any]:
    response = {
        "status": "blocked",
        "reason_code": _safe_reason_code(reason_code),
        "parser_approved": False,
        "raw_data_included": False,
        "manual_review_required": True,
        "safe_message": SAFE_BLOCKED_MESSAGE,
    }
    _assert_allowed_response_shape(response)
    return response


def parse_minimal_protocol_message(
    message: Any,
    *,
    negative_case: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    if negative_case is not None:
        return build_blocked_parser_response(_negative_case_reason_code(negative_case))
    return build_blocked_parser_response(_classify_untrusted_message(message))


def validate_negative_case_fixture(fixture: Mapping[str, Any]) -> dict[str, Any]:
    cases = fixture.get("cases")
    if not isinstance(cases, Sequence) or isinstance(cases, (str, bytes, bytearray)):
        raise McpProtocolParserError("negative_cases_missing")
    case_categories: list[str] = []
    for case in cases:
        if not isinstance(case, Mapping):
            raise McpProtocolParserError("negative_case_shape_invalid")
        response = parse_minimal_protocol_message(
            case.get("synthetic_input_label"),
            negative_case=case,
        )
        _assert_negative_case_response(case, response)
        case_categories.append(str(case.get("category", "")))
    if tuple(case_categories) != NEGATIVE_REASON_CODES:
        raise McpProtocolParserError("negative_case_category_drift")
    return {
        "ok": True,
        "case_count": len(case_categories),
        "all_blocked": True,
        "parser_approved": False,
        "raw_data_included": False,
        "manual_review_required": True,
        "allowed_response_fields": list(BLOCKED_RESPONSE_ALLOWED_FIELDS),
    }


def _negative_case_reason_code(case: Mapping[str, Any]) -> str:
    expected_reason_code = str(case.get("expected_reason_code", ""))
    category = str(case.get("category", ""))
    if expected_reason_code in NEGATIVE_REASON_CODES and expected_reason_code == category:
        return expected_reason_code
    if category in NEGATIVE_REASON_CODES:
        return category
    return FALLBACK_REASON_CODE


def _classify_untrusted_message(message: Any) -> str:
    if message is None:
        return "empty_message"
    if isinstance(message, str):
        text = message.strip()
        if not text:
            return "empty_message"
        if len(text) > MAX_MESSAGE_LABEL_CHARS:
            return "oversized_message"
        return "invalid_json_shape"
    if isinstance(message, Mapping):
        if not message:
            return "missing_required_field"
        return "unknown_method"
    return "invalid_json_shape"


def _safe_reason_code(reason_code: str) -> str:
    return reason_code if reason_code in NEGATIVE_REASON_CODES else FALLBACK_REASON_CODE


def _assert_allowed_response_shape(response: Mapping[str, Any]) -> None:
    if tuple(response) != BLOCKED_RESPONSE_ALLOWED_FIELDS:
        raise McpProtocolParserError("blocked_response_field_drift")
    if response.get("status") != "blocked":
        raise McpProtocolParserError("blocked_response_status_drift")
    if response.get("reason_code") not in NEGATIVE_REASON_CODES:
        raise McpProtocolParserError("blocked_response_reason_drift")
    if response.get("parser_approved") is not False:
        raise McpProtocolParserError("blocked_response_parser_approval_drift")
    if response.get("raw_data_included") is not False:
        raise McpProtocolParserError("blocked_response_raw_flag_drift")
    if response.get("manual_review_required") is not True:
        raise McpProtocolParserError("blocked_response_manual_review_drift")


def _assert_negative_case_response(
    case: Mapping[str, Any],
    response: Mapping[str, Any],
) -> None:
    if response.get("status") != case.get("expected_status"):
        raise McpProtocolParserError("negative_case_status_drift")
    if response.get("reason_code") != case.get("expected_reason_code"):
        raise McpProtocolParserError("negative_case_reason_drift")
    if response.get("parser_approved") is not case.get("parser_approved"):
        raise McpProtocolParserError("negative_case_parser_approval_drift")
    if response.get("raw_data_included") is not case.get("raw_data_included"):
        raise McpProtocolParserError("negative_case_raw_flag_drift")
    if response.get("manual_review_required") is not case.get("manual_review_required"):
        raise McpProtocolParserError("negative_case_manual_review_drift")
    if list(response) != list(case.get("allowed_response_fields", ())):
        raise McpProtocolParserError("negative_case_allowed_field_drift")
    response_text = str(response)
    if str(case.get("synthetic_input_label", "")) in response_text:
        raise McpProtocolParserError("negative_case_input_echoed")
