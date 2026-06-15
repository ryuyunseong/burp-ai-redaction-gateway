from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Mapping

from .live_capture_scope import (
    SCOPE_REASON_MATCHED,
    SCOPE_REASON_SUFFIX_MISMATCH,
    LiveCaptureScopeError,
    validate_live_capture_scope,
)


RECEIVER_SCOPE_REASON_IN_SCOPE = "receiver_scope_in_scope"
RECEIVER_SCOPE_REASON_OUT_OF_SCOPE = "receiver_scope_out_of_scope"
RECEIVER_SCOPE_REASON_MISSING_HOST = "receiver_scope_missing_host"
RECEIVER_SCOPE_REASON_INVALID_HOST = "receiver_scope_invalid_host"
RECEIVER_SCOPE_REASON_INVALID_SCOPE = "receiver_scope_invalid_scope"

RECEIVER_SCOPE_DECISION_ACCEPT = "would_accept"
RECEIVER_SCOPE_DECISION_DROP = "would_drop"

SAFE_HOST_METADATA_KEYS = ("request_host", "target_host", "host")
SAFE_HOST_METADATA_CONTAINERS = ("request_metadata", "metadata", "scope_metadata")


@dataclass(frozen=True)
class ReceiverScopeDryRunResult:
    decision: str
    reason: str
    match_reason: str
    host_alias: str
    scope_alias: str
    raw_data_included: bool = False
    ingest_performed: bool = False

    def to_summary(self) -> dict[str, Any]:
        return asdict(self)


def evaluate_receiver_scope_dry_run(payload: Mapping[str, Any], scope: str) -> ReceiverScopeDryRunResult:
    try:
        target_scope = validate_live_capture_scope(scope)
    except LiveCaptureScopeError as error:
        return _drop_result(RECEIVER_SCOPE_REASON_INVALID_SCOPE, error.reason)

    host = _safe_host_metadata(payload)
    if not host:
        return _drop_result(RECEIVER_SCOPE_REASON_MISSING_HOST, RECEIVER_SCOPE_REASON_MISSING_HOST, target_scope.alias)

    try:
        host_scope = validate_live_capture_scope(host)
    except LiveCaptureScopeError as error:
        return _drop_result(RECEIVER_SCOPE_REASON_INVALID_HOST, error.reason, target_scope.alias)

    matched = host_scope.normalized == target_scope.normalized or host_scope.normalized.endswith(
        f".{target_scope.normalized}"
    )
    if matched:
        return ReceiverScopeDryRunResult(
            decision=RECEIVER_SCOPE_DECISION_ACCEPT,
            reason=RECEIVER_SCOPE_REASON_IN_SCOPE,
            match_reason=SCOPE_REASON_MATCHED,
            host_alias=host_scope.alias,
            scope_alias=target_scope.alias,
        )
    return ReceiverScopeDryRunResult(
        decision=RECEIVER_SCOPE_DECISION_DROP,
        reason=RECEIVER_SCOPE_REASON_OUT_OF_SCOPE,
        match_reason=SCOPE_REASON_SUFFIX_MISMATCH,
        host_alias=host_scope.alias,
        scope_alias=target_scope.alias,
    )


def _safe_host_metadata(payload: Mapping[str, Any]) -> str:
    for key in SAFE_HOST_METADATA_KEYS:
        value = payload.get(key)
        if isinstance(value, str) and value:
            return value
    for container_key in SAFE_HOST_METADATA_CONTAINERS:
        container = payload.get(container_key)
        if not isinstance(container, Mapping):
            continue
        for key in SAFE_HOST_METADATA_KEYS:
            value = container.get(key)
            if isinstance(value, str) and value:
                return value
    return ""


def _drop_result(reason: str, match_reason: str, scope_alias: str = "") -> ReceiverScopeDryRunResult:
    return ReceiverScopeDryRunResult(
        decision=RECEIVER_SCOPE_DECISION_DROP,
        reason=reason,
        match_reason=match_reason,
        host_alias="",
        scope_alias=scope_alias,
    )
