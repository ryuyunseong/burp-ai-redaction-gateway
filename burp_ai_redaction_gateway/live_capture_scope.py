from __future__ import annotations

import hashlib
import ipaddress
import re
from dataclasses import dataclass


LIVE_CAPTURE_SCOPE_MAX_LENGTH = 253
LIVE_CAPTURE_SCOPE_LABEL_MAX_LENGTH = 63
LIVE_CAPTURE_SCOPE_RE = re.compile(r"^[a-z0-9.-]+$")

SCOPE_REASON_EMPTY = "scope_empty"
SCOPE_REASON_TOO_LONG = "scope_too_long"
SCOPE_REASON_CONTROL_OR_SPACE = "scope_control_or_space"
SCOPE_REASON_WILDCARD = "scope_wildcard_not_allowed"
SCOPE_REASON_URL_OR_PATH = "scope_url_or_path_not_allowed"
SCOPE_REASON_IP_LITERAL = "scope_ip_literal_not_allowed"
SCOPE_REASON_LOOPBACK_NAME = "scope_loopback_name_not_allowed"
SCOPE_REASON_MALFORMED = "scope_malformed_domain"
SCOPE_REASON_MALFORMED_LABEL = "scope_malformed_label"
SCOPE_REASON_SUFFIX_MISMATCH = "scope_suffix_mismatch"
SCOPE_REASON_MATCHED = "scope_matched"


class LiveCaptureScopeError(ValueError):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class LiveCaptureScope:
    normalized: str
    alias: str
    raw_data_included: bool = False


@dataclass(frozen=True)
class LiveCaptureScopeMatch:
    host_alias: str
    scope_alias: str
    matched: bool
    reason: str
    raw_data_included: bool = False


def normalize_live_capture_scope(value: str) -> str:
    target = str(value or "")
    if target != target.strip():
        raise LiveCaptureScopeError(SCOPE_REASON_CONTROL_OR_SPACE)
    target = target.lower()
    if not target:
        raise LiveCaptureScopeError(SCOPE_REASON_EMPTY)
    if len(target) > LIVE_CAPTURE_SCOPE_MAX_LENGTH:
        raise LiveCaptureScopeError(SCOPE_REASON_TOO_LONG)
    if any(char.isspace() or ord(char) < 32 for char in target):
        raise LiveCaptureScopeError(SCOPE_REASON_CONTROL_OR_SPACE)
    if "*" in target:
        raise LiveCaptureScopeError(SCOPE_REASON_WILDCARD)

    target = target.rstrip(".")
    if not target:
        raise LiveCaptureScopeError(SCOPE_REASON_EMPTY)
    try:
        ipaddress.ip_address(target)
    except ValueError:
        pass
    else:
        raise LiveCaptureScopeError(SCOPE_REASON_IP_LITERAL)

    if "://" in target or any(marker in target for marker in ("/", "\\", "?", "#", "@", ":")):
        raise LiveCaptureScopeError(SCOPE_REASON_URL_OR_PATH)

    if target in {"localhost", "local"} or target.endswith(".localhost") or target.endswith(".local"):
        raise LiveCaptureScopeError(SCOPE_REASON_LOOPBACK_NAME)
    if not LIVE_CAPTURE_SCOPE_RE.fullmatch(target):
        raise LiveCaptureScopeError(SCOPE_REASON_MALFORMED)

    labels = target.split(".")
    if len(labels) < 2:
        raise LiveCaptureScopeError(SCOPE_REASON_MALFORMED)
    for label in labels:
        if (
            not label
            or len(label) > LIVE_CAPTURE_SCOPE_LABEL_MAX_LENGTH
            or label.startswith("-")
            or label.endswith("-")
        ):
            raise LiveCaptureScopeError(SCOPE_REASON_MALFORMED_LABEL)
    return target


def live_capture_scope_alias(value: str) -> str:
    normalized = normalize_live_capture_scope(value)
    digest = hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:12]
    return f"target_alias_{digest}"


def validate_live_capture_scope(value: str) -> LiveCaptureScope:
    normalized = normalize_live_capture_scope(value)
    return LiveCaptureScope(normalized=normalized, alias=live_capture_scope_alias(normalized))


def host_matches_live_capture_scope(host: str, scope: str) -> bool:
    return evaluate_live_capture_scope_match(host, scope).matched


def evaluate_live_capture_scope_match(host: str, scope: str) -> LiveCaptureScopeMatch:
    try:
        host_scope = validate_live_capture_scope(host)
        target_scope = validate_live_capture_scope(scope)
    except LiveCaptureScopeError as error:
        return LiveCaptureScopeMatch(
            host_alias="",
            scope_alias="",
            matched=False,
            reason=error.reason,
        )

    matched = host_scope.normalized == target_scope.normalized or host_scope.normalized.endswith(
        f".{target_scope.normalized}"
    )
    return LiveCaptureScopeMatch(
        host_alias=host_scope.alias,
        scope_alias=target_scope.alias,
        matched=matched,
        reason=SCOPE_REASON_MATCHED if matched else SCOPE_REASON_SUFFIX_MISMATCH,
    )
