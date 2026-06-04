from __future__ import annotations

import math
import re
from dataclasses import dataclass


@dataclass(frozen=True)
class SensitiveMatch:
    kind: str
    excerpt: str


JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")
BEARER_RE = re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{10,}")
BASIC_RE = re.compile(r"(?i)\bbasic\s+[A-Za-z0-9+/=]{8,}")
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
PHONE_RE = re.compile(r"\b(?:01[016789]-?\d{3,4}-?\d{4}|\+?\d{1,3}[-.\s]?\d{3}[-.\s]?\d{3,4}[-.\s]?\d{4})\b")
KOR_RRN_RE = re.compile(r"\b\d{6}-[1-4]\d{6}\b")
FINANCIAL_RE = re.compile(r"\b(?:\d[ -]?){13,19}\b")
SECRET_ASSIGNMENT_RE = re.compile(
    r"(?i)\b(?:api[_-]?key|secret|token|password|passwd|pwd|csrf|session)\b"
    r"\s*[=:]\s*['\"]?[A-Za-z0-9._~+/=-]{8,}"
)
HIGH_ENTROPY_RE = re.compile(r"\b[A-Za-z0-9._~+/=-]{32,}\b")
PLACEHOLDER_RE = re.compile(r"<[A-Z0-9_:. -]+>")
DOMAIN_RE = re.compile(r"\b(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}\b")
SAFE_FIELD_PATH_RE = re.compile(
    r"^(?:request|response|xml|headers|body_schema|query|html)(?:\.[A-Za-z_][A-Za-z0-9_-]*)+$"
)
PRIVATE_IP_RE = re.compile(
    r"\b(?:10\.(?:\d{1,3}\.){2}\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|127\.\d{1,3}\.\d{1,3}\.\d{1,3})\b"
)
RAW_MARKER_RE = re.compile(r"(?i)\b(?:raw_request|raw_response|request_raw|response_raw)\b")
COOKIE_PAIR_RE = re.compile(r"\b([A-Za-z][A-Za-z0-9_.-]{1,63})=([^;,\s\"']+)")
SAFE_COOKIE_ATTRS = {"secure", "httponly", "samesite", "path", "domain", "max-age", "expires", "charset"}
SAFE_COOKIE_VALUES = {"true", "false", "lax", "strict", "none", "present", "<placeholder>", "{value}"}
ALLOWED_IP_BUCKETS = {"10.0.0.0", "127.0.0.0", "172.16.0.0", "192.168.0.0"}


def scan_text(text: str) -> list[SensitiveMatch]:
    safe_text = PLACEHOLDER_RE.sub("<PLACEHOLDER>", text)
    matches: list[SensitiveMatch] = []
    checks = [
        ("jwt", JWT_RE),
        ("bearer_token", BEARER_RE),
        ("basic_auth", BASIC_RE),
        ("email", EMAIL_RE),
        ("phone", PHONE_RE),
        ("kor_rrn", KOR_RRN_RE),
        ("financial_id", FINANCIAL_RE),
        ("secret_assignment", SECRET_ASSIGNMENT_RE),
        ("raw_marker", RAW_MARKER_RE),
    ]

    for kind, pattern in checks:
        for match in pattern.finditer(safe_text):
            matches.append(SensitiveMatch(kind, _excerpt(match.group(0))))

    for token in HIGH_ENTROPY_RE.findall(safe_text):
        if _looks_like_secret(token):
            matches.append(SensitiveMatch("high_entropy", _excerpt(token)))

    matches.extend(_scan_cookie_values(safe_text))
    matches.extend(_scan_private_ips(safe_text))
    matches.extend(_scan_domains(safe_text))
    return matches


def assert_no_sensitive_text(text: str) -> None:
    matches = scan_text(text)
    if matches:
        summary = ", ".join(f"{kind}:<REDACTED>" for kind in _unique_match_kinds(matches)[:5])
        raise ValueError(f"Output blocked by fail-closed scan: {summary}")


def has_high_entropy_secret(value: str) -> bool:
    return any(_looks_like_secret(token) for token in HIGH_ENTROPY_RE.findall(value))


def redacted_match_diagnostics(
    text: str,
    *,
    source_kind: str = "generated_output",
    field_path: str = "output",
    event_id: str | None = None,
) -> list[dict[str, str]]:
    diagnostics: list[dict[str, str]] = []
    for kind in _unique_match_kinds(scan_text(text)):
        item = {
            "failure_type": kind,
            "field_path": field_path,
            "source_kind": source_kind,
            "value_preview": "<REDACTED>",
        }
        if event_id:
            item["event_id"] = event_id
        diagnostics.append(item)
    return diagnostics


def _unique_match_kinds(matches: list[SensitiveMatch]) -> list[str]:
    kinds: list[str] = []
    for match in matches:
        if match.kind not in kinds:
            kinds.append(match.kind)
    return kinds


def _looks_like_secret(token: str) -> bool:
    if "REDACTED" in token or "PLACEHOLDER" in token:
        return False
    if token.startswith("LOCAL_ONLY"):
        return False
    if not any(c.isdigit() for c in token):
        return False
    if not any(c.isalpha() for c in token):
        return False
    if len(set(token)) < 12:
        return False
    return _shannon_entropy(token) >= 4.2


def _scan_cookie_values(text: str) -> list[SensitiveMatch]:
    matches: list[SensitiveMatch] = []
    for line in text.splitlines():
        if not re.search(r"(?i)\b(?:cookie|set-cookie)\b", line):
            continue
        for name, value in COOKIE_PAIR_RE.findall(line):
            if name.lower() in SAFE_COOKIE_ATTRS:
                continue
            if _is_safe_placeholder_value(value):
                continue
            matches.append(SensitiveMatch("cookie_value", _excerpt(f"{name}={value}")))
    return matches


def _scan_private_ips(text: str) -> list[SensitiveMatch]:
    matches: list[SensitiveMatch] = []
    for value in PRIVATE_IP_RE.findall(text):
        if value in ALLOWED_IP_BUCKETS:
            continue
        matches.append(SensitiveMatch("internal_ip", _excerpt(value)))
    return matches


def _scan_domains(text: str) -> list[SensitiveMatch]:
    matches: list[SensitiveMatch] = []
    for match in DOMAIN_RE.finditer(text):
        value = match.group(0)
        if match.start() >= 2 and text[match.start() - 2 : match.start()] == "$.":
            continue
        if value.lower().endswith((".md", ".json", ".jsonl", ".txt")):
            continue
        if SAFE_FIELD_PATH_RE.match(value):
            continue
        if value.lower() in {"example.com", "example.test"}:
            continue
        labels = value.lower().split(".")
        if labels[-1] in {"email", "phone", "accountnumber", "userid", "id", "token"}:
            continue
        matches.append(SensitiveMatch("domain", _excerpt(value)))
    return matches


def _is_safe_placeholder_value(value: str) -> bool:
    normalized = value.strip().strip("'\"").lower()
    if normalized in SAFE_COOKIE_VALUES:
        return True
    if normalized.startswith("<placeholder"):
        return True
    if "redacted" in normalized or "omitted" in normalized:
        return True
    return False


def _shannon_entropy(value: str) -> float:
    counts = {char: value.count(char) for char in set(value)}
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def _excerpt(value: str) -> str:
    if len(value) <= 18:
        return value
    return f"{value[:8]}...{value[-6:]}"
