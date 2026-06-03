from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


DEFAULT_POLICY_PATH = Path("policy.json")


@dataclass(frozen=True)
class RedactionPolicy:
    raw_output_allowed: bool
    fail_closed: bool
    preserve_header_names: bool
    preserve_cookie_names: bool
    preserve_json_keys: bool
    preserve_value_type: bool
    response_snippet_allowed: bool
    allow_error_snippet_after_scan: bool
    max_snippet_chars: int
    blocked_fields: tuple[str, ...]
    verify_extensions: tuple[str, ...]
    allowlisted_literals: tuple[str, ...]
    allowlist_notes: dict[str, str]
    source_path: str

    @property
    def policy_hash(self) -> str:
        payload = json.dumps(self.to_public_dict(include_source=False), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def to_public_dict(self, include_source: bool = True) -> dict[str, Any]:
        data = {
            "raw_output_allowed": self.raw_output_allowed,
            "fail_closed": self.fail_closed,
            "preserve_header_names": self.preserve_header_names,
            "preserve_cookie_names": self.preserve_cookie_names,
            "preserve_json_keys": self.preserve_json_keys,
            "preserve_value_type": self.preserve_value_type,
            "response_snippet_allowed": self.response_snippet_allowed,
            "allow_error_snippet_after_scan": self.allow_error_snippet_after_scan,
            "max_snippet_chars": self.max_snippet_chars,
            "blocked_fields": list(self.blocked_fields),
            "verify_extensions": list(self.verify_extensions),
            "allowlisted_literals": list(self.allowlisted_literals),
            "allowlist_notes": self.allowlist_notes,
        }
        if include_source:
            data["source_path"] = self.source_path
        return data


def load_policy(path: Path | None = None) -> RedactionPolicy:
    policy_path = path
    if policy_path is None and DEFAULT_POLICY_PATH.exists():
        policy_path = DEFAULT_POLICY_PATH

    data = _default_policy_data()
    source_path = "builtin-default"
    if policy_path is not None:
        loaded = json.loads(policy_path.read_text(encoding="utf-8"))
        data = _deep_merge(data, loaded)
        source_path = str(policy_path)

    redaction = data.get("redaction", {})
    output = data.get("output", {})
    verification = data.get("verification", {})
    return RedactionPolicy(
        raw_output_allowed=bool(data.get("project", {}).get("raw_output_allowed", False)),
        fail_closed=str(redaction.get("mode", "fail_closed")).lower() == "fail_closed",
        preserve_header_names=bool(redaction.get("preserve_header_names", True)),
        preserve_cookie_names=bool(redaction.get("preserve_cookie_names", True)),
        preserve_json_keys=bool(redaction.get("preserve_json_keys", True)),
        preserve_value_type=bool(redaction.get("preserve_value_type", True)),
        response_snippet_allowed=bool(output.get("allow_response_snippet", False)),
        allow_error_snippet_after_scan=bool(output.get("allow_error_snippet_after_scan", False)),
        max_snippet_chars=int(output.get("max_snippet_chars", 300)),
        blocked_fields=tuple(str(item).lower() for item in data.get("blocked_fields", [])),
        verify_extensions=tuple(str(item).lower() for item in verification.get("file_extensions", [])),
        allowlisted_literals=tuple(str(item) for item in verification.get("allowlisted_literals", [])),
        allowlist_notes={str(key): str(value) for key, value in verification.get("allowlist_notes", {}).items()},
        source_path=source_path,
    )


def _default_policy_data() -> dict[str, Any]:
    return {
        "project": {
            "alias": "client_alias_demo",
            "raw_output_allowed": False,
        },
        "redaction": {
            "mode": "fail_closed",
            "preserve_header_names": True,
            "preserve_cookie_names": True,
            "preserve_json_keys": True,
            "preserve_value_type": True,
            "preserve_value_length_bucket": True,
            "hmac_pseudonymization": False,
        },
        "blocked_fields": [
            "authorization",
            "cookie",
            "set-cookie",
            "x-api-key",
            "x-csrf-token",
            "password",
            "passwd",
            "pwd",
            "token",
            "secret",
            "session",
            "access_token",
            "refresh_token",
            "email",
            "phone",
            "rrn",
            "account",
            "card",
        ],
        "pii": {
            "detect_email": True,
            "detect_phone_kr": True,
            "detect_rrn_kr": True,
            "detect_account_number": True,
            "detect_card_number": True,
        },
        "output": {
            "allow_response_snippet": False,
            "allow_error_snippet_after_scan": False,
            "max_snippet_chars": 300,
            "include_raw_reference_id": True,
            "include_raw_value": False,
        },
        "verification": {
            "file_extensions": [".json", ".jsonl", ".md", ".txt"],
            "allowlisted_literals": [
                "10.0.0.0/8",
                "127.0.0.0/8",
                "172.16.0.0/12",
                "192.168.0.0/16",
            ],
            "allowlist_notes": {
                "10.0.0.0/8": "Network bucket only, not a raw internal host IP.",
                "127.0.0.0/8": "Loopback bucket only, not a raw host IP.",
                "172.16.0.0/12": "Network bucket only, not a raw internal host IP.",
                "192.168.0.0/16": "Network bucket only, not a raw internal host IP.",
            },
        },
    }


def _deep_merge(base: dict[str, Any], overlay: dict[str, Any]) -> dict[str, Any]:
    merged = dict(base)
    for key, value in overlay.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged

