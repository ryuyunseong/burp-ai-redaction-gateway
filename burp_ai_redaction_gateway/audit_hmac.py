from __future__ import annotations

import hashlib
import hmac
import json
import os
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .audit_review import review_audit_path
from .mcp_server import AUDIT_SCHEMA_VERSION
from .scanner import assert_no_sensitive_text, scan_text


DEFAULT_HMAC_ENV_VAR = "BURP_AI_AUDIT_HMAC_KEY"
HMAC_ALGORITHM = "HMAC-SHA256"
MANIFEST_SCHEMA_VERSION = "1.0"


@dataclass(frozen=True)
class AuditHmacResult:
    input_file: str
    manifest_file: str
    row_count: int
    audit_schema_version: str
    hmac_algorithm: str
    manifest_written: bool
    raw_data_included: bool = False

    def to_json(self) -> dict[str, object]:
        return {
            "status": "passed",
            "input_file": self.input_file,
            "manifest_file": self.manifest_file,
            "row_count": self.row_count,
            "audit_schema_version": self.audit_schema_version,
            "hmac_algorithm": self.hmac_algorithm,
            "manifest_written": self.manifest_written,
            "raw_data_included": self.raw_data_included,
        }


@dataclass(frozen=True)
class AuditHmacVerifyResult:
    input_file: str
    manifest_file: str
    row_count: int
    audit_schema_version: str
    hmac_algorithm: str
    raw_data_included: bool = False

    def to_json(self) -> dict[str, object]:
        return {
            "status": "passed",
            "input_file": self.input_file,
            "manifest_file": self.manifest_file,
            "row_count": self.row_count,
            "audit_schema_version": self.audit_schema_version,
            "hmac_algorithm": self.hmac_algorithm,
            "raw_data_included": self.raw_data_included,
        }


class AuditHmacError(ValueError):
    def __init__(self, error_type: str) -> None:
        super().__init__(error_type)
        self.error_type = error_type


def create_audit_hmac_manifest(
    input_path: Path,
    manifest_path: Path,
    *,
    secret: bytes,
    now: datetime | None = None,
) -> AuditHmacResult:
    _require_secret(secret)
    review = _review_input_file(input_path)
    if _same_path(input_path, manifest_path):
        raise AuditHmacError("manifest_path_matches_input")

    audit_bytes = _read_file_bytes(input_path)
    manifest = _build_manifest(input_path, review.events_checked, audit_bytes, secret, now)
    _assert_manifest_is_safe(manifest)

    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=True, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    _assert_manifest_is_safe(_read_manifest(manifest_path))

    result = AuditHmacResult(
        input_file=_safe_audit_file_label(input_path),
        manifest_file=_safe_manifest_file_label(manifest_path),
        row_count=review.events_checked,
        audit_schema_version=AUDIT_SCHEMA_VERSION,
        hmac_algorithm=HMAC_ALGORITHM,
        manifest_written=True,
    )
    _assert_summary_is_safe(result.to_json())
    return result


def verify_audit_hmac_manifest(
    input_path: Path,
    manifest_path: Path,
    *,
    secret: bytes,
) -> AuditHmacVerifyResult:
    _require_secret(secret)
    review = _review_input_file(input_path)
    manifest = _read_manifest(manifest_path)
    _review_manifest_metadata(input_path, manifest_path, manifest, review.events_checked)

    audit_bytes = _read_file_bytes(input_path)
    expected_sha256 = _sha256_hex(audit_bytes)
    if not hmac.compare_digest(str(manifest.get("sha256")), expected_sha256):
        raise AuditHmacError("sha256_mismatch")
    expected_hmac = _hmac_hex(secret, audit_bytes)
    if not hmac.compare_digest(str(manifest.get("hmac")), expected_hmac):
        raise AuditHmacError("hmac_mismatch")

    result = AuditHmacVerifyResult(
        input_file=_safe_audit_file_label(input_path),
        manifest_file=_safe_manifest_file_label(manifest_path),
        row_count=review.events_checked,
        audit_schema_version=AUDIT_SCHEMA_VERSION,
        hmac_algorithm=HMAC_ALGORITHM,
    )
    _assert_summary_is_safe(result.to_json())
    return result


def load_hmac_secret(*, env_var: str = DEFAULT_HMAC_ENV_VAR, key_file: Path | None = None) -> bytes:
    if key_file is not None:
        if not key_file.is_file():
            raise AuditHmacError("hmac_secret_file_not_found")
        value = key_file.read_text(encoding="utf-8").strip()
    else:
        value = os.environ.get(env_var, "").strip()
    if not value:
        raise AuditHmacError("hmac_secret_missing")
    return value.encode("utf-8")


def render_audit_hmac_summary(result: AuditHmacResult) -> str:
    lines = [
        "Audit HMAC manifest written.",
        "",
        f"Input file: {result.input_file}",
        f"Manifest file: {result.manifest_file}",
        f"Rows covered: {result.row_count}",
        f"Audit schema version: {result.audit_schema_version}",
        f"HMAC algorithm: {result.hmac_algorithm}",
        f"Manifest written: {str(result.manifest_written).lower()}",
        "Raw data included: false",
    ]
    text = "\n".join(lines) + "\n"
    assert_no_sensitive_text(text)
    return text


def render_audit_hmac_verify_summary(result: AuditHmacVerifyResult) -> str:
    lines = [
        "Audit HMAC verification passed.",
        "",
        f"Input file: {result.input_file}",
        f"Manifest file: {result.manifest_file}",
        f"Rows covered: {result.row_count}",
        f"Audit schema version: {result.audit_schema_version}",
        f"HMAC algorithm: {result.hmac_algorithm}",
        "Raw data included: false",
    ]
    text = "\n".join(lines) + "\n"
    assert_no_sensitive_text(text)
    return text


def _review_input_file(input_path: Path) -> Any:
    if not input_path.is_file():
        raise AuditHmacError("audit_input_not_found")
    review = review_audit_path(input_path)
    if not review.passed:
        raise AuditHmacError("audit_review_failed")
    if review.schema_version != AUDIT_SCHEMA_VERSION:
        raise AuditHmacError("invalid_audit_schema_version")
    return review


def _build_manifest(
    input_path: Path,
    row_count: int,
    audit_bytes: bytes,
    secret: bytes,
    now: datetime | None,
) -> dict[str, object]:
    return {
        "manifest_schema_version": MANIFEST_SCHEMA_VERSION,
        "audit_schema_version": AUDIT_SCHEMA_VERSION,
        "file_alias": _safe_audit_file_label(input_path),
        "row_count": row_count,
        "sha256": _sha256_hex(audit_bytes),
        "hmac_algorithm": HMAC_ALGORITHM,
        "hmac": _hmac_hex(secret, audit_bytes),
        "created_at_utc": _utc_timestamp(now),
        "raw_data_included": False,
    }


def _review_manifest_metadata(input_path: Path, manifest_path: Path, manifest: dict[str, Any], row_count: int) -> None:
    _assert_manifest_is_safe(manifest)
    if manifest.get("manifest_schema_version") != MANIFEST_SCHEMA_VERSION:
        raise AuditHmacError("invalid_manifest_schema_version")
    if manifest.get("audit_schema_version") != AUDIT_SCHEMA_VERSION:
        raise AuditHmacError("manifest_audit_schema_mismatch")
    if manifest.get("file_alias") != _safe_audit_file_label(input_path):
        raise AuditHmacError("manifest_file_alias_mismatch")
    if manifest.get("row_count") != row_count:
        raise AuditHmacError("manifest_row_count_mismatch")
    if not _is_hex_digest(manifest.get("sha256")):
        raise AuditHmacError("invalid_manifest_sha256")
    if manifest.get("hmac_algorithm") != HMAC_ALGORITHM:
        raise AuditHmacError("manifest_hmac_algorithm_mismatch")
    if not _is_hex_digest(manifest.get("hmac")):
        raise AuditHmacError("invalid_manifest_hmac")
    if not isinstance(manifest.get("created_at_utc"), str):
        raise AuditHmacError("invalid_manifest_created_at")
    if manifest.get("raw_data_included") is not False:
        raise AuditHmacError("manifest_raw_marker_not_false")
    if not manifest_path.is_file():
        raise AuditHmacError("manifest_input_not_found")


def _read_file_bytes(input_path: Path) -> bytes:
    try:
        return input_path.read_bytes()
    except OSError as error:
        raise AuditHmacError("audit_input_read_failed") from error


def _read_manifest(manifest_path: Path) -> dict[str, Any]:
    if not manifest_path.is_file():
        raise AuditHmacError("manifest_input_not_found")
    try:
        text = manifest_path.read_text(encoding="utf-8")
    except OSError as error:
        raise AuditHmacError("manifest_read_failed") from error
    if scan_text(text):
        raise AuditHmacError("manifest_sensitive_data")
    try:
        manifest = json.loads(text)
    except json.JSONDecodeError as error:
        raise AuditHmacError("manifest_parse_failed") from error
    if not isinstance(manifest, dict):
        raise AuditHmacError("manifest_not_object")
    return manifest


def _require_secret(secret: bytes) -> None:
    if not secret:
        raise AuditHmacError("hmac_secret_missing")


def _sha256_hex(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _hmac_hex(secret: bytes, value: bytes) -> str:
    return hmac.new(secret, value, hashlib.sha256).hexdigest()


def _utc_timestamp(value: datetime | None) -> str:
    current = datetime.now(UTC) if value is None else value
    if current.tzinfo is None:
        current = current.replace(tzinfo=UTC)
    return current.astimezone(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _same_path(left: Path, right: Path) -> bool:
    try:
        return left.resolve() == right.resolve()
    except OSError:
        return left.absolute() == right.absolute()


def _safe_audit_file_label(path: Path) -> str:
    name = path.name
    if name.startswith("mcp_audit") and name.endswith(".jsonl"):
        return name
    return "<audit_file>"


def _safe_manifest_file_label(path: Path) -> str:
    name = path.name
    if name.startswith("mcp_audit") and name.endswith(".manifest.json"):
        return name
    return "<manifest_file>"


def _is_hex_digest(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(char in "0123456789abcdef" for char in value)


def _assert_manifest_is_safe(manifest: dict[str, object]) -> None:
    assert_no_sensitive_text(json.dumps(manifest, ensure_ascii=True, sort_keys=True))


def _assert_summary_is_safe(summary: dict[str, object]) -> None:
    assert_no_sensitive_text(json.dumps(summary, ensure_ascii=True, sort_keys=True))
