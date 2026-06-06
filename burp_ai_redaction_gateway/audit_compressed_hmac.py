from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .audit_compression import AuditCompressionError, verify_compressed_audit_jsonl
from .audit_hmac import HMAC_ALGORITHM
from .scanner import assert_no_sensitive_text, scan_text


COMPRESSED_HMAC_MANIFEST_SCHEMA_VERSION = "1.0"


@dataclass(frozen=True)
class AuditCompressedHmacResult:
    input_file: str
    manifest_file: str
    compressed_size_bytes: int
    hmac_algorithm: str
    manifest_written: bool
    raw_data_included: bool = False

    def to_json(self) -> dict[str, object]:
        return {
            "status": "passed",
            "input_file": self.input_file,
            "manifest_file": self.manifest_file,
            "compressed_size_bytes": self.compressed_size_bytes,
            "hmac_algorithm": self.hmac_algorithm,
            "manifest_written": self.manifest_written,
            "raw_data_included": self.raw_data_included,
        }


@dataclass(frozen=True)
class AuditCompressedHmacVerifyResult:
    input_file: str
    manifest_file: str
    compressed_size_bytes: int
    hmac_algorithm: str
    raw_data_included: bool = False

    def to_json(self) -> dict[str, object]:
        return {
            "status": "passed",
            "input_file": self.input_file,
            "manifest_file": self.manifest_file,
            "compressed_size_bytes": self.compressed_size_bytes,
            "hmac_algorithm": self.hmac_algorithm,
            "raw_data_included": self.raw_data_included,
        }


class AuditCompressedHmacError(ValueError):
    def __init__(self, error_type: str) -> None:
        super().__init__(error_type)
        self.error_type = error_type


def create_compressed_audit_hmac_manifest(
    input_path: Path,
    manifest_path: Path,
    *,
    secret: bytes,
    now: datetime | None = None,
) -> AuditCompressedHmacResult:
    _require_secret(secret)
    review = _review_compressed_input(input_path)
    if _same_path(input_path, manifest_path):
        raise AuditCompressedHmacError("manifest_path_matches_input")

    archive_bytes = _read_archive_bytes(input_path)
    if len(archive_bytes) != review.compressed_size_bytes:
        raise AuditCompressedHmacError("compressed_size_mismatch")
    manifest = _build_manifest(input_path, archive_bytes, secret, now)
    _assert_manifest_is_safe(manifest)

    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=True, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    _assert_manifest_is_safe(_read_manifest(manifest_path))

    result = AuditCompressedHmacResult(
        input_file=_safe_archive_file_label(input_path),
        manifest_file=_safe_manifest_file_label(manifest_path),
        compressed_size_bytes=len(archive_bytes),
        hmac_algorithm=HMAC_ALGORITHM,
        manifest_written=True,
    )
    _assert_summary_is_safe(result.to_json())
    return result


def verify_compressed_audit_hmac_manifest(
    input_path: Path,
    manifest_path: Path,
    *,
    secret: bytes,
) -> AuditCompressedHmacVerifyResult:
    _require_secret(secret)
    review = _review_compressed_input(input_path)
    manifest = _read_manifest(manifest_path)
    _review_manifest_metadata(input_path, manifest_path, manifest, review.compressed_size_bytes)

    archive_bytes = _read_archive_bytes(input_path)
    expected_sha256 = _sha256_hex(archive_bytes)
    if not hmac.compare_digest(str(manifest.get("sha256")), expected_sha256):
        raise AuditCompressedHmacError("sha256_mismatch")
    expected_hmac = _hmac_hex(secret, archive_bytes)
    if not hmac.compare_digest(str(manifest.get("hmac")), expected_hmac):
        raise AuditCompressedHmacError("hmac_mismatch")

    result = AuditCompressedHmacVerifyResult(
        input_file=_safe_archive_file_label(input_path),
        manifest_file=_safe_manifest_file_label(manifest_path),
        compressed_size_bytes=review.compressed_size_bytes,
        hmac_algorithm=HMAC_ALGORITHM,
    )
    _assert_summary_is_safe(result.to_json())
    return result


def render_compressed_audit_hmac_summary(result: AuditCompressedHmacResult) -> str:
    lines = [
        "Compressed audit HMAC manifest written.",
        "",
        f"Input file: {result.input_file}",
        f"Manifest file: {result.manifest_file}",
        f"Compressed size bytes: {result.compressed_size_bytes}",
        f"HMAC algorithm: {result.hmac_algorithm}",
        f"Manifest written: {str(result.manifest_written).lower()}",
        "Raw data included: false",
    ]
    text = "\n".join(lines) + "\n"
    assert_no_sensitive_text(text)
    return text


def render_compressed_audit_hmac_verify_summary(result: AuditCompressedHmacVerifyResult) -> str:
    lines = [
        "Compressed audit HMAC verification passed.",
        "",
        f"Input file: {result.input_file}",
        f"Manifest file: {result.manifest_file}",
        f"Compressed size bytes: {result.compressed_size_bytes}",
        f"HMAC algorithm: {result.hmac_algorithm}",
        "Raw data included: false",
    ]
    text = "\n".join(lines) + "\n"
    assert_no_sensitive_text(text)
    return text


def _review_compressed_input(input_path: Path) -> Any:
    try:
        return verify_compressed_audit_jsonl(input_path)
    except AuditCompressionError as error:
        raise AuditCompressedHmacError(f"compressed_{error.error_type}") from error


def _build_manifest(
    input_path: Path,
    archive_bytes: bytes,
    secret: bytes,
    now: datetime | None,
) -> dict[str, object]:
    return {
        "manifest_schema_version": COMPRESSED_HMAC_MANIFEST_SCHEMA_VERSION,
        "archive_alias": _safe_archive_file_label(input_path),
        "compressed_size_bytes": len(archive_bytes),
        "sha256": _sha256_hex(archive_bytes),
        "hmac_algorithm": HMAC_ALGORITHM,
        "hmac": _hmac_hex(secret, archive_bytes),
        "created_at_utc": _utc_timestamp(now),
        "raw_data_included": False,
    }


def _review_manifest_metadata(
    input_path: Path,
    manifest_path: Path,
    manifest: dict[str, Any],
    compressed_size_bytes: int,
) -> None:
    _assert_manifest_is_safe(manifest)
    if manifest.get("manifest_schema_version") != COMPRESSED_HMAC_MANIFEST_SCHEMA_VERSION:
        raise AuditCompressedHmacError("invalid_manifest_schema_version")
    if manifest.get("archive_alias") != _safe_archive_file_label(input_path):
        raise AuditCompressedHmacError("manifest_archive_alias_mismatch")
    if manifest.get("compressed_size_bytes") != compressed_size_bytes:
        raise AuditCompressedHmacError("manifest_compressed_size_mismatch")
    if not _is_hex_digest(manifest.get("sha256")):
        raise AuditCompressedHmacError("invalid_manifest_sha256")
    if manifest.get("hmac_algorithm") != HMAC_ALGORITHM:
        raise AuditCompressedHmacError("manifest_hmac_algorithm_mismatch")
    if not _is_hex_digest(manifest.get("hmac")):
        raise AuditCompressedHmacError("invalid_manifest_hmac")
    if not isinstance(manifest.get("created_at_utc"), str):
        raise AuditCompressedHmacError("invalid_manifest_created_at")
    if manifest.get("raw_data_included") is not False:
        raise AuditCompressedHmacError("manifest_raw_marker_not_false")
    if not manifest_path.is_file():
        raise AuditCompressedHmacError("manifest_input_not_found")


def _read_archive_bytes(input_path: Path) -> bytes:
    try:
        return input_path.read_bytes()
    except OSError as error:
        raise AuditCompressedHmacError("archive_input_read_failed") from error


def _read_manifest(manifest_path: Path) -> dict[str, Any]:
    if not manifest_path.is_file():
        raise AuditCompressedHmacError("manifest_input_not_found")
    try:
        text = manifest_path.read_text(encoding="utf-8")
    except OSError as error:
        raise AuditCompressedHmacError("manifest_read_failed") from error
    if scan_text(text):
        raise AuditCompressedHmacError("manifest_sensitive_data")
    try:
        manifest = json.loads(text)
    except json.JSONDecodeError as error:
        raise AuditCompressedHmacError("manifest_parse_failed") from error
    if not isinstance(manifest, dict):
        raise AuditCompressedHmacError("manifest_not_object")
    return manifest


def _require_secret(secret: bytes) -> None:
    if not secret:
        raise AuditCompressedHmacError("hmac_secret_missing")


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


def _safe_archive_file_label(path: Path) -> str:
    if path.name.startswith("mcp_audit") and path.name.endswith(".jsonl.gz"):
        return "<compressed_audit_file>"
    return "<compressed_audit_file>"


def _safe_manifest_file_label(path: Path) -> str:
    if path.name.startswith("mcp_audit") and path.name.endswith(".manifest.json"):
        return "<compressed_manifest_file>"
    return "<compressed_manifest_file>"


def _is_hex_digest(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(char in "0123456789abcdef" for char in value)


def _assert_manifest_is_safe(manifest: dict[str, object]) -> None:
    assert_no_sensitive_text(json.dumps(manifest, ensure_ascii=True, sort_keys=True))


def _assert_summary_is_safe(summary: dict[str, object]) -> None:
    assert_no_sensitive_text(json.dumps(summary, ensure_ascii=True, sort_keys=True))
