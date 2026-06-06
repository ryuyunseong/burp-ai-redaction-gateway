from __future__ import annotations

import gzip
import json
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .audit_review import review_audit_path
from .mcp_server import AUDIT_SCHEMA_VERSION
from .scanner import assert_no_sensitive_text, scan_text


@dataclass(frozen=True)
class AuditCompressionResult:
    input_file: str
    output_file: str
    original_size_bytes: int
    compressed_size_bytes: int
    compression_ratio: float
    row_count: int
    raw_data_included: bool = False

    def to_json(self) -> dict[str, object]:
        return {
            "status": "passed",
            "input_file": self.input_file,
            "output_file": self.output_file,
            "original_size_bytes": self.original_size_bytes,
            "compressed_size_bytes": self.compressed_size_bytes,
            "compression_ratio": self.compression_ratio,
            "row_count": self.row_count,
            "raw_data_included": self.raw_data_included,
        }


@dataclass(frozen=True)
class AuditCompressionVerifyResult:
    input_file: str
    output_file: str
    original_size_bytes: int
    compressed_size_bytes: int
    compression_ratio: float
    row_count: int
    raw_data_included: bool = False

    def to_json(self) -> dict[str, object]:
        return {
            "status": "passed",
            "input_file": self.input_file,
            "output_file": self.output_file,
            "original_size_bytes": self.original_size_bytes,
            "compressed_size_bytes": self.compressed_size_bytes,
            "compression_ratio": self.compression_ratio,
            "row_count": self.row_count,
            "raw_data_included": self.raw_data_included,
        }


class AuditCompressionError(ValueError):
    def __init__(self, error_type: str) -> None:
        super().__init__(error_type)
        self.error_type = error_type


def compress_audit_jsonl(input_path: Path, output_path: Path) -> AuditCompressionResult:
    review = _review_input_file(input_path)
    _validate_compressed_output_path(input_path, output_path)

    audit_bytes = _read_audit_bytes(input_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with gzip.open(output_path, "wb", compresslevel=9) as output_file:
            output_file.write(audit_bytes)
    except OSError as error:
        raise AuditCompressionError("compressed_output_write_failed") from error

    verify_result = verify_compressed_audit_jsonl(output_path)
    if verify_result.row_count != review.events_checked:
        raise AuditCompressionError("compressed_output_row_count_mismatch")

    result = AuditCompressionResult(
        input_file=_safe_audit_file_label(input_path),
        output_file=_safe_compressed_file_label(output_path),
        original_size_bytes=len(audit_bytes),
        compressed_size_bytes=output_path.stat().st_size,
        compression_ratio=_compression_ratio(output_path.stat().st_size, len(audit_bytes)),
        row_count=review.events_checked,
    )
    _assert_summary_is_safe(result.to_json())
    return result


def verify_compressed_audit_jsonl(input_path: Path) -> AuditCompressionVerifyResult:
    _validate_compressed_input_path(input_path)
    compressed_size = input_path.stat().st_size
    audit_bytes = _read_gzip_bytes(input_path)
    audit_text = _decode_audit_bytes(audit_bytes)
    if scan_text(audit_text):
        raise AuditCompressionError("decompressed_audit_sensitive_data")

    with tempfile.TemporaryDirectory() as temp_dir:
        decompressed_path = Path(temp_dir) / _decompressed_audit_name(input_path)
        decompressed_path.write_text(audit_text, encoding="utf-8")
        review = review_audit_path(decompressed_path)

    if not review.passed:
        raise AuditCompressionError("decompressed_audit_review_failed")
    if review.schema_version != AUDIT_SCHEMA_VERSION:
        raise AuditCompressionError("invalid_audit_schema_version")

    result = AuditCompressionVerifyResult(
        input_file=_safe_compressed_file_label(input_path),
        output_file=_safe_decompressed_file_label(input_path),
        original_size_bytes=len(audit_bytes),
        compressed_size_bytes=compressed_size,
        compression_ratio=_compression_ratio(compressed_size, len(audit_bytes)),
        row_count=review.events_checked,
    )
    _assert_summary_is_safe(result.to_json())
    return result


def render_audit_compression_summary(result: AuditCompressionResult) -> str:
    lines = [
        "Audit compression passed.",
        "",
        f"Input file: {result.input_file}",
        f"Output file: {result.output_file}",
        f"Original size bytes: {result.original_size_bytes}",
        f"Compressed size bytes: {result.compressed_size_bytes}",
        f"Compression ratio: {result.compression_ratio:.4f}",
        f"Rows covered: {result.row_count}",
        "Raw data included: false",
    ]
    text = "\n".join(lines) + "\n"
    assert_no_sensitive_text(text)
    return text


def render_audit_compression_verify_summary(result: AuditCompressionVerifyResult) -> str:
    lines = [
        "Audit compression verification passed.",
        "",
        f"Input file: {result.input_file}",
        f"Output file: {result.output_file}",
        f"Original size bytes: {result.original_size_bytes}",
        f"Compressed size bytes: {result.compressed_size_bytes}",
        f"Compression ratio: {result.compression_ratio:.4f}",
        f"Rows covered: {result.row_count}",
        "Raw data included: false",
    ]
    text = "\n".join(lines) + "\n"
    assert_no_sensitive_text(text)
    return text


def _review_input_file(input_path: Path) -> Any:
    if not input_path.is_file():
        raise AuditCompressionError("audit_input_not_found")
    review = review_audit_path(input_path)
    if not review.passed:
        raise AuditCompressionError("audit_review_failed")
    if review.schema_version != AUDIT_SCHEMA_VERSION:
        raise AuditCompressionError("invalid_audit_schema_version")
    return review


def _validate_compressed_output_path(input_path: Path, output_path: Path) -> None:
    if not output_path.name.endswith(".jsonl.gz"):
        raise AuditCompressionError("invalid_compressed_output_suffix")
    if _same_path(input_path, output_path):
        raise AuditCompressionError("in_place_output_forbidden")


def _validate_compressed_input_path(input_path: Path) -> None:
    if not input_path.is_file():
        raise AuditCompressionError("compressed_input_not_found")
    if not input_path.name.endswith(".jsonl.gz"):
        raise AuditCompressionError("invalid_compressed_input_suffix")


def _read_audit_bytes(input_path: Path) -> bytes:
    try:
        data = input_path.read_bytes()
    except OSError as error:
        raise AuditCompressionError("audit_input_read_failed") from error
    _decode_audit_bytes(data)
    return data


def _read_gzip_bytes(input_path: Path) -> bytes:
    try:
        with gzip.open(input_path, "rb") as input_file:
            return input_file.read()
    except (OSError, EOFError, gzip.BadGzipFile) as error:
        raise AuditCompressionError("gzip_read_failed") from error


def _decode_audit_bytes(data: bytes) -> str:
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise AuditCompressionError("audit_decode_failed") from error


def _compression_ratio(compressed_size: int, original_size: int) -> float:
    if original_size <= 0:
        return 0.0
    return round(compressed_size / original_size, 4)


def _decompressed_audit_name(input_path: Path) -> str:
    name = input_path.name
    if name.endswith(".gz"):
        return name[:-3]
    return "mcp_audit.decompressed.jsonl"


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


def _safe_compressed_file_label(path: Path) -> str:
    return "<compressed_audit_file>"


def _safe_decompressed_file_label(path: Path) -> str:
    name = _decompressed_audit_name(path)
    if name.startswith("mcp_audit") and name.endswith(".jsonl"):
        return name
    return "<audit_file>"


def _assert_summary_is_safe(summary: dict[str, object]) -> None:
    assert_no_sensitive_text(json.dumps(summary, ensure_ascii=True, sort_keys=True))
