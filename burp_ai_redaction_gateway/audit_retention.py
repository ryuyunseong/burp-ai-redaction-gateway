from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from .audit_review import review_audit_path
from .scanner import assert_no_sensitive_text


@dataclass(frozen=True)
class AuditRetentionResult:
    input_file: str
    output_file: str
    total_rows: int
    retained_rows: int
    expired_rows: int
    earliest_retained_timestamp: str | None
    latest_retained_timestamp: str | None
    retention_days: int
    dry_run: bool
    output_written: bool
    raw_data_included: bool = False

    def to_json(self) -> dict[str, object]:
        return {
            "status": "passed",
            "input_file": self.input_file,
            "output_file": self.output_file,
            "total_rows": self.total_rows,
            "retained_rows": self.retained_rows,
            "expired_rows": self.expired_rows,
            "earliest_retained_timestamp": self.earliest_retained_timestamp,
            "latest_retained_timestamp": self.latest_retained_timestamp,
            "retention_days": self.retention_days,
            "dry_run": self.dry_run,
            "output_written": self.output_written,
            "raw_data_included": self.raw_data_included,
        }


class AuditRetentionError(ValueError):
    def __init__(self, error_type: str) -> None:
        super().__init__(error_type)
        self.error_type = error_type


def apply_audit_retention(
    input_path: Path,
    output_path: Path,
    *,
    retention_days: int,
    dry_run: bool = False,
    now: datetime | None = None,
) -> AuditRetentionResult:
    if retention_days < 0:
        raise AuditRetentionError("invalid_retention_days")
    if not input_path.is_file():
        raise AuditRetentionError("audit_input_not_found")
    if _same_path(input_path, output_path):
        raise AuditRetentionError("in_place_output_forbidden")

    input_review = review_audit_path(input_path)
    if not input_review.passed:
        raise AuditRetentionError("audit_review_failed")

    rows = _read_audit_rows(input_path)
    cutoff = _utc_now(now) - timedelta(days=retention_days)
    retained = [row for row in rows if _parse_timestamp(row.get("timestamp_utc")) >= cutoff]
    retained_timestamps = [str(row["timestamp_utc"]) for row in retained if isinstance(row.get("timestamp_utc"), str)]
    result = AuditRetentionResult(
        input_file=_safe_file_label(input_path),
        output_file=_safe_file_label(output_path),
        total_rows=len(rows),
        retained_rows=len(retained),
        expired_rows=len(rows) - len(retained),
        earliest_retained_timestamp=min(retained_timestamps) if retained_timestamps else None,
        latest_retained_timestamp=max(retained_timestamps) if retained_timestamps else None,
        retention_days=retention_days,
        dry_run=dry_run,
        output_written=not dry_run,
    )
    _assert_retention_result_is_safe(result)

    if dry_run:
        return result

    text = _audit_rows_text(retained)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(text, encoding="utf-8")
    output_review = review_audit_path(output_path)
    if not output_review.passed:
        raise AuditRetentionError("retained_output_review_failed")
    return result


def render_audit_retention_summary(result: AuditRetentionResult) -> str:
    lines = [
        "Audit retention passed.",
        "",
        f"Input file: {result.input_file}",
        f"Output file: {result.output_file}",
        f"Total rows: {result.total_rows}",
        f"Retained rows: {result.retained_rows}",
        f"Expired rows: {result.expired_rows}",
        f"Earliest retained timestamp: {result.earliest_retained_timestamp or '<none>'}",
        f"Latest retained timestamp: {result.latest_retained_timestamp or '<none>'}",
        f"Retention days: {result.retention_days}",
        f"Dry run: {str(result.dry_run).lower()}",
        f"Output written: {str(result.output_written).lower()}",
        "Raw data included: false",
    ]
    text = "\n".join(lines) + "\n"
    assert_no_sensitive_text(text)
    return text


def _read_audit_rows(input_path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line in input_path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        if not isinstance(row, dict):
            raise AuditRetentionError("audit_row_not_object")
        _parse_timestamp(row.get("timestamp_utc"))
        rows.append(row)
    return rows


def _audit_rows_text(rows: list[dict[str, Any]]) -> str:
    if not rows:
        return ""
    text = "\n".join(json.dumps(row, ensure_ascii=True, sort_keys=True) for row in rows) + "\n"
    assert_no_sensitive_text(text)
    return text


def _parse_timestamp(value: Any) -> datetime:
    if not isinstance(value, str):
        raise AuditRetentionError("invalid_timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise AuditRetentionError("invalid_timestamp") from error
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _utc_now(value: datetime | None) -> datetime:
    if value is None:
        return datetime.now(UTC)
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _same_path(left: Path, right: Path) -> bool:
    try:
        return left.resolve() == right.resolve()
    except OSError:
        return left.absolute() == right.absolute()


def _safe_file_label(path: Path) -> str:
    name = path.name
    if name.startswith("mcp_audit") and name.endswith(".jsonl"):
        return name
    return "<audit_file>"


def _assert_retention_result_is_safe(result: AuditRetentionResult) -> None:
    assert_no_sensitive_text(json.dumps(result.to_json(), ensure_ascii=True, sort_keys=True))
