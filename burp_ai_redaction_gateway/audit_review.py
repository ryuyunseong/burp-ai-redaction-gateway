from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .mcp_server import AUDIT_FILE_NAME, AUDIT_HASH_ALGORITHM, AUDIT_SCHEMA_VERSION
from .scanner import assert_no_sensitive_text, scan_text


REQUIRED_AUDIT_FIELDS = (
    "audit_schema_version",
    "event_id",
    "sequence_no",
    "chain_id",
    "prev_event_hash",
    "event_hash",
    "hash_algorithm",
    "event_type",
    "timestamp_utc",
    "tool_name",
    "output_id",
    "result_status",
    "response_class",
    "raw_data_included",
)


@dataclass(frozen=True)
class AuditReviewFinding:
    file: str
    line: int | None
    kind: str

    def to_json(self) -> dict[str, object]:
        item: dict[str, object] = {"file": self.file, "kind": self.kind}
        if self.line is not None:
            item["line"] = self.line
        return item


@dataclass(frozen=True)
class AuditReviewWarning:
    kind: str
    message: str

    def to_json(self) -> dict[str, str]:
        return {"kind": self.kind, "message": self.message}


@dataclass(frozen=True)
class AuditReviewResult:
    files_checked: int
    events_checked: int
    files: list[str]
    findings: list[AuditReviewFinding]
    warnings: list[AuditReviewWarning]
    schema_version: str
    chain_id: str
    sequence_start: int | None
    sequence_end: int | None
    hash_algorithm: str
    raw_free_scan_passed: bool
    retention_boundary: str

    @property
    def passed(self) -> bool:
        return not self.findings

    def to_json(self) -> dict[str, object]:
        return {
            "status": "passed" if self.passed else "failed",
            "files_checked": self.files_checked,
            "events_checked": self.events_checked,
            "files": self.files,
            "schema_version": self.schema_version,
            "chain_id": self.chain_id,
            "sequence_range": {"start": self.sequence_start, "end": self.sequence_end},
            "hash_algorithm": self.hash_algorithm,
            "raw_free_scan": "passed" if self.raw_free_scan_passed else "failed",
            "retention_boundary": self.retention_boundary,
            "warnings": [warning.to_json() for warning in self.warnings],
            "findings": [finding.to_json() for finding in self.findings],
        }


def review_audit_path(input_path: Path) -> AuditReviewResult:
    files, file_findings = _audit_files_for_input(input_path)
    findings = list(file_findings)
    warnings: list[AuditReviewWarning] = []
    events: list[tuple[Path, int, dict[str, Any]]] = []
    raw_free_scan_passed = True

    for file_path in files:
        label = _safe_audit_file_label(file_path)
        try:
            text = file_path.read_text(encoding="utf-8")
        except OSError:
            findings.append(AuditReviewFinding(label, None, "audit_file_read_failed"))
            continue
        raw_matches = scan_text(text)
        if raw_matches:
            raw_free_scan_passed = False
            for kind in _unique_kinds(raw_matches):
                findings.append(AuditReviewFinding(label, None, f"raw_sensitive_data:{kind}"))
        for line_no, line in enumerate(text.splitlines(), start=1):
            if not line.strip():
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                findings.append(AuditReviewFinding(label, line_no, "json_parse_error"))
                continue
            if not isinstance(event, dict):
                findings.append(AuditReviewFinding(label, line_no, "json_row_not_object"))
                continue
            events.append((file_path, line_no, event))

    _review_audit_events(events, findings, warnings)
    if not files:
        findings.append(AuditReviewFinding("<audit_file>", None, "audit_log_not_found"))

    schema_version = _common_value(events, "audit_schema_version") or "<none>"
    chain_id = _common_value(events, "chain_id") or "<none>"
    hash_algorithm = _common_value(events, "hash_algorithm") or "<none>"
    sequence_numbers = [
        event["sequence_no"]
        for _, _, event in events
        if isinstance(event.get("sequence_no"), int)
    ]
    retention_boundary = _retention_boundary(events)
    if retention_boundary == "retained_files_only":
        warnings.append(
            AuditReviewWarning(
                "retention_boundary",
                "Hash chain verification is limited to retained audit files and the active file.",
            )
        )

    result = AuditReviewResult(
        files_checked=len(files),
        events_checked=len(events),
        files=[_safe_audit_file_label(file_path) for file_path in files],
        findings=findings,
        warnings=warnings,
        schema_version=schema_version,
        chain_id=chain_id,
        sequence_start=min(sequence_numbers) if sequence_numbers else None,
        sequence_end=max(sequence_numbers) if sequence_numbers else None,
        hash_algorithm=hash_algorithm,
        raw_free_scan_passed=raw_free_scan_passed,
        retention_boundary=retention_boundary,
    )
    _assert_result_output_is_safe(result)
    return result


def render_audit_review_summary(result: AuditReviewResult) -> str:
    lines = ["Audit review passed." if result.passed else "Audit review failed.", ""]
    lines.append("Files checked:")
    if result.files:
        lines.extend(f"- {file_name}" for file_name in result.files)
    else:
        lines.append("- <none>")
    lines.extend(
        [
            "",
            f"Events checked: {result.events_checked}",
            f"Schema version: {result.schema_version}",
            f"Chain ID: {result.chain_id}",
            f"Sequence range: {_sequence_range_text(result)}",
            f"Hash algorithm: {result.hash_algorithm}",
            f"Raw-free scan: {'passed' if result.raw_free_scan_passed else 'failed'}",
            f"Retention boundary: {result.retention_boundary.replace('_', ' ')}",
        ]
    )
    if result.warnings:
        lines.append("Warnings:")
        lines.extend(f"- {warning.kind}: {warning.message}" for warning in result.warnings)
    if result.findings:
        lines.append("Findings:")
        for finding in result.findings[:20]:
            location = finding.file
            if finding.line is not None:
                location = f"{location}:line {finding.line}"
            lines.append(f"- {location}: {finding.kind}: <REDACTED>")
        if len(result.findings) > 20:
            lines.append(f"- ... {len(result.findings) - 20} additional findings omitted")
    text = "\n".join(lines) + "\n"
    assert_no_sensitive_text(text)
    return text


def _audit_files_for_input(input_path: Path) -> tuple[list[Path], list[AuditReviewFinding]]:
    findings: list[AuditReviewFinding] = []
    if input_path.is_file():
        return [input_path], findings
    if not input_path.is_dir():
        return [], [AuditReviewFinding("<audit_file>", None, "audit_input_not_found")]

    files: list[tuple[int, Path]] = []
    active = input_path / AUDIT_FILE_NAME
    prefix = "mcp_audit."
    suffix = ".jsonl"
    for file_path in input_path.glob("mcp_audit.*.jsonl"):
        name = file_path.name
        index_text = name[len(prefix) : -len(suffix)]
        if len(index_text) != 6 or not index_text.isdigit():
            findings.append(AuditReviewFinding("<invalid_audit_file>", None, "invalid_rotated_suffix"))
            continue
        files.append((int(index_text), file_path))
    ordered = [file_path for _, file_path in sorted(files, key=lambda item: item[0])]
    if active.is_file():
        ordered.append(active)
    return ordered, findings


def _review_audit_events(
    events: list[tuple[Path, int, dict[str, Any]]],
    findings: list[AuditReviewFinding],
    warnings: list[AuditReviewWarning],
) -> None:
    previous_hash: str | None = None
    previous_sequence: int | None = None
    chain_id: str | None = None
    seen_sequences: set[int] = set()
    seen_any_event = False

    for file_path, line_no, event in events:
        label = _safe_audit_file_label(file_path)
        _review_required_fields(label, line_no, event, findings)
        _review_event_types(label, line_no, event, findings)

        sequence_no = event.get("sequence_no")
        event_hash = event.get("event_hash")
        prev_event_hash = event.get("prev_event_hash")
        current_chain_id = event.get("chain_id")

        if isinstance(sequence_no, int):
            if sequence_no in seen_sequences:
                findings.append(AuditReviewFinding(label, line_no, "duplicate_sequence_no"))
            seen_sequences.add(sequence_no)
            if previous_sequence is not None and sequence_no != previous_sequence + 1:
                findings.append(AuditReviewFinding(label, line_no, "sequence_no_not_contiguous"))
            previous_sequence = sequence_no

        if chain_id is None and isinstance(current_chain_id, str):
            chain_id = current_chain_id
        elif isinstance(current_chain_id, str) and current_chain_id != chain_id:
            findings.append(AuditReviewFinding(label, line_no, "chain_id_mismatch"))

        if seen_any_event and prev_event_hash != previous_hash:
            findings.append(AuditReviewFinding(label, line_no, "prev_event_hash_mismatch"))
        seen_any_event = True

        if isinstance(event_hash, str):
            expected_hash = _audit_event_hash(event)
            if event_hash != expected_hash:
                findings.append(AuditReviewFinding(label, line_no, "event_hash_mismatch"))
            previous_hash = event_hash
        else:
            previous_hash = None

    _review_rotated_file_sequence_alignment(events, findings)


def _review_required_fields(
    label: str,
    line_no: int,
    event: dict[str, Any],
    findings: list[AuditReviewFinding],
) -> None:
    for field_name in REQUIRED_AUDIT_FIELDS:
        if field_name not in event:
            findings.append(AuditReviewFinding(label, line_no, f"missing_field:{field_name}"))


def _review_event_types(
    label: str,
    line_no: int,
    event: dict[str, Any],
    findings: list[AuditReviewFinding],
) -> None:
    if event.get("audit_schema_version") != AUDIT_SCHEMA_VERSION:
        findings.append(AuditReviewFinding(label, line_no, "invalid_audit_schema_version"))
    if not _is_standard_uuid(event.get("event_id")):
        findings.append(AuditReviewFinding(label, line_no, "invalid_event_id"))
    sequence_no = event.get("sequence_no")
    if not isinstance(sequence_no, int) or sequence_no <= 0:
        findings.append(AuditReviewFinding(label, line_no, "invalid_sequence_no"))
    if not isinstance(event.get("chain_id"), str) or not event.get("chain_id"):
        findings.append(AuditReviewFinding(label, line_no, "invalid_chain_id"))
    if not _is_sha256_hash_or_none(event.get("prev_event_hash")):
        findings.append(AuditReviewFinding(label, line_no, "invalid_prev_event_hash"))
    if not _is_sha256_hash(event.get("event_hash")):
        findings.append(AuditReviewFinding(label, line_no, "invalid_event_hash"))
    if event.get("hash_algorithm") != AUDIT_HASH_ALGORITHM:
        findings.append(AuditReviewFinding(label, line_no, "invalid_hash_algorithm"))
    if event.get("raw_data_included") is not False:
        findings.append(AuditReviewFinding(label, line_no, "raw_data_marker_not_false"))


def _review_rotated_file_sequence_alignment(
    events: list[tuple[Path, int, dict[str, Any]]],
    findings: list[AuditReviewFinding],
) -> None:
    first_event_by_file: dict[Path, dict[str, Any]] = {}
    for file_path, _, event in events:
        first_event_by_file.setdefault(file_path, event)
    for file_path, event in first_event_by_file.items():
        suffix = _rotated_suffix(file_path)
        if suffix is None:
            continue
        sequence_no = event.get("sequence_no")
        if isinstance(sequence_no, int) and suffix != sequence_no:
            findings.append(AuditReviewFinding(_safe_audit_file_label(file_path), None, "rotated_suffix_sequence_mismatch"))


def _retention_boundary(events: list[tuple[Path, int, dict[str, Any]]]) -> str:
    if not events:
        return "unknown"
    first_event = events[0][2]
    if first_event.get("sequence_no") == 1 and first_event.get("prev_event_hash") is None:
        return "full_chain_from_genesis"
    return "retained_files_only"


def _common_value(events: list[tuple[Path, int, dict[str, Any]]], field_name: str) -> str | None:
    values = [event.get(field_name) for _, _, event in events if isinstance(event.get(field_name), str)]
    if not values:
        return None
    first = str(values[0])
    if not all(str(value) == first for value in values):
        return "<mixed>"
    return _safe_metadata_value(first)


def _audit_event_hash(event: dict[str, Any]) -> str:
    canonical = json.dumps(
        {key: value for key, value in event.items() if key != "event_hash"},
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    )
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _is_standard_uuid(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    try:
        parsed = uuid.UUID(value)
    except ValueError:
        return False
    return str(parsed) == value.lower()


def _is_sha256_hash(value: Any) -> bool:
    if not isinstance(value, str) or not value.startswith("sha256:"):
        return False
    digest = value.removeprefix("sha256:")
    return len(digest) == 64 and all(char in "0123456789abcdef" for char in digest)


def _is_sha256_hash_or_none(value: Any) -> bool:
    return value is None or _is_sha256_hash(value)


def _rotated_suffix(path: Path) -> int | None:
    name = path.name
    prefix = "mcp_audit."
    suffix = ".jsonl"
    if not name.startswith(prefix) or not name.endswith(suffix):
        return None
    index_text = name[len(prefix) : -len(suffix)]
    if len(index_text) != 6 or not index_text.isdigit():
        return None
    return int(index_text)


def _safe_audit_file_label(path: Path) -> str:
    if path.name == AUDIT_FILE_NAME or _rotated_suffix(path) is not None:
        return path.name
    return "<audit_file>"


def _sequence_range_text(result: AuditReviewResult) -> str:
    if result.sequence_start is None or result.sequence_end is None:
        return "<none>"
    return f"{result.sequence_start}-{result.sequence_end}"


def _unique_kinds(matches: list[Any]) -> list[str]:
    kinds: list[str] = []
    for match in matches:
        kind = str(match.kind)
        if kind not in kinds:
            kinds.append(kind)
    return kinds


def _safe_metadata_value(value: str) -> str:
    if scan_text(value):
        return "<redacted_metadata>"
    return value


def _assert_result_output_is_safe(result: AuditReviewResult) -> None:
    assert_no_sensitive_text(json.dumps(result.to_json(), ensure_ascii=True, sort_keys=True))
