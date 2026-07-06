from __future__ import annotations

import json
import re
from dataclasses import dataclass
from html import escape
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "redacted-viewer-fixture-contract-v1"
SAFE_FILE_ALLOWLIST = (
    "analysis_packet.json",
    "chatgpt_prompt.md",
    "codex_task_prompt.md",
    "report_draft.md",
)
DEFAULT_MAX_ARTIFACT_BYTES = 256 * 1024
ACCEPTED_VERIFICATION_STATUSES = {"passed"}

_VALID_REQUIRED_FIELDS = {
    "artifact_id",
    "schema_version",
    "generated_at",
    "source_kind",
    "redaction_status",
    "findings",
    "display_sections",
    "audit",
}
_NEGATIVE_REASON_CODES = {
    "raw_like_value_detected",
    "credential_like_value_detected",
    "unsafe_path_label_detected",
}
_FORBIDDEN_TEXT_PATTERNS = (
    re.compile(r'"raw_request"', re.IGNORECASE),
    re.compile(r'"raw_response"', re.IGNORECASE),
    re.compile(r"\bGET\s+/", re.IGNORECASE),
    re.compile(r"\bPOST\s+/", re.IGNORECASE),
    re.compile(r"\bHTTP/1\.[01]\b", re.IGNORECASE),
    re.compile(r"\bCookie\s*[:=]\s*\S+", re.IGNORECASE),
    re.compile(r"\bAuthorization\s*[:=]\s*\S+", re.IGNORECASE),
    re.compile(r"\bBearer\s+[A-Za-z0-9._-]+", re.IGNORECASE),
    re.compile(r"\bapi[_-]?key\s*[:=]\s*\S+", re.IGNORECASE),
    re.compile(r"\bpassword\s*[:=]\s*\S+", re.IGNORECASE),
    re.compile(r"\bsession[_-]?id\s*[:=]\s*\S+", re.IGNORECASE),
    re.compile(r"\btoken\s*[:=]\s*\S+", re.IGNORECASE),
)


class RedactedStaticViewerError(ValueError):
    def __init__(self, error_type: str) -> None:
        super().__init__(error_type)
        self.error_type = error_type


@dataclass(frozen=True)
class RedactedStaticViewerResult:
    output_path: Path
    artifact_id: str
    finding_count: int
    section_count: int
    raw_data_included: bool
    manual_review_required: bool

    def to_json(self) -> dict[str, object]:
        return {
            "output_file": self.output_path.name,
            "artifact_id": self.artifact_id,
            "finding_count": self.finding_count,
            "section_count": self.section_count,
            "raw_data_included": self.raw_data_included,
            "manual_review_required": self.manual_review_required,
        }


def write_static_viewer_html(
    input_path: Path,
    output_path: Path,
    *,
    max_bytes: int = DEFAULT_MAX_ARTIFACT_BYTES,
) -> RedactedStaticViewerResult:
    artifact = load_redacted_viewer_artifact(input_path, max_bytes=max_bytes)
    html = render_static_viewer_html(artifact)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(html, encoding="utf-8")
    return RedactedStaticViewerResult(
        output_path=output_path,
        artifact_id=str(artifact["artifact_id"]),
        finding_count=len(artifact["findings"]),
        section_count=len(artifact["display_sections"]),
        raw_data_included=False,
        manual_review_required=True,
    )


def load_redacted_viewer_artifact(input_path: Path, *, max_bytes: int = DEFAULT_MAX_ARTIFACT_BYTES) -> dict[str, Any]:
    if input_path.suffix.lower() != ".json":
        raise RedactedStaticViewerError("unsupported_extension")
    try:
        size = input_path.stat().st_size
    except OSError as error:
        raise RedactedStaticViewerError("artifact_not_readable") from error
    if size > max_bytes:
        raise RedactedStaticViewerError("artifact_too_large")
    try:
        artifact = json.loads(input_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RedactedStaticViewerError("malformed_artifact") from error
    validate_redacted_viewer_artifact(artifact)
    return artifact


def validate_redacted_viewer_artifact(artifact: Any) -> None:
    if not isinstance(artifact, dict):
        raise RedactedStaticViewerError("invalid_json_shape")
    if artifact.get("schema_version") != SCHEMA_VERSION:
        raise RedactedStaticViewerError("missing_or_unsupported_schema")
    if artifact.get("fixture_kind") == "negative" or artifact.get("expected_decision") == "reject":
        reason_code = artifact.get("rejection_reason_code")
        if reason_code in _NEGATIVE_REASON_CODES:
            raise RedactedStaticViewerError(str(reason_code))
        raise RedactedStaticViewerError("negative_fixture_rejected")
    if artifact.get("fixture_kind") != "valid" or artifact.get("expected_decision") != "accept":
        raise RedactedStaticViewerError("unsupported_fixture_kind")
    if not _VALID_REQUIRED_FIELDS.issubset(artifact):
        raise RedactedStaticViewerError("missing_required_field")
    if artifact.get("viewer_implementation_included") is not False:
        raise RedactedStaticViewerError("unexpected_viewer_implementation_flag")
    if artifact.get("raw_data_included") is not False:
        raise RedactedStaticViewerError("raw_data_flag_not_false")
    if artifact.get("manual_review_required") is not True:
        raise RedactedStaticViewerError("manual_review_not_required")
    if tuple(artifact.get("safe_file_allowlist", ())) != SAFE_FILE_ALLOWLIST:
        raise RedactedStaticViewerError("safe_file_allowlist_mismatch")

    redaction_status = artifact["redaction_status"]
    if not isinstance(redaction_status, dict):
        raise RedactedStaticViewerError("invalid_redaction_status")
    if redaction_status.get("verification_status") not in ACCEPTED_VERIFICATION_STATUSES:
        raise RedactedStaticViewerError("verification_not_passed")
    if redaction_status.get("raw_free") is not True:
        raise RedactedStaticViewerError("raw_free_not_confirmed")
    if redaction_status.get("credential_values_removed") is not True:
        raise RedactedStaticViewerError("credential_removal_not_confirmed")
    if redaction_status.get("target_identifiers_removed") is not True:
        raise RedactedStaticViewerError("target_identifier_removal_not_confirmed")

    _validate_findings(artifact["findings"])
    _validate_display_sections(artifact["display_sections"])
    _validate_audit(artifact["audit"])
    _reject_forbidden_text(artifact)
    _reject_unsafe_path_values(artifact)


def render_static_viewer_html(artifact: dict[str, Any]) -> str:
    validate_redacted_viewer_artifact(artifact)
    artifact_id = _html(str(artifact["artifact_id"]))
    generated_at = _html(str(artifact["generated_at"]))
    source_kind = _html(str(artifact["source_kind"]))
    sections = "\n".join(_render_section(section) for section in artifact["display_sections"])
    findings = "\n".join(_render_finding(finding) for finding in artifact["findings"])
    safe_files = "\n".join(f"<li>{_html(name)}</li>" for name in SAFE_FILE_ALLOWLIST)
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Redacted Static Viewer</title>
  <style>
    body {{ font-family: system-ui, sans-serif; margin: 2rem; color: #1f2937; background: #f9fafb; }}
    main {{ max-width: 960px; margin: 0 auto; }}
    section {{ background: #ffffff; border: 1px solid #d1d5db; border-radius: 8px; padding: 1rem; margin: 1rem 0; }}
    table {{ border-collapse: collapse; width: 100%; }}
    th, td {{ border: 1px solid #d1d5db; padding: 0.5rem; text-align: left; vertical-align: top; }}
    th {{ background: #f3f4f6; }}
    code {{ background: #f3f4f6; padding: 0.1rem 0.25rem; border-radius: 4px; }}
  </style>
</head>
<body>
  <main>
    <h1>Redacted Static Viewer</h1>
    <section>
      <h2>Artifact Status</h2>
      <dl>
        <dt>Artifact</dt><dd><code>{artifact_id}</code></dd>
        <dt>Generated</dt><dd>{generated_at}</dd>
        <dt>Source kind</dt><dd>{source_kind}</dd>
        <dt>Verification</dt><dd>passed</dd>
        <dt>Raw data included</dt><dd>false</dd>
        <dt>Manual review required</dt><dd>true</dd>
      </dl>
    </section>
    <section>
      <h2>Safe File Allowlist</h2>
      <ul>
        {safe_files}
      </ul>
    </section>
    <section>
      <h2>Display Sections</h2>
      <table>
        <thead><tr><th>ID</th><th>Title</th><th>Source alias</th></tr></thead>
        <tbody>
          {sections}
        </tbody>
      </table>
    </section>
    <section>
      <h2>Candidate Findings</h2>
      <table>
        <thead><tr><th>ID</th><th>Title</th><th>Status</th><th>Risk</th><th>Evidence</th><th>Safe summary</th></tr></thead>
        <tbody>
          {findings}
        </tbody>
      </table>
    </section>
  </main>
</body>
</html>
"""


def render_static_viewer_summary(result: RedactedStaticViewerResult) -> str:
    return "\n".join(
        [
            "Static viewer HTML written: <viewer_html_path>",
            f"Artifact: {result.artifact_id}",
            f"Finding count: {result.finding_count}",
            f"Display section count: {result.section_count}",
            "Raw data included: false",
            "Manual review required: true",
            "",
        ]
    )


def _validate_findings(findings: Any) -> None:
    if not isinstance(findings, list) or not findings:
        raise RedactedStaticViewerError("invalid_findings")
    for finding in findings:
        if not isinstance(finding, dict):
            raise RedactedStaticViewerError("invalid_finding_shape")
        if finding.get("status") != "candidate":
            raise RedactedStaticViewerError("finding_status_not_candidate")
        if finding.get("risk") != "draft":
            raise RedactedStaticViewerError("finding_risk_not_draft")
        if finding.get("severity_finalized") is not False:
            raise RedactedStaticViewerError("severity_finalized")
        evidence_aliases = finding.get("evidence_aliases")
        if not isinstance(evidence_aliases, list) or not set(evidence_aliases).issubset(SAFE_FILE_ALLOWLIST):
            raise RedactedStaticViewerError("safe_file_allowlist_violation")
        for alias in evidence_aliases:
            _reject_unsafe_path_label(str(alias))
        for field in ("id", "title", "safe_summary"):
            if not isinstance(finding.get(field), str) or not finding[field]:
                raise RedactedStaticViewerError("missing_required_field")


def _validate_display_sections(sections: Any) -> None:
    if not isinstance(sections, list) or not sections:
        raise RedactedStaticViewerError("invalid_display_sections")
    for section in sections:
        if not isinstance(section, dict):
            raise RedactedStaticViewerError("invalid_display_section_shape")
        for field in ("id", "title", "source_alias"):
            if not isinstance(section.get(field), str) or not section[field]:
                raise RedactedStaticViewerError("missing_required_field")
        _reject_unsafe_path_label(section["source_alias"])
        if section["source_alias"] not in SAFE_FILE_ALLOWLIST:
            raise RedactedStaticViewerError("safe_file_allowlist_violation")


def _validate_audit(audit: Any) -> None:
    if not isinstance(audit, dict):
        raise RedactedStaticViewerError("invalid_audit")
    if audit.get("verify_status") != "passed":
        raise RedactedStaticViewerError("audit_verify_not_passed")
    if audit.get("manual_review_required") is not True:
        raise RedactedStaticViewerError("manual_review_not_required")
    if audit.get("blocked_reason_code") is not None:
        raise RedactedStaticViewerError("blocked_artifact_not_rendered")


def _render_section(section: dict[str, Any]) -> str:
    return (
        "<tr>"
        f"<td>{_html(section['id'])}</td>"
        f"<td>{_html(section['title'])}</td>"
        f"<td>{_html(section['source_alias'])}</td>"
        "</tr>"
    )


def _render_finding(finding: dict[str, Any]) -> str:
    aliases = ", ".join(str(alias) for alias in finding["evidence_aliases"])
    return (
        "<tr>"
        f"<td>{_html(finding['id'])}</td>"
        f"<td>{_html(finding['title'])}</td>"
        f"<td>{_html(finding['status'])}</td>"
        f"<td>{_html(finding['risk'])}</td>"
        f"<td>{_html(aliases)}</td>"
        f"<td>{_html(finding['safe_summary'])}</td>"
        "</tr>"
    )


def _reject_forbidden_text(artifact: Any) -> None:
    text = json.dumps(artifact, ensure_ascii=True, sort_keys=True)
    for pattern in _FORBIDDEN_TEXT_PATTERNS:
        if pattern.search(text):
            raise RedactedStaticViewerError("forbidden_value_detected")


def _reject_unsafe_path_values(value: Any) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            if isinstance(item, str) and _is_path_key(str(key)):
                _reject_unsafe_path_label(item)
            _reject_unsafe_path_values(item)
    elif isinstance(value, list):
        for item in value:
            _reject_unsafe_path_values(item)


def _is_path_key(key: str) -> bool:
    normalized = key.lower()
    return normalized in {"path", "local_path", "file_path", "source_path"} or normalized.endswith("_path")


def _reject_unsafe_path_label(label: str) -> None:
    normalized = label.replace("\\", "/")
    if (
        "../" in normalized
        or normalized.startswith("/")
        or re.match(r"^[A-Za-z]:[\\/]", label)
        or normalized.lower().startswith("file://")
        or re.match(r"^[A-Za-z][A-Za-z0-9+.-]*://", label)
    ):
        raise RedactedStaticViewerError("unsafe_path_label_detected")


def _html(value: object) -> str:
    return escape(str(value), quote=True)
