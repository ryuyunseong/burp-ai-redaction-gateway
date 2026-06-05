from __future__ import annotations

import html
import json
import os
from dataclasses import dataclass
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, quote, urlsplit

from .audit_hmac import AuditHmacError, load_hmac_secret, verify_audit_hmac_manifest
from .audit_review import review_audit_path
from .mcp_server import AUDIT_DIR_NAME, AUDIT_FILE_NAME, FORBIDDEN_PATH_PARTS
from .policy import RedactionPolicy, load_policy
from .scanner import assert_no_sensitive_text, scan_text
from .verifier import VerificationResult, verify_path


DEFAULT_DASHBOARD_HOST = "127.0.0.1"
DEFAULT_DASHBOARD_PORT = 8766
SAFE_PREVIEW_FILES = (
    "analysis_packet.json",
    "chatgpt_prompt.md",
    "codex_task_prompt.md",
    "report_draft.md",
)
OUTPUT_MARKER_FILE = "analysis_packet.json"
FINDINGS_FILE = "finding_candidates.json"
MAX_PREVIEW_BYTES = 1024 * 1024


@dataclass(frozen=True)
class DashboardConfig:
    root: Path
    policy_path: Path | None = None


@dataclass(frozen=True)
class DashboardOutput:
    output_id: str
    label: str
    path: Path
    verification: VerificationResult
    candidate_count: int
    prompt_files: list[str]
    report_available: bool


class DashboardError(ValueError):
    def __init__(self, error_type: str, status: HTTPStatus = HTTPStatus.BAD_REQUEST) -> None:
        super().__init__(error_type)
        self.error_type = error_type
        self.status = status


class DashboardHttpServer(ThreadingHTTPServer):
    def __init__(self, server_address: tuple[str, int], config: DashboardConfig, policy: RedactionPolicy) -> None:
        validated_root = _validated_root(config.root)
        super().__init__(server_address, DashboardRequestHandler)
        self.config = DashboardConfig(root=validated_root, policy_path=config.policy_path)
        self.policy = policy


class DashboardRequestHandler(BaseHTTPRequestHandler):
    server: DashboardHttpServer

    def do_GET(self) -> None:
        try:
            parsed = urlsplit(self.path)
            if parsed.path == "/":
                self._send_html(render_home(self.server.config.root, self.server.policy))
                return
            if parsed.path == "/output":
                output_id = _required_query_value(parsed.query, "project")
                output = _verified_output(self.server.config.root, self.server.policy, output_id)
                self._send_html(render_output_detail(output))
                return
            if parsed.path == "/preview":
                output_id = _required_query_value(parsed.query, "project")
                file_name = _safe_file_name(_required_query_value(parsed.query, "file"))
                output = _verified_output(self.server.config.root, self.server.policy, output_id)
                text = _safe_preview_text(output.path, file_name)
                self._send_html(render_preview(output, file_name, text))
                return
            if parsed.path == "/download":
                output_id = _required_query_value(parsed.query, "project")
                file_name = _safe_file_name(_required_query_value(parsed.query, "file"))
                output = _verified_output(self.server.config.root, self.server.policy, output_id)
                self._send_download(output.path, file_name)
                return
            self._send_error("not_found", HTTPStatus.NOT_FOUND)
        except DashboardError as error:
            self._send_error(error.error_type, error.status)
        except OSError:
            self._send_error("file_access_failed", HTTPStatus.INTERNAL_SERVER_ERROR)
        except ValueError:
            self._send_error("dashboard_request_failed", HTTPStatus.BAD_REQUEST)

    def do_POST(self) -> None:
        self._send_error("state_changing_requests_disabled", HTTPStatus.METHOD_NOT_ALLOWED)

    def log_message(self, format: str, *args: Any) -> None:
        return

    def _send_html(self, body: str, status: HTTPStatus = HTTPStatus.OK) -> None:
        data = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def _send_download(self, output_dir: Path, file_name: str) -> None:
        text = _safe_preview_text(output_dir, file_name)
        data = text.encode("utf-8")
        content_type = "application/json" if file_name.endswith(".json") else "text/markdown; charset=utf-8"
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Disposition", f'attachment; filename="{file_name}"')
        self.end_headers()
        self.wfile.write(data)

    def _send_error(self, error_type: str, status: HTTPStatus) -> None:
        safe_error = _safe_error_type(error_type)
        body = render_error(safe_error, status)
        self._send_html(body, status)


def create_dashboard_server(host: str, port: int, config: DashboardConfig) -> DashboardHttpServer:
    if host != DEFAULT_DASHBOARD_HOST:
        raise DashboardError("non_loopback_bind_rejected", HTTPStatus.FORBIDDEN)
    policy = load_policy(config.policy_path)
    return DashboardHttpServer((host, port), config, policy)


def serve_dashboard(host: str, port: int, root: Path, policy_path: Path | None) -> None:
    server = create_dashboard_server(host, port, DashboardConfig(root=root, policy_path=policy_path))
    try:
        server.serve_forever()
    finally:
        server.server_close()


def render_home(root: Path, policy: RedactionPolicy) -> str:
    outputs, blocked_count = _discover_outputs(root, policy)
    audit_status = _audit_status(root)
    rows = "\n".join(_output_row(output) for output in outputs) or (
        '<tr><td colspan="6" class="empty">No verified output directories found.</td></tr>'
    )
    return _page(
        "Local Review Dashboard",
        f"""
        <section class="topbar">
          <div>
            <h1>Burp AI Redaction Gateway</h1>
            <p class="subtitle">Verified sanitized output only. Raw HTTP viewing and replay are unavailable.</p>
          </div>
          <div class="status-stack">
            <span class="badge good">Loopback only</span>
            <span class="badge neutral">Read-only preview</span>
          </div>
        </section>
        {_safety_strip()}
        <section class="metrics">
          <div class="metric"><span class="metric-value">{len(outputs)}</span><span>Verified outputs</span></div>
          <div class="metric"><span class="metric-value">{blocked_count}</span><span>Blocked or hidden outputs</span></div>
          <div class="metric"><span class="metric-value">{_h(audit_status["review_status"])}</span><span>Audit review</span></div>
          <div class="metric"><span class="metric-value">false</span><span>Raw data displayed</span></div>
        </section>
        <section class="panel">
          <div class="panel-head">
            <h2>Outputs</h2>
            <span class="muted">Selection is allowed only after verify passes.</span>
          </div>
          <table>
            <thead>
              <tr>
                <th>Output</th>
                <th>Candidates</th>
                <th>Prompt files</th>
                <th>Report</th>
                <th>Status</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>{rows}</tbody>
          </table>
        </section>
        <section class="panel">
          <div class="panel-head">
            <h2>Audit</h2>
            <span class="muted">Metadata only; audit rows are not displayed.</span>
          </div>
          {_audit_panel(audit_status)}
        </section>
        """,
    )


def render_output_detail(output: DashboardOutput) -> str:
    candidates = _load_candidates(output.path)
    candidate_cards = "\n".join(_candidate_card(candidate) for candidate in candidates[:40]) or (
        '<div class="empty">No finding candidates were present.</div>'
    )
    file_cards = "\n".join(_safe_file_card(output, name) for name in SAFE_PREVIEW_FILES)
    return _page(
        f"Output {output.label}",
        f"""
        <section class="topbar">
          <div>
            <a class="back" href="/">Back to outputs</a>
            <h1>{_h(output.label)}</h1>
            <p class="subtitle">Candidate findings require manual verification. Confidence is evidence confidence, not severity.</p>
          </div>
          <span class="badge good">Verification passed</span>
        </section>
        <section class="safety-strip">
          <div class="rail"><span>Verify</span><strong>passed</strong></div>
          <div class="rail"><span>Display mode</span><strong>raw-free</strong></div>
          <div class="rail"><span>Finding status</span><strong>candidate only</strong></div>
          <div class="rail"><span>Severity</span><strong>separate rating required</strong></div>
        </section>
        <section class="grid">
          <div class="panel">
            <div class="panel-head"><h2>Safe Files</h2><span class="muted">Only AI-safe files are exposed.</span></div>
            <div class="file-grid">{file_cards}</div>
          </div>
          <div class="panel">
            <div class="panel-head"><h2>Finding Candidates</h2><span class="muted">{len(candidates)} total</span></div>
            <div class="candidate-list">{candidate_cards}</div>
          </div>
        </section>
        """,
    )


def render_preview(output: DashboardOutput, file_name: str, text: str) -> str:
    display = _format_preview(file_name, text)
    return _page(
        f"Preview {file_name}",
        f"""
        <section class="topbar">
          <div>
            <a class="back" href="{_output_href(output.output_id)}">Back to output</a>
            <h1>{_h(file_name)}</h1>
            <p class="subtitle">{_h(output.label)} - verified sanitized file</p>
          </div>
          <a class="button" href="{_download_href(output.output_id, file_name)}">Download</a>
        </section>
        <section class="panel">
          <pre class="preview">{_h(display)}</pre>
        </section>
        """,
    )


def render_error(error_type: str, status: HTTPStatus) -> str:
    return _page(
        "Request blocked",
        f"""
        <section class="topbar">
          <div>
            <a class="back" href="/">Back to outputs</a>
            <h1>Request blocked</h1>
            <p class="subtitle">Safe error only. No raw request, response, cookie, token, domain, or personal data is printed.</p>
          </div>
          <span class="badge danger">{status.value}</span>
        </section>
        <section class="panel">
          <dl class="facts">
            <div><dt>Error type</dt><dd>{_h(error_type)}</dd></div>
            <div><dt>Raw data included</dt><dd>false</dd></div>
          </dl>
        </section>
        """,
    )


def _discover_outputs(root: Path, policy: RedactionPolicy) -> tuple[list[DashboardOutput], int]:
    outputs: list[DashboardOutput] = []
    blocked = 0
    for marker in sorted(root.rglob(OUTPUT_MARKER_FILE)):
        output_dir = marker.parent
        try:
            output_id = _relative_output_id(root, output_dir)
            _reject_sensitive_output_id(output_id)
            output = _verified_output(root, policy, output_id)
        except (DashboardError, FileNotFoundError, ValueError):
            blocked += 1
            continue
        outputs.append(output)
    return outputs, blocked


def _verified_output(root: Path, policy: RedactionPolicy, output_id: str) -> DashboardOutput:
    _reject_sensitive_output_id(output_id)
    output_dir = _resolve_output_dir(root, output_id)
    verification = verify_path(output_dir, policy)
    if not verification.passed:
        raise DashboardError("verification_failed", HTTPStatus.FORBIDDEN)
    return DashboardOutput(
        output_id=_relative_output_id(root, output_dir),
        label=_safe_label(_relative_output_id(root, output_dir)),
        path=output_dir,
        verification=verification,
        candidate_count=len(_load_candidates(output_dir)),
        prompt_files=[name for name in SAFE_PREVIEW_FILES if (output_dir / name).is_file()],
        report_available=(output_dir / "report_draft.md").is_file(),
    )


def _resolve_output_dir(root: Path, output_id: str) -> Path:
    relative = Path(output_id.replace("\\", "/"))
    if relative.is_absolute():
        raise DashboardError("absolute_output_path_forbidden", HTTPStatus.FORBIDDEN)
    _reject_forbidden_parts(relative.parts)
    if not relative.parts or any(part in {"", ".", ".."} for part in relative.parts):
        raise DashboardError("invalid_output_id", HTTPStatus.BAD_REQUEST)
    candidate = (root / relative).resolve()
    if not _is_relative_to(candidate, root):
        raise DashboardError("path_traversal_rejected", HTTPStatus.FORBIDDEN)
    if not candidate.is_dir():
        raise DashboardError("output_not_found", HTTPStatus.NOT_FOUND)
    return candidate


def _relative_output_id(root: Path, output_dir: Path) -> str:
    relative = output_dir.resolve().relative_to(root.resolve())
    _reject_forbidden_parts(relative.parts)
    output_id = relative.as_posix()
    _reject_sensitive_output_id(output_id)
    return output_id


def _safe_file_name(file_name: str) -> str:
    if file_name not in SAFE_PREVIEW_FILES:
        raise DashboardError("safe_file_not_allowed", HTTPStatus.FORBIDDEN)
    return file_name


def _safe_preview_text(output_dir: Path, file_name: str) -> str:
    path = output_dir / _safe_file_name(file_name)
    if not path.is_file():
        raise DashboardError("safe_file_not_found", HTTPStatus.NOT_FOUND)
    if path.stat().st_size > MAX_PREVIEW_BYTES:
        raise DashboardError("safe_file_too_large_for_preview", HTTPStatus.REQUEST_ENTITY_TOO_LARGE)
    text = path.read_text(encoding="utf-8")
    assert_no_sensitive_text(text)
    return text


def _load_candidates(output_dir: Path) -> list[dict[str, Any]]:
    path = output_dir / FINDINGS_FILE
    if not path.is_file():
        return []
    text = path.read_text(encoding="utf-8")
    assert_no_sensitive_text(text)
    data = json.loads(text)
    candidates = data.get("finding_candidates") if isinstance(data, dict) else None
    if not isinstance(candidates, list):
        return []
    return [candidate for candidate in candidates if isinstance(candidate, dict)]


def _audit_status(root: Path) -> dict[str, str]:
    audit_dir = root / AUDIT_DIR_NAME
    status = {
        "review_status": "not found",
        "events": "0",
        "files": "0",
        "retained_status": "not found",
        "hmac_status": "not configured",
    }
    if audit_dir.is_dir() or (root / AUDIT_FILE_NAME).is_file():
        try:
            review = review_audit_path(audit_dir if audit_dir.is_dir() else root / AUDIT_FILE_NAME)
            status["review_status"] = "passed" if review.passed else "failed"
            status["events"] = str(review.events_checked)
            status["files"] = str(review.files_checked)
        except ValueError:
            status["review_status"] = "failed"

    retained = audit_dir / "mcp_audit.retained.jsonl"
    if retained.is_file():
        try:
            retained_review = review_audit_path(retained)
            status["retained_status"] = "passed" if retained_review.passed else "failed"
        except ValueError:
            status["retained_status"] = "failed"

    manifest = audit_dir / "mcp_audit.retained.manifest.json"
    if manifest.is_file():
        status["hmac_status"] = _hmac_status(retained, manifest)
    return status


def _hmac_status(input_file: Path, manifest_file: Path) -> str:
    if not input_file.is_file():
        return "input_missing"
    try:
        secret = load_hmac_secret()
        verify_audit_hmac_manifest(input_file, manifest_file, secret=secret)
    except AuditHmacError as error:
        return _safe_error_type(error.error_type)
    return "passed"


def _output_row(output: DashboardOutput) -> str:
    file_count = len(output.prompt_files)
    return f"""
    <tr>
      <td><span class="output-label">{_h(output.label)}</span></td>
      <td>{output.candidate_count}</td>
      <td>{file_count}</td>
      <td>{'available' if output.report_available else 'missing'}</td>
      <td><span class="badge good">verify passed</span></td>
      <td><a class="button small" href="{_output_href(output.output_id)}">Open</a></td>
    </tr>
    """


def _safe_file_card(output: DashboardOutput, file_name: str) -> str:
    exists = (output.path / file_name).is_file()
    status = "available" if exists else "missing"
    actions = (
        f'<a class="button small" href="{_preview_href(output.output_id, file_name)}">Preview</a>'
        f'<a class="button small secondary" href="{_download_href(output.output_id, file_name)}">Download</a>'
        if exists
        else '<span class="muted">Not generated</span>'
    )
    return f"""
    <div class="file-card">
      <div>
        <strong>{_h(file_name)}</strong>
        <span>{status}</span>
        <small>{_h(_safe_file_description(file_name))}</small>
      </div>
      <div class="actions">{actions}</div>
    </div>
    """


def _candidate_card(candidate: dict[str, Any]) -> str:
    finding_id = _safe_value(candidate.get("finding_id"), "candidate")
    title = _safe_value(candidate.get("title"), "Finding candidate")
    kind = _safe_value(candidate.get("type"), "unknown_type")
    endpoint = _safe_value(candidate.get("affected_endpoint"), "unknown_endpoint")
    confidence = _safe_value(candidate.get("confidence"), "unknown")
    manual_required = str(bool(candidate.get("manual_verification_required", True))).lower()
    rationale = _safe_list(candidate.get("rationale"))
    confidence_rationale = _safe_list(candidate.get("confidence_rationale"))
    manual_tests = _safe_list(candidate.get("recommended_manual_tests"))
    do_not_claim = _safe_list(candidate.get("do_not_claim"))
    risk_summary = _risk_rating_summary(candidate.get("risk_rating_draft"))
    return f"""
    <article class="candidate">
      <div class="candidate-head">
        <div>
          <span class="kicker">Candidate finding</span>
          <h3>{_h(finding_id)} - {_h(title)}</h3>
          <p>{_h(kind)} on {_h(endpoint)}</p>
        </div>
        <div class="status-stack">
          <span class="badge neutral">evidence confidence: {_h(confidence)}</span>
          <span class="badge warning">manual check required</span>
        </div>
      </div>
      <dl class="facts compact">
        <div><dt>Manual verification</dt><dd>{manual_required}</dd></div>
        <div><dt>Risk rating draft</dt><dd>{risk_summary}</dd></div>
        <div><dt>Rationale</dt><dd>{_bullets(rationale)}</dd></div>
        <div><dt>Confidence basis</dt><dd>{_bullets(confidence_rationale)}</dd></div>
        <div><dt>Manual tests</dt><dd>{_bullets(manual_tests)}</dd></div>
        <div><dt>Do not claim</dt><dd>{_bullets(do_not_claim)}</dd></div>
      </dl>
    </article>
    """


def _risk_rating_summary(value: Any) -> str:
    if not isinstance(value, dict):
        return "Manual risk rating required before severity assignment."
    severity = _safe_value(value.get("severity_draft"), "unknown")
    likelihood = _safe_value(value.get("likelihood_draft"), "unknown")
    impact = _safe_value(value.get("impact_draft"), "unknown")
    finalized = str(bool(value.get("risk_rating_finalized", False))).lower()
    return (
        f"Severity draft: {_h(severity)}; "
        f"likelihood draft: {_h(likelihood)}; "
        f"impact draft: {_h(impact)}; "
        f"finalized: {_h(finalized)}"
    )


def _audit_panel(status: dict[str, str]) -> str:
    return f"""
    <dl class="facts">
      <div><dt>Review status</dt><dd>{_status_badge(status["review_status"])}</dd></div>
      <div><dt>Events checked</dt><dd>{_h(status["events"])}</dd></div>
      <div><dt>Files checked</dt><dd>{_h(status["files"])}</dd></div>
      <div><dt>Retained JSONL</dt><dd>{_status_badge(status["retained_status"])}</dd></div>
      <div><dt>HMAC manifest</dt><dd>{_status_badge(status["hmac_status"])}</dd></div>
      <div><dt>Displayed content</dt><dd>metadata only</dd></div>
    </dl>
    """


def _safety_strip() -> str:
    return """
    <section class="safety-strip" aria-label="Dashboard safety boundary">
      <div class="rail"><span>Input gate</span><strong>verify passed only</strong></div>
      <div class="rail"><span>Display mode</span><strong>raw-free</strong></div>
      <div class="rail"><span>Report stance</span><strong>candidate only</strong></div>
      <div class="rail"><span>Actions</span><strong>read-only</strong></div>
    </section>
    """


def _safe_file_description(file_name: str) -> str:
    descriptions = {
        "analysis_packet.json": "Structured candidate evidence packet.",
        "chatgpt_prompt.md": "Safe ChatGPT review prompt.",
        "codex_task_prompt.md": "Safe Codex task prompt.",
        "report_draft.md": "Candidate report draft.",
    }
    return descriptions.get(file_name, "Safe generated file.")


def _status_badge(value: str) -> str:
    safe = _h(value)
    if value == "passed":
        return f'<span class="badge good">{safe}</span>'
    if value in {"failed", "input_missing"} or value.endswith("_missing"):
        return f'<span class="badge danger">{safe}</span>'
    return f'<span class="badge neutral">{safe}</span>'


def _format_preview(file_name: str, text: str) -> str:
    if file_name.endswith(".json"):
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            return text
        return json.dumps(parsed, ensure_ascii=True, sort_keys=True, indent=2)
    return text


def _required_query_value(query: str, name: str) -> str:
    values = parse_qs(query, keep_blank_values=False).get(name)
    if not values or not values[0].strip():
        raise DashboardError(f"missing_query:{name}", HTTPStatus.BAD_REQUEST)
    return values[0]


def _validated_root(root: Path) -> Path:
    resolved = root.resolve()
    if not resolved.is_dir():
        raise DashboardError("dashboard_root_not_found", HTTPStatus.NOT_FOUND)
    _reject_forbidden_parts(resolved.parts)
    return resolved


def _reject_forbidden_parts(parts: tuple[str, ...]) -> None:
    lowered = {part.lower() for part in parts}
    if lowered & FORBIDDEN_PATH_PARTS:
        raise DashboardError("forbidden_directory", HTTPStatus.FORBIDDEN)


def _reject_sensitive_output_id(output_id: str) -> None:
    if scan_text(output_id):
        raise DashboardError("output_id_sensitive", HTTPStatus.FORBIDDEN)


def _is_relative_to(candidate: Path, root: Path) -> bool:
    return candidate == root or root in candidate.parents


def _safe_value(value: Any, fallback: str) -> str:
    if value is None:
        return fallback
    text = str(value).replace("\r", " ").replace("\n", " ").strip() or fallback
    if scan_text(text):
        return "<redacted>"
    return text


def _safe_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [_safe_value(item, "") for item in value if _safe_value(item, "")]


def _safe_label(value: str) -> str:
    return _safe_value(value, "<redacted_output_id>")


def _safe_error_type(value: str) -> str:
    text = str(value).replace("\r", "_").replace("\n", "_")
    safe = "".join(char if char.isalnum() or char in {"_", ":", "-"} else "_" for char in text)
    return safe[:120] or "error"


def _bullets(items: list[str]) -> str:
    if not items:
        return '<span class="muted">none</span>'
    return "<ul>" + "".join(f"<li>{_h(item)}</li>" for item in items[:6]) + "</ul>"


def _output_href(output_id: str) -> str:
    return "/output?project=" + quote(output_id, safe="")


def _preview_href(output_id: str, file_name: str) -> str:
    return "/preview?project=" + quote(output_id, safe="") + "&file=" + quote(file_name, safe="")


def _download_href(output_id: str, file_name: str) -> str:
    return "/download?project=" + quote(output_id, safe="") + "&file=" + quote(file_name, safe="")


def _h(value: Any) -> str:
    return html.escape(str(value), quote=True)


def _page(title: str, body: str) -> str:
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{_h(title)} - Burp AI Redaction Gateway</title>
  <style>
    :root {{
      color-scheme: light;
      --bg: #f7f8fa;
      --surface: #ffffff;
      --surface-2: #eef4f2;
      --text: #17211f;
      --muted: #65716d;
      --border: #d9e0dd;
      --accent: #0f766e;
      --accent-2: #334155;
      --danger: #b42318;
      --ok: #0f7a4f;
      --shadow: 0 8px 24px rgba(22, 31, 28, 0.08);
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      font-family: Segoe UI, Arial, sans-serif;
      background: var(--bg);
      color: var(--text);
      letter-spacing: 0;
    }}
    main {{
      width: min(1180px, calc(100vw - 32px));
      margin: 0 auto;
      padding: 28px 0 42px;
    }}
    h1, h2, h3, p {{ margin-top: 0; }}
    h1 {{ font-size: 28px; line-height: 1.2; margin-bottom: 8px; }}
    h2 {{ font-size: 18px; line-height: 1.3; margin-bottom: 0; }}
    h3 {{ font-size: 15px; line-height: 1.35; margin-bottom: 5px; }}
    a {{ color: var(--accent); }}
    .topbar {{
      display: flex;
      justify-content: space-between;
      gap: 18px;
      align-items: flex-start;
      margin-bottom: 18px;
    }}
    .subtitle {{ color: var(--muted); margin-bottom: 0; max-width: 760px; }}
    .status-stack, .actions {{ display: flex; gap: 8px; flex-wrap: wrap; justify-content: flex-end; }}
    .badge {{
      display: inline-flex;
      align-items: center;
      min-height: 28px;
      padding: 4px 10px;
      border-radius: 6px;
      border: 1px solid var(--border);
      background: var(--surface-2);
      color: var(--accent-2);
      font-size: 13px;
      font-weight: 600;
      white-space: nowrap;
    }}
    .badge.good {{ color: var(--ok); background: #eaf7ef; border-color: #bfe6cb; }}
    .badge.danger {{ color: var(--danger); background: #fff0ed; border-color: #fac7be; }}
    .badge.warning {{ color: #805600; background: #fff7df; border-color: #f1d38d; }}
    .safety-strip {{
      display: grid;
      grid-template-columns: repeat(4, minmax(0, 1fr));
      gap: 10px;
      margin-bottom: 14px;
    }}
    .rail {{
      min-height: 74px;
      padding: 12px;
      border: 1px solid var(--border);
      border-radius: 8px;
      background: var(--surface);
      box-shadow: var(--shadow);
    }}
    .rail span, .kicker, .file-card small {{
      display: block;
      color: var(--muted);
      font-size: 12px;
      font-weight: 700;
      line-height: 1.35;
    }}
    .rail strong {{
      display: block;
      margin-top: 6px;
      font-size: 15px;
      line-height: 1.3;
    }}
    .kicker {{
      color: var(--accent);
      text-transform: uppercase;
      margin-bottom: 5px;
    }}
    .metrics {{
      display: grid;
      grid-template-columns: repeat(4, minmax(0, 1fr));
      gap: 12px;
      margin-bottom: 14px;
    }}
    .metric, .panel {{
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 8px;
      box-shadow: var(--shadow);
    }}
    .metric {{ padding: 16px; display: flex; flex-direction: column; gap: 5px; color: var(--muted); }}
    .metric-value {{ color: var(--text); font-size: 24px; font-weight: 700; }}
    .panel {{ padding: 16px; margin-bottom: 14px; }}
    .panel-head {{
      display: flex;
      justify-content: space-between;
      gap: 12px;
      align-items: center;
      margin-bottom: 12px;
    }}
    .grid {{ display: grid; grid-template-columns: minmax(280px, 0.85fr) minmax(420px, 1.4fr); gap: 14px; }}
    table {{ width: 100%; border-collapse: collapse; table-layout: fixed; }}
    th, td {{ text-align: left; padding: 11px 10px; border-bottom: 1px solid var(--border); vertical-align: middle; }}
    th {{ color: var(--muted); font-size: 12px; font-weight: 700; text-transform: uppercase; }}
    td {{ font-size: 14px; word-break: break-word; }}
    .output-label {{ font-weight: 650; }}
    .button {{
      display: inline-flex;
      align-items: center;
      justify-content: center;
      min-height: 34px;
      padding: 7px 12px;
      border-radius: 6px;
      background: var(--accent);
      color: #ffffff;
      text-decoration: none;
      font-weight: 650;
      border: 1px solid var(--accent);
    }}
    .button.small {{ min-height: 30px; padding: 5px 10px; font-size: 13px; }}
    .button.secondary {{ color: var(--accent); background: #ffffff; }}
    .back {{ display: inline-flex; margin-bottom: 10px; color: var(--accent-2); font-weight: 650; text-decoration: none; }}
    .muted, .empty {{ color: var(--muted); }}
    .file-grid, .candidate-list {{ display: grid; gap: 10px; }}
    .file-card {{
      display: flex;
      justify-content: space-between;
      gap: 10px;
      padding: 12px;
      border: 1px solid var(--border);
      border-radius: 8px;
      background: #fbfcfc;
    }}
    .file-card strong, .file-card span {{ display: block; }}
    .file-card small {{ margin-top: 5px; font-weight: 500; }}
    .candidate {{
      padding: 13px;
      border: 1px solid var(--border);
      border-radius: 8px;
      background: #fbfcfc;
    }}
    .candidate-head {{ display: flex; justify-content: space-between; gap: 10px; }}
    .candidate p {{ color: var(--muted); margin-bottom: 0; }}
    .facts {{ display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 10px; margin: 0; }}
    .facts.compact {{ grid-template-columns: 1fr; margin-top: 12px; }}
    .facts div {{ padding: 10px; background: var(--surface-2); border-radius: 6px; min-width: 0; }}
    dt {{ color: var(--muted); font-size: 12px; font-weight: 700; margin-bottom: 5px; }}
    dd {{ margin: 0; word-break: break-word; }}
    ul {{ margin: 0; padding-left: 18px; }}
    pre.preview {{
      min-height: 360px;
      max-height: 70vh;
      overflow: auto;
      margin: 0;
      padding: 14px;
      background: #111827;
      color: #e5edf2;
      border-radius: 8px;
      white-space: pre-wrap;
      word-break: break-word;
      font-family: Consolas, SFMono-Regular, monospace;
      font-size: 13px;
      line-height: 1.5;
    }}
    @media (max-width: 820px) {{
      main {{ width: min(100vw - 20px, 760px); padding-top: 18px; }}
      .topbar, .panel-head, .file-card, .candidate-head {{ flex-direction: column; align-items: stretch; }}
      .metrics, .grid, .facts, .safety-strip {{ grid-template-columns: 1fr; }}
      table {{ table-layout: auto; }}
      th:nth-child(3), td:nth-child(3), th:nth-child(4), td:nth-child(4) {{ display: none; }}
      .status-stack, .actions {{ justify-content: flex-start; }}
    }}
  </style>
</head>
<body>
  <main>{body}</main>
</body>
</html>
"""
