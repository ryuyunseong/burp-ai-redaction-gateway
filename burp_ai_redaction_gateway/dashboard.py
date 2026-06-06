from __future__ import annotations

import html
import json
import os
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, quote, urlsplit

from .audit_hmac import AuditHmacError, load_hmac_secret, verify_audit_hmac_manifest
from .audit_review import review_audit_path
from .mcp_server import (
    AUDIT_DIR_NAME,
    AUDIT_FILE_NAME,
    DEFAULT_AUDIT_MAX_BYTES,
    DEFAULT_AUDIT_MAX_ROTATED_FILES,
    FORBIDDEN_PATH_PARTS,
    _append_audit_event,
    _safe_identifier,
    _safe_output_id,
    _safe_status,
)
from .policy import RedactionPolicy, load_policy
from .report import DEFAULT_REPORT_PROFILE, REPORT_PROFILE_NAMES, write_report_draft
from .review import build_review, render_review_summary
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
MAX_FORM_BYTES = 16 * 1024
ACTION_NAMES = {"verify", "review", "report", "export"}


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


@dataclass(frozen=True)
class DashboardActionResult:
    title: str
    status: str
    output: DashboardOutput | None
    summary_lines: list[str]
    details: str | None = None
    blocked_reason: str = ""
    exported_files: tuple[str, ...] = ()
    report_profile: str = ""


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
        self.csrf_token = secrets.token_hex(16)


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
                self._send_html(render_output_detail(output, self.server.csrf_token))
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
        action_for_audit = "unknown_action"
        output_for_audit = "unknown_output"
        audit_written = False
        try:
            parsed = urlsplit(self.path)
            if parsed.path != "/action":
                self._send_error("not_found", HTTPStatus.NOT_FOUND)
                return
            form = self._read_form()
            action_for_audit = _audit_form_action(form)
            output_for_audit = _audit_form_output(form)
            csrf_token = _optional_form_value(form, "csrf_token")
            if not csrf_token:
                self._write_dashboard_audit_event(
                    action_for_audit,
                    output_for_audit,
                    result_status="blocked",
                    blocked_reason="csrf_missing",
                )
                audit_written = True
                raise DashboardError("csrf_token_missing", HTTPStatus.BAD_REQUEST)
            try:
                _validate_csrf(csrf_token, self.server.csrf_token)
            except DashboardError:
                self._write_dashboard_audit_event(
                    action_for_audit,
                    output_for_audit,
                    result_status="blocked",
                    blocked_reason="csrf_invalid",
                )
                audit_written = True
                raise
            output_id = _required_form_value(form, "project")
            action = _safe_action_name(_required_form_value(form, "action"))
            profile = form.get("profile", [DEFAULT_REPORT_PROFILE])[0]
            result = run_dashboard_action(self.server.config.root, self.server.policy, output_id, action, profile)
            self._write_dashboard_audit_event(
                action,
                output_id,
                result_status=_dashboard_result_status(result),
                blocked_reason=result.blocked_reason,
                exported_files=result.exported_files,
                report_profile=result.report_profile,
            )
            audit_written = True
            self._send_html(render_action_result(result, self.server.csrf_token))
        except DashboardError as error:
            if not audit_written and self.path.startswith("/action"):
                self._write_dashboard_audit_event(
                    action_for_audit,
                    output_for_audit,
                    result_status=_dashboard_error_status(error.error_type),
                    blocked_reason=_dashboard_error_blocked_reason(error.error_type),
                    error_type=error.error_type,
                )
            self._send_error(error.error_type, error.status)
        except OSError:
            if not audit_written and self.path.startswith("/action"):
                self._write_dashboard_audit_event(
                    action_for_audit,
                    output_for_audit,
                    result_status="error",
                    error_type="dashboard_action_file_access_failed",
                )
            self._send_error("dashboard_action_file_access_failed", HTTPStatus.INTERNAL_SERVER_ERROR)
        except ValueError:
            if not audit_written and self.path.startswith("/action"):
                self._write_dashboard_audit_event(
                    action_for_audit,
                    output_for_audit,
                    result_status="error",
                    error_type="dashboard_action_failed",
                )
            self._send_error("dashboard_action_failed", HTTPStatus.BAD_REQUEST)

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

    def _read_form(self) -> dict[str, list[str]]:
        length_text = self.headers.get("Content-Length", "0")
        try:
            length = int(length_text)
        except ValueError as error:
            raise DashboardError("invalid_content_length", HTTPStatus.BAD_REQUEST) from error
        if length <= 0:
            raise DashboardError("empty_form", HTTPStatus.BAD_REQUEST)
        if length > MAX_FORM_BYTES:
            raise DashboardError("form_too_large", HTTPStatus.REQUEST_ENTITY_TOO_LARGE)
        content_type = self.headers.get("Content-Type", "")
        if "application/x-www-form-urlencoded" not in content_type:
            raise DashboardError("unsupported_form_content_type", HTTPStatus.UNSUPPORTED_MEDIA_TYPE)
        body = self.rfile.read(length).decode("utf-8", errors="replace")
        return parse_qs(body, keep_blank_values=False)

    def _write_dashboard_audit_event(
        self,
        action_name: str,
        output_id: str,
        *,
        result_status: str,
        blocked_reason: str = "",
        error_type: str = "",
        exported_files: tuple[str, ...] = (),
        report_profile: str = "",
    ) -> None:
        write_dashboard_action_audit_event(
            self.server.config.root,
            action_name=action_name,
            output_id=output_id,
            result_status=result_status,
            blocked_reason=blocked_reason,
            error_type=error_type,
            exported_files=exported_files,
            report_profile=report_profile,
        )


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


def run_dashboard_action(
    root: Path,
    policy: RedactionPolicy,
    output_id: str,
    action: str,
    profile_name: str = DEFAULT_REPORT_PROFILE,
) -> DashboardActionResult:
    action_name = _safe_action_name(action)
    if action_name == "verify":
        output_dir = _resolve_output_dir(root, output_id)
        verification = verify_path(output_dir, policy)
        if not verification.passed:
            return DashboardActionResult(
                title="산출물 검증",
                status="failed",
                output=None,
                summary_lines=[
                    "검증에 실패했습니다.",
                    f"검사한 파일 수: {verification.files_checked}.",
                    f"탐지 항목 수: {len(verification.findings)}.",
                    "원문 탐지 값은 표시하지 않습니다.",
                ],
                blocked_reason="verify_failed",
            )
        output = _verified_output(root, policy, output_id)
        return DashboardActionResult(
            title="산출물 검증",
            status="passed",
            output=output,
            summary_lines=[
                "검증을 통과했습니다.",
                f"검사한 파일 수: {verification.files_checked}.",
                "원문 데이터 포함 여부: false.",
            ],
        )

    output = _verified_output(root, policy, output_id)
    if action_name == "review":
        result = build_review(output.path, policy)
        return DashboardActionResult(
            title="리뷰 요약",
            status="passed",
            output=output,
            summary_lines=[
                f"후보 항목 수: {result.candidate_count}.",
                f"프롬프트 파일 수: {len(result.prompt_files)}.",
                "원문 데이터 포함 여부: false.",
            ],
            details=render_review_summary(result),
        )
    if action_name == "report":
        profile = _safe_report_profile(profile_name)
        result = write_report_draft(output.path, None, policy, profile)
        refreshed = _verified_output(root, policy, output_id)
        return DashboardActionResult(
            title="보고서 초안",
            status="passed",
            output=refreshed,
            summary_lines=[
                "보고서 초안을 생성했습니다.",
                f"프로필: {result.profile}.",
                f"후보 항목 수: {result.candidate_count}.",
                "원문 데이터 포함 여부: false.",
            ],
            report_profile=result.profile,
        )
    if action_name == "export":
        export_dir = _dashboard_export_dir(root, output.output_id)
        exported = _export_safe_files(output, export_dir)
        return DashboardActionResult(
            title="안전 파일 내보내기",
            status="passed",
            output=output,
            summary_lines=[
                "안전 파일을 내보냈습니다.",
                "내보내기 디렉터리: <safe_export_dir>.",
                f"내보낸 파일 수: {len(exported)}.",
                "원문 데이터 포함 여부: false.",
            ],
            details="\n".join(f"- {name}" for name in exported) + "\n",
            exported_files=tuple(exported),
        )
    raise DashboardError("unsupported_dashboard_action", HTTPStatus.BAD_REQUEST)


def write_dashboard_action_audit_event(
    root: Path,
    *,
    action_name: str,
    output_id: str,
    result_status: str,
    blocked_reason: str = "",
    error_type: str = "",
    exported_files: tuple[str, ...] = (),
    report_profile: str = "",
) -> None:
    event: dict[str, Any] = {
        "timestamp_utc": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "event_type": "dashboard_action",
        "action_name": _safe_dashboard_audit_action(action_name),
        "tool_name": _safe_identifier(f"dashboard_{_safe_dashboard_audit_action(action_name)}", "dashboard_action"),
        "output_id": _safe_dashboard_audit_output(output_id),
        "result_status": _safe_status(result_status),
        "response_class": "dashboard_action_result",
        "raw_data_included": False,
    }
    if blocked_reason:
        event["blocked_reason"] = _safe_identifier(blocked_reason, "blocked")
    if error_type:
        event["error_type"] = _safe_identifier(error_type, "error")
    safe_exported = _safe_exported_files(exported_files)
    if safe_exported:
        event["exported_files"] = list(safe_exported)
    if report_profile:
        event["report_profile"] = _safe_identifier(report_profile, DEFAULT_REPORT_PROFILE)
    _append_audit_event(
        root / AUDIT_DIR_NAME / AUDIT_FILE_NAME,
        event,
        max_bytes=DEFAULT_AUDIT_MAX_BYTES,
        max_rotated_files=DEFAULT_AUDIT_MAX_ROTATED_FILES,
    )


def render_home(root: Path, policy: RedactionPolicy) -> str:
    outputs, blocked_count = _discover_outputs(root, policy)
    audit_status = _audit_status(root)
    rows = "\n".join(_output_row(output) for output in outputs) or (
        '<tr><td colspan="6" class="empty">검증을 통과한 산출물 디렉터리가 없습니다.</td></tr>'
    )
    return _page(
        "로컬 리뷰 대시보드",
        f"""
        <section class="topbar">
          <div>
            <h1>Burp AI Redaction Gateway</h1>
            <p class="subtitle">검증을 통과한 정제 산출물만 표시합니다. 원문 HTTP 보기와 재전송 기능은 제공하지 않습니다.</p>
          </div>
          <div class="status-stack">
            <span class="badge good">로컬 전용</span>
            <span class="badge neutral">안전 미리보기</span>
          </div>
        </section>
        {_safety_strip()}
        <section class="metrics">
          <div class="metric"><span class="metric-value">{len(outputs)}</span><span>검증 통과 산출물</span></div>
          <div class="metric"><span class="metric-value">{blocked_count}</span><span>차단 또는 숨김</span></div>
          <div class="metric"><span class="metric-value">{_h(_status_label(audit_status["review_status"]))}</span><span>감사 로그 검토</span></div>
          <div class="metric"><span class="metric-value">false</span><span>원문 표시 여부</span></div>
        </section>
        <section class="panel">
          <div class="panel-head">
            <h2>산출물</h2>
            <span class="muted">검증을 통과한 산출물만 선택할 수 있습니다.</span>
          </div>
          <table>
            <thead>
              <tr>
                <th>산출물</th>
                <th>후보</th>
                <th>프롬프트 파일</th>
                <th>보고서</th>
                <th>상태</th>
                <th>작업</th>
              </tr>
            </thead>
            <tbody>{rows}</tbody>
          </table>
        </section>
        <section class="panel">
          <div class="panel-head">
            <h2>감사 로그</h2>
            <span class="muted">메타데이터만 표시하며 감사 로그 원문 row는 표시하지 않습니다.</span>
          </div>
          {_audit_panel(audit_status)}
        </section>
        """,
    )


def render_output_detail(output: DashboardOutput, csrf_token: str) -> str:
    candidates = _load_candidates(output.path)
    candidate_cards = "\n".join(_candidate_card(candidate) for candidate in candidates[:40]) or (
        '<div class="empty">표시할 finding 후보가 없습니다.</div>'
    )
    file_cards = "\n".join(_safe_file_card(output, name) for name in SAFE_PREVIEW_FILES)
    return _page(
        f"산출물 {output.label}",
        f"""
        <section class="topbar">
          <div>
            <a class="back" href="/">산출물 목록으로</a>
            <h1>{_h(output.label)}</h1>
            <p class="subtitle">탐지 후보는 수동 검증이 필요합니다. 신뢰도는 증거 신뢰도이며 심각도가 아닙니다.</p>
          </div>
          <span class="badge good">검증 통과</span>
        </section>
        <section class="safety-strip">
          <div class="rail"><span>검증</span><strong>통과</strong></div>
          <div class="rail"><span>표시 모드</span><strong>원문 없음</strong></div>
          <div class="rail"><span>탐지 상태</span><strong>후보만 표시</strong></div>
          <div class="rail"><span>심각도</span><strong>별도 산정 필요</strong></div>
        </section>
        <section class="grid">
          <div class="panel">
            <div class="panel-head"><h2>안전 파일</h2><span class="muted">AI에 넣어도 되는 안전 파일만 표시합니다.</span></div>
            <div class="file-grid">{file_cards}</div>
          </div>
          <div class="panel">
            <div class="panel-head"><h2>대시보드 실행</h2><span class="muted">POST 실행은 CSRF 보호를 사용합니다.</span></div>
            {_action_panel(output, csrf_token)}
          </div>
          <div class="panel">
            <div class="panel-head"><h2>탐지 후보</h2><span class="muted">총 {len(candidates)}개</span></div>
            <div class="candidate-list">{candidate_cards}</div>
          </div>
        </section>
        """,
    )


def render_action_result(result: DashboardActionResult, csrf_token: str) -> str:
    output_link = _output_href(result.output.output_id) if result.output else "/"
    details = f'<pre class="preview">{_h(result.details)}</pre>' if result.details else ""
    summary = "\n".join(f"<li>{_h(line)}</li>" for line in result.summary_lines)
    return _page(
        result.title,
        f"""
        <section class="topbar">
          <div>
            <a class="back" href="{output_link}">산출물로 돌아가기</a>
            <h1>{_h(result.title)}</h1>
            <p class="subtitle">안전한 실행 요약만 표시합니다. 원문 요청/응답, 쿠키, 토큰, 도메인, 개인정보 값은 출력하지 않습니다.</p>
          </div>
          <span class="badge good">{_h(_status_label(result.status))}</span>
        </section>
        <section class="panel">
          <dl class="facts">
            <div><dt>실행 상태</dt><dd>{_h(_status_label(result.status))}</dd></div>
            <div><dt>CSRF 보호</dt><dd>true</dd></div>
            <div><dt>원문 데이터 포함</dt><dd>false</dd></div>
            <div><dt>상태 변경 범위</dt><dd>안전 파일만</dd></div>
          </dl>
          <ul>{summary}</ul>
        </section>
        {details}
        {f'<section class="panel"><div class="panel-head"><h2>다른 실행</h2><span class="muted">같은 산출물에 대해 안전한 실행만 제공합니다.</span></div>{_action_panel(result.output, csrf_token)}</section>' if result.output else ''}
        """,
    )


def render_preview(output: DashboardOutput, file_name: str, text: str) -> str:
    display = _format_preview(file_name, text)
    return _page(
        f"미리보기 {file_name}",
        f"""
        <section class="topbar">
          <div>
            <a class="back" href="{_output_href(output.output_id)}">산출물로 돌아가기</a>
            <h1>{_h(file_name)}</h1>
            <p class="subtitle">{_h(output.label)} - 검증된 정제 파일</p>
          </div>
          <a class="button" href="{_download_href(output.output_id, file_name)}">다운로드</a>
        </section>
        <section class="panel">
          <pre class="preview">{_h(display)}</pre>
        </section>
        """,
    )


def render_error(error_type: str, status: HTTPStatus) -> str:
    return _page(
        "요청 차단",
        f"""
        <section class="topbar">
          <div>
            <a class="back" href="/">산출물 목록으로</a>
            <h1>요청이 차단되었습니다</h1>
            <p class="subtitle">안전한 오류 요약만 표시합니다. 원문 요청/응답, 쿠키, 토큰, 도메인, 개인정보는 출력하지 않습니다.</p>
          </div>
          <span class="badge danger">{status.value}</span>
        </section>
        <section class="panel">
          <dl class="facts">
            <div><dt>오류 유형</dt><dd>{_h(error_type)}</dd></div>
            <div><dt>원문 데이터 포함</dt><dd>false</dd></div>
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


def _export_safe_files(output: DashboardOutput, export_dir: Path) -> list[str]:
    export_dir.mkdir(parents=True, exist_ok=True)
    exported: list[str] = []
    for name in SAFE_PREVIEW_FILES:
        source = output.path / name
        if not source.is_file():
            continue
        text = _safe_preview_text(output.path, name)
        (export_dir / name).write_text(text, encoding="utf-8")
        exported.append(name)
    return exported


def _dashboard_export_dir(root: Path, output_id: str) -> Path:
    return root.resolve().parent / "exports" / "dashboard" / _safe_export_id(output_id)


def _safe_export_id(output_id: str) -> str:
    safe = "".join(char if char.isalnum() or char in {"-", "_"} else "_" for char in output_id)
    return safe[:80] or "output"


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
      <td>{'있음' if output.report_available else '없음'}</td>
      <td><span class="badge good">검증 통과</span></td>
      <td><a class="button small" href="{_output_href(output.output_id)}">열기</a></td>
    </tr>
    """


def _safe_file_card(output: DashboardOutput, file_name: str) -> str:
    exists = (output.path / file_name).is_file()
    status = "사용 가능" if exists else "없음"
    actions = (
        f'<a class="button small" href="{_preview_href(output.output_id, file_name)}">미리보기</a>'
        f'<a class="button small secondary" href="{_download_href(output.output_id, file_name)}">다운로드</a>'
        if exists
        else '<span class="muted">생성되지 않음</span>'
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


def _action_panel(output: DashboardOutput, csrf_token: str) -> str:
    project = _h(output.output_id)
    token = _h(csrf_token)
    profile_options = "\n".join(
        f'<option value="{_h(name)}"{" selected" if name == DEFAULT_REPORT_PROFILE else ""}>{_h(name)}</option>'
        for name in REPORT_PROFILE_NAMES
    )
    return f"""
    <div class="action-grid">
      {_action_form(project, token, "verify", "검증", "fail-closed 산출물 검증을 다시 실행합니다.")}
      {_action_form(project, token, "review", "리뷰", "안전한 리뷰 요약을 생성합니다.")}
      <form class="action-card" method="post" action="/action">
        <input type="hidden" name="csrf_token" value="{token}">
        <input type="hidden" name="project" value="{project}">
        <input type="hidden" name="action" value="report">
        <label>보고서 프로필<select name="profile">{profile_options}</select></label>
        <button type="submit">보고서</button>
        <small>검증 통과 후 report_draft.md를 생성하거나 갱신합니다.</small>
      </form>
      {_action_form(project, token, "export", "내보내기", "안전 미리보기 파일만 복사합니다.")}
      <a class="action-card refresh-card" href="{_output_href(output.output_id)}">
        <strong>새로고침</strong>
        <small>읽기 전용 GET 요청으로 이 산출물 화면을 다시 불러옵니다.</small>
      </a>
    </div>
    """


def _action_form(project: str, token: str, action: str, label: str, description: str) -> str:
    return f"""
    <form class="action-card" method="post" action="/action">
      <input type="hidden" name="csrf_token" value="{token}">
      <input type="hidden" name="project" value="{project}">
      <input type="hidden" name="action" value="{_h(action)}">
      <button type="submit">{_h(label)}</button>
      <small>{_h(description)}</small>
    </form>
    """


def _candidate_card(candidate: dict[str, Any]) -> str:
    finding_id = _safe_value(candidate.get("finding_id"), "candidate")
    title = _safe_value(candidate.get("title"), "탐지 후보")
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
          <span class="kicker">탐지 후보</span>
          <h3>{_h(finding_id)} - {_h(title)}</h3>
          <p>{_h(kind)} / {_h(endpoint)}</p>
        </div>
        <div class="status-stack">
          <span class="badge neutral">증거 신뢰도: {_h(confidence)}</span>
          <span class="badge warning">수동 확인 필요</span>
        </div>
      </div>
      <dl class="facts compact">
        <div><dt>수동 검증</dt><dd>{manual_required}</dd></div>
        <div><dt>위험도 초안</dt><dd>{risk_summary}</dd></div>
        <div><dt>판단 근거</dt><dd>{_bullets(rationale)}</dd></div>
        <div><dt>신뢰도 근거</dt><dd>{_bullets(confidence_rationale)}</dd></div>
        <div><dt>수동 테스트</dt><dd>{_bullets(manual_tests)}</dd></div>
        <div><dt>확정 전 금지 표현</dt><dd>{_bullets(do_not_claim)}</dd></div>
      </dl>
    </article>
    """


def _risk_rating_summary(value: Any) -> str:
    if not isinstance(value, dict):
        return "심각도 산정 전 수동 위험도 평가가 필요합니다."
    severity = _safe_value(value.get("severity_draft"), "unknown")
    likelihood = _safe_value(value.get("likelihood_draft"), "unknown")
    impact = _safe_value(value.get("impact_draft"), "unknown")
    finalized = str(bool(value.get("risk_rating_finalized", False))).lower()
    return (
        f"심각도 초안: {_h(severity)}; "
        f"likelihood 초안: {_h(likelihood)}; "
        f"impact 초안: {_h(impact)}; "
        f"확정 여부: {_h(finalized)}"
    )


def _audit_panel(status: dict[str, str]) -> str:
    return f"""
    <dl class="facts">
      <div><dt>검토 상태</dt><dd>{_status_badge(status["review_status"])}</dd></div>
      <div><dt>검사한 이벤트</dt><dd>{_h(status["events"])}</dd></div>
      <div><dt>검사한 파일</dt><dd>{_h(status["files"])}</dd></div>
      <div><dt>보존 JSONL</dt><dd>{_status_badge(status["retained_status"])}</dd></div>
      <div><dt>HMAC manifest</dt><dd>{_status_badge(status["hmac_status"])}</dd></div>
      <div><dt>표시 내용</dt><dd>메타데이터만</dd></div>
    </dl>
    """


def _safety_strip() -> str:
    return """
    <section class="safety-strip" aria-label="대시보드 안전 경계">
      <div class="rail"><span>입력 게이트</span><strong>검증 통과만</strong></div>
      <div class="rail"><span>표시 모드</span><strong>원문 없음</strong></div>
      <div class="rail"><span>보고서 표현</span><strong>후보만 표시</strong></div>
      <div class="rail"><span>실행</span><strong>CSRF 보호</strong></div>
    </section>
    """


def _safe_file_description(file_name: str) -> str:
    descriptions = {
        "analysis_packet.json": "구조화된 후보 증거 패킷입니다.",
        "chatgpt_prompt.md": "ChatGPT 검토용 안전 프롬프트입니다.",
        "codex_task_prompt.md": "Codex 작업용 안전 프롬프트입니다.",
        "report_draft.md": "탐지 후보 보고서 초안입니다.",
    }
    return descriptions.get(file_name, "안전하게 생성된 파일입니다.")


def _status_badge(value: str) -> str:
    safe = _h(_status_label(value))
    if value == "passed":
        return f'<span class="badge good">{safe}</span>'
    if value in {"failed", "input_missing"} or value.endswith("_missing"):
        return f'<span class="badge danger">{safe}</span>'
    return f'<span class="badge neutral">{safe}</span>'


def _status_label(value: str) -> str:
    labels = {
        "passed": "통과",
        "failed": "실패",
        "success": "성공",
        "blocked": "차단",
        "error": "오류",
        "not found": "없음",
        "not configured": "설정 안 됨",
        "input_missing": "입력 없음",
    }
    return labels.get(value, value)


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


def _required_form_value(form: dict[str, list[str]], name: str) -> str:
    values = form.get(name)
    if not values or not str(values[0]).strip():
        raise DashboardError(f"missing_form:{name}", HTTPStatus.BAD_REQUEST)
    return str(values[0])


def _optional_form_value(form: dict[str, list[str]], name: str) -> str:
    values = form.get(name)
    if not values or not str(values[0]).strip():
        return ""
    return str(values[0])


def _validate_csrf(value: str, expected: str) -> None:
    if not secrets.compare_digest(value, expected):
        raise DashboardError("csrf_token_invalid", HTTPStatus.FORBIDDEN)


def _safe_action_name(value: str) -> str:
    action = str(value).strip().lower()
    if action not in ACTION_NAMES:
        raise DashboardError("unsupported_dashboard_action", HTTPStatus.BAD_REQUEST)
    return action


def _safe_report_profile(value: str) -> str:
    profile = str(value).strip()
    if profile not in REPORT_PROFILE_NAMES:
        raise DashboardError("invalid_report_profile", HTTPStatus.BAD_REQUEST)
    return profile


def _audit_form_action(form: dict[str, list[str]]) -> str:
    value = _optional_form_value(form, "action")
    try:
        return _safe_action_name(value)
    except DashboardError:
        return "unknown_action"


def _audit_form_output(form: dict[str, list[str]]) -> str:
    value = _optional_form_value(form, "project")
    return value if value else "unknown_output"


def _dashboard_result_status(result: DashboardActionResult) -> str:
    if result.status == "passed":
        return "success"
    if result.blocked_reason:
        return "blocked"
    return "error"


def _dashboard_error_status(error_type: str) -> str:
    return "blocked" if _dashboard_error_blocked_reason(error_type) else "error"


def _dashboard_error_blocked_reason(error_type: str) -> str:
    reasons = {
        "csrf_token_missing": "csrf_missing",
        "csrf_token_invalid": "csrf_invalid",
        "verification_failed": "verify_failed",
        "safe_file_not_allowed": "unsafe_export",
        "path_traversal_forbidden": "path_traversal",
        "absolute_output_path_forbidden": "path_traversal",
        "forbidden_directory": "forbidden_directory",
        "unsupported_dashboard_action": "unsupported_action",
    }
    return reasons.get(error_type, "")


def _safe_dashboard_audit_action(value: str) -> str:
    action = str(value).strip().lower()
    return action if action in ACTION_NAMES else "unknown_action"


def _safe_dashboard_audit_output(value: str) -> str:
    safe = _safe_output_id(value)
    return "redacted_output" if scan_text(safe) else safe


def _safe_exported_files(file_names: tuple[str, ...]) -> tuple[str, ...]:
    safe = []
    for name in file_names:
        if name in SAFE_PREVIEW_FILES:
            safe.append(name)
    return tuple(safe)


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
<html lang="ko">
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
    .action-grid {{ display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 10px; }}
    .action-card {{
      display: flex;
      flex-direction: column;
      gap: 8px;
      min-height: 118px;
      padding: 12px;
      border: 1px solid var(--border);
      border-radius: 8px;
      background: #fbfcfc;
      text-decoration: none;
      color: var(--text);
    }}
    .action-card button {{
      min-height: 34px;
      border-radius: 6px;
      border: 1px solid var(--accent);
      background: var(--accent);
      color: #ffffff;
      font-weight: 650;
      cursor: pointer;
    }}
    .action-card small {{ color: var(--muted); line-height: 1.35; }}
    .action-card label {{ display: grid; gap: 6px; font-size: 13px; color: var(--muted); font-weight: 700; }}
    .action-card select {{
      min-height: 34px;
      border-radius: 6px;
      border: 1px solid var(--border);
      background: #ffffff;
      color: var(--text);
      padding: 0 8px;
    }}
    .refresh-card strong {{ color: var(--accent); }}
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
