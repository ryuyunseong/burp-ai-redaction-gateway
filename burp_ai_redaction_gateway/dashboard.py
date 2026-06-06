from __future__ import annotations

import html
import hashlib
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

from .audit_compressed_hmac import AuditCompressedHmacError, verify_compressed_audit_hmac_manifest
from .audit_compression import AuditCompressionError, verify_compressed_audit_jsonl
from .audit_hmac import DEFAULT_HMAC_ENV_VAR, AuditHmacError, load_hmac_secret, verify_audit_hmac_manifest
from .audit_review import review_audit_path
from .mcp_server import (
    AUDIT_DIR_NAME,
    AUDIT_FILE_NAME,
    AUDIT_SCHEMA_VERSION,
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
from .risk import DEFAULT_RISK_RATING_PROFILE, RISK_RATING_PROFILE_NAMES
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
OPERATIONS_GUIDES = (
    ("빠른 시작", "docs/USER_QUICKSTART.md", "receiver, Burp 전송, dashboard 실행 흐름"),
    ("GUI 사용자 흐름", "docs/GUI_USER_FLOW.md", "처음 실행부터 AI 투입 전까지의 화면 흐름"),
    ("AI-safe preflight", "docs/GUI_AI_SAFE_PREFLIGHT.md", "AI 투입 전 read-only 상태 확인"),
    ("AI handoff index", "docs/GUI_AI_HANDOFF_INDEX.md", "AI 투입 파일 순서와 주의사항"),
    ("Finding triage index", "docs/GUI_FINDING_TRIAGE_INDEX.md", "finding 후보 검토 순서와 수동 판단 경계"),
    ("Report readiness index", "docs/GUI_REPORT_READINESS_INDEX.md", "report_draft 초안 검토 상태와 수동 제출 경계"),
    ("Windows 실행기", "docs/WINDOWS_LAUNCHER_GUIDE.md", "start/stop 스크립트와 포트 충돌 처리"),
    ("감사 운영", "docs/AUDIT_OPERATIONS_GUIDE.md", "review-audit, retention, HMAC, archive 순서"),
    ("GUI 감사 패널", "docs/GUI_AUDIT_PANEL_GUIDE.md", "감사/보관 상태 표시 해석"),
    ("위험도 초안", "docs/RISK_RATING_GUIDE.md", "risk profile과 수동 severity 결정"),
    ("v0.4 릴리스", "docs/RELEASE_NOTES_v0.4.md", "dashboard 계열 변경 기준선"),
)
FORBIDDEN_AI_ITEMS = (
    "raw request/response",
    "Cookie",
    "Authorization",
    "token/JWT/session",
    "실제 도메인/IP",
    "개인정보",
    "local_only/",
    "raw/",
    "raw_vault/",
    "검증 실패 out/",
)


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


@dataclass(frozen=True)
class AiSafePreflight:
    output: DashboardOutput
    file_statuses: list[tuple[str, str]]
    ready_status: str
    marker_scan_status: str
    marker_scan_files: int
    missing_files: list[str]
    candidate_count: int
    report_available: bool
    files_checked: int


@dataclass(frozen=True)
class HandoffFile:
    name: str
    order: int
    purpose: str
    status: str
    size_bytes: int | None
    modified_utc: str
    sha256: str


@dataclass(frozen=True)
class AiHandoffIndex:
    output: DashboardOutput
    preflight: AiSafePreflight
    files: list[HandoffFile]


@dataclass(frozen=True)
class TriageCandidate:
    index: int
    candidate_id: str
    category: str
    title: str
    summary: str
    confidence: str
    severity_draft: str
    likelihood_draft: str
    impact_draft: str
    risk_profile: str
    manual_required: bool


@dataclass(frozen=True)
class FindingTriageIndex:
    output: DashboardOutput
    candidates: list[TriageCandidate]
    analysis_packet_status: str
    report_draft_status: str


@dataclass(frozen=True)
class ReportReadinessFile:
    name: str
    purpose: str
    status: str
    size_bytes: int | None
    modified_utc: str
    sha256: str


@dataclass(frozen=True)
class ReportReadinessIndex:
    output: DashboardOutput
    files: list[ReportReadinessFile]
    candidate_count: int
    report_status: str
    analysis_status: str


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
            if parsed.path == "/settings":
                self._send_html(render_settings(self.server.config.root))
                return
            if parsed.path in {"/help", "/operations"}:
                self._send_html(render_operations_help())
                return
            if parsed.path == "/output":
                output_id = _required_query_value(parsed.query, "project")
                output = _verified_output(self.server.config.root, self.server.policy, output_id)
                self._send_html(render_output_detail(output, self.server.csrf_token))
                return
            if parsed.path == "/preflight":
                output_id = _required_query_value(parsed.query, "project")
                output = _verified_output(self.server.config.root, self.server.policy, output_id)
                self._send_html(render_ai_safe_preflight(_build_ai_safe_preflight(output)))
                return
            if parsed.path == "/handoff":
                output_id = _required_query_value(parsed.query, "project")
                output = _verified_output(self.server.config.root, self.server.policy, output_id)
                self._send_html(render_ai_handoff_index(_build_ai_handoff_index(output)))
                return
            if parsed.path == "/triage":
                output_id = _required_query_value(parsed.query, "project")
                output = _verified_output(self.server.config.root, self.server.policy, output_id)
                self._send_html(render_finding_triage_index(_build_finding_triage_index(output)))
                return
            if parsed.path == "/report-readiness":
                output_id = _required_query_value(parsed.query, "project")
                output = _verified_output(self.server.config.root, self.server.policy, output_id)
                self._send_html(render_report_readiness_index(_build_report_readiness_index(output)))
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
            <a class="button secondary" href="/help">운영 가이드</a>
            <a class="button secondary" href="/settings">설정/상태</a>
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


def render_settings(root: Path) -> str:
    audit_status = _audit_status(root)
    safe_files = "".join(f"<li>{_h(name)}</li>" for name in SAFE_PREVIEW_FILES)
    profiles = ", ".join(REPORT_PROFILE_NAMES)
    risk_profiles = ", ".join(RISK_RATING_PROFILE_NAMES)
    return _page(
        "설정 및 보안 상태",
        f"""
        <section class="topbar">
          <div>
            <a class="back" href="/">산출물 목록으로</a>
            <h1>설정 및 보안 상태</h1>
            <p class="subtitle">로컬 대시보드의 안전 경계와 설정 상태만 표시합니다. 비밀값, 환경변수 값, 원문 데이터는 표시하지 않습니다.</p>
          </div>
          <div class="status-stack">
            <span class="badge good">조회 전용</span>
            <span class="badge neutral">메타데이터만</span>
            <a class="button secondary" href="/help">운영 가이드</a>
          </div>
        </section>
        <section class="safety-strip">
          <div class="rail"><span>바인딩</span><strong>localhost-only</strong></div>
          <div class="rail"><span>실행 요청</span><strong>CSRF 보호</strong></div>
          <div class="rail"><span>위험도</span><strong>draft only</strong></div>
          <div class="rail"><span>원문 표시</span><strong>false</strong></div>
        </section>
        <section class="grid">
          <div class="panel">
            <div class="panel-head"><h2>대시보드 상태</h2><span class="muted">설정 변경 기능은 없습니다.</span></div>
            <dl class="facts">
              <div><dt>root alias</dt><dd>{_h(_safe_root_alias(root))}</dd></div>
              <div><dt>bind mode</dt><dd>127.0.0.1 only</dd></div>
              <div><dt>dashboard mode</dt><dd>safe actions enabled</dd></div>
              <div><dt>settings page</dt><dd>read-only</dd></div>
              <div><dt>CSRF 보호</dt><dd>enabled; 값 숨김</dd></div>
              <div><dt>HTML 출력</dt><dd>escaped</dd></div>
            </dl>
          </div>
          <div class="panel">
            <div class="panel-head"><h2>허용된 안전 파일</h2><span class="muted">미리보기와 다운로드 허용 목록입니다.</span></div>
            <ul class="safe-list">{safe_files}</ul>
          </div>
          <div class="panel">
            <div class="panel-head"><h2>보고서와 위험도</h2><span class="muted">확정 심각도는 별도 수동 검토가 필요합니다.</span></div>
            <dl class="facts">
              <div><dt>report profiles</dt><dd>{_h(profiles)}</dd></div>
              <div><dt>risk profiles</dt><dd>{_h(risk_profiles)}</dd></div>
              <div><dt>default risk profile</dt><dd>{_h(DEFAULT_RISK_RATING_PROFILE)}</dd></div>
              <div><dt>risk rating mode</dt><dd>draft only</dd></div>
              <div><dt>confidence_is_severity</dt><dd>false</dd></div>
              <div><dt>severity decision</dt><dd>manual review required</dd></div>
            </dl>
          </div>
          <div class="panel">
            <div class="panel-head"><h2>감사와 무결성</h2><span class="muted">감사 row와 비밀값은 표시하지 않습니다.</span></div>
            <dl class="facts">
              <div><dt>audit schema</dt><dd>{_h(AUDIT_SCHEMA_VERSION)}</dd></div>
              <div><dt>audit path alias</dt><dd>&lt;root&gt;/.audit/{_h(AUDIT_FILE_NAME)}</dd></div>
              <div><dt>audit review</dt><dd>{_status_badge(audit_status["review_status"])}</dd></div>
              <div><dt>audit log</dt><dd>{_status_badge(audit_status["audit_log_status"])}</dd></div>
              <div><dt>HMAC configured</dt><dd>{_h(_hmac_configured_label())}</dd></div>
              <div><dt>HMAC manifest</dt><dd>{_status_badge(audit_status["hmac_status"])}</dd></div>
              <div><dt>retained JSONL</dt><dd>{_status_badge(audit_status["retained_status"])}</dd></div>
              <div><dt>compressed archive</dt><dd>{_status_badge(audit_status["archive_status"])}</dd></div>
              <div><dt>compressed archive verify</dt><dd>{_status_badge(audit_status["archive_verify_status"])}</dd></div>
              <div><dt>compressed archive HMAC manifest</dt><dd>{_status_badge(audit_status["archive_hmac_manifest_status"])}</dd></div>
              <div><dt>compressed archive HMAC verify</dt><dd>{_status_badge(audit_status["archive_hmac_status"])}</dd></div>
            </dl>
          </div>
          <div class="panel">
            <div class="panel-head"><h2>차단 범위</h2><span class="muted">대시보드에 추가하지 않는 기능입니다.</span></div>
            <ul class="safe-list">
              <li>원문 요청/응답 보기 없음</li>
              <li>재전송 또는 active scan 없음</li>
              <li>delete/edit 기능 없음</li>
              <li>비밀값 또는 환경변수 값 표시 없음</li>
              <li>검증 실패 산출물 사용 금지</li>
            </ul>
          </div>
        </section>
        """,
    )


def render_operations_help() -> str:
    guide_cards = "".join(_guide_card(title, path, description) for title, path, description in OPERATIONS_GUIDES)
    safe_files = "".join(f"<li>{_h(name)}</li>" for name in SAFE_PREVIEW_FILES)
    forbidden_items = "".join(f"<li>{_h(name)}</li>" for name in FORBIDDEN_AI_ITEMS)
    return _page(
        "운영 인덱스",
        f"""
        <section class="topbar">
          <div>
            <a class="back" href="/">산출물 목록으로</a>
            <h1>운영 인덱스</h1>
            <p class="subtitle">GUI에서 자주 필요한 사용 흐름, 문서 위치, 안전 경계를 한 화면에 모아 둔 read-only 안내입니다.</p>
          </div>
          <div class="status-stack">
            <span class="badge good">조회 전용</span>
            <span class="badge neutral">실행 버튼 없음</span>
            <a class="button secondary" href="/settings">설정/상태</a>
          </div>
        </section>
        <section class="safety-strip">
          <div class="rail"><span>접속</span><strong>127.0.0.1 전용</strong></div>
          <div class="rail"><span>표시</span><strong>HTML escaped</strong></div>
          <div class="rail"><span>finding</span><strong>candidate</strong></div>
          <div class="rail"><span>risk rating</span><strong>draft</strong></div>
        </section>
        <section class="grid">
          <div class="panel">
            <div class="panel-head"><h2>빠른 흐름</h2><span class="muted">CLI와 GUI 병행 사용 순서입니다.</span></div>
            <ol class="safe-list">
              <li>receiver를 127.0.0.1에서 실행합니다.</li>
              <li>Burp scoped HTTP history를 로컬 receiver로 전송합니다.</li>
              <li>정제 산출물이 생성되고 verify를 통과했는지 확인합니다.</li>
              <li>dashboard에서 산출물을 선택합니다.</li>
              <li>검증, 리뷰, 보고서, 내보내기를 verified safe output에만 실행합니다.</li>
              <li>AI에는 아래 안전 파일 4개만 넣습니다.</li>
            </ol>
          </div>
          <div class="panel">
            <div class="panel-head"><h2>문서 진입점</h2><span class="muted">repository-relative 경로만 표시합니다.</span></div>
            <div class="file-grid">{guide_cards}</div>
          </div>
          <div class="panel">
            <div class="panel-head"><h2>AI 사용 가능 파일</h2><span class="muted">검증 통과 후에만 사용합니다.</span></div>
            <ul class="safe-list">{safe_files}</ul>
          </div>
          <div class="panel">
            <div class="panel-head"><h2>AI/문서/PR 금지 항목</h2><span class="muted">원문 또는 민감값은 옮기지 않습니다.</span></div>
            <ul class="safe-list">{forbidden_items}</ul>
          </div>
          <div class="panel">
            <div class="panel-head"><h2>결과 해석</h2><span class="muted">확정 표현을 피합니다.</span></div>
            <dl class="facts">
              <div><dt>finding</dt><dd>candidate이며 수동 검증 전 확정 취약점이 아닙니다.</dd></div>
              <div><dt>risk rating</dt><dd>draft이며 final severity가 아닙니다.</dd></div>
              <div><dt>confidence</dt><dd>증거 신뢰도이며 severity가 아닙니다.</dd></div>
              <div><dt>final severity</dt><dd>Burp 재현, 권한별 비교, 영향도 판단 후 수동 결정합니다.</dd></div>
            </dl>
          </div>
          <div class="panel">
            <div class="panel-head"><h2>이번 화면의 경계</h2><span class="muted">상태 안내만 제공합니다.</span></div>
            <ul class="safe-list">
              <li>raw viewer를 제공하지 않습니다.</li>
              <li>재전송 또는 active scan을 제공하지 않습니다.</li>
              <li>archive/HMAC 생성 또는 검증 실행 버튼을 제공하지 않습니다.</li>
              <li>risk profile 변경 버튼을 제공하지 않습니다.</li>
              <li>form, POST action, delete/edit 기능을 추가하지 않습니다.</li>
            </ul>
          </div>
        </section>
        """,
    )


def render_output_detail(output: DashboardOutput, csrf_token: str) -> str:
    candidates = _load_candidates(output.path)
    candidate_cards = "\n".join(_candidate_card(candidate) for candidate in candidates[:40]) or (
        '<div class="empty">표시할 finding 후보가 없습니다.</div>'
    )
    file_cards = "\n".join(_safe_file_card(output, name) for name in SAFE_PREVIEW_FILES)
    preflight = _build_ai_safe_preflight(output)
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
            <div class="panel-head"><h2>AI-safe preflight</h2><span class="muted">AI handoff before-check, read-only.</span></div>
            {_preflight_summary(preflight)}
            <a class="button small secondary" href="{_preflight_href(output.output_id)}">preflight detail</a>
            <a class="button small secondary" href="{_handoff_href(output.output_id)}">handoff index</a>
            <a class="button small secondary" href="{_triage_href(output.output_id)}">triage index</a>
            <a class="button small secondary" href="{_report_readiness_href(output.output_id)}">report readiness</a>
          </div>
          <div class="panel">
            <div class="panel-head"><h2>탐지 후보</h2><span class="muted">총 {len(candidates)}개</span></div>
            <div class="candidate-list">{candidate_cards}</div>
          </div>
        </section>
        """,
    )


def render_ai_handoff_index(index: AiHandoffIndex) -> str:
    output = index.output
    file_rows = "\n".join(_handoff_file_card(file) for file in index.files)
    forbidden_items = "".join(
        f"<li>{_h(item)}</li>"
        for item in (
            "raw request/response",
            "Cookie or Authorization values",
            "token, JWT, or session values",
            "real domain, URL, or IP values",
            "personal data",
            "HMAC secret or CSRF token values",
            "local-only raw storage or unverified output artifacts",
            "audit logs, archives, or manifests",
        )
    )
    return _page(
        f"AI handoff index {output.label}",
        f"""
        <section class="topbar">
          <div>
            <a class="back" href="{_output_href(output.output_id)}">산출물로 돌아가기</a>
            <h1>AI handoff index</h1>
            <p class="subtitle">Read-only handoff checklist for AI-safe candidate files. Verify first; manual review required.</p>
          </div>
          <span class="badge good">read-only</span>
        </section>
        <section class="safety-strip">
          <div class="rail"><span>file set</span><strong>AI-safe candidate files</strong></div>
          <div class="rail"><span>verify</span><strong>verify first</strong></div>
          <div class="rail"><span>review</span><strong>manual review required</strong></div>
          <div class="rail"><span>severity</span><strong>human decision</strong></div>
        </section>
        <section class="grid">
          <div class="panel">
            <div class="panel-head"><h2>Handoff summary</h2><span class="muted">metadata only</span></div>
            {_handoff_summary(index)}
          </div>
          <div class="panel">
            <div class="panel-head"><h2>Recommended order</h2><span class="muted">operator reading sequence</span></div>
            <div class="file-grid">{file_rows}</div>
          </div>
          <div class="panel">
            <div class="panel-head"><h2>Related flow</h2><span class="muted">read-only navigation</span></div>
            <dl class="facts">
              <div><dt>preflight status</dt><dd><a href="{_preflight_href(output.output_id)}">open preflight checklist</a></dd></div>
              <div><dt>review/report/export flow</dt><dd><a href="{_output_href(output.output_id)}">return to verified output detail</a></dd></div>
              <div><dt>finding</dt><dd>candidate finding until manual verification is complete</dd></div>
              <div><dt>risk</dt><dd>draft risk, not severity confirmation</dd></div>
              <div><dt>final severity</dt><dd>final severity requires human decision</dd></div>
            </dl>
          </div>
          <div class="panel">
            <div class="panel-head"><h2>Do not send</h2><span class="muted">categories only; no values are shown</span></div>
            <ul class="safe-list">{forbidden_items}</ul>
          </div>
        </section>
        """,
    )


def render_finding_triage_index(index: FindingTriageIndex) -> str:
    output = index.output
    candidate_rows = "\n".join(_triage_candidate_card(candidate) for candidate in index.candidates) or (
        '<div class="empty">No finding candidates are available for triage.</div>'
    )
    safe_files = "".join(f"<li>{_h(name)}</li>" for name in SAFE_PREVIEW_FILES)
    forbidden_items = "".join(
        f"<li>{_h(item)}</li>"
        for item in (
            "raw request/response",
            "Cookie or Authorization values",
            "token, JWT, or session values",
            "real domain, URL, or IP values",
            "personal data",
            "HMAC secret or CSRF token values",
            "full local path",
            "local_only/, raw/, raw_vault/, unverified out/, or out/.audit artifacts",
        )
    )
    return _page(
        f"Finding triage index {output.label}",
        f"""
        <section class="topbar">
          <div>
            <a class="back" href="{_output_href(output.output_id)}">산출물로 돌아가기</a>
            <h1>Finding triage index</h1>
            <p class="subtitle">Read-only triage checklist for sanitized finding candidates. Candidate findings and draft risk require manual review.</p>
          </div>
          <span class="badge good">read-only</span>
        </section>
        <section class="safety-strip">
          <div class="rail"><span>project alias</span><strong>{_h(output.label)}</strong></div>
          <div class="rail"><span>finding candidates</span><strong>{len(index.candidates)}</strong></div>
          <div class="rail"><span>finding status</span><strong>candidate</strong></div>
          <div class="rail"><span>severity decision</span><strong>manual review required</strong></div>
        </section>
        <section class="grid">
          <div class="panel">
            <div class="panel-head"><h2>Triage summary</h2><span class="muted">safe metadata only</span></div>
            <dl class="facts">
              <div><dt>project alias</dt><dd>{_h(output.label)}</dd></div>
              <div><dt>finding candidate count</dt><dd>{len(index.candidates)}</dd></div>
              <div><dt>analysis_packet.json</dt><dd>{_status_badge(index.analysis_packet_status)}</dd></div>
              <div><dt>report_draft.md</dt><dd>{_status_badge(index.report_draft_status)}</dd></div>
              <div><dt>raw_data_included</dt><dd>false</dd></div>
              <div><dt>file paths shown</dt><dd>false</dd></div>
            </dl>
          </div>
          <div class="panel">
            <div class="panel-head"><h2>AI-safe file allowlist</h2><span class="muted">verified files only</span></div>
            <ul class="safe-list">{safe_files}</ul>
          </div>
          <div class="panel">
            <div class="panel-head"><h2>Related flow</h2><span class="muted">read-only navigation</span></div>
            <dl class="facts">
              <div><dt>preflight</dt><dd><a href="{_preflight_href(output.output_id)}">open AI-safe preflight</a></dd></div>
              <div><dt>handoff</dt><dd><a href="{_handoff_href(output.output_id)}">open AI handoff index</a></dd></div>
              <div><dt>report readiness</dt><dd><a href="{_report_readiness_href(output.output_id)}">open report readiness index</a></dd></div>
              <div><dt>review/report/export flow</dt><dd><a href="{_output_href(output.output_id)}">return to verified output detail</a></dd></div>
              <div><dt>boundary</dt><dd>read-only triage checklist; no form or POST action</dd></div>
            </dl>
          </div>
          <div class="panel">
            <div class="panel-head"><h2>Interpretation boundary</h2><span class="muted">candidate and draft only</span></div>
            <dl class="facts">
              <div><dt>finding</dt><dd>candidate finding until manual verification is complete</dd></div>
              <div><dt>risk</dt><dd>draft risk, not severity confirmation</dd></div>
              <div><dt>confidence</dt><dd>evidence confidence, not severity</dd></div>
              <div><dt>final severity</dt><dd>final severity requires manual decision</dd></div>
            </dl>
          </div>
          <div class="panel">
            <div class="panel-head"><h2>Do not use in triage</h2><span class="muted">categories only; no values are shown</span></div>
            <ul class="safe-list">{forbidden_items}</ul>
          </div>
          <div class="panel">
            <div class="panel-head"><h2>Candidate checklist</h2><span class="muted">sanitized metadata only</span></div>
            <div class="candidate-list">{candidate_rows}</div>
          </div>
        </section>
        """,
    )


def render_report_readiness_index(index: ReportReadinessIndex) -> str:
    output = index.output
    file_rows = "\n".join(_report_readiness_file_card(file) for file in index.files)
    checklist_items = "".join(
        f"<li>{_h(item)}</li>"
        for item in (
            "scope confirmation",
            "affected endpoint confirmation",
            "evidence quality confirmation",
            "false positive possibility",
            "impact statement review",
            "remediation wording review",
            "final severity manual decision",
            "customer submission sensitive-info review",
        )
    )
    forbidden_items = "".join(
        f"<li>{_h(item)}</li>"
        for item in (
            "raw request/response",
            "raw audit row body",
            "Cookie or Authorization values",
            "token, JWT, or session values",
            "real domain, URL, or IP values",
            "personal data",
            "HMAC secret or CSRF token values",
            "full local path",
            "local_only/, raw/, raw_vault/, unverified out/, or out/.audit artifacts",
        )
    )
    return _page(
        f"Report readiness index {output.label}",
        f"""
        <section class="topbar">
          <div>
            <a class="back" href="{_output_href(output.output_id)}">산출물로 돌아가기</a>
            <h1>Report readiness index</h1>
            <p class="subtitle">Read-only draft report checklist before manual review. report_draft.md is a draft report, not a submission report.</p>
          </div>
          <span class="badge good">read-only</span>
        </section>
        <section class="safety-strip">
          <div class="rail"><span>project alias</span><strong>{_h(output.label)}</strong></div>
          <div class="rail"><span>draft report status</span><strong>{_h(index.report_status)}</strong></div>
          <div class="rail"><span>finding candidates</span><strong>{index.candidate_count}</strong></div>
          <div class="rail"><span>severity decision</span><strong>manual review required</strong></div>
        </section>
        <section class="grid">
          <div class="panel">
            <div class="panel-head"><h2>Readiness summary</h2><span class="muted">safe metadata only</span></div>
            <dl class="facts">
              <div><dt>project alias</dt><dd>{_h(output.label)}</dd></div>
              <div><dt>report_draft.md</dt><dd>{_status_badge(index.report_status)}</dd></div>
              <div><dt>analysis_packet.json</dt><dd>{_status_badge(index.analysis_status)}</dd></div>
              <div><dt>finding candidate count</dt><dd>{index.candidate_count}</dd></div>
              <div><dt>draft report status summary</dt><dd>{_h(_report_readiness_status_summary(index))}</dd></div>
              <div><dt>raw_data_included</dt><dd>false</dd></div>
              <div><dt>file paths shown</dt><dd>false</dd></div>
            </dl>
          </div>
          <div class="panel">
            <div class="panel-head"><h2>Related flow</h2><span class="muted">read-only navigation</span></div>
            <dl class="facts">
              <div><dt>triage link</dt><dd><a href="{_triage_href(output.output_id)}">open finding triage index</a></dd></div>
              <div><dt>preflight link</dt><dd><a href="{_preflight_href(output.output_id)}">open AI-safe preflight</a></dd></div>
              <div><dt>handoff link</dt><dd><a href="{_handoff_href(output.output_id)}">open AI handoff index</a></dd></div>
              <div><dt>export/review/report flow link</dt><dd><a href="{_output_href(output.output_id)}">return to verified output detail</a></dd></div>
              <div><dt>boundary</dt><dd>read-only draft report checklist; no form or POST action</dd></div>
            </dl>
          </div>
          <div class="panel">
            <div class="panel-head"><h2>File metadata</h2><span class="muted">no body preview</span></div>
            <div class="file-grid">{file_rows}</div>
          </div>
          <div class="panel">
            <div class="panel-head"><h2>Operator checklist</h2><span class="muted">manual review required</span></div>
            <ul class="safe-list">{checklist_items}</ul>
          </div>
          <div class="panel">
            <div class="panel-head"><h2>Interpretation boundary</h2><span class="muted">candidate and draft only</span></div>
            <dl class="facts">
              <div><dt>findings</dt><dd>finding candidates until manual verification is complete</dd></div>
              <div><dt>risk</dt><dd>risk is draft, not severity confirmation</dd></div>
              <div><dt>confidence</dt><dd>evidence confidence, not severity</dd></div>
              <div><dt>report draft</dt><dd>report_draft.md is a draft report, not a submission report</dd></div>
              <div><dt>severity decision</dt><dd>final severity is a manual decision</dd></div>
              <div><dt>hash type</dt><dd>SHA-256 file fingerprint, not HMAC</dd></div>
            </dl>
          </div>
          <div class="panel">
            <div class="panel-head"><h2>Do not use in report readiness</h2><span class="muted">categories only; no values are shown</span></div>
            <ul class="safe-list">{forbidden_items}</ul>
          </div>
        </section>
        """,
    )


def render_ai_safe_preflight(preflight: AiSafePreflight) -> str:
    output = preflight.output
    file_rows = "\n".join(
        f"<div><dt>{_h(name)}</dt><dd>{_status_badge(status)}</dd></div>"
        for name, status in preflight.file_statuses
    )
    safe_files = "".join(f"<li>{_h(name)}</li>" for name in SAFE_PREVIEW_FILES)
    forbidden_items = "".join(
        f"<li>{_h(item)}</li>"
        for item in (
            "raw request/response",
            "Cookie or Authorization values",
            "token, JWT, or session values",
            "real domain, URL, or IP values",
            "personal data",
            "HMAC secret or CSRF token values",
            "local-only raw storage or unverified output artifacts",
            "audit logs, archives, or manifests",
        )
    )
    return _page(
        f"AI-safe preflight {output.label}",
        f"""
        <section class="topbar">
          <div>
            <a class="back" href="{_output_href(output.output_id)}">산출물로 돌아가기</a>
            <h1>AI-safe preflight</h1>
            <p class="subtitle">Read-only checklist before ChatGPT or Codex handoff. It shows aliases and status metadata only.</p>
          </div>
          <span class="badge good">read-only</span>
        </section>
        <section class="safety-strip">
          <div class="rail"><span>verify</span><strong>{_h(_status_label("passed"))}</strong></div>
          <div class="rail"><span>handoff</span><strong>{_h(_status_label(preflight.ready_status))}</strong></div>
          <div class="rail"><span>raw data included</span><strong>false</strong></div>
          <div class="rail"><span>final severity</span><strong>manual decision</strong></div>
        </section>
        <section class="grid">
          <div class="panel">
            <div class="panel-head"><h2>Preflight summary</h2><span class="muted">safe metadata only</span></div>
            {_preflight_summary(preflight)}
          </div>
          <div class="panel">
            <div class="panel-head"><h2>Safe files for AI</h2><span class="muted">verify first, manual review required</span></div>
            <dl class="facts">{file_rows}</dl>
            <ul class="safe-list">{safe_files}</ul>
          </div>
          <div class="panel">
            <div class="panel-head"><h2>Do not send</h2><span class="muted">categories only; no values are shown</span></div>
            <ul class="safe-list">{forbidden_items}</ul>
          </div>
          <div class="panel">
            <div class="panel-head"><h2>Interpretation boundary</h2><span class="muted">candidate and draft only</span></div>
            <dl class="facts">
              <div><dt>finding</dt><dd>candidate until manual verification is complete</dd></div>
              <div><dt>risk rating</dt><dd>draft, not final severity</dd></div>
              <div><dt>confidence</dt><dd>evidence confidence, not severity</dd></div>
              <div><dt>CVSS</dt><dd>separate calculation scope</dd></div>
            </dl>
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


def _build_ai_safe_preflight(output: DashboardOutput) -> AiSafePreflight:
    file_statuses: list[tuple[str, str]] = []
    missing_files: list[str] = []
    marker_hits: list[str] = []
    marker_scan_files = 0
    for name in SAFE_PREVIEW_FILES:
        path = output.path / name
        if not path.is_file():
            file_statuses.append((name, "missing"))
            missing_files.append(name)
            continue
        file_statuses.append((name, "present"))
        if path.stat().st_size > MAX_PREVIEW_BYTES:
            marker_hits.append(name)
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        marker_scan_files += 1
        if scan_text(text):
            marker_hits.append(name)

    marker_scan_status = "passed" if not marker_hits else "forbidden_marker_found"
    if marker_hits:
        ready_status = "needs_manual_review"
    elif missing_files:
        ready_status = "missing_safe_files"
    else:
        ready_status = "ready_candidate"
    return AiSafePreflight(
        output=output,
        file_statuses=file_statuses,
        ready_status=ready_status,
        marker_scan_status=marker_scan_status,
        marker_scan_files=marker_scan_files,
        missing_files=missing_files,
        candidate_count=output.candidate_count,
        report_available=output.report_available,
        files_checked=output.verification.files_checked,
    )


def _build_ai_handoff_index(output: DashboardOutput) -> AiHandoffIndex:
    preflight = _build_ai_safe_preflight(output)
    files: list[HandoffFile] = []
    for index, name in enumerate(SAFE_PREVIEW_FILES, start=1):
        path = output.path / name
        if not path.is_file():
            files.append(
                HandoffFile(
                    name=name,
                    order=index,
                    purpose=_safe_handoff_purpose(name),
                    status="missing",
                    size_bytes=None,
                    modified_utc="missing",
                    sha256="missing",
                )
            )
            continue
        stat = path.stat()
        files.append(
            HandoffFile(
                name=name,
                order=index,
                purpose=_safe_handoff_purpose(name),
                status="present",
                size_bytes=stat.st_size,
                modified_utc=datetime.fromtimestamp(stat.st_mtime, UTC).replace(microsecond=0).isoformat(),
                sha256=_sha256_file(path),
            )
        )
    return AiHandoffIndex(output=output, preflight=preflight, files=files)


def _build_finding_triage_index(output: DashboardOutput) -> FindingTriageIndex:
    candidates = [
        _triage_candidate_from_json(index, candidate)
        for index, candidate in enumerate(_load_candidates(output.path), start=1)
    ]
    return FindingTriageIndex(
        output=output,
        candidates=candidates,
        analysis_packet_status="present" if (output.path / "analysis_packet.json").is_file() else "missing",
        report_draft_status="present" if (output.path / "report_draft.md").is_file() else "missing",
    )


def _build_report_readiness_index(output: DashboardOutput) -> ReportReadinessIndex:
    files = [
        _report_readiness_file(output.path, "report_draft.md", "Draft report text for manual review."),
        _report_readiness_file(output.path, "analysis_packet.json", "Structured sanitized candidate evidence packet."),
    ]
    report_status = "present" if (output.path / "report_draft.md").is_file() else "missing"
    analysis_status = "present" if (output.path / "analysis_packet.json").is_file() else "missing"
    return ReportReadinessIndex(
        output=output,
        files=files,
        candidate_count=output.candidate_count,
        report_status=report_status,
        analysis_status=analysis_status,
    )


def _report_readiness_file(output_dir: Path, name: str, purpose: str) -> ReportReadinessFile:
    path = output_dir / name
    if not path.is_file():
        return ReportReadinessFile(
            name=name,
            purpose=purpose,
            status="missing",
            size_bytes=None,
            modified_utc="missing",
            sha256="missing",
        )
    stat = path.stat()
    return ReportReadinessFile(
        name=name,
        purpose=purpose,
        status="present",
        size_bytes=stat.st_size,
        modified_utc=datetime.fromtimestamp(stat.st_mtime, UTC).replace(microsecond=0).isoformat(),
        sha256=_sha256_file(path),
    )


def _report_readiness_status_summary(index: ReportReadinessIndex) -> str:
    if index.report_status == "present" and index.analysis_status == "present":
        return "draft present; manual review required before customer submission"
    if index.report_status == "missing":
        return "draft missing; run Report after verified review output"
    return "analysis packet missing; regenerate verified output before report review"


def _triage_candidate_from_json(index: int, candidate: dict[str, Any]) -> TriageCandidate:
    risk_rating = candidate.get("risk_rating_draft")
    risk = risk_rating if isinstance(risk_rating, dict) else {}
    title = _safe_value(candidate.get("title"), "Finding candidate")
    category = _safe_value(candidate.get("type"), "unknown_type")
    endpoint = _safe_value(candidate.get("affected_endpoint"), "sanitized endpoint unavailable")
    summary = f"{title}; sanitized endpoint template: {endpoint}"
    return TriageCandidate(
        index=index,
        candidate_id=_safe_value(candidate.get("finding_id") or candidate.get("candidate_id"), f"candidate-{index}"),
        category=category,
        title=title,
        summary=_safe_value(summary, "Sanitized candidate summary unavailable."),
        confidence=_safe_value(candidate.get("confidence"), "unknown"),
        severity_draft=_safe_value(risk.get("severity_draft"), "unknown"),
        likelihood_draft=_safe_value(risk.get("likelihood_draft"), "unknown"),
        impact_draft=_safe_value(risk.get("impact_draft"), "unknown"),
        risk_profile=_safe_value(risk.get("risk_profile"), DEFAULT_RISK_RATING_PROFILE),
        manual_required=bool(candidate.get("manual_verification_required", True)),
    )


def _handoff_summary(index: AiHandoffIndex) -> str:
    present_count = sum(1 for file in index.files if file.status == "present")
    return f"""
    <dl class="facts">
      <div><dt>handoff status</dt><dd>{_status_badge(index.preflight.ready_status)}</dd></div>
      <div><dt>safe file count</dt><dd>{present_count}/{len(SAFE_PREVIEW_FILES)}</dd></div>
      <div><dt>verify status</dt><dd>{_status_badge("passed")}</dd></div>
      <div><dt>preflight status</dt><dd>{_status_badge(index.preflight.ready_status)}</dd></div>
      <div><dt>forbidden marker scan</dt><dd>{_status_badge(index.preflight.marker_scan_status)}</dd></div>
      <div><dt>finding candidate count</dt><dd>{index.preflight.candidate_count}</dd></div>
      <div><dt>raw_data_included</dt><dd>false</dd></div>
      <div><dt>file paths shown</dt><dd>false</dd></div>
      <div><dt>hash type</dt><dd>SHA-256 file fingerprint, not HMAC</dd></div>
    </dl>
    """


def _handoff_file_card(file: HandoffFile) -> str:
    size = str(file.size_bytes) if file.size_bytes is not None else "missing"
    return f"""
    <article class="file-card">
      <div>
        <span class="kicker">order {file.order}</span>
        <strong>{_h(file.name)}</strong>
        <span>{_status_badge(file.status)}</span>
        <small>{_h(file.purpose)}</small>
      </div>
      <dl class="facts compact">
        <div><dt>purpose</dt><dd>{_h(file.purpose)}</dd></div>
        <div><dt>size bytes</dt><dd>{_h(size)}</dd></div>
        <div><dt>modified UTC</dt><dd>{_h(file.modified_utc)}</dd></div>
        <div><dt>SHA-256</dt><dd>{_h(file.sha256)}</dd></div>
      </dl>
    </article>
    """


def _report_readiness_file_card(file: ReportReadinessFile) -> str:
    size = str(file.size_bytes) if file.size_bytes is not None else "missing"
    return f"""
    <article class="file-card">
      <div>
        <span class="kicker">report readiness metadata</span>
        <strong>{_h(file.name)}</strong>
        <span>{_status_badge(file.status)}</span>
        <small>{_h(file.purpose)}</small>
      </div>
      <dl class="facts compact">
        <div><dt>purpose</dt><dd>{_h(file.purpose)}</dd></div>
        <div><dt>exists or missing</dt><dd>{_h(file.status)}</dd></div>
        <div><dt>file size in bytes</dt><dd>{_h(size)}</dd></div>
        <div><dt>modified UTC timestamp</dt><dd>{_h(file.modified_utc)}</dd></div>
        <div><dt>SHA-256 file fingerprint</dt><dd>{_h(file.sha256)}</dd></div>
      </dl>
    </article>
    """


def _triage_candidate_card(candidate: TriageCandidate) -> str:
    manual_required = str(candidate.manual_required).lower()
    return f"""
    <article class="candidate">
      <div class="candidate-head">
        <div>
          <span class="kicker">candidate #{candidate.index}</span>
          <h3>{_h(candidate.candidate_id)} - {_h(candidate.title)}</h3>
          <p>{_h(candidate.category)}</p>
        </div>
        <div class="status-stack">
          <span class="badge neutral">confidence: {_h(candidate.confidence)}</span>
          <span class="badge warning">manual review required</span>
        </div>
      </div>
      <dl class="facts compact">
        <div><dt>stable id</dt><dd>{_h(candidate.candidate_id)}</dd></div>
        <div><dt>category/type</dt><dd>{_h(candidate.category)}</dd></div>
        <div><dt>sanitized summary</dt><dd>{_h(candidate.summary)}</dd></div>
        <div><dt>draft risk</dt><dd>profile: {_h(candidate.risk_profile)}; severity draft: {_h(candidate.severity_draft)}; likelihood draft: {_h(candidate.likelihood_draft)}; impact draft: {_h(candidate.impact_draft)}</dd></div>
        <div><dt>confidence</dt><dd>{_h(candidate.confidence)} evidence confidence, not severity</dd></div>
        <div><dt>manual verification required</dt><dd>{_h(manual_required)}</dd></div>
        <div><dt>final severity</dt><dd>final severity requires manual decision</dd></div>
      </dl>
    </article>
    """


def _preflight_summary(preflight: AiSafePreflight) -> str:
    missing = ", ".join(preflight.missing_files) if preflight.missing_files else "none"
    report_status = "present" if preflight.report_available else "missing"
    return f"""
    <dl class="facts">
      <div><dt>preflight status</dt><dd>{_status_badge(preflight.ready_status)}</dd></div>
      <div><dt>verify status</dt><dd>{_status_badge("passed")}</dd></div>
      <div><dt>verify files checked</dt><dd>{preflight.files_checked}</dd></div>
      <div><dt>finding candidate count</dt><dd>{preflight.candidate_count}</dd></div>
      <div><dt>report_draft.md</dt><dd>{_status_badge(report_status)}</dd></div>
      <div><dt>forbidden marker scan</dt><dd>{_status_badge(preflight.marker_scan_status)}</dd></div>
      <div><dt>marker scanned safe files</dt><dd>{preflight.marker_scan_files}</dd></div>
      <div><dt>missing safe files</dt><dd>{_h(missing)}</dd></div>
      <div><dt>raw_data_included</dt><dd>false</dd></div>
    </dl>
    """


def _safe_handoff_purpose(file_name: str) -> str:
    purposes = {
        "analysis_packet.json": "Read first for structured sanitized candidate evidence.",
        "chatgpt_prompt.md": "Use when asking ChatGPT for manual-review assistance.",
        "codex_task_prompt.md": "Use when asking Codex for implementation or review assistance.",
        "report_draft.md": "Read last as a candidate report draft for human review.",
    }
    return purposes.get(file_name, "AI-safe candidate file metadata.")


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


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
    audit_log = audit_dir / AUDIT_FILE_NAME if audit_dir.is_dir() else root / AUDIT_FILE_NAME
    retained = audit_dir / "mcp_audit.retained.jsonl"
    retained_manifest = audit_dir / "mcp_audit.retained.manifest.json"
    archive = audit_dir / "mcp_audit.retained.jsonl.gz"
    archive_manifest = audit_dir / "mcp_audit.retained.jsonl.gz.manifest.json"
    status = {
        "review_status": "not found",
        "audit_log_status": "not found",
        "events": "0",
        "files": "0",
        "retained_status": "not found",
        "hmac_status": "not configured",
        "archive_status": "not found",
        "archive_verify_status": "not found",
        "archive_hmac_manifest_status": "not found",
        "archive_hmac_status": "not configured",
    }
    if audit_log.is_file():
        status["audit_log_status"] = "present"
    if audit_dir.is_dir() or audit_log.is_file():
        try:
            review = review_audit_path(audit_log if audit_log.is_file() else audit_dir)
            status["review_status"] = "passed" if review.passed else "failed"
            status["events"] = str(review.events_checked)
            status["files"] = str(review.files_checked)
        except ValueError:
            status["review_status"] = "failed"

    if retained.is_file():
        try:
            retained_review = review_audit_path(retained)
            status["retained_status"] = "passed" if retained_review.passed else "failed"
        except ValueError:
            status["retained_status"] = "failed"

    if retained_manifest.is_file():
        status["hmac_status"] = _hmac_status(retained, retained_manifest)
    if archive.is_file():
        status["archive_status"] = "present"
        status["archive_verify_status"] = _compressed_archive_status(archive)
    if archive_manifest.is_file():
        status["archive_hmac_manifest_status"] = "present"
        status["archive_hmac_status"] = _compressed_archive_hmac_status(archive, archive_manifest)
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


def _compressed_archive_status(archive_file: Path) -> str:
    try:
        verify_compressed_audit_jsonl(archive_file)
    except AuditCompressionError as error:
        return _safe_error_type(error.error_type)
    return "passed"


def _compressed_archive_hmac_status(archive_file: Path, manifest_file: Path) -> str:
    if not archive_file.is_file():
        return "input_missing"
    try:
        secret = load_hmac_secret()
        verify_compressed_audit_hmac_manifest(archive_file, manifest_file, secret=secret)
    except (AuditCompressedHmacError, AuditHmacError) as error:
        return _safe_error_type(error.error_type)
    return "passed"


def _hmac_configured_label() -> str:
    return "configured" if os.environ.get(DEFAULT_HMAC_ENV_VAR) else "not configured"


def _safe_root_alias(root: Path) -> str:
    alias = root.resolve().name or "dashboard_root"
    return "redacted_root" if scan_text(alias) else alias


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


def _guide_card(title: str, path: str, description: str) -> str:
    return f"""
    <div class="file-card">
      <div>
        <strong>{_h(title)}</strong>
        <span>{_h(path)}</span>
        <small>{_h(description)}</small>
      </div>
    </div>
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
    risk_profile = _safe_value(value.get("risk_profile"), DEFAULT_RISK_RATING_PROFILE)
    finalized = str(bool(value.get("risk_rating_finalized", False))).lower()
    return (
        f"profile: {_h(risk_profile)}; "
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
      <div><dt>compressed archive</dt><dd>{_status_badge(status["archive_status"])}</dd></div>
      <div><dt>compressed archive verify</dt><dd>{_status_badge(status["archive_verify_status"])}</dd></div>
      <div><dt>compressed archive HMAC manifest</dt><dd>{_status_badge(status["archive_hmac_manifest_status"])}</dd></div>
      <div><dt>compressed archive HMAC verify</dt><dd>{_status_badge(status["archive_hmac_status"])}</dd></div>
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
    if value in {"passed", "present", "ready_candidate"}:
        return f'<span class="badge good">{safe}</span>'
    if _is_error_status(value):
        return f'<span class="badge danger">{safe}</span>'
    return f'<span class="badge neutral">{safe}</span>'


def _is_error_status(value: str) -> bool:
    return (
        value in {"failed", "input_missing", "missing", "missing_safe_files", "forbidden_marker_found"}
        or value.endswith("_missing")
        or value.endswith("_failed")
        or value.endswith("_mismatch")
        or value.endswith("_forbidden")
        or value.startswith("invalid_")
        or value.startswith("compressed_")
        or value.startswith("manifest_")
    )


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
        "present": "present",
        "missing": "missing",
        "ready_candidate": "ready candidate",
        "missing_safe_files": "missing safe files",
        "needs_manual_review": "needs manual review",
        "forbidden_marker_found": "forbidden marker found",
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


def _preflight_href(output_id: str) -> str:
    return "/preflight?project=" + quote(output_id, safe="")


def _handoff_href(output_id: str) -> str:
    return "/handoff?project=" + quote(output_id, safe="")


def _triage_href(output_id: str) -> str:
    return "/triage?project=" + quote(output_id, safe="")


def _report_readiness_href(output_id: str) -> str:
    return "/report-readiness?project=" + quote(output_id, safe="")


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
    .safe-list {{ display: grid; gap: 8px; color: var(--text); }}
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
