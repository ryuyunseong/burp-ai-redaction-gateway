from __future__ import annotations

import html
import hashlib
import json
import os
import re
import secrets
import threading
from dataclasses import dataclass
from datetime import UTC, datetime
from email import policy as email_policy
from email.parser import BytesParser
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, quote, urlsplit

from .findings import build_finding_candidates
from .http_server import ExclusiveThreadingHTTPServer
from .audit_compressed_hmac import AuditCompressedHmacError, verify_compressed_audit_hmac_manifest
from .audit_compression import AuditCompressionError, verify_compressed_audit_jsonl
from .audit_hmac import DEFAULT_HMAC_ENV_VAR, AuditHmacError, load_hmac_secret, verify_audit_hmac_manifest
from .audit_review import review_audit_path
from .live_capture_scope import (
    LIVE_CAPTURE_SCOPE_MAX_LENGTH,
    LiveCaptureScopeError,
    live_capture_scope_alias,
)
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
from .output import write_outputs
from .parser import load_events
from .policy import RedactionPolicy, load_policy
from .report import DEFAULT_REPORT_PROFILE, REPORT_PROFILE_NAMES, write_report_draft
from .review import build_review, render_review_summary
from .risk import DEFAULT_RISK_RATING_PROFILE, RISK_RATING_PROFILE_NAMES
from .redaction import Redactor
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
SAFE_FILE_PURPOSES = (
    ("analysis_packet.json", "고급 산출물: 구조화된 분석 packet"),
    ("chatgpt_prompt.md", "기본 보기: ChatGPT용 프롬프트"),
    ("codex_task_prompt.md", "고급 산출물: Codex 작업 프롬프트"),
    ("report_draft.md", "기본 보기: 보고서 초안"),
)
OUTPUT_MARKER_FILE = "analysis_packet.json"
FINDINGS_FILE = "finding_candidates.json"
MAX_PREVIEW_BYTES = 1024 * 1024
MAX_FORM_BYTES = 16 * 1024
MAX_UPLOAD_BYTES = 10 * 1024 * 1024
MAX_UPLOAD_FORM_BYTES = MAX_UPLOAD_BYTES + 16 * 1024
ACTION_NAMES = {"verify", "review", "report", "export"}
LIVE_CAPTURE_ACTION_NAMES = {"live_capture_start", "live_capture_stop"}
AUDIT_ACTION_NAMES = ACTION_NAMES | {"upload"} | LIVE_CAPTURE_ACTION_NAMES
UPLOAD_PROJECT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
UPLOAD_ALLOWED_SUFFIXES = {".xml", ".json"}
OPERATIONS_GUIDES = (
    ("빠른 시작", "docs/USER_QUICKSTART.md", "receiver, Burp 전송, dashboard 실행 흐름"),
    ("GUI 사용자 흐름", "docs/GUI_USER_FLOW.md", "처음 실행부터 AI 투입 전까지의 화면 흐름"),
    ("Live Capture 세션 placeholder", "docs/LIVE_CAPTURE_WIZARD_DESIGN_v0.5.md", "v0.5 live capture 세션 상태와 start/stop placeholder 경계"),
    ("Upload Wizard", "docs/GUI_UPLOAD_WIZARD.md", "dashboard에서 local Burp export를 처리하는 v0.5 진입점"),
    ("간단 대시보드", "docs/GUI_SIMPLE_DASHBOARD.md", "처음 보는 사용자를 위한 read-only 상태 요약"),
    ("AI 안전 사전 점검", "docs/GUI_AI_SAFE_PREFLIGHT.md", "AI 투입 전 조회 전용 상태 확인"),
    ("AI 핸드오프 인덱스", "docs/GUI_AI_HANDOFF_INDEX.md", "AI 투입 파일 순서와 주의사항"),
    ("Prompt readiness 인덱스", "docs/GUI_PROMPT_READINESS_INDEX.md", "prompt 파일 투입 전 조회 전용 점검"),
    ("Evidence boundary 인덱스", "docs/GUI_EVIDENCE_BOUNDARY_INDEX.md", "정제 증거와 raw 금지 범위의 조회 전용 경계"),
    ("Operator runbook 인덱스", "docs/GUI_OPERATOR_RUNBOOK_INDEX.md", "수집부터 AI 투입 전 수동 검토까지 운영 순서 점검"),
    ("Safe file inventory 인덱스", "docs/GUI_SAFE_FILE_INVENTORY_INDEX.md", "AI 후보 파일 4개의 안전 metadata 점검"),
    ("Finding 후보 분류 인덱스", "docs/GUI_FINDING_TRIAGE_INDEX.md", "finding 후보 검토 순서와 수동 판단 경계"),
    ("보고서 준비 인덱스", "docs/GUI_REPORT_READINESS_INDEX.md", "report_draft 초안 검토 상태와 수동 제출 경계"),
    ("작업 흐름 상태 인덱스", "docs/GUI_WORKFLOW_STATUS_INDEX.md", "검증된 산출물의 조회 전용 작업 흐름 점검"),
    ("Windows 실행기", "docs/WINDOWS_LAUNCHER_GUIDE.md", "start/stop 스크립트와 포트 충돌 처리"),
    ("감사 운영", "docs/AUDIT_OPERATIONS_GUIDE.md", "review-audit, retention, HMAC, archive 순서"),
    ("GUI 감사 패널", "docs/GUI_AUDIT_PANEL_GUIDE.md", "감사/보관 상태 표시 해석"),
    ("위험도 초안", "docs/RISK_RATING_GUIDE.md", "risk profile과 수동 severity 결정"),
    ("v0.4 릴리스", "docs/RELEASE_NOTES_v0.4.md", "dashboard 계열 변경 기준선"),
)
FORBIDDEN_AI_ITEMS = (
    "raw 요청/응답",
    "Cookie 값",
    "Authorization 값",
    "token/JWT/session 값",
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
class UploadWizardForm:
    project_alias: str
    upload_file_name: str
    upload_bytes: bytes
    csrf_token: str


@dataclass(frozen=True)
class UploadWizardResult:
    status: str
    project_alias: str
    output_id: str
    title: str
    summary_lines: list[str]
    stage_statuses: list[tuple[str, str]]
    candidate_count: int = 0
    safe_files_present: tuple[str, ...] = ()
    files_checked: int = 0
    blocked_reason: str = ""
    raw_data_included: bool = False


@dataclass(frozen=True)
class LiveCaptureSession:
    status: str
    session_alias: str = "none"
    target_alias: str = "none"
    updated_at_utc: str = ""


@dataclass(frozen=True)
class LiveCaptureActionResult:
    action_name: str
    status: str
    session: LiveCaptureSession
    summary_lines: list[str]
    blocked_reason: str = ""


@dataclass(frozen=True)
class LiveCaptureReceiverOutputEvidence:
    evidence_source: str
    receiver_output_alias: str
    receiver_verify_status: str
    safe_file_existence_status: str
    candidate_count: int
    raw_data_included: bool
    safe_navigation_available: bool


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


@dataclass(frozen=True)
class PromptReadinessFile:
    name: str
    purpose: str
    status: str
    size_bytes: int | None
    modified_utc: str
    sha256: str


@dataclass(frozen=True)
class PromptReadinessCheck:
    name: str
    status: str
    summary: str


@dataclass(frozen=True)
class PromptReadinessIndex:
    output: DashboardOutput
    files: list[PromptReadinessFile]
    checks: list[PromptReadinessCheck]
    prompt_status: str
    chatgpt_status: str
    codex_status: str
    safe_file_count: int


@dataclass(frozen=True)
class EvidenceBoundaryFile:
    name: str
    purpose: str
    status: str
    size_bytes: int | None
    modified_utc: str
    sha256: str


@dataclass(frozen=True)
class EvidenceBoundaryIndex:
    output: DashboardOutput
    files: list[EvidenceBoundaryFile]
    candidate_count: int
    sanitized_evidence_status: str
    finding_candidate_status: str
    analysis_status: str
    report_status: str
    chatgpt_status: str
    codex_status: str
    safe_file_count: int


@dataclass(frozen=True)
class WorkflowStep:
    name: str
    status: str
    summary: str
    href: str


@dataclass(frozen=True)
class WorkflowStatusIndex:
    output: DashboardOutput
    file_statuses: list[tuple[str, str]]
    steps: list[WorkflowStep]
    candidate_count: int
    review_status: str
    report_status: str
    analysis_status: str


@dataclass(frozen=True)
class OperatorRunbookStep:
    order: int
    name: str
    status: str
    purpose: str
    safe_metadata: tuple[str, ...]
    href: str


@dataclass(frozen=True)
class OperatorRunbookIndex:
    output: DashboardOutput
    file_statuses: list[tuple[str, str]]
    steps: list[OperatorRunbookStep]
    candidate_count: int
    review_status: str
    report_status: str
    analysis_status: str
    safe_file_count: int


@dataclass(frozen=True)
class SafeFileInventoryFile:
    name: str
    purpose: str
    recommended_use: str
    verify_required: bool
    status: str
    size_bytes: int | None
    modified_utc: str
    sha256: str


@dataclass(frozen=True)
class SafeFileInventoryIndex:
    output: DashboardOutput
    files: list[SafeFileInventoryFile]
    candidate_count: int
    safe_file_count: int
    report_status: str
    analysis_status: str


class DashboardError(ValueError):
    def __init__(self, error_type: str, status: HTTPStatus = HTTPStatus.BAD_REQUEST) -> None:
        super().__init__(error_type)
        self.error_type = error_type
        self.status = status


class DashboardHttpServer(ExclusiveThreadingHTTPServer):
    def __init__(self, server_address: tuple[str, int], config: DashboardConfig, policy: RedactionPolicy) -> None:
        validated_root = _validated_root(config.root)
        super().__init__(server_address, DashboardRequestHandler)
        self.config = DashboardConfig(root=validated_root, policy_path=config.policy_path)
        self.policy = policy
        self.csrf_token = secrets.token_hex(16)
        self.live_capture_lock = threading.Lock()
        self.live_capture_session = LiveCaptureSession(status="idle", updated_at_utc=_utc_now())


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
            if parsed.path == "/live-capture":
                output_id = _optional_query_value(parsed.query, "project")
                output = _verified_output(self.server.config.root, self.server.policy, output_id) if output_id else None
                alias_selector = _render_output_alias_selector(
                    self.server.config.root,
                    self.server.policy,
                    output.output_id if output else "",
                )
                self._send_html(
                    render_live_capture_readiness(
                        self.server.csrf_token,
                        self.server.live_capture_session,
                        output=output,
                        alias_selector_html=alias_selector,
                    )
                )
                return
            if parsed.path == "/upload":
                self._send_html(render_upload_wizard(self.server.csrf_token))
                return
            if parsed.path == "/output":
                output_id = _required_query_value(parsed.query, "project")
                output = _verified_output(self.server.config.root, self.server.policy, output_id)
                self._send_html(render_output_detail(output, self.server.csrf_token))
                return
            if parsed.path in {"/simple", "/dashboard-simple"}:
                output_id = _required_query_value(parsed.query, "project")
                output = _verified_output(self.server.config.root, self.server.policy, output_id)
                self._send_html(render_simple_dashboard(output))
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
                alias_selector = _render_output_alias_selector(self.server.config.root, self.server.policy, output.output_id)
                self._send_html(
                    render_finding_triage_index(_build_finding_triage_index(output), alias_selector_html=alias_selector)
                )
                return
            if parsed.path == "/report-readiness":
                output_id = _required_query_value(parsed.query, "project")
                output = _verified_output(self.server.config.root, self.server.policy, output_id)
                alias_selector = _render_output_alias_selector(self.server.config.root, self.server.policy, output.output_id)
                self._send_html(
                    render_report_readiness_index(
                        _build_report_readiness_index(output),
                        alias_selector_html=alias_selector,
                    )
                )
                return
            if parsed.path == "/prompt-readiness":
                output_id = _required_query_value(parsed.query, "project")
                output = _verified_output(self.server.config.root, self.server.policy, output_id)
                self._send_html(render_prompt_readiness_index(_build_prompt_readiness_index(output)))
                return
            if parsed.path == "/evidence-boundary":
                output_id = _required_query_value(parsed.query, "project")
                output = _verified_output(self.server.config.root, self.server.policy, output_id)
                self._send_html(render_evidence_boundary_index(_build_evidence_boundary_index(output)))
                return
            if parsed.path == "/workflow":
                output_id = _required_query_value(parsed.query, "project")
                output = _verified_output(self.server.config.root, self.server.policy, output_id)
                alias_selector = _render_output_alias_selector(self.server.config.root, self.server.policy, output.output_id)
                self._send_html(
                    render_workflow_status_index(_build_workflow_status_index(output), alias_selector_html=alias_selector)
                )
                return
            if parsed.path == "/operator-runbook":
                output_id = _required_query_value(parsed.query, "project")
                output = _verified_output(self.server.config.root, self.server.policy, output_id)
                self._send_html(render_operator_runbook_index(_build_operator_runbook_index(output)))
                return
            if parsed.path == "/safe-files":
                output_id = _required_query_value(parsed.query, "project")
                output = _verified_output(self.server.config.root, self.server.policy, output_id)
                alias_selector = _render_output_alias_selector(self.server.config.root, self.server.policy, output.output_id)
                self._send_html(
                    render_safe_file_inventory_index(
                        _build_safe_file_inventory_index(output),
                        alias_selector_html=alias_selector,
                    )
                )
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
            if parsed.path == "/upload":
                form = self._read_upload_form()
                action_for_audit = "upload"
                output_for_audit = form.project_alias or "unknown_output"
                if not form.csrf_token:
                    self._write_dashboard_audit_event(
                        "upload",
                        output_for_audit,
                        result_status="blocked",
                        blocked_reason="csrf_missing",
                    )
                    audit_written = True
                    raise DashboardError("csrf_token_missing", HTTPStatus.BAD_REQUEST)
                try:
                    _validate_csrf(form.csrf_token, self.server.csrf_token)
                except DashboardError:
                    self._write_dashboard_audit_event(
                        "upload",
                        output_for_audit,
                        result_status="blocked",
                        blocked_reason="csrf_invalid",
                    )
                    audit_written = True
                    raise
                result = run_upload_wizard(self.server.config.root, self.server.policy, form)
                self._write_dashboard_audit_event(
                    "upload",
                    result.project_alias,
                    result_status="success" if result.status == "passed" else "blocked",
                    blocked_reason=result.blocked_reason,
                )
                audit_written = True
                self._send_html(render_upload_result(result, self.server.csrf_token))
                return
            if parsed.path in {"/live-capture/start", "/live-capture/stop"}:
                self._handle_live_capture_post(parsed.path)
                return
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
            if not audit_written and self.path.startswith(("/action", "/upload", "/live-capture")):
                self._write_dashboard_audit_event(
                    action_for_audit,
                    output_for_audit,
                    result_status=_dashboard_error_status(error.error_type),
                    blocked_reason=_dashboard_error_blocked_reason(error.error_type),
                    error_type=error.error_type,
                )
            self._send_error(error.error_type, error.status)
        except OSError:
            if not audit_written and self.path.startswith(("/action", "/upload", "/live-capture")):
                self._write_dashboard_audit_event(
                    action_for_audit,
                    output_for_audit,
                    result_status="error",
                    error_type="dashboard_action_file_access_failed",
                )
            self._send_error("dashboard_action_file_access_failed", HTTPStatus.INTERNAL_SERVER_ERROR)
        except ValueError:
            if not audit_written and self.path.startswith(("/action", "/upload", "/live-capture")):
                self._write_dashboard_audit_event(
                    action_for_audit,
                    output_for_audit,
                    result_status="error",
                    error_type="dashboard_action_failed",
                )
            self._send_error("dashboard_action_failed", HTTPStatus.BAD_REQUEST)

    def _handle_live_capture_post(self, path: str) -> None:
        form = self._read_form()
        action_name = "live_capture_start" if path.endswith("/start") else "live_capture_stop"
        csrf_token = _optional_form_value(form, "csrf_token")
        if not csrf_token:
            self._write_dashboard_audit_event(
                action_name,
                "live_capture",
                result_status="blocked",
                blocked_reason="csrf_missing",
            )
            self._send_error("csrf_token_missing", HTTPStatus.BAD_REQUEST)
            return
        try:
            _validate_csrf(csrf_token, self.server.csrf_token)
        except DashboardError:
            self._write_dashboard_audit_event(
                action_name,
                "live_capture",
                result_status="blocked",
                blocked_reason="csrf_invalid",
            )
            self._send_error("csrf_token_invalid", HTTPStatus.FORBIDDEN)
            return

        if action_name == "live_capture_start":
            result = run_live_capture_start_placeholder(self.server, _optional_form_value(form, "target"))
        else:
            result = run_live_capture_stop_placeholder(self.server)
        self._write_dashboard_audit_event(
            action_name,
            result.session.session_alias,
            result_status=_live_capture_result_status(result),
            blocked_reason=result.blocked_reason,
        )
        status = HTTPStatus.OK
        if result.blocked_reason.startswith("invalid_target"):
            status = HTTPStatus.BAD_REQUEST
        elif result.blocked_reason:
            status = HTTPStatus.CONFLICT
        self._send_html(render_live_capture_readiness(self.server.csrf_token, result.session, result), status)

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

    def _read_upload_form(self) -> UploadWizardForm:
        length_text = self.headers.get("Content-Length", "0")
        try:
            length = int(length_text)
        except ValueError as error:
            raise DashboardError("invalid_content_length", HTTPStatus.BAD_REQUEST) from error
        if length <= 0:
            raise DashboardError("empty_form", HTTPStatus.BAD_REQUEST)
        if length > MAX_UPLOAD_FORM_BYTES:
            raise DashboardError("upload_too_large", HTTPStatus.REQUEST_ENTITY_TOO_LARGE)
        content_type = self.headers.get("Content-Type", "")
        if "multipart/form-data" not in content_type:
            raise DashboardError("unsupported_upload_content_type", HTTPStatus.UNSUPPORTED_MEDIA_TYPE)
        raw_body = self.rfile.read(length)
        message = BytesParser(policy=email_policy.default).parsebytes(
            b"Content-Type: "
            + content_type.encode("utf-8", errors="replace")
            + b"\r\nMIME-Version: 1.0\r\n\r\n"
            + raw_body
        )
        fields: dict[str, str] = {}
        upload_file_name = ""
        upload_bytes = b""
        for part in message.iter_parts():
            if part.get_content_disposition() != "form-data":
                continue
            name = part.get_param("name", header="content-disposition") or ""
            filename = part.get_filename() or ""
            payload = part.get_payload(decode=True) or b""
            if name == "burp_export":
                upload_file_name = filename
                upload_bytes = payload
            elif name in {"project", "csrf_token"}:
                fields[name] = payload.decode("utf-8", errors="replace").strip()
        return UploadWizardForm(
            project_alias=fields.get("project", ""),
            upload_file_name=upload_file_name,
            upload_bytes=upload_bytes,
            csrf_token=fields.get("csrf_token", ""),
        )

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
    try:
        return DashboardHttpServer((host, port), config, policy)
    except OSError:
        raise DashboardError("port_unavailable", HTTPStatus.SERVICE_UNAVAILABLE) from None


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


def run_upload_wizard(root: Path, policy: RedactionPolicy, form: UploadWizardForm) -> UploadWizardResult:
    project_alias = _safe_upload_project_alias(form.project_alias)
    suffix = _safe_upload_suffix(form.upload_file_name)
    if not form.upload_bytes:
        raise DashboardError("upload_validation_failed", HTTPStatus.BAD_REQUEST)
    if len(form.upload_bytes) > MAX_UPLOAD_BYTES:
        raise DashboardError("upload_too_large", HTTPStatus.REQUEST_ENTITY_TOO_LARGE)

    output_dir = _upload_output_dir(root, project_alias)
    if output_dir.exists():
        raise DashboardError("upload_output_exists", HTTPStatus.CONFLICT)

    upload_dir = _upload_storage_dir(root)
    upload_dir.mkdir(parents=True, exist_ok=True)
    upload_path = upload_dir / _internal_upload_file_name(project_alias, suffix)
    upload_path.write_bytes(form.upload_bytes)

    stage_statuses: list[tuple[str, str]] = [
        ("upload validation", "passed"),
        ("raw local storage", "stored under local_only alias"),
    ]
    try:
        raw_events = load_events(upload_path)
        redactor = Redactor(policy)
        sanitized = [redactor.sanitize_event(event, index) for index, event in enumerate(raw_events, start=1)]
        findings = build_finding_candidates(sanitized, DEFAULT_RISK_RATING_PROFILE)
        write_outputs(project_alias, output_dir, sanitized, findings, policy)
        stage_statuses.append(("redaction/generate", "passed"))
    except (OSError, SyntaxError, ValueError):
        stage_statuses.append(("redaction/generate", "failed"))
        stage_statuses.append(("verify", "skipped"))
        stage_statuses.append(("review", "skipped"))
        stage_statuses.append(("report", "skipped"))
        return UploadWizardResult(
            status="failed",
            project_alias=project_alias,
            output_id=project_alias,
            title="업로드 처리 실패",
            summary_lines=[
                "generate failed",
                "원본 값이나 파일 경로는 표시하지 않습니다.",
                "검증 전 산출물은 AI 입력 후보가 아닙니다.",
            ],
            stage_statuses=stage_statuses,
            blocked_reason="generate_failed",
        )

    verification = verify_path(output_dir, policy)
    if not verification.passed:
        stage_statuses.append(("verify", "failed safely"))
        stage_statuses.append(("review", "skipped"))
        stage_statuses.append(("report", "skipped"))
        return UploadWizardResult(
            status="failed",
            project_alias=project_alias,
            output_id=project_alias,
            title="검증 실패",
            summary_lines=[
                "verify failed safely",
                f"검증한 파일 수: {verification.files_checked}.",
                "safe files are hidden because verification did not pass.",
                "원본 값이나 탐지 문자열은 표시하지 않습니다.",
            ],
            stage_statuses=stage_statuses,
            files_checked=verification.files_checked,
            blocked_reason="verify_failed",
        )
    stage_statuses.append(("verify", "passed"))

    try:
        review_result = build_review(output_dir, policy)
        stage_statuses.append(("review", "passed"))
    except ValueError:
        stage_statuses.append(("review", "failed"))
        stage_statuses.append(("report", "skipped"))
        return UploadWizardResult(
            status="failed",
            project_alias=project_alias,
            output_id=project_alias,
            title="리뷰 실패",
            summary_lines=[
                "review failed",
                "safe files are hidden because the workflow did not complete.",
                "원본 값이나 파일 경로는 표시하지 않습니다.",
            ],
            stage_statuses=stage_statuses,
            files_checked=verification.files_checked,
            blocked_reason="review_failed",
        )

    try:
        report_result = write_report_draft(output_dir, None, policy, DEFAULT_REPORT_PROFILE)
        stage_statuses.append(("report", "passed"))
    except ValueError:
        stage_statuses.append(("report", "failed"))
        return UploadWizardResult(
            status="failed",
            project_alias=project_alias,
            output_id=project_alias,
            title="보고서 초안 실패",
            summary_lines=[
                "report skipped",
                "safe files are hidden because report generation did not complete.",
                "원본 값이나 파일 경로는 표시하지 않습니다.",
            ],
            stage_statuses=stage_statuses,
            files_checked=verification.files_checked,
            blocked_reason="report_failed",
        )

    refreshed = _verified_output(root, policy, project_alias)
    safe_files = tuple(name for name in SAFE_PREVIEW_FILES if (output_dir / name).is_file())
    return UploadWizardResult(
        status="passed",
        project_alias=project_alias,
        output_id=refreshed.output_id,
        title="업로드 처리 완료",
        summary_lines=[
            "upload validation passed",
            "redaction, verify, review, and report completed",
            f"검증한 파일 수: {refreshed.verification.files_checked}.",
            f"후보 finding 수: {report_result.candidate_count}.",
            f"AI 입력 후보 파일 수: {len(safe_files)}.",
            "raw_data_included: false",
        ],
        stage_statuses=stage_statuses,
        candidate_count=review_result.candidate_count,
        safe_files_present=safe_files,
        files_checked=refreshed.verification.files_checked,
    )


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


def run_live_capture_start_placeholder(server: DashboardHttpServer, target: str) -> LiveCaptureActionResult:
    with server.live_capture_lock:
        current = server.live_capture_session
        if current.status == "running_placeholder":
            return LiveCaptureActionResult(
                action_name="live_capture_start",
                status="blocked",
                session=current,
                summary_lines=[
                    "duplicate start blocked",
                    f"session state: {current.status}",
                    "raw_data_included: false",
                ],
                blocked_reason="duplicate_start",
            )
    try:
        target_alias = live_capture_scope_alias(target)
    except LiveCaptureScopeError as error:
        session = LiveCaptureSession(status="failed_validation", updated_at_utc=_utc_now())
        with server.live_capture_lock:
            server.live_capture_session = session
        return LiveCaptureActionResult(
            action_name="live_capture_start",
            status="blocked",
            session=session,
            summary_lines=[
                "target validation failed",
                f"reason: {error.reason}",
                "session state: failed_validation",
                "raw_data_included: false",
            ],
            blocked_reason=f"invalid_target_{error.reason}",
        )

    with server.live_capture_lock:
        current = server.live_capture_session
        if current.status == "running_placeholder":
            return LiveCaptureActionResult(
                action_name="live_capture_start",
                status="blocked",
                session=current,
                summary_lines=[
                    "duplicate start blocked",
                    f"session state: {current.status}",
                    "raw_data_included: false",
                ],
                blocked_reason="duplicate_start",
            )
        session = LiveCaptureSession(
            status="running_placeholder",
            session_alias=_new_live_capture_session_alias(),
            target_alias=target_alias,
            updated_at_utc=_utc_now(),
        )
        server.live_capture_session = session
    return LiveCaptureActionResult(
        action_name="live_capture_start",
        status="passed",
        session=session,
        summary_lines=[
            "start placeholder accepted",
            "actual traffic capture is not implemented in this PR",
            "collector and receiver behavior unchanged",
            "raw_data_included: false",
        ],
    )


def run_live_capture_stop_placeholder(server: DashboardHttpServer) -> LiveCaptureActionResult:
    with server.live_capture_lock:
        current = server.live_capture_session
        if current.status != "running_placeholder":
            return LiveCaptureActionResult(
                action_name="live_capture_stop",
                status="blocked",
                session=current,
                summary_lines=[
                    "stop blocked because no running placeholder session exists",
                    f"session state: {current.status}",
                    "raw_data_included: false",
                ],
                blocked_reason="no_active_session",
            )
        session = LiveCaptureSession(
            status="stopped",
            session_alias=current.session_alias,
            target_alias=current.target_alias,
            updated_at_utc=_utc_now(),
        )
        server.live_capture_session = session
    return LiveCaptureActionResult(
        action_name="live_capture_stop",
        status="passed",
        session=session,
        summary_lines=[
            "stop placeholder accepted",
            "actual traffic capture was not running",
            "raw_data_included: false",
        ],
    )


def render_home(root: Path, policy: RedactionPolicy) -> str:
    outputs, blocked_count = _discover_outputs(root, policy)
    rows = "\n".join(_output_row(output) for output in outputs)
    records = (
        f'<table class="records-table"><thead><tr><th>작업 이름</th><th>검토할 항목</th>'
        f'<th>전달 후보 파일</th><th>보고서</th><th>검증</th><th>결과</th></tr></thead>'
        f'<tbody>{rows}</tbody></table>'
        if outputs else '<p class="empty-state">아직 처리한 기록이 없습니다.</p>'
    )
    file_rows = "\n".join(
        f"<tr><td>{_h(name)}</td><td>{_h(_safe_file_description(name))}</td></tr>"
        for name in SAFE_PREVIEW_FILES
    )
    return _page(
        "처리한 기록",
        f"""
        <header class="topbar">
          <div>
            <p class="app-name">Burp AI Redaction Gateway</p>
            <h1>Burp 기록 정리</h1>
            <p class="subtitle">검증을 통과한 기록과 보고서 초안</p>
          </div>
          <nav class="actions" aria-label="주요 메뉴">
            <a class="button" href="/upload">파일 업로드</a>
            <a class="button secondary" href="/help">도움말</a>
            <a class="button secondary" href="/settings">설정</a>
          </nav>
        </header>
        <div class="summary-line">
          <span>처리한 기록 <strong>{len(outputs)}개</strong></span>
          <span>검증 실패로 숨긴 기록 <strong>{blocked_count}개</strong></span>
          <span class="badge neutral">자동 전송 없음</span>
        </div>
        <section class="workspace-section" aria-labelledby="records-title">
          <h2 id="records-title">처리한 기록</h2>
          {records}
        </section>
        <p class="review-note">표시된 항목은 취약점 확정 결과가 아닙니다. 외부에 전달하기 전에 내용을 직접 확인하세요.</p>
        <details class="secondary-details">
          <summary>AI 전달 후보 파일 4개</summary>
          <table class="result-table"><thead><tr><th>파일</th><th>내용</th></tr></thead>
          <tbody>{file_rows}</tbody></table>
        </details>
        <details class="secondary-details">
          <summary>감사 기록과 Burp 수집 상태</summary>
          {_audit_panel(_audit_status(root))}
          <a href="/live-capture">Burp 수집 상태</a>
        </details>
        """,
    )


def render_settings(root: Path) -> str:
    return _page(
        "설정 확인",
        f"""
        <header class="topbar">
          <div><a class="back" href="/">처리한 기록으로</a><h1>설정 확인</h1></div>
          <a class="button secondary" href="/help">도움말</a>
        </header>
        <p>현재 설정을 확인하는 화면입니다. 여기서는 설정을 변경하지 않습니다.</p>
        <dl class="facts">
          <div><dt>결과 폴더 이름</dt><dd>{_h(_safe_root_alias(root))}</dd></div>
          <div><dt>접속 범위</dt><dd>이 컴퓨터만 (127.0.0.1)</dd></div>
          <div><dt>요청 위조 방지(CSRF)</dt><dd>사용 중 · 보호값은 숨김</dd></div>
          <div><dt>HTML 문자 처리</dt><dd>화면에 코드를 삽입하지 못하도록 문자 변환</dd></div>
          <div><dt>보고서 작성 방식</dt><dd>기본 검토용 / 상세 검토용</dd></div>
          <div><dt>위험도</dt><dd>참고용 초안 · 최종 판단은 직접 확인</dd></div>
        </dl>
        <p class="review-note">원본 요청·응답, 인증정보, 비밀값, 환경변수 값은 표시하지 않습니다.
        요청 재전송, 능동 스캔, 파일 삭제 기능도 제공하지 않습니다.</p>
        <details class="secondary-details"><summary>감사 기록과 위변조 검사</summary>
          {_audit_panel(_audit_status(root))}
          <p>무결성 검사용 비밀키 설정: {_h(_status_label(_hmac_configured_label()))}</p>
          <p>감사 형식 버전: {_h(AUDIT_SCHEMA_VERSION)}</p>
        </details>
        """,
    )


def render_operations_help() -> str:
    return _page(
        "도움말",
        """
        <header class="topbar">
          <div><a class="back" href="/">처리한 기록으로</a><h1>도움말</h1></div>
          <a class="button" href="/upload">파일 업로드</a>
        </header>
        <section class="workspace-section">
          <h2>사용 순서</h2>
          <ol class="safe-list">
            <li>Burp의 HTTP history에서 필요한 요청을 XML로 저장합니다. 예제 JSON도 사용할 수 있습니다.</li>
            <li>파일 업로드에서 파일을 선택하고 새 작업 이름을 입력합니다.</li>
            <li>처리가 끝나면 결과 파일 확인에서 내용을 읽고 필요한 파일만 내려받습니다.</li>
          </ol>
          <p class="review-note">검증에 실패한 기록은 사용할 수 없습니다. 점검 결과는 취약점 후보이고 보고서는 초안입니다.
          실제 취약점 여부와 최종 심각도는 직접 확인하세요. AI로 자동 전송하지 않습니다.</p>
        </section>
        <section class="workspace-section">
          <h2>처리가 안 될 때</h2>
          <ul class="safe-list">
            <li>파일이 XML 또는 JSON인지, 크기가 10 MiB 이하인지 확인하세요.</li>
            <li>이미 사용한 작업 이름은 다른 이름으로 바꾸세요.</li>
            <li>파일을 읽지 못하면 Burp에서 요청을 선택해 다시 저장하세요.</li>
          </ul>
        </section>
        <details class="secondary-details"><summary>Burp 수집기와 MCP 설정</summary>
          <p>파일 업로드만 사용한다면 별도 연결은 필요 없습니다.</p>
          <p>Burp 탐색 중 수집은 별도 수신기와 확장이 필요합니다.
          <a href="/live-capture">Burp 수집 상태</a> 화면만 열어서는 수집이 시작되지 않습니다.</p>
          <p>설정 문서: <code>docs/MONTOYA_COLLECTOR.md</code>, <code>docs/LOCALHOST_RECEIVER.md</code></p>
          <p>MCP는 검증된 결과를 읽는 연결입니다. Burp를 직접 조작하지 않습니다.
          설정 문서: <code>docs/READ_ONLY_MCP.md</code></p>
        </details>
        """,
    )


def render_live_capture_readiness(
    _csrf_token: str,
    session: LiveCaptureSession,
    result: LiveCaptureActionResult | None = None,
    output: DashboardOutput | None = None,
    alias_selector_html: str = "",
) -> str:
    evidence = _build_live_capture_receiver_output_evidence(output)
    navigation = (
        f'<a class="button" href="{_output_href(output.output_id)}">결과 파일 확인</a>'
        f'<a class="button secondary" href="{_simple_dashboard_href(output.output_id)}">결과 요약</a>'
        if output and evidence.safe_navigation_available
        else '<p>검증된 기록을 선택하면 결과를 확인할 수 있습니다.</p>'
    )
    result_summary = (
        f'<p>처리 결과: {_status_badge(result.status)}</p>'
        f'<p>차단 사유: {_h(result.blocked_reason)}</p>'
        if result else ""
    )
    return _page(
        "Burp 수집 상태",
        f"""
        <header class="topbar">
          <div><a class="back" href="/">처리한 기록으로</a><h1>Burp 수집 상태</h1></div>
          <a class="button secondary" href="/upload">파일 업로드</a>
        </header>
        <p>별도로 실행한 수신기의 결과를 확인합니다. 이 화면에서 수집을 시작하거나 중지하지 않습니다.</p>
        <p class="review-note">확장과 수신기의 실제 실행 여부나 전송 건수는 이 화면에서 확인하지 않습니다.
        현재 작업 상태와 수신 결과의 검증 상태는 서로 다릅니다.</p>
        <section class="workspace-section">
          <h2>수신 결과</h2>
          <dl class="facts">
            <div><dt>작업 이름</dt><dd>{_h(_status_label(evidence.receiver_output_alias))}</dd></div>
            <div><dt>검증</dt><dd>{_status_badge(evidence.receiver_verify_status)}</dd></div>
            <div><dt>전달 후보 파일</dt><dd>{_status_badge(evidence.safe_file_existence_status)}</dd></div>
            <div><dt>검토할 항목</dt><dd>{evidence.candidate_count}개</dd></div>
          </dl>
          <div class="actions">{navigation}</div>
        </section>
        <details class="secondary-details"><summary>다른 기록 선택</summary>{alias_selector_html}</details>
        <details class="secondary-details"><summary>작업 상태</summary>
          <p>상태: {_status_badge(session.status)}</p>
          <p>작업 별칭: {_h(session.session_alias)}</p>
          <p>대상 별칭: {_h(session.target_alias)}</p>
          <p>갱신 시각(UTC): {_h(session.updated_at_utc or "없음")}</p>
          {result_summary}
        </details>
        <p>설정 방법은 저장소의 <code>docs/MONTOYA_COLLECTOR.md</code>를 참고하세요.</p>
        """,
    )
def render_upload_wizard(csrf_token: str) -> str:
    file_rows = "\n".join(
        f"<tr><td>{_h(name)}</td><td>{_h(_safe_file_description(name))}</td></tr>"
        for name in SAFE_PREVIEW_FILES
    )
    return _page(
        "파일 업로드",
        f"""
        <header class="topbar">
          <div>
            <a class="back" href="/">처리한 기록으로</a>
            <h1>파일 업로드</h1>
            <p class="subtitle">Burp XML 또는 JSON · 최대 10 MiB</p>
          </div>
          <span class="badge neutral">이 컴퓨터에서 처리</span>
        </header>
        <div class="workflow-grid">
          <section class="workspace-section">
            <form class="stacked-form" method="post" action="/upload" enctype="multipart/form-data">
              <input type="hidden" name="csrf_token" value="{_h(csrf_token)}">
              <label>Burp 기록 파일
                <input type="file" name="burp_export" accept=".xml,.json" required>
              </label>
              <label>작업 이름
                <input type="text" name="project" required pattern="[A-Za-z0-9][A-Za-z0-9_-]{{0,63}}"
                       placeholder="check01" maxlength="64" aria-describedby="project-hint">
              </label>
              <small id="project-hint">영문과 숫자로 시작하세요. 밑줄·하이픈을 쓸 수 있으며 실제 고객명은 넣지 마세요.</small>
              <button type="submit">민감정보 제거 시작</button>
            </form>
            <p class="review-note">선택한 원본은 이 컴퓨터의 local_only/ 폴더에 보관합니다. 화면에는 원문을 표시하지 않습니다.</p>
          </section>
          <section class="workspace-section">
            <h2>처리 후 확인할 파일</h2>
            <table class="result-table"><thead><tr><th>파일</th><th>내용</th></tr></thead>
              <tbody>{file_rows}</tbody>
            </table>
            <p class="review-note">검증에 실패하면 이후 처리를 중단합니다. 결과가 만들어져도 AI로 자동 전송하지 않습니다.</p>
          </section>
        </div>
        """,
    )


def render_upload_result(result: UploadWizardResult, csrf_token: str) -> str:
    passed = result.status == "passed"
    stage_names = {
        "upload validation": "입력 파일 확인",
        "raw local storage": "원본 로컬 보관",
        "redaction/generate": "민감정보 제거",
        "verify": "잔존 정보 검사",
        "review": "검토 자료 정리",
        "report": "보고서 초안 생성",
    }
    stages = "".join(
        f"<tr><td>{_h(stage_names.get(name, name))}</td><td>{_status_badge(status)}</td></tr>"
        for name, status in result.stage_statuses
    )
    safe_rows = "".join(
        f"<tr><td>{_h(name)}</td><td>{_h(_safe_file_description(name))}</td>"
        f"<td>{_status_badge('present' if name in result.safe_files_present else 'missing')}</td></tr>"
        for name in SAFE_PREVIEW_FILES
    )
    messages = {
        "generate_failed": "파일 형식을 확인해 주세요. 처리하지 못한 결과는 사용할 수 없습니다.",
        "verify_failed": "검사에서 문제가 발견돼 중단했습니다. 이 결과를 AI에 전달하지 마세요.",
        "review_failed": "검토 자료를 만들지 못했습니다. 이 결과를 AI에 전달하지 마세요.",
        "report_failed": "보고서 초안을 만들지 못했습니다. 이 결과를 AI에 전달하지 마세요.",
    }
    if passed:
        links = f"""
          <a class="button" href="{_output_href(result.output_id)}">결과 파일 확인</a>
          <a class="button secondary" href="{_simple_dashboard_href(result.output_id)}">결과 요약</a>
        """
        contents = f"""
        <section class="workspace-section">
          <h2>AI 전달 후보 파일 4개</h2>
          <table class="result-table"><thead><tr><th>파일</th><th>내용</th><th>상태</th></tr></thead>
          <tbody>{safe_rows}</tbody></table>
        </section>
        <p class="review-note">검사가 끝났습니다. 공유 전에 파일 내용을 직접 확인하세요. 점검 항목과 위험도는 수동 검토 전 초안입니다.</p>
        """
    else:
        links = '<a class="button" href="/upload">다시 업로드</a>'
        contents = f'<p class="failure-note" role="alert">{_h(messages.get(result.blocked_reason, "처리를 완료하지 못했습니다. 입력 파일을 확인해 주세요."))}</p>'
    title = "처리 완료" if passed else result.title
    return _page(
        title,
        f"""
        <header class="topbar">
          <div>
            <a class="back" href="/">처리한 기록으로</a>
            <h1>{_h(title)}</h1>
          </div>
          <div class="actions">
            {links}
            <a class="button secondary" href="/upload">다른 파일 처리</a>
          </div>
        </header>
        <div class="summary-line">
          <span>작업 <strong>{_h(result.project_alias)}</strong></span>
          <span>검토할 항목 <strong>{result.candidate_count}개</strong></span>
          <span>전달 후보 <strong>{len(result.safe_files_present)}/4개</strong></span>
          {_status_badge(result.status)}
        </div>
        {contents}
        <details class="secondary-details">
          <summary>처리 단계 확인</summary>
          <table class="result-table"><thead><tr><th>단계</th><th>결과</th></tr></thead><tbody>{stages}</tbody></table>
        </details>
        """,
    )


def render_output_detail(output: DashboardOutput, csrf_token: str) -> str:
    candidates = _load_candidates(output.path)
    candidate_cards = "\n".join(_candidate_card(candidate) for candidate in candidates[:40]) or (
        '<p class="empty">검토할 항목이 없습니다.</p>'
    )
    file_cards = "\n".join(_safe_file_card(output, name) for name in SAFE_PREVIEW_FILES)
    return _page(
        f"결과 파일 {output.label}",
        f"""
        <header class="topbar">
          <div>
            <a class="back" href="/">처리한 기록으로</a>
            <h1>결과 파일</h1>
            <p class="subtitle">{_h(output.label)}</p>
          </div>
          <div class="actions">
            <a class="button secondary" href="{_simple_dashboard_href(output.output_id)}">결과 요약</a>
            <a class="button secondary" href="/upload">다른 파일 처리</a>
          </div>
        </header>
        <section class="workspace-section">
          <h2>AI 전달 후보 파일</h2>
          <div class="file-grid">{file_cards}</div>
        </section>
        <p class="review-note">자동 검사는 공유 승인을 대신하지 않습니다. 내용을 읽어보고 필요한 파일만 사용하세요.</p>
        <section class="workspace-section">
          <h2>다시 검사하거나 내보내기</h2>
          {_action_panel(output, csrf_token)}
        </section>
        <details class="secondary-details">
          <summary>검토할 항목 {len(candidates)}개</summary>
          <p class="review-note">확정된 취약점이 아닙니다. 증거 신뢰도와 심각도는 구분해 판단하세요.</p>
          <div class="candidate-list">{candidate_cards}</div>
        </details>
        <details class="secondary-details">
          <summary>공유 전 추가 점검</summary>
          <nav class="secondary-links">
            <a href="{_preflight_href(output.output_id)}">공유 전 점검</a>
            <a href="{_handoff_href(output.output_id)}">전달할 파일</a>
            <a href="{_triage_href(output.output_id)}">검토할 항목</a>
            <a href="{_report_readiness_href(output.output_id)}">보고서 확인</a>
            <a href="{_prompt_readiness_href(output.output_id)}">프롬프트 확인</a>
            <a href="{_evidence_boundary_href(output.output_id)}">공유할 자료</a>
            <a href="{_workflow_href(output.output_id)}">처리 순서</a>
            <a href="{_operator_runbook_href(output.output_id)}">사용 순서</a>
            <a href="{_safe_files_href(output.output_id)}">파일 상태</a>
          </nav>
        </details>
        """,
    )


def render_simple_dashboard(output: DashboardOutput) -> str:
    safe_rows = "\n".join(_simple_safe_file_row(output, name) for name in SAFE_PREVIEW_FILES)
    safe_file_count = sum(1 for name in SAFE_PREVIEW_FILES if (output.path / name).is_file())
    return _page(
        f"결과 요약 {output.label}",
        f"""
        <header class="topbar">
          <div>
            <a class="back" href="/">처리한 기록으로</a>
            <h1>결과 요약</h1>
            <p class="subtitle">{_h(output.label)}</p>
          </div>
          <div class="actions">
            <a class="button" href="{_output_href(output.output_id)}">결과 파일 확인</a>
            <a class="button secondary" href="/upload">다른 파일 처리</a>
          </div>
        </header>
        <div class="summary-line">
          <span>검토할 항목 <strong>{output.candidate_count}개</strong></span>
          <span>전달 후보 <strong>{safe_file_count}/4개</strong></span>
          <span>보고서 초안 <strong>{'있음' if output.report_available else '없음'}</strong></span>
          <span class="badge good">검증 통과</span>
        </div>
        <section class="workspace-section">
          <h2>AI 전달 후보 파일</h2>
          <table class="result-table"><thead><tr><th>파일</th><th>내용</th><th>상태</th></tr></thead>
          <tbody>{safe_rows}</tbody></table>
        </section>
        <p class="review-note">점검 결과는 취약점 확정이 아닌 후보입니다. 위험도와 최종 심각도는 수동 검토가 필요합니다. 파일을 확인한 뒤 필요한 범위만 사용하세요.</p>
        <details class="secondary-details">
          <summary>추가 점검</summary>
          <nav class="secondary-links" aria-label="추가 점검">
            <a href="{_safe_files_href(output.output_id)}">파일 상태</a>
            <a href="{_preflight_href(output.output_id)}">공유 전 점검</a>
            <a href="{_triage_href(output.output_id)}">검토할 항목</a>
            <a href="{_report_readiness_href(output.output_id)}">보고서 확인</a>
            <a href="{_workflow_href(output.output_id)}">처리 순서</a>
            <a href="{_evidence_boundary_href(output.output_id)}">공유할 자료</a>
            <a href="{_operator_runbook_href(output.output_id)}">사용 순서</a>
            <a href="/live-capture">Burp 수집 상태</a>
          </nav>
        </details>
        """,
    )


def _advanced_check_page(title: str, output: DashboardOutput, content: str, details: str = "") -> str:
    links = (
        ("파일 상태", _safe_files_href(output.output_id)),
        ("공유 전 점검", _preflight_href(output.output_id)),
        ("검토할 항목", _triage_href(output.output_id)),
        ("보고서 확인", _report_readiness_href(output.output_id)),
        ("프롬프트 확인", _prompt_readiness_href(output.output_id)),
        ("전달할 파일", _handoff_href(output.output_id)),
        ("공유할 자료", _evidence_boundary_href(output.output_id)),
        ("사용 순서", _operator_runbook_href(output.output_id)),
        ("처리 순서", _workflow_href(output.output_id)),
    )
    navigation = "".join(
        f'<a href="{_h(href)}">{_h(label)}</a>' for label, href in links if label != title
    )
    extra = (
        f'<details class="secondary-details"><summary>상세 정보</summary>{details}</details>'
        if details else ""
    )
    return _page(
        f"{title} {output.label}",
        f"""
        <header class="topbar">
          <div><a class="back" href="/">처리한 기록으로</a><h1>{_h(title)}</h1>
            <p class="subtitle">{_h(output.label)}</p></div>
          <a class="button" href="{_output_href(output.output_id)}">결과 파일 확인</a>
        </header>
        <div class="summary-line">
          <span>검토할 항목 <strong>{output.candidate_count}개</strong></span>
          <span class="badge good">검증 통과</span>
          <span class="badge neutral">조회 전용</span>
        </div>
        <section class="workspace-section">{content}</section>
        <p class="review-note">점검 항목은 확인이 필요한 후보이며 보고서는 초안입니다.
        실제 취약점 여부와 최종 심각도는 직접 확인해야 합니다. 공유 전 파일 내용을 읽어보세요.</p>
        {extra}
        <details class="secondary-details"><summary>다른 점검</summary>
          <nav class="secondary-links">{navigation}</nav>
        </details>
        """,
    )


def render_ai_handoff_index(index: AiHandoffIndex) -> str:
    rows = "\n".join(
        f"<tr><td>{file.order}</td><td>{_h(file.name)}</td>"
        f"<td>{_h(_safe_file_description(file.name))}</td><td>{_status_badge(file.status)}</td></tr>"
        for file in index.files
    )
    details = _handoff_summary(index) + '<div class="file-grid">' + "".join(
        _handoff_file_card(file) for file in index.files
    ) + "</div>"
    return _advanced_check_page(
        "전달할 파일", index.output,
        f'<p>아래 순서로 내용을 읽고 필요한 파일만 사용하세요. AI로 자동 전송하지 않습니다.</p>'
        f'<table class="result-table handoff-table"><thead><tr><th>순서</th><th>파일</th><th>내용</th><th>상태</th></tr></thead><tbody>{rows}</tbody></table>',
        details,
    )


def render_finding_triage_index(index: FindingTriageIndex, alias_selector_html: str = "") -> str:
    candidates = "\n".join(_triage_candidate_card(candidate) for candidate in index.candidates)
    return _advanced_check_page(
        "검토할 항목", index.output,
        '<p>자동 점검에서 확인이 필요하다고 분류한 항목입니다. 실제 재현과 영향은 별도로 확인하세요.</p>'
        f'<div class="candidate-list">{candidates or "<p>검토할 항목이 없습니다.</p>"}</div>',
        alias_selector_html,
    )


def render_report_readiness_index(index: ReportReadinessIndex, alias_selector_html: str = "") -> str:
    checklist = "".join(
        f"<li>{item}</li>" for item in (
            "점검 범위와 요청 경로가 맞는지 확인합니다.",
            "탐지 오류 가능성과 실제 영향을 검토합니다.",
            "근거가 충분한지 확인하고 조치 방법을 보완합니다.",
            "최종 심각도를 결정하고 민감정보가 남아 있지 않은지 확인합니다.",
        )
    )
    details = alias_selector_html + '<div class="file-grid">' + "".join(
        _report_readiness_file_card(file) for file in index.files
    ) + "</div>"
    return _advanced_check_page(
        "보고서 확인", index.output,
        f'<p>보고서 초안: {_status_badge(index.report_status)}</p>'
        '<p><code>report_draft.md</code>는 검토용 초안입니다. 제출 전 아래 내용을 확인하세요.</p>'
        f'<ol class="safe-list">{checklist}</ol>',
        details,
    )


def render_prompt_readiness_index(index: PromptReadinessIndex) -> str:
    rows = "".join(
        f"<tr><td>{_h(check.name)}</td><td>{_status_badge(check.status)}</td></tr>"
        for check in index.checks
    )
    descriptions = '<h2>검사 항목 설명</h2><dl class="facts">' + "".join(
        f"<div><dt>{_h(check.name)}</dt><dd>{_h(check.summary)}</dd></div>" for check in index.checks
    ) + "</dl>"
    details = descriptions + '<div class="file-grid">' + "".join(
        _prompt_readiness_file_card(file) for file in index.files
    ) + "</div>"
    return _advanced_check_page(
        "프롬프트 확인", index.output,
        '<p>ChatGPT용 파일은 분석 검토에, Codex용 파일은 코드 검토와 작업 요청에 사용합니다.</p>'
        '<p>아래 검사는 안내 문구의 키워드 유무만 확인합니다. 내용을 직접 읽는 검토를 대신하지 않습니다.</p>'
        f'<p>안내 문구 점검: {_status_badge(index.prompt_status)}</p>'
        f'<table class="result-table check-table"><thead><tr><th>확인 항목</th><th>결과</th></tr></thead><tbody>{rows}</tbody></table>',
        details,
    )


def render_evidence_boundary_index(index: EvidenceBoundaryIndex) -> str:
    details = '<div class="file-grid">' + "".join(
        _evidence_boundary_file_card(file) for file in index.files
    ) + "</div>"
    return _advanced_check_page(
        "공유할 자료", index.output,
        '<h2>공유 전 확인할 파일</h2>'
        '<p>분석 요약, 프롬프트, 보고서 초안만 검토 대상입니다. 결과 폴더 전체를 올리지 마세요.</p>'
        '<ul class="safe-list">' + "".join(f"<li>{_h(name)}</li>" for name in SAFE_PREVIEW_FILES) + "</ul>"
        '<h2>공유하지 않을 자료</h2>'
        '<p>원본 요청·응답, 인증정보, 개인정보, 실제 대상 주소, 전체 로컬 경로는 보내지 마세요. '
        '원본 보관 폴더와 감사 기록도 AI 전달 대상이 아닙니다.</p>',
        details,
    )


def render_operator_runbook_index(index: OperatorRunbookIndex) -> str:
    details = '<div class="file-grid">' + "".join(
        _operator_runbook_step_card(step) for step in index.steps
    ) + "</div>"
    return _advanced_check_page(
        "사용 순서", index.output,
        '<ol class="safe-list">'
        '<li><a href="/upload">파일 업로드</a>에서 Burp XML 또는 JSON을 처리합니다.</li>'
        '<li>처리가 끝나면 결과 파일 확인에서 네 파일의 내용을 읽습니다.</li>'
        '<li>검토할 항목을 재현하고 보고서 초안을 수정합니다.</li>'
        '<li>민감정보가 없는지 확인한 뒤 필요한 파일만 사용합니다.</li></ol>'
        '<p>Burp 탐색 중 수집은 별도 수신기와 확장이 필요합니다. '
        '<a href="/live-capture">Burp 수집 상태</a>에서 결과를 확인할 수 있지만 수집을 시작하거나 중지할 수는 없습니다.</p>',
        details,
    )


def render_safe_file_inventory_index(index: SafeFileInventoryIndex, alias_selector_html: str = "") -> str:
    rows = "".join(
        f"<tr><td>{_h(file.name)}</td><td>{_h(_safe_file_description(file.name))}</td>"
        f"<td>{_status_badge(file.status)}</td></tr>" for file in index.files
    )
    details = alias_selector_html + '<div class="file-grid">' + "".join(
        _safe_file_inventory_card(file) for file in index.files
    ) + "</div>"
    return _advanced_check_page(
        "파일 상태", index.output,
        '<p>전달 후보 파일이 만들어졌는지 확인합니다. 내용을 읽거나 내려받으려면 결과 파일 확인으로 이동하세요.</p>'
        f'<table class="result-table"><thead><tr><th>파일</th><th>내용</th><th>상태</th></tr></thead><tbody>{rows}</tbody></table>',
        details,
    )


def render_workflow_status_index(index: WorkflowStatusIndex, alias_selector_html: str = "") -> str:
    steps = "".join(_workflow_step_card(step) for step in index.steps)
    return _advanced_check_page(
        "처리 순서", index.output,
        '<p>각 단계의 결과를 확인하는 화면입니다. 링크를 눌러도 처리를 다시 실행하지 않습니다.</p>'
        f'<div class="file-grid">{steps}</div>',
        alias_selector_html,
    )


def render_ai_safe_preflight(preflight: AiSafePreflight) -> str:
    rows = "".join(
        f"<tr><td>{_h(name)}</td><td>{_status_badge(status)}</td></tr>"
        for name, status in preflight.file_statuses
    )
    return _advanced_check_page(
        "공유 전 점검", preflight.output,
        f'<p>파일 준비 상태: {_status_badge(preflight.ready_status)}</p>'
        f'<p>민감정보 검사: {_status_badge(preflight.marker_scan_status)}</p>'
        '<p>검증을 통과했더라도 파일 내용을 직접 확인하세요. 검사 통과가 외부 공유 승인을 뜻하지는 않습니다.</p>'
        f'<table class="result-table"><thead><tr><th>파일</th><th>상태</th></tr></thead><tbody>{rows}</tbody></table>',
        _preflight_summary(preflight),
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
    messages = {
        "upload_output_exists": "이미 사용한 작업 이름입니다. 다른 이름으로 다시 올려주세요.",
        "upload_validation_failed": "입력 파일과 작업 이름을 확인해 주세요.",
        "upload_too_large": "파일이 10 MiB를 넘습니다. Burp에서 요청을 나눠 저장해 주세요.",
        "unsupported_file_type": "XML 또는 JSON 파일을 선택해 주세요.",
        "invalid_project_alias": "작업 이름은 영문·숫자·밑줄·하이픈으로 입력하고, 영문이나 숫자로 시작하세요.",
        "csrf_token_missing": "요청을 확인할 수 없습니다. 업로드 화면을 다시 열어주세요.",
        "csrf_token_invalid": "화면이 만료됐을 수 있습니다. 업로드 화면을 다시 열어주세요.",
        "verification_failed": "검사에서 문제가 발견됐습니다. 이 결과를 AI에 전달하지 마세요.",
    }
    message = messages.get(error_type, "요청을 처리하지 못했습니다. 입력 내용을 확인하거나 도움말을 참고해 주세요.")
    return _page(
        "요청 확인",
        f"""
        <header class="topbar"><div>
          <a class="back" href="/">처리한 기록으로</a>
          <h1>요청을 처리하지 못했습니다</h1>
        </div></header>
        <p class="failure-note" role="alert">{_h(message)}</p>
        <div class="actions">
          <a class="button" href="/upload">파일 다시 선택</a>
          <a class="button secondary" href="/help">도움말</a>
        </div>
        <details class="secondary-details">
          <summary>오류 정보</summary>
          <p>오류 코드: {_h(error_type)} · HTTP {status.value}</p>
        </details>
        """,
    )


def _discover_outputs(root: Path, policy: RedactionPolicy) -> tuple[list[DashboardOutput], int]:
    outputs: list[DashboardOutput] = []
    blocked = 0
    for marker in sorted(root.rglob(OUTPUT_MARKER_FILE)):
        output_dir = marker.parent
        if output_dir.name == "ai_candidates" and (output_dir.parent / OUTPUT_MARKER_FILE).is_file():
            continue
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


def _render_output_alias_selector(
    root: Path,
    policy: RedactionPolicy,
    current_output_id: str = "",
    outputs: list[DashboardOutput] | None = None,
) -> str:
    verified_outputs = outputs if outputs is not None else _discover_outputs(root, policy)[0]
    if not verified_outputs:
        return '<p>검증을 통과한 기록이 없습니다. <a href="/upload">파일 업로드</a>에서 시작하세요.</p>'
    cards = "".join(_output_alias_selector_card(output, current_output_id) for output in verified_outputs)
    return f'<section class="workspace-section"><h2>다른 기록 선택</h2><div class="file-grid">{cards}</div></section>'


def _output_alias_selector_card(output: DashboardOutput, current_output_id: str) -> str:
    selected = '<span class="badge good">선택됨</span>' if output.output_id == current_output_id else ""
    links = "".join(
        f'<a href="{_h(href)}">{_h(label)}</a>'
        for label, href in _output_alias_selector_links(output.output_id)
    )
    return f"""
    <div class="guide-card output-alias-card">
      <strong>{_h(output.label)}</strong>{selected}
      <span>검토할 항목 {output.candidate_count}개 · 전달 후보 파일 {len(output.prompt_files)}/4개</span>
      <nav class="secondary-links">{links}</nav>
    </div>
    """


def _output_alias_selector_links(output_id: str) -> tuple[tuple[str, str], ...]:
    return (
        ("파일 상태", _safe_files_href(output_id)),
        ("검토할 항목", _triage_href(output_id)),
        ("보고서 확인", _report_readiness_href(output_id)),
        ("처리 순서", _workflow_href(output_id)),
    )


def _build_live_capture_receiver_output_evidence(
    output: DashboardOutput | None,
) -> LiveCaptureReceiverOutputEvidence:
    if output is None:
        return LiveCaptureReceiverOutputEvidence(
            evidence_source="receiver_output_alias",
            receiver_output_alias="not selected",
            receiver_verify_status="not selected",
            safe_file_existence_status="hidden until verify passes",
            candidate_count=0,
            raw_data_included=False,
            safe_navigation_available=False,
        )

    return LiveCaptureReceiverOutputEvidence(
        evidence_source="receiver_output_alias",
        receiver_output_alias=output.label,
        receiver_verify_status="passed",
        safe_file_existence_status="available",
        candidate_count=output.candidate_count,
        raw_data_included=False,
        safe_navigation_available=True,
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
        _report_readiness_file(output.path, "report_draft.md", "수동 검토를 위한 보고서 초안입니다."),
        _report_readiness_file(output.path, "analysis_packet.json", "정제된 후보 증거 구조화 패킷입니다."),
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


def _build_prompt_readiness_index(output: DashboardOutput) -> PromptReadinessIndex:
    files = [_prompt_readiness_file(output.path, name) for name in SAFE_PREVIEW_FILES]
    chatgpt_text = _prompt_text_for_checks(output.path, "chatgpt_prompt.md")
    codex_text = _prompt_text_for_checks(output.path, "codex_task_prompt.md")
    combined_text = "\n".join(text for text in (chatgpt_text, codex_text) if text)
    checks = [
        PromptReadinessCheck(
            name="전달 후보 파일 안내",
            status="present" if _contains_all(combined_text, SAFE_PREVIEW_FILES) else "needs_manual_review",
            summary="전달 후보 파일 네 개를 안내하는지 확인합니다.",
        ),
        PromptReadinessCheck(
            name="민감정보 공유 금지 안내",
            status=(
                "present"
                if (
                    _contains_all(combined_text, ("raw", "Cookie", "Authorization", "token", "domain", "IP"))
                    or _contains_all(combined_text, ("요청·응답 원문", "쿠키·인증 헤더·토큰·세션 값", "실제 도메인·IP·개인정보", "복원·출력·저장·로그 기록하지"))
                )
                else "needs_manual_review"
            ),
            summary="원문과 인증정보, 실제 대상 주소를 보내지 말라는 안내가 있는지 확인합니다.",
        ),
        PromptReadinessCheck(
            name="사전 검증 안내",
            status=(
                "present"
                if _contains_any(combined_text, ("verify", "verified")) or _contains_all(combined_text, ("검사를 통과한", "자료만 사용"))
                else "needs_manual_review"
            ),
            summary="검증을 통과한 결과만 사용하라는 안내가 있는지 확인합니다.",
        ),
        PromptReadinessCheck(
            name="후보와 초안에 대한 안내",
            status=(
                "present"
                if (
                    _contains_all(combined_text, ("candidate", "draft", "manual"))
                    or _contains_all(combined_text, ("모든 항목은 검토 후보", "위험도 초안은 확정 평가가 아니며", "사람이 직접 확인"))
                )
                else "needs_manual_review"
            ),
            summary="점검 결과와 위험도는 초안이며 직접 확인해야 한다는 안내가 있는지 확인합니다.",
        ),
        PromptReadinessCheck(
            name="최종 심각도 수동 결정 경고",
            status=(
                "present"
                if (
                    _contains_any(combined_text, ("severity decision", "manual-review severity draft"))
                    or _contains_all(combined_text, ("위험도 초안은 확정 평가가 아니며", "심각도 결정·위험도 평가 완료를 단정하지"))
                )
                else "needs_manual_review"
            ),
            summary="최종 심각도는 직접 판단해야 한다는 안내가 있는지 확인합니다.",
        ),
        PromptReadinessCheck(
            name="원문 요청·응답 공유 금지 안내",
            status=(
                "present"
                if (
                    _contains_any(combined_text, ("raw request/response", "raw request or response", "raw HTTP"))
                    or _contains_all(combined_text, ("요청·응답 원문", "요청하거나 복원·출력·저장·로그 기록하지"))
                )
                else "needs_manual_review"
            ),
            summary="원문 요청·응답을 요구하거나 복원하지 말라는 안내가 있는지 확인합니다.",
        ),
        PromptReadinessCheck(
            name="Codex 작업 범위 안내",
            status=(
                "present"
                if (
                    _contains_all(codex_text, ("Hard requirements", "Do not", "manual verification"))
                    or _contains_all(codex_text, ("## 검토 기준", "코드가 없으면", "능동 스캔·외부 전송은 실행하지"))
                )
                else "needs_manual_review"
            ),
            summary="Codex에 요청할 작업과 금지한 작업이 구분되어 있는지 확인합니다.",
        ),
        PromptReadinessCheck(
            name="ChatGPT 분석 범위 안내",
            status=(
                "present"
                if (
                    _contains_all(chatgpt_text, ("Analyze", "candidate", "manual verification"))
                    or _contains_all(chatgpt_text, ("ChatGPT 검토 요청", "후보별 발견 내용과 근거", "직접 확인할 방법과 조치 제안", "## 검토 기준"))
                )
                else "needs_manual_review"
            ),
            summary="분석 목적과 직접 확인할 부분을 안내하는지 확인합니다.",
        ),
    ]
    prompt_status = "present" if all(check.status == "present" for check in checks) else "needs_manual_review"
    return PromptReadinessIndex(
        output=output,
        files=files,
        checks=checks,
        prompt_status=prompt_status,
        chatgpt_status=_file_status(output.path, "chatgpt_prompt.md"),
        codex_status=_file_status(output.path, "codex_task_prompt.md"),
        safe_file_count=sum(1 for file in files if file.status == "present"),
    )


def _build_evidence_boundary_index(output: DashboardOutput) -> EvidenceBoundaryIndex:
    files = [_evidence_boundary_file(output.path, name) for name in SAFE_PREVIEW_FILES]
    analysis_status = _file_status(output.path, "analysis_packet.json")
    report_status = _file_status(output.path, "report_draft.md")
    chatgpt_status = _file_status(output.path, "chatgpt_prompt.md")
    codex_status = _file_status(output.path, "codex_task_prompt.md")
    safe_file_count = sum(1 for file in files if file.status == "present")
    finding_candidate_status = "present" if output.candidate_count else "missing"
    sanitized_evidence_status = (
        "present"
        if analysis_status == "present" and finding_candidate_status == "present" and safe_file_count
        else "needs_manual_review"
    )
    return EvidenceBoundaryIndex(
        output=output,
        files=files,
        candidate_count=output.candidate_count,
        sanitized_evidence_status=sanitized_evidence_status,
        finding_candidate_status=finding_candidate_status,
        analysis_status=analysis_status,
        report_status=report_status,
        chatgpt_status=chatgpt_status,
        codex_status=codex_status,
        safe_file_count=safe_file_count,
    )


def _build_workflow_status_index(output: DashboardOutput) -> WorkflowStatusIndex:
    file_statuses = [
        (name, "present" if (output.path / name).is_file() else "missing")
        for name in SAFE_PREVIEW_FILES
    ]
    report_status = "draft available" if (output.path / "report_draft.md").is_file() else "missing"
    analysis_status = "candidate available" if (output.path / "analysis_packet.json").is_file() else "missing"
    review_status = "candidate available" if output.candidate_count else "missing"
    steps = [
        WorkflowStep(
            name="검증",
            status="passed",
            summary="검증을 통과한 결과만 확인할 수 있습니다.",
            href=_output_href(output.output_id),
        ),
        WorkflowStep(
            name="후보 검토",
            status=review_status,
            summary="확인이 필요한 항목을 요약해서 보여줍니다.",
            href=_output_href(output.output_id),
        ),
        WorkflowStep(
            name="보고서",
            status=report_status,
            summary="report_draft.md는 수동 검토용 보고서 초안입니다.",
            href=_output_href(output.output_id),
        ),
        WorkflowStep(
            name="공유 전 점검",
            status="manual review required",
            summary="공유 전 네 파일의 상태를 확인합니다.",
            href=_preflight_href(output.output_id),
        ),
        WorkflowStep(
            name="파일 상태",
            status="manual review required",
            summary="네 파일이 만들어졌는지 확인합니다. 크기와 해시는 상세 정보에서 볼 수 있습니다.",
            href=_safe_files_href(output.output_id),
        ),
        WorkflowStep(
            name="전달할 파일",
            status="manual review required",
            summary="사용할 파일의 목적과 읽는 순서를 확인합니다.",
            href=_handoff_href(output.output_id),
        ),
        WorkflowStep(
            name="프롬프트 확인",
            status="manual review required",
            summary="프롬프트에 필요한 주의사항이 있는지 확인합니다.",
            href=_prompt_readiness_href(output.output_id),
        ),
        WorkflowStep(
            name="공유할 자료",
            status="manual review required",
            summary="공유할 수 있는 자료와 보내면 안 되는 원본을 구분합니다.",
            href=_evidence_boundary_href(output.output_id),
        ),
        WorkflowStep(
            name="검토할 항목",
            status="manual review required",
            summary="확인이 필요한 항목의 근거와 위험도 초안을 검토합니다.",
            href=_triage_href(output.output_id),
        ),
        WorkflowStep(
            name="보고서 확인",
            status="manual review required",
            summary="보고서 초안과 제출 전 확인할 항목을 봅니다.",
            href=_report_readiness_href(output.output_id),
        ),
        WorkflowStep(
            name="결과 파일 확인",
            status="manual review required",
            summary="파일 확인과 다시 검증은 결과 파일 화면에서 사용합니다.",
            href=_output_href(output.output_id),
        ),
    ]
    return WorkflowStatusIndex(
        output=output,
        file_statuses=file_statuses,
        steps=steps,
        candidate_count=output.candidate_count,
        review_status=review_status,
        report_status=report_status,
        analysis_status=analysis_status,
    )


def _build_operator_runbook_index(output: DashboardOutput) -> OperatorRunbookIndex:
    file_statuses = [
        (name, "present" if (output.path / name).is_file() else "missing")
        for name in SAFE_PREVIEW_FILES
    ]
    safe_file_count = sum(1 for _, status in file_statuses if status == "present")
    report_status = "draft available" if (output.path / "report_draft.md").is_file() else "missing"
    analysis_status = "candidate available" if (output.path / "analysis_packet.json").is_file() else "missing"
    review_status = "candidate available" if output.candidate_count else "missing"
    steps = [
        OperatorRunbookStep(
            order=1,
            name="Burp 기록 준비",
            status="manual review required",
            purpose="점검이 허용된 범위의 Burp 기록만 준비합니다.",
            safe_metadata=("스코프 확인", "대상 별칭", "원문 값 미표시"),
            href="/help",
        ),
        OperatorRunbookStep(
            order=2,
            name="로컬 수신 결과 확인",
            status="manual review required",
            purpose="이 컴퓨터에서 실행한 수신기가 결과를 만들었는지 확인합니다.",
            safe_metadata=("receiver 포트", "output alias", "project alias"),
            href="/operations",
        ),
        OperatorRunbookStep(
            order=3,
            name="민감정보 제거와 검증",
            status="passed",
            purpose="검증을 통과한 결과만 다음 단계에서 사용합니다.",
            safe_metadata=("검증한 파일 수", "safe file 상태", "raw_data_included=false"),
            href=_output_href(output.output_id),
        ),
        OperatorRunbookStep(
            order=4,
            name="후보 검토",
            status=review_status,
            purpose="검토할 항목과 근거를 확인합니다.",
            safe_metadata=("candidate count", "finding id", "risk draft metadata"),
            href=_triage_href(output.output_id),
        ),
        OperatorRunbookStep(
            order=5,
            name="보고서 초안 확인",
            status=report_status,
            purpose="수동 검토용 보고서 초안 존재 여부를 확인합니다.",
            safe_metadata=("report_draft.md 상태", "파일 fingerprint", "초안 경계"),
            href=_report_readiness_href(output.output_id),
        ),
        OperatorRunbookStep(
            order=6,
            name="공유 전 점검",
            status="manual review required",
            purpose="공유할 네 파일과 민감정보 검사 결과를 확인합니다.",
            safe_metadata=("safe files 4개", "금지 마커 스캔", "verify 선행 여부"),
            href=_preflight_href(output.output_id),
        ),
        OperatorRunbookStep(
            order=7,
            name="전달할 파일 확인",
            status="manual review required",
            purpose="파일을 읽는 순서와 용도를 확인합니다.",
            safe_metadata=("file alias", "purpose", "SHA-256 fingerprint"),
            href=_handoff_href(output.output_id),
        ),
        OperatorRunbookStep(
            order=8,
            name="검토할 항목 확인",
            status="manual review required",
            purpose="점검 항목의 실제 영향과 심각도를 직접 판단합니다.",
            safe_metadata=("candidate status", "confidence", "severity draft"),
            href=_triage_href(output.output_id),
        ),
        OperatorRunbookStep(
            order=9,
            name="보고서 확인",
            status="manual review required",
            purpose="보고서 초안과 수동 제출 전 확인 항목을 분리해 봅니다.",
            safe_metadata=("report draft status", "manual checklist", "safe file metadata"),
            href=_report_readiness_href(output.output_id),
        ),
        OperatorRunbookStep(
            order=10,
            name="프롬프트 확인",
            status="manual review required",
            purpose="프롬프트의 안내 문구와 파일 상태를 확인합니다.",
            safe_metadata=("prompt file status", "body preview=false", "manual review boundary"),
            href=_prompt_readiness_href(output.output_id),
        ),
        OperatorRunbookStep(
            order=11,
            name="공유할 자료 확인",
            status="manual review required",
            purpose="공유할 자료에 원본이나 민감정보가 섞이지 않았는지 확인합니다.",
            safe_metadata=("sanitized evidence status", "forbidden data categories", "full path=false"),
            href=_evidence_boundary_href(output.output_id),
        ),
        OperatorRunbookStep(
            order=12,
            name="처리 순서 확인",
            status="manual review required",
            purpose="진행한 단계와 추가로 확인할 부분을 봅니다.",
            safe_metadata=("step status", "related index links", "no state change"),
            href=_workflow_href(output.output_id),
        ),
    ]
    return OperatorRunbookIndex(
        output=output,
        file_statuses=file_statuses,
        steps=steps,
        candidate_count=output.candidate_count,
        review_status=review_status,
        report_status=report_status,
        analysis_status=analysis_status,
        safe_file_count=safe_file_count,
    )


def _build_safe_file_inventory_index(output: DashboardOutput) -> SafeFileInventoryIndex:
    files = [_safe_file_inventory_file(output.path, name) for name in SAFE_PREVIEW_FILES]
    safe_file_count = sum(1 for file in files if file.status == "present")
    return SafeFileInventoryIndex(
        output=output,
        files=files,
        candidate_count=output.candidate_count,
        safe_file_count=safe_file_count,
        report_status=_file_status(output.path, "report_draft.md"),
        analysis_status=_file_status(output.path, "analysis_packet.json"),
    )


def _safe_file_inventory_file(output_dir: Path, name: str) -> SafeFileInventoryFile:
    path = output_dir / name
    if not path.is_file():
        return SafeFileInventoryFile(
            name=name,
            purpose=_safe_file_inventory_purpose(name),
            recommended_use=_safe_file_inventory_recommended_use(name),
            verify_required=True,
            status="missing",
            size_bytes=None,
            modified_utc="missing",
            sha256="missing",
        )
    stat = path.stat()
    return SafeFileInventoryFile(
        name=name,
        purpose=_safe_file_inventory_purpose(name),
        recommended_use=_safe_file_inventory_recommended_use(name),
        verify_required=True,
        status="present",
        size_bytes=stat.st_size,
        modified_utc=datetime.fromtimestamp(stat.st_mtime, UTC).replace(microsecond=0).isoformat(),
        sha256=_sha256_file(path),
    )


def _safe_file_inventory_purpose(file_name: str) -> str:
    purposes = {
        "analysis_packet.json": "정제된 finding candidate 구조와 수동 검토 경계를 확인합니다.",
        "chatgpt_prompt.md": "ChatGPT에 후보 분석 보조를 요청하기 전 prompt 파일 상태를 확인합니다.",
        "codex_task_prompt.md": "Codex에 구현, 리뷰, 테스트 보조를 요청하기 전 prompt 파일 상태를 확인합니다.",
        "report_draft.md": "사람이 검토할 보고서 초안의 존재와 fingerprint를 확인합니다.",
    }
    return purposes.get(file_name, "검증된 safe file 후보 메타데이터를 확인합니다.")


def _safe_file_inventory_recommended_use(file_name: str) -> str:
    uses = {
        "analysis_packet.json": "AI 분석 전 구조화된 후보 증거 기준으로 사용합니다.",
        "chatgpt_prompt.md": "ChatGPT에 필요한 범위만 투입하기 전 사람이 읽습니다.",
        "codex_task_prompt.md": "Codex 작업 요청 전 범위와 금지 데이터를 재확인합니다.",
        "report_draft.md": "최종 제출 전 사람이 수정할 보고서 초안으로만 사용합니다.",
    }
    return uses.get(file_name, "AI 투입 전 사람이 직접 검토합니다.")


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


def _prompt_readiness_file(output_dir: Path, name: str) -> PromptReadinessFile:
    path = output_dir / name
    if not path.is_file():
        return PromptReadinessFile(
            name=name,
            purpose=_prompt_readiness_purpose(name),
            status="missing",
            size_bytes=None,
            modified_utc="missing",
            sha256="missing",
        )
    stat = path.stat()
    return PromptReadinessFile(
        name=name,
        purpose=_prompt_readiness_purpose(name),
        status="present",
        size_bytes=stat.st_size,
        modified_utc=datetime.fromtimestamp(stat.st_mtime, UTC).replace(microsecond=0).isoformat(),
        sha256=_sha256_file(path),
    )


def _evidence_boundary_file(output_dir: Path, name: str) -> EvidenceBoundaryFile:
    path = output_dir / name
    if not path.is_file():
        return EvidenceBoundaryFile(
            name=name,
            purpose=_evidence_boundary_purpose(name),
            status="missing",
            size_bytes=None,
            modified_utc="missing",
            sha256="missing",
        )
    stat = path.stat()
    return EvidenceBoundaryFile(
        name=name,
        purpose=_evidence_boundary_purpose(name),
        status="present",
        size_bytes=stat.st_size,
        modified_utc=datetime.fromtimestamp(stat.st_mtime, UTC).replace(microsecond=0).isoformat(),
        sha256=_sha256_file(path),
    )


def _evidence_boundary_purpose(file_name: str) -> str:
    purposes = {
        "analysis_packet.json": "정제된 finding candidate 구조와 수동 검토 경계를 담습니다.",
        "chatgpt_prompt.md": "AI 분석 보조에 사용할 정제 prompt 파일입니다.",
        "codex_task_prompt.md": "구현, 리뷰, 테스트 보조에 사용할 정제 prompt 파일입니다.",
        "report_draft.md": "사람이 검토할 보고서 초안이며 제출용 최종본이 아닙니다.",
    }
    return purposes.get(file_name, "검증된 정제 evidence 후보 파일입니다.")


def _prompt_readiness_purpose(file_name: str) -> str:
    purposes = {
        "analysis_packet.json": "정제된 finding 후보 구조와 제약 조건을 담은 기준 packet입니다.",
        "chatgpt_prompt.md": "ChatGPT에 후보 분석과 수동 검토 보조를 요청할 때 사용합니다.",
        "codex_task_prompt.md": "Codex에 구현, 리뷰, 테스트 보강 같은 작업 보조를 요청할 때 사용합니다.",
        "report_draft.md": "사람이 검토할 후보 보고서 초안이며 제출용 최종본이 아닙니다.",
    }
    return purposes.get(file_name, "검증된 안전 파일 후보입니다.")


def _prompt_text_for_checks(output_dir: Path, file_name: str) -> str:
    path = output_dir / _safe_file_name(file_name)
    if not path.is_file() or path.stat().st_size > MAX_PREVIEW_BYTES:
        return ""
    try:
        text = path.read_text(encoding="utf-8")
        assert_no_sensitive_text(text)
    except (OSError, UnicodeError, ValueError):
        return ""
    return text


def _file_status(output_dir: Path, file_name: str) -> str:
    return "present" if (output_dir / file_name).is_file() else "missing"


def _contains_all(text: str, terms: tuple[str, ...]) -> bool:
    lowered = text.lower()
    return all(term.lower() in lowered for term in terms)


def _contains_any(text: str, terms: tuple[str, ...]) -> bool:
    lowered = text.lower()
    return any(term.lower() in lowered for term in terms)


def _report_readiness_status_summary(index: ReportReadinessIndex) -> str:
    if index.report_status == "present" and index.analysis_status == "present":
        return "초안 있음; 고객 제출 전 수동 검토 필요"
    if index.report_status == "missing":
        return "초안 없음; 검증된 리뷰 산출물에서 Report를 실행하세요"
    return "analysis packet 없음; 보고서 검토 전 검증된 산출물을 다시 생성하세요"


def _triage_candidate_from_json(index: int, candidate: dict[str, Any]) -> TriageCandidate:
    risk_rating = candidate.get("risk_rating_draft")
    risk = risk_rating if isinstance(risk_rating, dict) else {}
    title = _safe_value(candidate.get("title"), "Finding candidate")
    category = _safe_value(candidate.get("type"), "unknown_type")
    endpoint = _safe_value(candidate.get("affected_endpoint"), "정제된 endpoint 없음")
    summary = f"{_finding_label(category, title)}; 요청 경로: {endpoint}"
    return TriageCandidate(
        index=index,
        candidate_id=_safe_value(candidate.get("finding_id") or candidate.get("candidate_id"), f"candidate-{index}"),
        category=category,
        title=title,
        summary=_safe_value(summary, "정제된 후보 요약 없음."),
        confidence=_safe_value(candidate.get("confidence"), "unknown"),
        severity_draft=_safe_value(risk.get("severity_draft"), "unknown"),
        likelihood_draft=_safe_value(risk.get("likelihood_draft"), "unknown"),
        impact_draft=_safe_value(risk.get("impact_draft"), "unknown"),
        risk_profile=_safe_value(risk.get("risk_profile"), DEFAULT_RISK_RATING_PROFILE),
        manual_required=bool(candidate.get("manual_verification_required", True)),
    )


def _handoff_summary(index: AiHandoffIndex) -> str:
    return f"""
    <dl class="facts">
      <div><dt>파일 준비</dt><dd>{_status_badge(index.preflight.ready_status)}</dd></div>
      <div><dt>민감정보 검사</dt><dd>{_status_badge(index.preflight.marker_scan_status)}</dd></div>
      <div><dt>원문 포함</dt><dd>없음</dd></div>
    </dl>
    <p>파일 해시는 내용이 같은지 확인하는 값입니다. 비밀키로 검증하는 HMAC과는 다릅니다.</p>
    """


def _file_details(file: HandoffFile | ReportReadinessFile | PromptReadinessFile | EvidenceBoundaryFile | SafeFileInventoryFile) -> str:
    size = f"{file.size_bytes:,} 바이트" if file.size_bytes is not None else "없음"
    return f"""
    <article class="file-card">
      <div><strong>{_h(file.name)}</strong>{_status_badge(file.status)}
        <small>{_h(_safe_file_description(file.name))}</small></div>
      <dl class="facts compact">
        <div><dt>크기</dt><dd>{_h(size)}</dd></div>
        <div><dt>수정 시각(UTC)</dt><dd>{_h(_status_label(file.modified_utc))}</dd></div>
        <div><dt>파일 해시(SHA-256)</dt><dd>{_h(_status_label(file.sha256))}</dd></div>
      </dl>
    </article>
    """


def _handoff_file_card(file: HandoffFile) -> str:
    return _file_details(file)


def _report_readiness_file_card(file: ReportReadinessFile) -> str:
    return _file_details(file)


def _prompt_readiness_file_card(file: PromptReadinessFile) -> str:
    return _file_details(file)


def _prompt_readiness_check_card(check: PromptReadinessCheck) -> str:
    return f"""
    <article class="file-card">
      <div>
        <span class="kicker">read-only check</span>
        <strong>{_h(check.name)}</strong>
        <span>{_status_badge(check.status)}</span>
        <small>{_h(check.summary)}</small>
      </div>
      <dl class="facts compact">
        <div><dt>상태</dt><dd>{_h(_status_label(check.status))}</dd></div>
        <div><dt>점검 방식</dt><dd>prompt 본문을 표시하지 않고 키워드 존재 여부만 요약합니다.</dd></div>
        <div><dt>수동 검토</dt><dd>필요</dd></div>
      </dl>
    </article>
    """


def _evidence_boundary_file_card(file: EvidenceBoundaryFile) -> str:
    return _file_details(file)


def _workflow_step_card(step: WorkflowStep) -> str:
    return f"""
    <article class="file-card">
      <div><strong>{_h(step.name)}</strong>{_status_badge(step.status)}<small>{_h(step.summary)}</small></div>
      <a href="{_h(step.href)}">확인하기</a>
    </article>
    """


def _operator_runbook_step_card(step: OperatorRunbookStep) -> str:
    return f"""
    <article class="file-card">
      <div><strong>{step.order}. {_h(step.name)}</strong>{_status_badge(step.status)}
        <small>{_h(step.purpose)}</small></div>
      <a href="{_h(step.href)}">확인하기</a>
    </article>
    """


def _safe_file_inventory_card(file: SafeFileInventoryFile) -> str:
    return _file_details(file)


def _finding_label(category: str, fallback: str) -> str:
    labels = {
        "missing_security_headers": "보안 헤더 누락 확인",
        "weak_cookie_attributes": "쿠키 보호 설정 확인",
        "cors_candidate": "다른 출처의 접근 허용 설정 확인",
        "cache_control_on_authenticated_response": "로그인 응답의 캐시 설정 확인",
        "error_exposure": "오류 메시지의 내부 정보 노출 확인",
        "idor_candidate": "다른 사용자 자료에 접근할 수 있는지 확인",
        "sensitive_data_exposure_candidate": "응답의 민감정보 노출 확인",
    }
    return labels.get(category, fallback)


def _triage_candidate_card(candidate: TriageCandidate) -> str:
    title = _finding_label(candidate.category, candidate.title)
    return f"""
    <article class="candidate">
      <div class="candidate-head">
        <div><span class="kicker">후보 #{candidate.index}</span>
          <h3>{_h(title)}</h3><p>{_h(candidate.candidate_id)}</p></div>
        <span class="badge warning">확인 필요</span>
      </div>
      <dl class="facts compact">
        <div><dt>근거 신뢰도</dt><dd>{_h(_status_label(candidate.confidence))}</dd></div>
        <div><dt>심각도 초안</dt><dd>{_h(_status_label(candidate.severity_draft))}</dd></div>
        <div><dt>발생 가능성</dt><dd>{_h(_status_label(candidate.likelihood_draft))}</dd></div>
        <div><dt>영향도</dt><dd>{_h(_status_label(candidate.impact_draft))}</dd></div>
        <div><dt>직접 확인 필요</dt><dd>{"예" if candidate.manual_required else "아니오"}</dd></div>
      </dl>
      <p class="review-note">근거 신뢰도는 판단을 뒷받침하는 자료의 정도이며 위험도와 다릅니다.</p>
      <details class="secondary-details"><summary>분류 코드와 분석 요약</summary>
        <p>분류 코드: {_h(candidate.category)}</p><p>{_h(candidate.summary)}</p>
        <p>평가 기준: {_h(_status_label(candidate.risk_profile))}</p>
      </details>
    </article>
    """


def _preflight_summary(preflight: AiSafePreflight) -> str:
    missing = ", ".join(preflight.missing_files) if preflight.missing_files else "없음"
    return f"""
    <dl class="facts">
      <div><dt>검증한 파일 수</dt><dd>{preflight.files_checked}</dd></div>
      <div><dt>민감정보를 검사한 전달 후보 파일</dt><dd>{preflight.marker_scan_files}개</dd></div>
      <div><dt>누락 파일</dt><dd>{_h(missing)}</dd></div>
      <div><dt>원문 포함</dt><dd>없음</dd></div>
    </dl>
    """


def _safe_handoff_purpose(file_name: str) -> str:
    purposes = {
        "analysis_packet.json": "정제된 후보 증거 구조를 먼저 확인합니다.",
        "chatgpt_prompt.md": "ChatGPT에 수동 검토 보조를 요청할 때 사용합니다.",
        "codex_task_prompt.md": "Codex에 구현 또는 리뷰 보조를 요청할 때 사용합니다.",
        "report_draft.md": "사람이 검토할 후보 보고서 초안으로 마지막에 읽습니다.",
    }
    return purposes.get(file_name, "AI 안전 후보 파일 메타데이터입니다.")


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
    return f"""
    <tr>
      <td><span class="output-label">{_h(output.label)}</span></td>
      <td>{output.candidate_count}개</td>
      <td>{len(output.prompt_files)}/4개</td>
      <td>{'있음' if output.report_available else '없음'}</td>
      <td><span class="badge good">검증 통과</span></td>
      <td class="record-actions">
        <a class="button small" href="{_simple_dashboard_href(output.output_id)}">결과 보기</a>
        <a class="button small secondary" href="{_output_href(output.output_id)}">파일 확인</a>
      </td>
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


def _simple_safe_file_row(output: DashboardOutput, file_name: str) -> str:
    status = "present" if (output.path / file_name).is_file() else "missing"
    return f"""
    <tr>
      <td>{_h(file_name)}</td>
      <td>{_h(_safe_file_description(file_name))}</td>
      <td>{_status_badge(status)}</td>
    </tr>
    """


def _action_panel(output: DashboardOutput, csrf_token: str) -> str:
    project = _h(output.output_id)
    token = _h(csrf_token)
    profile_labels = {"conservative": "기본 검토용", "consultant": "상세 검토용"}
    profile_options = "\n".join(
        f'<option value="{_h(name)}"{" selected" if name == DEFAULT_REPORT_PROFILE else ""}>{_h(profile_labels.get(name, name))}</option>'
        for name in REPORT_PROFILE_NAMES
    )
    return f"""
    <div class="action-grid">
      {_action_form(project, token, "verify", "다시 검증", "결과에 민감정보가 남아 있는지 다시 검사합니다.")}
      {_action_form(project, token, "review", "검토 요약", "검토할 항목의 요약을 확인합니다.")}
      <form class="action-card" method="post" action="/action">
        <input type="hidden" name="csrf_token" value="{token}">
        <input type="hidden" name="project" value="{project}">
        <input type="hidden" name="action" value="report">
        <label>보고서 작성 방식<select name="profile">{profile_options}</select></label>
        <button type="submit">보고서 다시 만들기</button>
        <small>검사를 통과하면 보고서 초안을 갱신합니다.</small>
      </form>
      {_action_form(project, token, "export", "파일 4개 내보내기", "전달 후보 파일을 별도 폴더에 복사합니다.")}
      <a class="action-card refresh-card" href="{_output_href(output.output_id)}">
        <strong>새로고침</strong>
        <small>현재 결과를 다시 불러옵니다.</small>
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
    title = _finding_label(kind, title)
    endpoint = _safe_value(candidate.get("affected_endpoint"), "unknown_endpoint")
    confidence = _safe_value(candidate.get("confidence"), "unknown")
    manual_required = "예" if candidate.get("manual_verification_required", True) else "아니오"
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
          <span class="badge neutral">근거 신뢰도: {_h(_status_label(confidence))}</span>
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
        f"평가 기준: {_h(_status_label(risk_profile))}; "
        f"심각도 초안: {_h(_status_label(severity))}; "
        f"발생 가능성: {_h(_status_label(likelihood))}; "
        f"영향도: {_h(_status_label(impact))}; "
        f"확정 여부: {'예' if finalized == 'true' else '아니오'}"
    )


def _audit_panel(status: dict[str, str]) -> str:
    return f"""
    <dl class="facts">
      <div><dt>기록 검사</dt><dd>{_status_badge(status["review_status"])}</dd></div>
      <div><dt>검사한 기록 수</dt><dd>{_h(status["events"])}</dd></div>
      <div><dt>검사한 파일 수</dt><dd>{_h(status["files"])}</dd></div>
      <div><dt>보관 기록(JSONL)</dt><dd>{_status_badge(status["retained_status"])}</dd></div>
      <div><dt>위변조 검사표(HMAC)</dt><dd>{_status_badge(status["hmac_status"])}</dd></div>
      <div><dt>압축 보관 파일</dt><dd>{_status_badge(status["archive_status"])}</dd></div>
      <div><dt>압축 파일 검사</dt><dd>{_status_badge(status["archive_verify_status"])}</dd></div>
      <div><dt>압축 파일 위변조 검사표(HMAC)</dt><dd>{_status_badge(status["archive_hmac_manifest_status"])}</dd></div>
      <div><dt>압축 파일 위변조 검사</dt><dd>{_status_badge(status["archive_hmac_status"])}</dd></div>
      <div><dt>표시 내용</dt><dd>상태만</dd></div>
    </dl>
    """


def _read_only_troubleshooting_panel() -> str:
    categories = (
        (
            "setup friction",
            "Windows 실행, 포트 충돌, dashboard 시작 문제를 먼저 확인합니다.",
            "/help",
            "docs/WINDOWS_LAUNCHER_GUIDE.md",
        ),
        (
            "upload/export friction",
            "Burp export 입력과 Upload Wizard 경계를 확인합니다.",
            "/upload",
            "docs/GUI_UPLOAD_WIZARD.md",
        ),
        (
            "verify/review/report friction",
            "verify 실패, 후보 finding, report draft 생성 흐름을 점검합니다.",
            "/operations",
            "docs/USER_QUICKSTART.md",
        ),
        (
            "live-capture friction",
            "Live Capture는 상태 확인과 runtime evidence만 read-only로 봅니다.",
            "/live-capture",
            "docs/LIVE_CAPTURE_RUNTIME_SMOKE_CHECKLIST_v0.5.md",
        ),
        (
            "safe-files friction",
            "AI 입력 후보 파일 4개와 수동 검토 경계를 확인합니다.",
            "/help",
            "docs/GUI_SAFE_FILE_INVENTORY_INDEX.md",
        ),
        (
            "MCP boundary friction",
            "MCP는 read-only 경계와 별도 구현 단위를 먼저 확인합니다.",
            "/operations",
            "docs/READ_ONLY_MCP.md",
        ),
    )
    cards = "\n".join(
        f"""
              <a class="guide-card" href="{_h(href)}">
                <strong>{_h(title)}</strong>
                <span>{_h(summary)}</span>
                <small>read-only navigation only; raw traffic은 표시하지 않습니다.</small>
                <code>{_h(reference)}</code>
              </a>
        """
        for title, summary, href, reference in categories
    )
    return f"""
        <section class="panel read-only-troubleshooting-panel" aria-label="read-only troubleshooting categories">
          <div class="panel-head">
            <h2>Read-only troubleshooting categories</h2>
            <span class="muted">setup, upload, verify, live-capture, safe-files, MCP boundary를 빠르게 찾습니다.</span>
          </div>
          <p class="muted">이 패널은 안내 링크만 제공합니다. POST action, 실행 버튼, raw preview, replay, active scan, ChatGPT 자동 전송은 없습니다.</p>
          <div class="file-grid">{cards}</div>
        </section>
        """


def _release_readiness_status_panel() -> str:
    readiness_items = (
        (
            "v0.5 local-use baseline",
            "published; local-use 기준선으로 유지합니다.",
            "docs/RELEASE_READINESS_v0.5.md",
        ),
        (
            "v0.6 planning",
            "read-only UX와 MCP read-only 준비를 분리해서 진행합니다.",
            "docs/ROADMAP_v0.6.md",
        ),
        (
            "v0.5 hotfix policy",
            "기능 추가 없이 회귀, 문서, 실행 마찰만 고칩니다.",
            "docs/V0.5_HOTFIX_POLICY.md",
        ),
        (
            "Montoya runtime smoke evidence",
            "release 판단 근거는 raw-free metadata로만 기록합니다.",
            "docs/V05_MONTOYA_RUNTIME_SMOKE_RELEASE_EVIDENCE.md",
        ),
    )
    rows = "\n".join(
        f"""
              <div>
                <dt>{_h(title)}</dt>
                <dd><span>{_h(summary)}</span><br><code>{_h(href)}</code></dd>
              </div>
        """
        for title, summary, href in readiness_items
    )
    return f"""
        <section class="panel release-readiness-status-panel" aria-label="release readiness status">
          <div class="panel-head">
            <h2>Release readiness status</h2>
            <span class="muted">문서 파일명과 상태 metadata만 표시합니다.</span>
          </div>
          <dl class="facts">
            {rows}
            <div><dt>tag action</dt><dd>not available in dashboard</dd></div>
            <div><dt>GitHub Release action</dt><dd>not available in dashboard</dd></div>
            <div><dt>raw_data_included</dt><dd>false</dd></div>
          </dl>
          <p class="muted">Tag와 GitHub Release는 별도 승인 후 CLI/GitHub 흐름에서만 처리합니다.</p>
        </section>
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
        "analysis_packet.json": "요청 요약과 점검 후보",
        "chatgpt_prompt.md": "ChatGPT 검토용 질문",
        "codex_task_prompt.md": "Codex 검토용 질문",
        "report_draft.md": "검토할 보고서 초안",
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
        "present": "있음",
        "missing": "없음",
        "ready_candidate": "후보 준비됨",
        "missing_safe_files": "안전 파일 누락",
        "needs_manual_review": "수동 검토 필요",
        "forbidden_marker_found": "금지 마커 발견",
        "candidate available": "후보 있음",
        "draft available": "초안 있음",
        "manual review required": "수동 검토 필요",
        "skipped": "건너뜀",
        "failed safely": "차단됨",
        "stored under local_only alias": "로컬에 보관",
        "low": "낮음",
        "medium": "보통",
        "high": "높음",
        "critical": "매우 높음",
        "unknown": "판단 전",
        "unknown_type": "분류 전",
        "idle": "대기 중",
        "running": "진행 중",
        "stopped": "중지됨",
        "not selected": "선택 안 됨",
        "not_selected": "선택 안 됨",
        "conservative": "기본 검토 기준",
        "conservative_strict": "보수적인 검토 기준",
        "configured": "설정됨",
        "none": "없음",
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


def _optional_query_value(query: str, name: str) -> str:
    values = parse_qs(query, keep_blank_values=False).get(name)
    if not values or not values[0].strip():
        return ""
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


def _new_live_capture_session_alias() -> str:
    return f"live_capture_session_{secrets.token_hex(6)}"


def _utc_now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


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


def _safe_upload_project_alias(value: str) -> str:
    alias = str(value).strip()
    if not UPLOAD_PROJECT_RE.fullmatch(alias):
        raise DashboardError("invalid_project_alias", HTTPStatus.BAD_REQUEST)
    if alias.lower() in FORBIDDEN_PATH_PARTS:
        raise DashboardError("invalid_project_alias", HTTPStatus.BAD_REQUEST)
    if scan_text(alias):
        raise DashboardError("invalid_project_alias", HTTPStatus.BAD_REQUEST)
    return alias


def _safe_upload_suffix(file_name: str) -> str:
    suffix = Path(str(file_name or "")).suffix.lower()
    if suffix not in UPLOAD_ALLOWED_SUFFIXES:
        raise DashboardError("unsupported_file_type", HTTPStatus.BAD_REQUEST)
    return suffix


def _upload_output_dir(root: Path, project_alias: str) -> Path:
    relative = Path(project_alias)
    _reject_forbidden_parts(relative.parts)
    candidate = (root / relative).resolve()
    if not _is_relative_to(candidate, root):
        raise DashboardError("path_traversal_rejected", HTTPStatus.FORBIDDEN)
    return candidate


def _upload_storage_dir(root: Path) -> Path:
    base = _dashboard_workspace_root(root)
    storage = (base / "local_only" / "dashboard_uploads").resolve()
    if storage.is_dir() or not storage.exists():
        return storage
    raise DashboardError("upload_storage_unavailable", HTTPStatus.INTERNAL_SERVER_ERROR)


def _dashboard_workspace_root(root: Path) -> Path:
    resolved = root.resolve()
    for candidate in (resolved, *resolved.parents):
        if (candidate / ".git").exists() and (candidate / "pyproject.toml").is_file():
            return candidate
    return resolved.parent


def _internal_upload_file_name(project_alias: str, suffix: str) -> str:
    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    nonce = secrets.token_hex(6)
    return f"dashboard_upload_{timestamp}_{project_alias}_{nonce}{suffix}"


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


def _live_capture_result_status(result: LiveCaptureActionResult) -> str:
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
        "upload_validation_failed": "upload_validation_failed",
        "unsupported_file_type": "unsupported_file_type",
        "invalid_project_alias": "invalid_project_alias",
        "upload_output_exists": "upload_output_exists",
        "generate_failed": "generate_failed",
        "verify_failed": "verify_failed",
        "review_failed": "review_failed",
        "report_failed": "report_failed",
        "safe_file_not_allowed": "unsafe_export",
        "path_traversal_forbidden": "path_traversal",
        "path_traversal_rejected": "path_traversal",
        "absolute_output_path_forbidden": "path_traversal",
        "forbidden_directory": "forbidden_directory",
        "unsupported_dashboard_action": "unsupported_action",
    }
    return reasons.get(error_type, "")


def _safe_dashboard_audit_action(value: str) -> str:
    action = str(value).strip().lower()
    return action if action in AUDIT_ACTION_NAMES else "unknown_action"


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


def _simple_dashboard_href(output_id: str) -> str:
    return "/simple?project=" + quote(output_id, safe="")


def _preflight_href(output_id: str) -> str:
    return "/preflight?project=" + quote(output_id, safe="")


def _handoff_href(output_id: str) -> str:
    return "/handoff?project=" + quote(output_id, safe="")


def _triage_href(output_id: str) -> str:
    return "/triage?project=" + quote(output_id, safe="")


def _report_readiness_href(output_id: str) -> str:
    return "/report-readiness?project=" + quote(output_id, safe="")


def _prompt_readiness_href(output_id: str) -> str:
    return "/prompt-readiness?project=" + quote(output_id, safe="")


def _evidence_boundary_href(output_id: str) -> str:
    return "/evidence-boundary?project=" + quote(output_id, safe="")


def _workflow_href(output_id: str) -> str:
    return "/workflow?project=" + quote(output_id, safe="")


def _operator_runbook_href(output_id: str) -> str:
    return "/operator-runbook?project=" + quote(output_id, safe="")


def _safe_files_href(output_id: str) -> str:
    return "/safe-files?project=" + quote(output_id, safe="")


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
    .app-name {{ color: var(--muted); font-size: 13px; margin-bottom: 6px; }}
    .summary-line {{ display: flex; flex-wrap: wrap; gap: 12px 28px; align-items: center; min-height: 64px; border-top: 1px solid var(--border); border-bottom: 1px solid var(--border); margin-bottom: 20px; padding: 12px 0; }}
    .summary-line span {{ line-height: 1.6; }}
    .workspace-section {{ margin: 0 0 24px; min-width: 0; }}
    .workspace-section h2 {{ margin: 0 0 16px; }}
    .workflow-grid {{ display: grid; grid-template-columns: minmax(0, 1fr) minmax(0, 1fr); gap: 40px; }}
    .review-note {{ color: var(--muted); font-size: 14px; line-height: 1.65; margin: 16px 0 22px; }}
    .failure-note {{ border-left: 3px solid var(--danger); padding: 14px 18px; line-height: 1.65; background: #fff0ed; }}
    .empty-state {{ padding: 40px 0; color: var(--muted); border-bottom: 1px solid var(--border); }}
    .secondary-details {{ border-top: 1px solid var(--border); padding: 16px 0; }}
    .secondary-details summary {{ cursor: pointer; font-weight: 600; }}
    .secondary-details[open] summary {{ margin-bottom: 18px; }}
    .secondary-links {{ display: flex; flex-wrap: wrap; gap: 14px 24px; }}
    .record-actions {{ display: flex; flex-wrap: wrap; gap: 6px; }}
    .records-table th:first-child {{ width: 22%; }}
    .records-table th:last-child {{ width: 28%; }}
    .result-table th:first-child {{ width: 35%; }}
    .result-table th:last-child:not(:nth-child(2)) {{ width: 18%; }}
    .result-table td {{ overflow-wrap: anywhere; line-height: 1.6; }}
    .stacked-form {{ display: grid; gap: 16px; }}
    .stacked-form label {{ display: grid; gap: 8px; font-weight: 600; min-width: 0; }}
    .stacked-form input {{ width: 100%; min-width: 0; padding: 12px; border: 1px solid var(--border); border-radius: 6px; font: inherit; background: var(--surface); color: var(--text); }}
    .stacked-form input[type="file"] {{ padding: 10px; font-size: 14px; }}
    .stacked-form small {{ color: var(--muted); line-height: 1.6; }}
    .stacked-form button {{ min-height: 44px; padding: 10px 16px; font: inherit; font-weight: 600; color: #ffffff; background: var(--accent); border: 1px solid var(--accent); border-radius: 6px; cursor: pointer; }}
    a:focus-visible, summary:focus-visible, button:focus-visible, input:focus-visible {{ outline: 3px solid #e0ae35; outline-offset: 3px; }}
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
      .workflow-grid {{ grid-template-columns: minmax(0, 1fr); gap: 16px; }}
      .summary-line {{ gap: 8px 18px; }}
      .records-table th:nth-child(2), .records-table td:nth-child(2), .records-table th:nth-child(5), .records-table td:nth-child(5) {{ display: none; }}
      .records-table th:first-child, .records-table th:last-child {{ width: 50%; }}
      .result-table th, .result-table td {{ display: table-cell; }}
      .result-table {{ table-layout: fixed; }}
      .result-table th:first-child {{ width: 40%; }}
      .result-table th:last-child:not(:nth-child(2)) {{ width: 20%; }}
    }}
    .check-table th:first-child {{ width: 65%; }}
    .check-table .badge {{ max-width: 100%; white-space: normal; text-align: center; justify-content: center; }}
    .handoff-table th:first-child {{ width: 8%; }}
    .handoff-table th:nth-child(2) {{ width: 35%; }}
  </style>
</head>
<body>
  <main>{body}</main>
</body>
</html>
"""
