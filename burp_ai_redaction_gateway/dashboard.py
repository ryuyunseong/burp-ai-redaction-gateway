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
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, quote, urlsplit

from .findings import build_finding_candidates
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
    ("analysis_packet.json", "정제된 분석 metadata 후보"),
    ("chatgpt_prompt.md", "ChatGPT 검토용 prompt 후보"),
    ("codex_task_prompt.md", "Codex 후속 작업용 prompt 후보"),
    ("report_draft.md", "사람이 편집할 보고서 초안"),
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


class DashboardHttpServer(ThreadingHTTPServer):
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
    audit_status = _audit_status(root)
    rows = "\n".join(_output_row(output) for output in outputs) or (
        '<tr><td colspan="6" class="empty">검증을 통과한 산출물 디렉터리가 없습니다.</td></tr>'
    )
    first_output_id = outputs[0].output_id if outputs else ""
    safe_files_href = _safe_files_href(first_output_id) if first_output_id else "/help"
    safe_file_cards = "\n".join(
        f"""
        <div class="guide-card">
          <strong>{_h(name)}</strong>
          <span>{_h(purpose)}</span>
          <small>AI 입력 후보 파일이며 사람이 수동 검토해야 합니다.</small>
        </div>
        """
        for name, purpose in SAFE_FILE_PURPOSES
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
            <a class="button secondary" href="/live-capture">Live Capture 준비</a>
            <a class="button" href="/upload">업로드 마법사</a>
            <a class="button secondary" href="/help">운영 가이드</a>
            <a class="button secondary" href="/settings">설정/상태</a>
          </div>
        </section>
        {_safety_strip()}
        {_render_output_alias_selector(root, policy, first_output_id, outputs)}
        {_read_only_troubleshooting_panel()}
        {_release_readiness_status_panel()}
        <section class="grid">
          <div class="panel">
            <div class="panel-head"><h2>처음 시작하기</h2><span class="muted">PowerShell을 덜 쓰고 화면 순서대로 확인합니다.</span></div>
            <div class="file-grid">
              <a class="guide-card" href="/upload">
                <strong>파일 업로드</strong>
                <span>Burp export를 선택하고 redaction, verify, review, report를 순서대로 실행합니다.</span>
              </a>
              <a class="guide-card" href="/live-capture">
                <strong>Live Capture 상태 확인</strong>
                <span>Burp 탐색 후 receiver output 준비 상태를 조회합니다. 이 화면은 실행 화면이 아닙니다.</span>
              </a>
              <a class="guide-card" href="{_h(safe_files_href)}">
                <strong>AI에 넣을 수 있는 후보 파일 확인</strong>
                <span>검증 통과 산출물이 있으면 목록의 첫 번째 safe files로 이동합니다. 최종 결과가 아닙니다.</span>
              </a>
              <a class="guide-card" href="/help">
                <strong>운영 도움말</strong>
                <span>문제가 생기면 도움말과 troubleshooting 문서 흐름을 먼저 확인합니다.</span>
              </a>
            </div>
          </div>
          <div class="panel">
            <div class="panel-head"><h2>safe files 4개</h2><span class="muted">AI 입력 후보 allowlist입니다.</span></div>
            <div class="file-grid">{safe_file_cards}</div>
            <p class="muted">finding은 후보, risk는 초안이며 final severity와 CVSS는 사람이 수동 결정합니다.</p>
          </div>
        </section>
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
            <a class="button secondary" href="/live-capture">Live Capture 준비</a>
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
              <div><dt>root 별칭</dt><dd>{_h(_safe_root_alias(root))}</dd></div>
              <div><dt>바인딩 모드</dt><dd>127.0.0.1 전용</dd></div>
              <div><dt>대시보드 모드</dt><dd>안전 action 사용 가능</dd></div>
              <div><dt>설정 화면</dt><dd>조회 전용</dd></div>
              <div><dt>CSRF 보호</dt><dd>활성화됨; 값 숨김</dd></div>
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
              <div><dt>보고서 profile</dt><dd>{_h(profiles)}</dd></div>
              <div><dt>위험도 profile</dt><dd>{_h(risk_profiles)}</dd></div>
              <div><dt>기본 위험도 profile</dt><dd>{_h(DEFAULT_RISK_RATING_PROFILE)}</dd></div>
              <div><dt>위험도 모드</dt><dd>초안 전용</dd></div>
              <div><dt>confidence_is_severity</dt><dd>false</dd></div>
              <div><dt>심각도 결정</dt><dd>수동 검토 필요</dd></div>
            </dl>
          </div>
          <div class="panel">
            <div class="panel-head"><h2>감사와 무결성</h2><span class="muted">감사 row와 비밀값은 표시하지 않습니다.</span></div>
            <dl class="facts">
              <div><dt>감사 schema</dt><dd>{_h(AUDIT_SCHEMA_VERSION)}</dd></div>
              <div><dt>감사 경로 별칭</dt><dd>&lt;root&gt;/.audit/{_h(AUDIT_FILE_NAME)}</dd></div>
              <div><dt>감사 검토</dt><dd>{_status_badge(audit_status["review_status"])}</dd></div>
              <div><dt>감사 로그</dt><dd>{_status_badge(audit_status["audit_log_status"])}</dd></div>
              <div><dt>HMAC 설정</dt><dd>{_h(_hmac_configured_label())}</dd></div>
              <div><dt>HMAC manifest</dt><dd>{_status_badge(audit_status["hmac_status"])}</dd></div>
              <div><dt>보존 JSONL</dt><dd>{_status_badge(audit_status["retained_status"])}</dd></div>
              <div><dt>압축 archive</dt><dd>{_status_badge(audit_status["archive_status"])}</dd></div>
              <div><dt>압축 archive 검증</dt><dd>{_status_badge(audit_status["archive_verify_status"])}</dd></div>
              <div><dt>압축 archive HMAC manifest</dt><dd>{_status_badge(audit_status["archive_hmac_manifest_status"])}</dd></div>
              <div><dt>압축 archive HMAC 검증</dt><dd>{_status_badge(audit_status["archive_hmac_status"])}</dd></div>
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
            <p class="subtitle">GUI에서 자주 필요한 사용 흐름, 문서 위치, 안전 경계를 한 화면에 모아 둔 조회 전용 안내입니다.</p>
          </div>
          <div class="status-stack">
            <span class="badge good">조회 전용</span>
            <span class="badge neutral">실행 버튼 없음</span>
            <a class="button secondary" href="/live-capture">Live Capture 준비</a>
            <a class="button" href="/upload">업로드 마법사</a>
            <a class="button secondary" href="/settings">설정/상태</a>
          </div>
        </section>
        <section class="safety-strip">
          <div class="rail"><span>접속</span><strong>127.0.0.1 전용</strong></div>
          <div class="rail"><span>표시</span><strong>HTML escape 적용</strong></div>
          <div class="rail"><span>finding</span><strong>후보</strong></div>
          <div class="rail"><span>위험도</span><strong>초안</strong></div>
        </section>
        {_read_only_troubleshooting_panel()}
        {_release_readiness_status_panel()}
        <section class="grid">
          <div class="panel">
            <div class="panel-head"><h2>빠른 흐름</h2><span class="muted">CLI와 GUI 병행 사용 순서입니다.</span></div>
            <ol class="safe-list">
              <li>PowerShell 명령 없이 시작하려면 <a href="/upload">업로드 마법사</a>에서 파일을 선택합니다.</li>
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
              <div><dt>finding</dt><dd>후보이며 수동 검증 전 확정 취약점이 아닙니다.</dd></div>
              <div><dt>위험도</dt><dd>초안이며 최종 심각도가 아닙니다.</dd></div>
              <div><dt>confidence</dt><dd>증거 신뢰도이며 심각도가 아닙니다.</dd></div>
              <div><dt>최종 심각도</dt><dd>Burp 재현, 권한별 비교, 영향도 판단 후 수동 결정합니다.</dd></div>
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


def render_live_capture_readiness(
    _csrf_token: str,
    session: LiveCaptureSession,
    result: LiveCaptureActionResult | None = None,
    output: DashboardOutput | None = None,
    alias_selector_html: str = "",
) -> str:
    safe_files = "".join(f"<li>{_h(name)}</li>" for name in SAFE_PREVIEW_FILES)
    receiver_evidence = _build_live_capture_receiver_output_evidence(output)
    result_panel = ""
    if result:
        summary = "".join(f"<li>{_h(line)}</li>" for line in result.summary_lines)
        result_panel = f"""
          <div class="panel">
            <div class="panel-head"><h2>Live Capture action result</h2><span class="muted">raw-free metadata only</span></div>
            <dl class="facts">
              <div><dt>action</dt><dd>{_h(result.action_name)}</dd></div>
              <div><dt>result status</dt><dd>{_h(result.status)}</dd></div>
              <div><dt>blocked reason</dt><dd>{_h(result.blocked_reason or "none")}</dd></div>
              <div><dt>raw_data_included</dt><dd>false</dd></div>
            </dl>
            <ul class="safe-list">{summary}</ul>
          </div>
        """
    receiver_output_alias = receiver_evidence.receiver_output_alias
    receiver_verify_status = receiver_evidence.receiver_verify_status
    safe_navigation_status = receiver_evidence.safe_file_existence_status
    raw_data_included = "true" if receiver_evidence.raw_data_included else "false"
    safe_navigation = (
        f"""
          <div class="panel">
            <div class="panel-head"><h2>Verified receiver output navigation</h2><span class="muted">read-only links</span></div>
            <dl class="facts">
              <div><dt>evidence source</dt><dd>{_h(receiver_evidence.evidence_source)}</dd></div>
              <div><dt>receiver output alias</dt><dd>{_h(receiver_evidence.receiver_output_alias)}</dd></div>
              <div><dt>receiver verify status</dt><dd>{_status_badge("passed")}</dd></div>
              <div><dt>safe files</dt><dd>{_status_badge(receiver_evidence.safe_file_existence_status)}</dd></div>
              <div><dt>candidate count</dt><dd>{_h(str(receiver_evidence.candidate_count))}</dd></div>
              <div><dt>raw_data_included</dt><dd>{raw_data_included}</dd></div>
            </dl>
            <ul class="safe-list">
              <li><a href="{_simple_dashboard_href(output.output_id)}">simple dashboard</a></li>
              <li><a href="{_safe_files_href(output.output_id)}">safe files</a></li>
              <li><a href="{_triage_href(output.output_id)}">triage</a></li>
              <li><a href="{_report_readiness_href(output.output_id)}">report readiness</a></li>
              <li><a href="{_workflow_href(output.output_id)}">workflow</a></li>
            </ul>
          </div>
        """
        if output and receiver_evidence.safe_navigation_available
        else """
          <div class="panel">
            <div class="panel-head"><h2>Verified receiver output navigation</h2><span class="muted">hidden until verify passes</span></div>
            <dl class="facts">
              <div><dt>evidence source</dt><dd>receiver_output_alias</dd></div>
              <div><dt>receiver output alias</dt><dd>not selected</dd></div>
              <div><dt>receiver verify status</dt><dd>not selected</dd></div>
              <div><dt>safe files</dt><dd>hidden until verify passes</dd></div>
              <div><dt>candidate count</dt><dd>0</dd></div>
              <div><dt>raw_data_included</dt><dd>false</dd></div>
            </dl>
            <p class="muted">Open this page with a verified receiver output alias to show safe navigation links.</p>
          </div>
        """
    )
    return _page(
        "Live Capture read-only status",
        f"""
        <section class="topbar">
          <div>
            <a class="back" href="/">대시보드로 돌아가기</a>
            <h1>Live Capture read-only status</h1>
            <p class="subtitle">v0.5 Live Capture의 read-only 상태 패널입니다. runtime smoke 상태와 verified receiver output alias만 안내하며 dashboard에서 capture를 시작하거나 중지하지 않습니다.</p>
          </div>
          <div class="status-stack">
            <span class="badge good">read-only</span>
            <span class="badge neutral">no form</span>
            <span class="badge neutral">no POST action</span>
          </div>
        </section>
        <section class="safety-strip">
          <div class="rail"><span>session state</span><strong>{_h(session.status)}</strong></div>
          <div class="rail"><span>receiver verify</span><strong>{_h(receiver_verify_status)}</strong></div>
          <div class="rail"><span>receiver output alias</span><strong>{_h(receiver_output_alias)}</strong></div>
          <div class="rail"><span>safe navigation</span><strong>{_h(safe_navigation_status)}</strong></div>
          <div class="rail"><span>evidence source</span><strong>{_h(receiver_evidence.evidence_source)}</strong></div>
          <div class="rail"><span>raw_data_included</span><strong>{raw_data_included}</strong></div>
        </section>
        {alias_selector_html}
        {_read_only_troubleshooting_panel()}
        <section class="grid">
          {result_panel}
          <div class="panel">
            <div class="panel-head"><h2>Runtime smoke status panel</h2><span class="muted">count/status labels only</span></div>
            <dl class="facts">
              <div><dt>extension load status</dt><dd>manual evidence not recorded in dashboard</dd></div>
              <div><dt>local receiver status</dt><dd>manual evidence not recorded in dashboard</dd></div>
              <div><dt>in-scope handoff count</dt><dd>not recorded in dashboard</dd></div>
              <div><dt>out-of-scope skip count</dt><dd>not recorded in dashboard</dd></div>
              <div><dt>missing_host_skipped</dt><dd>not recorded in dashboard</dd></div>
              <div><dt>invalid_host_skipped</dt><dd>not recorded in dashboard</dd></div>
              <div><dt>receiver verify status</dt><dd>{_h(receiver_verify_status)}</dd></div>
              <div><dt>receiver output alias</dt><dd>{_h(receiver_output_alias)}</dd></div>
              <div><dt>safe file existence status</dt><dd>{_h(receiver_evidence.safe_file_existence_status)}</dd></div>
              <div><dt>candidate count</dt><dd>{_h(str(receiver_evidence.candidate_count))}</dd></div>
              <div><dt>evidence source</dt><dd>{_h(receiver_evidence.evidence_source)}</dd></div>
              <div><dt>raw_data_included</dt><dd>{raw_data_included}</dd></div>
            </dl>
          </div>
          {safe_navigation}
          <div class="panel">
            <div class="panel-head"><h2>Current session</h2><span class="muted">dashboard-local metadata only</span></div>
            <dl class="facts">
              <div><dt>status</dt><dd>{_h(session.status)}</dd></div>
              <div><dt>session alias</dt><dd>{_h(session.session_alias)}</dd></div>
              <div><dt>target alias</dt><dd>{_h(session.target_alias)}</dd></div>
              <div><dt>updated UTC</dt><dd>{_h(session.updated_at_utc or "none")}</dd></div>
              <div><dt>collector/receiver integration</dt><dd>separate PR</dd></div>
              <div><dt>dashboard capture execution</dt><dd>false</dd></div>
            </dl>
          </div>
          <div class="panel">
            <div class="panel-head"><h2>Read-only boundary</h2><span class="muted">no dashboard execution</span></div>
            <dl class="facts">
              <div><dt>GET /live-capture</dt><dd>read-only status panel</dd></div>
              <div><dt>dashboard form</dt><dd>none</dd></div>
              <div><dt>dashboard action button</dt><dd>none</dd></div>
              <div><dt>collector forwarding changes</dt><dd>none</dd></div>
              <div><dt>receiver ingest changes</dt><dd>none</dd></div>
              <div><dt>raw preview/download</dt><dd>none</dd></div>
              <div><dt>replay or active scan</dt><dd>none</dd></div>
              <div><dt>AI automatic handoff</dt><dd>false</dd></div>
            </dl>
          </div>
          <div class="panel">
            <div class="panel-head"><h2>AI input candidate files</h2><span class="muted">manual review required</span></div>
            <ul class="safe-list">{safe_files}</ul>
            <p class="muted">Findings remain candidates. Risk remains draft. Final severity and CVSS remain manual decisions.</p>
          </div>
          <div class="panel">
            <div class="panel-head"><h2>Values not displayed</h2><span class="muted">principles only</span></div>
            <ul class="safe-list">
              <li>raw request or response body</li>
              <li>credential, cookie, token, JWT, or session value</li>
              <li>actual target identifier or full local path</li>
              <li>personal data, integrity secret, or request forgery token value</li>
              <li>unverified output, raw audit row, or archive content</li>
            </ul>
          </div>
          <div class="panel">
            <div class="panel-head"><h2>Related routes and documents</h2><span class="muted">read-only references</span></div>
            <dl class="facts">
              <div><dt>operations hub</dt><dd><a href="/help">/help</a></dd></div>
              <div><dt>upload flow</dt><dd><a href="/upload">/upload</a></dd></div>
              <div><dt>integration plan</dt><dd>docs/LIVE_CAPTURE_DASHBOARD_INTEGRATION_PLAN_v0.5.md</dd></div>
              <div><dt>runtime smoke checklist</dt><dd>docs/LIVE_CAPTURE_RUNTIME_SMOKE_CHECKLIST_v0.5.md</dd></div>
              <div><dt>troubleshooting</dt><dd>docs/TROUBLESHOOTING_v0.5.md</dd></div>
              <div><dt>dashboard home</dt><dd><a href="/">/</a></dd></div>
            </dl>
          </div>
        </section>
        """,
    )
def render_upload_wizard(csrf_token: str) -> str:
    safe_files = "".join(f"<li>{_h(name)}</li>" for name in SAFE_PREVIEW_FILES)
    token = _h(csrf_token)
    return _page(
        "업로드 마법사",
        f"""
        <section class="topbar">
          <div>
            <a class="back" href="/">산출물 목록으로</a>
            <h1>업로드 마법사</h1>
            <p class="subtitle">Burp export 파일을 로컬에서 받아 redaction, verify, review, report까지 실행한 뒤 AI 입력 후보 파일 4개만 안내합니다.</p>
          </div>
          <div class="status-stack">
            <span class="badge warning">state-changing POST</span>
            <span class="badge neutral">raw-free result</span>
            <a class="button secondary" href="/live-capture">Live Capture 준비</a>
            <a class="button secondary" href="/help">운영 허브</a>
          </div>
        </section>
        <section class="safety-strip">
          <div class="rail"><span>저장 위치</span><strong>ignored local_only alias</strong></div>
          <div class="rail"><span>업로드 형식</span><strong>.xml 또는 .json</strong></div>
          <div class="rail"><span>최대 크기</span><strong>{MAX_UPLOAD_BYTES // (1024 * 1024)} MB</strong></div>
          <div class="rail"><span>자동 전송</span><strong>false</strong></div>
        </section>
        <section class="grid">
          <div class="panel">
            <div class="panel-head"><h2>파일 업로드</h2><span class="muted">원본 본문이나 실제 파일명은 결과 화면에 표시하지 않습니다.</span></div>
            <form class="stacked-form" method="post" action="/upload" enctype="multipart/form-data">
              <input type="hidden" name="csrf_token" value="{token}">
              <label>Burp export 파일
                <input type="file" name="burp_export" accept=".xml,.json" required>
              </label>
              <label>프로젝트 별칭
                <input type="text" name="project" required pattern="[A-Za-z0-9][A-Za-z0-9_-]{{0,63}}" placeholder="client_alias_demo">
              </label>
              <button type="submit">마스킹 및 검증 시작</button>
              <small>POST에는 CSRF 보호가 적용됩니다. ChatGPT API 자동 전송은 수행하지 않습니다.</small>
            </form>
          </div>
          <div class="panel">
            <div class="panel-head"><h2>자동 처리 순서</h2><span class="muted">verify fail-closed를 통과한 경우에만 safe files 링크를 제공합니다.</span></div>
            <ol class="safe-list">
              <li>업로드 파일 형식과 프로젝트 별칭을 검증합니다.</li>
              <li>원본 파일을 ignored local-only 저장소에 내부 이름으로 보관합니다.</li>
              <li>redaction과 sanitized output 생성을 실행합니다.</li>
              <li>verify를 실행하고 실패하면 review/report를 건너뜁니다.</li>
              <li>verify 통과 후 review와 report draft를 생성합니다.</li>
              <li>결과 화면에서 AI 입력 후보 파일 4개 상태만 표시합니다.</li>
            </ol>
          </div>
          <div class="panel">
            <div class="panel-head"><h2>AI 입력 후보 파일</h2><span class="muted">성공 후 직접 확인할 수 있는 후보 파일입니다.</span></div>
            <ul class="safe-list">{safe_files}</ul>
          </div>
          <div class="panel">
            <div class="panel-head"><h2>표시하지 않는 값</h2><span class="muted">실패 결과에도 원본 값과 내부 경로는 표시하지 않습니다.</span></div>
            <ul class="safe-list">
              <li>원본 요청/응답 본문</li>
              <li>Cookie, Authorization, token, JWT, session 값</li>
              <li>실제 URL, domain, IP, 개인정보</li>
              <li>무결성 비밀값과 요청 위조 방지 보호값</li>
              <li>전체 로컬 경로와 실제 local-only 파일명</li>
              <li>prompt/report 본문 미리보기</li>
            </ul>
          </div>
        </section>
        """,
    )


def render_upload_result(result: UploadWizardResult, csrf_token: str) -> str:
    status_badge = _status_badge(result.status)
    summaries = "".join(f"<li>{_h(line)}</li>" for line in result.summary_lines)
    stages = "".join(
        f"<tr><td>{_h(name)}</td><td>{_status_badge(status)}</td></tr>" for name, status in result.stage_statuses
    )
    safe_rows = "".join(
        f"<tr><td>{_h(name)}</td><td>{_status_badge('present' if name in result.safe_files_present else 'missing')}</td></tr>"
        for name in SAFE_PREVIEW_FILES
    )
    links = ""
    retry = f'<a class="button secondary" href="/upload">다시 업로드</a>'
    if result.status == "passed":
        links = f"""
        <div class="actions">
          <a class="button" href="{_simple_dashboard_href(result.output_id)}">Simple Dashboard</a>
          <a class="button secondary" href="{_safe_files_href(result.output_id)}">Safe Files</a>
          <a class="button secondary" href="{_triage_href(result.output_id)}">Triage</a>
          <a class="button secondary" href="{_report_readiness_href(result.output_id)}">Report Readiness</a>
          {retry}
        </div>
        """
    else:
        links = f"""
        <div class="actions">
          {retry}
          <a class="button secondary" href="/">산출물 목록</a>
        </div>
        <p class="muted">검증 또는 처리 실패 상태에서는 safe file 링크를 제공하지 않습니다.</p>
        """
    return _page(
        result.title,
        f"""
        <section class="topbar">
          <div>
            <a class="back" href="/upload">업로드 마법사로 돌아가기</a>
            <h1>{_h(result.title)}</h1>
            <p class="subtitle">결과는 raw-free metadata만 표시합니다. ChatGPT 자동 전송은 수행하지 않습니다.</p>
          </div>
          <div class="status-stack">
            {status_badge}
            <span class="badge neutral">raw_data_included=false</span>
          </div>
        </section>
        <section class="safety-strip">
          <div class="rail"><span>project alias</span><strong>{_h(result.project_alias)}</strong></div>
          <div class="rail"><span>verify files</span><strong>{result.files_checked}</strong></div>
          <div class="rail"><span>후보 finding</span><strong>{result.candidate_count}</strong></div>
          <div class="rail"><span>safe files</span><strong>{len(result.safe_files_present)}</strong></div>
        </section>
        <section class="grid">
          <div class="panel">
            <div class="panel-head"><h2>처리 요약</h2><span class="muted">원본 값, 실제 파일명, 전체 경로는 제외합니다.</span></div>
            <ul class="safe-list">{summaries}</ul>
            {links}
          </div>
          <div class="panel">
            <div class="panel-head"><h2>단계 상태</h2><span class="muted">실패 단계 이후 작업은 건너뜁니다.</span></div>
            <table><tbody>{stages}</tbody></table>
          </div>
          <div class="panel">
            <div class="panel-head"><h2>AI 입력 후보 파일 4개</h2><span class="muted">성공 상태에서만 확인 대상으로 안내합니다.</span></div>
            <table><tbody>{safe_rows}</tbody></table>
          </div>
          <div class="panel">
            <div class="panel-head"><h2>해석 경계</h2><span class="muted">자동 처리 결과는 수동 검토 전 초안입니다.</span></div>
            <ul class="safe-list">
              <li>finding은 candidate입니다.</li>
              <li>risk는 draft입니다.</li>
              <li>final severity와 CVSS는 수동 결정입니다.</li>
              <li>upload 성공은 외부 공유 가능 보장이 아닙니다.</li>
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
            <div class="panel-head"><h2>AI 안전 사전 점검</h2><span class="muted">AI 핸드오프 전 조회 전용 점검입니다.</span></div>
            {_preflight_summary(preflight)}
            <a class="button small secondary" href="{_simple_dashboard_href(output.output_id)}">간단 대시보드</a>
            <a class="button small secondary" href="{_preflight_href(output.output_id)}">사전 점검 상세</a>
            <a class="button small secondary" href="{_handoff_href(output.output_id)}">핸드오프 인덱스</a>
            <a class="button small secondary" href="{_triage_href(output.output_id)}">후보 분류 인덱스</a>
            <a class="button small secondary" href="{_report_readiness_href(output.output_id)}">보고서 준비</a>
            <a class="button small secondary" href="{_prompt_readiness_href(output.output_id)}">Prompt readiness</a>
            <a class="button small secondary" href="{_evidence_boundary_href(output.output_id)}">증거 경계</a>
            <a class="button small secondary" href="{_workflow_href(output.output_id)}">작업 흐름 상태</a>
            <a class="button small secondary" href="{_operator_runbook_href(output.output_id)}">Operator runbook</a>
            <a class="button small secondary" href="{_safe_files_href(output.output_id)}">Safe file inventory</a>
          </div>
          <div class="panel">
            <div class="panel-head"><h2>탐지 후보</h2><span class="muted">총 {len(candidates)}개</span></div>
            <div class="candidate-list">{candidate_cards}</div>
          </div>
        </section>
        """,
    )


def render_simple_dashboard(output: DashboardOutput) -> str:
    safe_rows = "\n".join(_simple_safe_file_row(output, name) for name in SAFE_PREVIEW_FILES)
    safe_file_count = sum(1 for name in SAFE_PREVIEW_FILES if (output.path / name).is_file())
    all_safe_files_present = safe_file_count == len(SAFE_PREVIEW_FILES)
    report_status = "present" if output.report_available else "missing"
    safe_file_status = "present" if all_safe_files_present else "missing"
    return _page(
        f"간단 대시보드 {output.label}",
        f"""
        <section class="topbar">
          <div>
            <a class="back" href="{_output_href(output.output_id)}">상세 화면으로 돌아가기</a>
            <h1>간단 대시보드</h1>
            <p class="subtitle">처음 보는 사용자를 위한 read-only 간단 체크 화면입니다. 본문 preview, download, POST action은 제공하지 않습니다.</p>
          </div>
          <div class="status-stack">
            <span class="badge good">read-only</span>
            <span class="badge neutral">간단 모드</span>
            <a class="button secondary" href="/live-capture">Live Capture 준비</a>
            <a class="button secondary" href="/upload">새 업로드</a>
          </div>
        </section>
        <section class="safety-strip">
          <div class="rail"><span>현재 상태</span><strong>검증 통과</strong></div>
          <div class="rail"><span>후보 finding</span><strong>{output.candidate_count}</strong></div>
          <div class="rail"><span>AI 후보 파일</span><strong>{safe_file_count}/4</strong></div>
          <div class="rail"><span>화면 성격</span><strong>조회 전용</strong></div>
        </section>
        <section class="grid">
          <div class="panel">
            <div class="panel-head"><h2>현재 상태</h2><span class="muted">검증된 output의 안전 메타데이터만 표시합니다.</span></div>
            <dl class="facts">
              <div><dt>project alias</dt><dd>{_h(output.label)}</dd></div>
              <div><dt>verify 결과</dt><dd>{_status_badge("passed")}</dd></div>
              <div><dt>후보 finding</dt><dd>{output.candidate_count}</dd></div>
              <div><dt>report_draft.md</dt><dd>{_status_badge(report_status)}</dd></div>
              <div><dt>AI 삽입 후보 파일</dt><dd>{_status_badge(safe_file_status)}</dd></div>
              <div><dt>주의</dt><dd>후보 finding은 확정 취약점이 아니며, 초안 risk와 최종 심각도는 수동 검토가 필요합니다.</dd></div>
            </dl>
          </div>
          <div class="panel">
            <div class="panel-head"><h2>AI에 넣을 후보 파일</h2><span class="muted">exists 또는 missing만 표시합니다. 파일 본문과 전체 경로는 표시하지 않습니다.</span></div>
            <table>
              <thead>
                <tr><th>파일</th><th>상태</th></tr>
              </thead>
              <tbody>{safe_rows}</tbody>
            </table>
          </div>
          <div class="panel">
            <div class="panel-head"><h2>다음 행동</h2><span class="muted">고급 화면으로 이동하는 조회 링크입니다.</span></div>
            <ol class="steps">
              <li>새 Burp export는 <a href="/upload">업로드 마법사</a>에서 redaction/verify/review/report를 한 번에 실행합니다.</li>
              <li><a href="{_safe_files_href(output.output_id)}">/safe-files</a>와 <a href="{_preflight_href(output.output_id)}">/preflight</a>에서 AI 삽입 전 후보 파일을 확인합니다.</li>
              <li><a href="{_triage_href(output.output_id)}">/triage</a>에서 후보 finding을 수동 검토합니다.</li>
              <li><a href="{_report_readiness_href(output.output_id)}">/report-readiness</a>에서 보고서 초안을 수동 검토합니다.</li>
              <li><a href="{_workflow_href(output.output_id)}">/workflow</a>에서 전체 고급 흐름을 확인합니다.</li>
              <li><a href="/live-capture">/live-capture</a>에서 v0.5 live capture 준비 조건을 read-only로 확인합니다.</li>
            </ol>
          </div>
          <div class="panel">
            <div class="panel-head"><h2>고급 화면</h2><span class="muted">필요할 때만 상세 체크리스트를 엽니다.</span></div>
            <dl class="facts">
              <div><dt>작업 흐름</dt><dd><a href="{_workflow_href(output.output_id)}">/workflow</a></dd></div>
              <div><dt>safe files</dt><dd><a href="{_safe_files_href(output.output_id)}">/safe-files</a></dd></div>
              <div><dt>finding triage</dt><dd><a href="{_triage_href(output.output_id)}">/triage</a></dd></div>
              <div><dt>evidence boundary</dt><dd><a href="{_evidence_boundary_href(output.output_id)}">/evidence-boundary</a></dd></div>
              <div><dt>operator runbook</dt><dd><a href="{_operator_runbook_href(output.output_id)}">/operator-runbook</a></dd></div>
              <div><dt>live capture 준비</dt><dd><a href="/live-capture">/live-capture</a></dd></div>
            </dl>
          </div>
          <div class="panel">
            <div class="panel-head"><h2>보안 경계</h2><span class="muted">간단 화면은 상태 표시만 합니다.</span></div>
            <ul class="safe-list">
              <li>raw request/response, Cookie, Authorization, token/JWT/session은 표시하지 않습니다.</li>
              <li>실제 domain/IP, 개인정보, 무결성 검증 비밀값, 요청 위조 방지 값은 표시하지 않습니다.</li>
              <li>request body, response body, prompt body, report body preview는 표시하지 않습니다.</li>
              <li>전체 로컬 경로, local_only, raw, raw_vault, out 원본은 AI 입력 대상으로 표시하지 않습니다.</li>
              <li>replay, active scan, 파일 삭제, retention 정책 변경, 무결성 검증 비밀값 처리는 제공하지 않습니다.</li>
            </ul>
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
            "raw 요청/응답",
            "Cookie 또는 Authorization 값",
            "token, JWT, session 값",
            "실제 도메인, URL, IP 값",
            "개인정보",
            "무결성 검증 비밀값 또는 요청 위조 방지 값",
            "로컬 전용 raw 저장소 또는 검증 전 산출물",
            "감사 로그, 압축 archive, manifest",
        )
    )
    return _page(
        f"AI 핸드오프 인덱스 {output.label}",
        f"""
        <section class="topbar">
          <div>
            <a class="back" href="{_output_href(output.output_id)}">산출물로 돌아가기</a>
            <h1>AI 핸드오프 인덱스</h1>
            <p class="subtitle">AI 안전 후보 파일의 조회 전용 핸드오프 점검입니다. 먼저 검증하고 수동 검토해야 합니다.</p>
          </div>
          <span class="badge good">조회 전용</span>
        </section>
        <section class="safety-strip">
          <div class="rail"><span>파일 묶음</span><strong>AI 안전 후보 파일</strong></div>
          <div class="rail"><span>검증</span><strong>먼저 verify</strong></div>
          <div class="rail"><span>검토</span><strong>수동 검토 필요</strong></div>
          <div class="rail"><span>심각도</span><strong>사람이 결정</strong></div>
        </section>
        <section class="grid">
          <div class="panel">
            <div class="panel-head"><h2>핸드오프 요약</h2><span class="muted">메타데이터만 표시합니다.</span></div>
            {_handoff_summary(index)}
          </div>
          <div class="panel">
            <div class="panel-head"><h2>권장 확인 순서</h2><span class="muted">운영자 읽기 순서입니다.</span></div>
            <div class="file-grid">{file_rows}</div>
          </div>
          <div class="panel">
            <div class="panel-head"><h2>관련 흐름</h2><span class="muted">조회 전용 이동 링크입니다.</span></div>
            <dl class="facts">
              <div><dt>사전 점검 상태</dt><dd><a href="{_preflight_href(output.output_id)}">사전 점검 열기</a></dd></div>
              <div><dt>리뷰/보고서/내보내기 흐름</dt><dd><a href="{_output_href(output.output_id)}">검증된 산출물 상세로 돌아가기</a></dd></div>
              <div><dt>finding</dt><dd>수동 검증이 끝날 때까지 후보입니다.</dd></div>
              <div><dt>위험도</dt><dd>초안이며 심각도 확정이 아닙니다.</dd></div>
              <div><dt>최종 심각도</dt><dd>최종 심각도는 사람이 결정합니다.</dd></div>
            </dl>
          </div>
          <div class="panel">
            <div class="panel-head"><h2>전송 금지 항목</h2><span class="muted">분류만 표시하고 실제 값은 표시하지 않습니다.</span></div>
            <ul class="safe-list">{forbidden_items}</ul>
          </div>
        </section>
        """,
    )


def render_finding_triage_index(index: FindingTriageIndex, alias_selector_html: str = "") -> str:
    output = index.output
    candidate_rows = "\n".join(_triage_candidate_card(candidate) for candidate in index.candidates) or (
        '<div class="empty">분류할 finding 후보가 없습니다.</div>'
    )
    safe_files = "".join(f"<li>{_h(name)}</li>" for name in SAFE_PREVIEW_FILES)
    forbidden_items = "".join(
        f"<li>{_h(item)}</li>"
        for item in (
            "raw 요청/응답",
            "Cookie 또는 Authorization 값",
            "token, JWT, session 값",
            "실제 도메인, URL, IP 값",
            "개인정보",
            "무결성 검증 비밀값 또는 요청 위조 방지 값",
            "전체 로컬 경로",
            "local_only/, raw/, raw_vault/, 검증 전 out/, out/.audit 산출물",
        )
    )
    return _page(
        f"Finding 후보 분류 인덱스 {output.label}",
        f"""
        <section class="topbar">
          <div>
            <a class="back" href="{_output_href(output.output_id)}">산출물로 돌아가기</a>
            <h1>Finding 후보 분류 인덱스</h1>
            <p class="subtitle">정제된 finding 후보를 검토하는 조회 전용 분류 점검입니다. 후보 finding과 위험도 초안은 수동 검토가 필요합니다.</p>
          </div>
          <span class="badge good">조회 전용</span>
        </section>
        <section class="safety-strip">
          <div class="rail"><span>프로젝트 별칭</span><strong>{_h(output.label)}</strong></div>
          <div class="rail"><span>finding 후보</span><strong>{len(index.candidates)}</strong></div>
          <div class="rail"><span>finding 상태</span><strong>후보</strong></div>
          <div class="rail"><span>심각도 결정</span><strong>수동 검토 필요</strong></div>
        </section>
        {alias_selector_html}
        <section class="grid">
          <div class="panel">
            <div class="panel-head"><h2>분류 요약</h2><span class="muted">안전 메타데이터만 표시합니다.</span></div>
            <dl class="facts">
              <div><dt>프로젝트 별칭</dt><dd>{_h(output.label)}</dd></div>
              <div><dt>finding 후보 수</dt><dd>{len(index.candidates)}</dd></div>
              <div><dt>analysis_packet.json</dt><dd>{_status_badge(index.analysis_packet_status)}</dd></div>
              <div><dt>report_draft.md</dt><dd>{_status_badge(index.report_draft_status)}</dd></div>
              <div><dt>raw_data_included</dt><dd>false</dd></div>
              <div><dt>파일 경로 표시</dt><dd>false</dd></div>
            </dl>
          </div>
          <div class="panel">
            <div class="panel-head"><h2>AI 안전 파일 allowlist</h2><span class="muted">검증된 파일만 사용합니다.</span></div>
            <ul class="safe-list">{safe_files}</ul>
          </div>
          <div class="panel">
            <div class="panel-head"><h2>관련 흐름</h2><span class="muted">조회 전용 이동 링크입니다.</span></div>
            <dl class="facts">
              <div><dt>사전 점검</dt><dd><a href="{_preflight_href(output.output_id)}">AI 안전 사전 점검 열기</a></dd></div>
              <div><dt>핸드오프</dt><dd><a href="{_handoff_href(output.output_id)}">AI 핸드오프 인덱스 열기</a></dd></div>
              <div><dt>보고서 준비</dt><dd><a href="{_report_readiness_href(output.output_id)}">보고서 준비 인덱스 열기</a></dd></div>
              <div><dt>리뷰/보고서/내보내기 흐름</dt><dd><a href="{_output_href(output.output_id)}">검증된 산출물 상세로 돌아가기</a></dd></div>
              <div><dt>경계</dt><dd>조회 전용 분류 점검이며 form 또는 POST action이 없습니다.</dd></div>
            </dl>
          </div>
          <div class="panel">
            <div class="panel-head"><h2>해석 경계</h2><span class="muted">후보와 초안으로만 봅니다.</span></div>
            <dl class="facts">
              <div><dt>finding</dt><dd>수동 검증이 끝날 때까지 후보입니다.</dd></div>
              <div><dt>위험도</dt><dd>초안이며 심각도 확정이 아닙니다.</dd></div>
              <div><dt>confidence</dt><dd>증거 신뢰도이며 심각도가 아닙니다.</dd></div>
              <div><dt>최종 심각도</dt><dd>최종 심각도는 수동 결정이 필요합니다.</dd></div>
            </dl>
          </div>
          <div class="panel">
            <div class="panel-head"><h2>분류에 사용 금지</h2><span class="muted">분류만 표시하고 실제 값은 표시하지 않습니다.</span></div>
            <ul class="safe-list">{forbidden_items}</ul>
          </div>
          <div class="panel">
            <div class="panel-head"><h2>후보 점검</h2><span class="muted">정제된 메타데이터만 표시합니다.</span></div>
            <div class="candidate-list">{candidate_rows}</div>
          </div>
        </section>
        """,
    )


def render_report_readiness_index(index: ReportReadinessIndex, alias_selector_html: str = "") -> str:
    output = index.output
    file_rows = "\n".join(_report_readiness_file_card(file) for file in index.files)
    checklist_items = "".join(
        f"<li>{_h(item)}</li>"
        for item in (
            "범위 확인",
            "영향 endpoint 확인",
            "증거 품질 확인",
            "false positive 가능성 검토",
            "영향 설명 검토",
            "조치 문구 검토",
            "최종 심각도 수동 결정",
            "고객 제출 전 민감정보 검토",
        )
    )
    forbidden_items = "".join(
        f"<li>{_h(item)}</li>"
        for item in (
            "raw 요청/응답",
            "raw 감사 row body",
            "Cookie 또는 Authorization 값",
            "token, JWT, session 값",
            "실제 도메인, URL, IP 값",
            "개인정보",
            "무결성 검증 비밀값 또는 요청 위조 방지 값",
            "전체 로컬 경로",
            "local_only/, raw/, raw_vault/, 검증 전 out/, out/.audit 산출물",
        )
    )
    return _page(
        f"보고서 준비 인덱스 {output.label}",
        f"""
        <section class="topbar">
          <div>
            <a class="back" href="{_output_href(output.output_id)}">산출물로 돌아가기</a>
            <h1>보고서 준비 인덱스</h1>
            <p class="subtitle">수동 검토 전 사용하는 조회 전용 보고서 초안 점검입니다. report_draft.md는 제출용 보고서가 아니라 초안입니다.</p>
          </div>
          <span class="badge good">조회 전용</span>
        </section>
        <section class="safety-strip">
          <div class="rail"><span>프로젝트 별칭</span><strong>{_h(output.label)}</strong></div>
          <div class="rail"><span>보고서 초안 상태</span><strong>{_h(_status_label(index.report_status))}</strong></div>
          <div class="rail"><span>finding 후보</span><strong>{index.candidate_count}</strong></div>
          <div class="rail"><span>심각도 결정</span><strong>수동 검토 필요</strong></div>
        </section>
        {alias_selector_html}
        <section class="grid">
          <div class="panel">
            <div class="panel-head"><h2>준비 상태 요약</h2><span class="muted">안전 메타데이터만 표시합니다.</span></div>
            <dl class="facts">
              <div><dt>프로젝트 별칭</dt><dd>{_h(output.label)}</dd></div>
              <div><dt>report_draft.md</dt><dd>{_status_badge(index.report_status)}</dd></div>
              <div><dt>analysis_packet.json</dt><dd>{_status_badge(index.analysis_status)}</dd></div>
              <div><dt>finding 후보 수</dt><dd>{index.candidate_count}</dd></div>
              <div><dt>보고서 초안 상태 요약</dt><dd>{_h(_report_readiness_status_summary(index))}</dd></div>
              <div><dt>raw_data_included</dt><dd>false</dd></div>
              <div><dt>파일 경로 표시</dt><dd>false</dd></div>
            </dl>
          </div>
          <div class="panel">
            <div class="panel-head"><h2>관련 흐름</h2><span class="muted">조회 전용 이동 링크입니다.</span></div>
            <dl class="facts">
              <div><dt>후보 분류 링크</dt><dd><a href="{_triage_href(output.output_id)}">finding 후보 분류 인덱스 열기</a></dd></div>
              <div><dt>사전 점검 링크</dt><dd><a href="{_preflight_href(output.output_id)}">AI 안전 사전 점검 열기</a></dd></div>
              <div><dt>핸드오프 링크</dt><dd><a href="{_handoff_href(output.output_id)}">AI 핸드오프 인덱스 열기</a></dd></div>
              <div><dt>내보내기/리뷰/보고서 흐름 링크</dt><dd><a href="{_output_href(output.output_id)}">검증된 산출물 상세로 돌아가기</a></dd></div>
              <div><dt>경계</dt><dd>조회 전용 보고서 초안 점검이며 form 또는 POST action이 없습니다.</dd></div>
            </dl>
          </div>
          <div class="panel">
            <div class="panel-head"><h2>파일 메타데이터</h2><span class="muted">본문 미리보기는 제공하지 않습니다.</span></div>
            <div class="file-grid">{file_rows}</div>
          </div>
          <div class="panel">
            <div class="panel-head"><h2>운영자 점검</h2><span class="muted">수동 검토가 필요합니다.</span></div>
            <ul class="safe-list">{checklist_items}</ul>
          </div>
          <div class="panel">
            <div class="panel-head"><h2>해석 경계</h2><span class="muted">후보와 초안으로만 봅니다.</span></div>
            <dl class="facts">
              <div><dt>findings</dt><dd>수동 검증이 끝날 때까지 finding 후보입니다.</dd></div>
              <div><dt>risk</dt><dd>초안이며 심각도 확정이 아닙니다.</dd></div>
              <div><dt>confidence</dt><dd>증거 신뢰도이며 심각도가 아닙니다.</dd></div>
              <div><dt>report draft</dt><dd>report_draft.md는 제출용 보고서가 아니라 초안입니다.</dd></div>
              <div><dt>심각도 결정</dt><dd>최종 심각도는 수동 결정입니다.</dd></div>
              <div><dt>hash 종류</dt><dd>SHA-256 파일 fingerprint이며 HMAC이 아닙니다.</dd></div>
            </dl>
          </div>
          <div class="panel">
            <div class="panel-head"><h2>보고서 준비에 사용 금지</h2><span class="muted">분류만 표시하고 실제 값은 표시하지 않습니다.</span></div>
            <ul class="safe-list">{forbidden_items}</ul>
          </div>
        </section>
        """,
    )


def render_prompt_readiness_index(index: PromptReadinessIndex) -> str:
    output = index.output
    file_rows = "\n".join(_prompt_readiness_file_card(file) for file in index.files)
    check_rows = "\n".join(_prompt_readiness_check_card(check) for check in index.checks)
    safe_files = "".join(f"<li>{_h(name)}</li>" for name in SAFE_PREVIEW_FILES)
    forbidden_items = "".join(
        f"<li>{_h(item)}</li>"
        for item in (
            "raw 요청/응답",
            "raw 감사 row body",
            "Cookie 또는 Authorization 값",
            "token, JWT, session 값",
            "실제 도메인, URL, IP 값",
            "개인정보",
            "무결성 검증 비밀값 또는 요청 위조 방지 값",
            "전체 로컬 경로",
            "local_only/, raw/, raw_vault/, 검증 전 out/, out/.audit 산출물",
        )
    )
    return _page(
        f"Prompt readiness 인덱스 {output.label}",
        f"""
        <section class="topbar">
          <div>
            <a class="back" href="{_output_href(output.output_id)}">검증된 산출물 상세</a>
            <h1>Prompt readiness 인덱스</h1>
            <p class="subtitle">chatgpt_prompt.md와 codex_task_prompt.md를 AI에 넣기 전에 상태를 점검하는 조회 전용 prompt readiness checklist입니다. 이 화면은 판단을 대신하지 않습니다.</p>
          </div>
          <span class="badge good">조회 전용</span>
        </section>
        <section class="safety-strip">
          <div class="rail"><span>프로젝트 별칭</span><strong>{_h(output.label)}</strong></div>
          <div class="rail"><span>prompt 상태</span><strong>{_h(_status_label(index.prompt_status))}</strong></div>
          <div class="rail"><span>safe files</span><strong>{index.safe_file_count}/{len(SAFE_PREVIEW_FILES)}</strong></div>
          <div class="rail"><span>본문 preview</span><strong>false</strong></div>
        </section>
        <section class="grid">
          <div class="panel">
            <div class="panel-head"><h2>준비 상태 요약</h2><span class="muted">본문 없이 메타데이터와 점검 결과만 표시합니다.</span></div>
            <dl class="facts">
              <div><dt>프로젝트 별칭</dt><dd>{_h(output.label)}</dd></div>
              <div><dt>chatgpt_prompt.md</dt><dd>{_status_badge(index.chatgpt_status)}</dd></div>
              <div><dt>codex_task_prompt.md</dt><dd>{_status_badge(index.codex_status)}</dd></div>
              <div><dt>analysis_packet.json</dt><dd>{_status_badge(_file_status(output.path, "analysis_packet.json"))}</dd></div>
              <div><dt>report_draft.md</dt><dd>{_status_badge(_file_status(output.path, "report_draft.md"))}</dd></div>
              <div><dt>검증 선행</dt><dd>이 화면은 verify를 통과한 산출물에만 표시됩니다.</dd></div>
              <div><dt>raw_data_included</dt><dd>false</dd></div>
              <div><dt>파일 본문 preview</dt><dd>false</dd></div>
              <div><dt>전체 로컬 경로 표시</dt><dd>false</dd></div>
            </dl>
          </div>
          <div class="panel">
            <div class="panel-head"><h2>safe files 4개</h2><span class="muted">AI 투입 후보 파일 allowlist입니다.</span></div>
            <ul class="safe-list">{safe_files}</ul>
          </div>
          <div class="panel">
            <div class="panel-head"><h2>Prompt 파일 메타데이터</h2><span class="muted">SHA-256은 HMAC이 아닌 파일 fingerprint입니다.</span></div>
            <div class="file-grid">{file_rows}</div>
          </div>
          <div class="panel">
            <div class="panel-head"><h2>Prompt readiness 점검</h2><span class="muted">본문을 표시하지 않고 검사 결과만 요약합니다.</span></div>
            <div class="file-grid">{check_rows}</div>
          </div>
          <div class="panel">
            <div class="panel-head"><h2>Prompt 목적과 차이</h2><span class="muted">사용 전에 사람이 읽고 확인해야 합니다.</span></div>
            <dl class="facts">
              <div><dt>ChatGPT용 prompt</dt><dd>정제된 후보 분석, 수동 검토 보조, 조심스러운 보고서 문구 초안에 사용합니다.</dd></div>
              <div><dt>Codex용 prompt</dt><dd>구현, 리뷰, 테스트 보강 같은 작업 보조에 사용하되 금지 범위를 함께 확인합니다.</dd></div>
              <div><dt>finding</dt><dd>수동 검증이 끝날 때까지 후보입니다.</dd></div>
              <div><dt>risk</dt><dd>초안이며 심각도 확정이 아닙니다.</dd></div>
              <div><dt>최종 심각도 결정</dt><dd>Burp 재현, 권한별 비교, 영향도 판단 후 사람이 결정합니다.</dd></div>
              <div><dt>prompt 파일</dt><dd>검증된 산출물이더라도 AI 투입 전 사람이 직접 검토해야 합니다.</dd></div>
            </dl>
          </div>
          <div class="panel">
            <div class="panel-head"><h2>권장 사용 순서</h2><span class="muted">조회 전용 링크입니다.</span></div>
            <ol class="safe-list">
              <li><a href="{_preflight_href(output.output_id)}">AI 안전 사전 점검</a>에서 safe files 상태를 봅니다.</li>
              <li><a href="{_handoff_href(output.output_id)}">AI 핸드오프 인덱스</a>에서 파일 목적과 순서를 봅니다.</li>
              <li><a href="{_workflow_href(output.output_id)}">작업 흐름 상태 인덱스</a>에서 전체 흐름을 봅니다.</li>
              <li><a href="{_evidence_boundary_href(output.output_id)}">Evidence boundary 인덱스</a>에서 정제 증거와 raw 금지 범위를 봅니다.</li>
              <li><a href="{_triage_href(output.output_id)}">finding 후보 분류 인덱스</a>와 <a href="{_report_readiness_href(output.output_id)}">보고서 준비 인덱스</a>에서 후보/초안 경계를 봅니다.</li>
              <li>prompt 파일을 사람이 검토한 뒤 필요한 안전 파일만 AI에 입력합니다.</li>
            </ol>
          </div>
          <div class="panel">
            <div class="panel-head"><h2>Prompt에 넣으면 안 되는 항목</h2><span class="muted">분류명만 표시하고 실제 값은 표시하지 않습니다.</span></div>
            <ul class="safe-list">{forbidden_items}</ul>
          </div>
        </section>
        """,
    )


def render_evidence_boundary_index(index: EvidenceBoundaryIndex) -> str:
    output = index.output
    file_rows = "\n".join(_evidence_boundary_file_card(file) for file in index.files)
    safe_files = "".join(f"<li>{_h(name)}</li>" for name in SAFE_PREVIEW_FILES)
    allowed_items = "".join(
        f"<li>{_h(item)}</li>"
        for item in (
            "검증 통과 후 생성된 safe files 4개",
            "analysis_packet.json의 정제 finding 후보 구조",
            "report_draft.md의 보고서 초안",
            "chatgpt_prompt.md와 codex_task_prompt.md의 AI 작업 안내",
            "후보 수, 파일 크기, 수정 시각, SHA-256 fingerprint 같은 안전 메타데이터",
        )
    )
    forbidden_items = "".join(
        f"<li>{_h(item)}</li>"
        for item in (
            "raw 요청/응답 본문",
            "raw 감사 row 전문",
            "Cookie 또는 Authorization 값",
            "token, JWT, session 값",
            "실제 도메인, URL, IP 값",
            "개인정보",
            "무결성 검증 비밀값 또는 요청 위조 방지 값",
            "전체 로컬 경로",
            "local_only/, raw/, raw_vault/, 검증 전 out/, out/.audit 산출물",
        )
    )
    return _page(
        f"Evidence boundary 인덱스 {output.label}",
        f"""
        <section class="topbar">
          <div>
            <a class="back" href="{_output_href(output.output_id)}">검증된 산출물 상세</a>
            <h1>Evidence boundary 인덱스</h1>
            <p class="subtitle">보고서와 AI 검토에 사용할 정제 증거와 절대 노출하지 않을 raw 증거 범위를 구분하는 조회 전용 evidence boundary checklist입니다.</p>
          </div>
          <span class="badge good">조회 전용</span>
        </section>
        <section class="safety-strip">
          <div class="rail"><span>프로젝트 별칭</span><strong>{_h(output.label)}</strong></div>
          <div class="rail"><span>정제 증거</span><strong>{_h(_status_label(index.sanitized_evidence_status))}</strong></div>
          <div class="rail"><span>finding 후보 수</span><strong>{index.candidate_count}</strong></div>
          <div class="rail"><span>raw 표시</span><strong>false</strong></div>
        </section>
        <section class="grid">
          <div class="panel">
            <div class="panel-head"><h2>조회 전용 증거 경계 요약</h2><span class="muted">본문 없이 안전 메타데이터만 표시합니다.</span></div>
            <dl class="facts">
              <div><dt>프로젝트 별칭</dt><dd>{_h(output.label)}</dd></div>
              <div><dt>정제 evidence</dt><dd>{_status_badge(index.sanitized_evidence_status)}</dd></div>
              <div><dt>finding candidate</dt><dd>{_status_badge(index.finding_candidate_status)}</dd></div>
              <div><dt>candidate count</dt><dd>{index.candidate_count}</dd></div>
              <div><dt>analysis_packet.json</dt><dd>{_status_badge(index.analysis_status)}</dd></div>
              <div><dt>report_draft.md</dt><dd>{_status_badge(index.report_status)}</dd></div>
              <div><dt>chatgpt_prompt.md</dt><dd>{_status_badge(index.chatgpt_status)}</dd></div>
              <div><dt>codex_task_prompt.md</dt><dd>{_status_badge(index.codex_status)}</dd></div>
              <div><dt>safe files</dt><dd>{index.safe_file_count}/{len(SAFE_PREVIEW_FILES)}</dd></div>
              <div><dt>raw_data_included</dt><dd>false</dd></div>
              <div><dt>본문 preview</dt><dd>false</dd></div>
              <div><dt>전체 로컬 경로 표시</dt><dd>false</dd></div>
            </dl>
          </div>
          <div class="panel">
            <div class="panel-head"><h2>정제 증거 파일 메타데이터</h2><span class="muted">safe files allowlist만 표시합니다.</span></div>
            <div class="file-grid">{file_rows}</div>
          </div>
          <div class="panel">
            <div class="panel-head"><h2>허용되는 evidence 범위</h2><span class="muted">검증 통과 후 사람이 검토해야 합니다.</span></div>
            <ul class="safe-list">{allowed_items}</ul>
            <ul class="safe-list">{safe_files}</ul>
          </div>
          <div class="panel">
            <div class="panel-head"><h2>금지되는 raw evidence 범위</h2><span class="muted">분류명만 표시하고 실제 값은 표시하지 않습니다.</span></div>
            <ul class="safe-list">{forbidden_items}</ul>
          </div>
          <div class="panel">
            <div class="panel-head"><h2>후보와 초안 경계</h2><span class="muted">확정 판단을 대신하지 않습니다.</span></div>
            <dl class="facts">
              <div><dt>finding</dt><dd>수동 검증이 끝날 때까지 candidate입니다.</dd></div>
              <div><dt>risk</dt><dd>draft이며 severity 결정으로 취급하지 않습니다.</dd></div>
              <div><dt>evidence confidence</dt><dd>증거 신뢰도이며 severity가 아닙니다.</dd></div>
              <div><dt>최종 심각도</dt><dd>Burp 재현, 권한별 비교, 영향도 판단 후 사람이 결정합니다.</dd></div>
              <div><dt>CVSS</dt><dd>별도 산정 범위입니다.</dd></div>
            </dl>
          </div>
          <div class="panel">
            <div class="panel-head"><h2>관련 조회 전용 인덱스</h2><span class="muted">GET 링크만 제공합니다.</span></div>
            <dl class="facts">
              <div><dt>사전 점검</dt><dd><a href="{_preflight_href(output.output_id)}">AI 안전 사전 점검 열기</a></dd></div>
              <div><dt>핸드오프</dt><dd><a href="{_handoff_href(output.output_id)}">AI 핸드오프 인덱스 열기</a></dd></div>
              <div><dt>Prompt readiness</dt><dd><a href="{_prompt_readiness_href(output.output_id)}">Prompt readiness 인덱스 열기</a></dd></div>
              <div><dt>Evidence boundary</dt><dd><a href="{_evidence_boundary_href(output.output_id)}">Evidence boundary 인덱스 열기</a></dd></div>
              <div><dt>Safe file inventory</dt><dd><a href="{_safe_files_href(output.output_id)}">Safe file inventory 인덱스 열기</a></dd></div>
              <div><dt>후보 분류</dt><dd><a href="{_triage_href(output.output_id)}">finding 후보 분류 인덱스 열기</a></dd></div>
              <div><dt>보고서 준비</dt><dd><a href="{_report_readiness_href(output.output_id)}">보고서 준비 인덱스 열기</a></dd></div>
              <div><dt>작업 흐름</dt><dd><a href="{_workflow_href(output.output_id)}">작업 흐름 상태 인덱스 열기</a></dd></div>
              <div><dt>운영 runbook</dt><dd><a href="{_operator_runbook_href(output.output_id)}">Operator runbook 인덱스 열기</a></dd></div>
              <div><dt>경계</dt><dd>read-only evidence boundary checklist이며 form, POST action, download action이 없습니다.</dd></div>
            </dl>
          </div>
        </section>
        """,
    )


def render_operator_runbook_index(index: OperatorRunbookIndex) -> str:
    output = index.output
    step_cards = "\n".join(_operator_runbook_step_card(step) for step in index.steps)
    file_rows = "\n".join(
        f"<div><dt>{_h(name)}</dt><dd>{_status_badge(status)}</dd></div>"
        for name, status in index.file_statuses
    )
    safe_files = "".join(f"<li>{_h(name)}</li>" for name in SAFE_PREVIEW_FILES)
    ai_candidate_items = "".join(
        f"<li>{_h(item)}</li>"
        for item in (
            "검증을 통과한 safe files 4개",
            "sanitized finding candidate metadata",
            "candidate count, 파일 크기, 수정 시각, SHA-256 fingerprint",
            "preflight, handoff, triage, report-readiness, prompt-readiness, evidence-boundary 상태",
            "workflow status recap에서 확인한 운영 순서",
        )
    )
    forbidden_items = "".join(
        f"<li>{_h(item)}</li>"
        for item in (
            "raw request/response body",
            "raw audit row 전문",
            "Cookie 값",
            "Authorization 값",
            "token/JWT/session 값",
            "실제 URL/도메인/IP",
            "개인정보",
            "무결성 검증 비밀값",
            "요청 위조 방지 값",
            "전체 로컬 경로",
            "local_only/, raw/, raw_vault/, verify 전 out/, out/.audit 산출물",
        )
    )
    return _page(
        f"Operator runbook 인덱스 {output.label}",
        f"""
        <section class="topbar">
          <div>
            <a class="back" href="{_output_href(output.output_id)}">검증된 산출물 상세</a>
            <h1>Operator runbook 인덱스</h1>
            <p class="subtitle">Burp 수집부터 AI 투입 전 수동 검토까지 운영자가 확인할 순서를 보여주는 조회 전용 operator runbook checklist입니다.</p>
          </div>
          <span class="badge good">조회 전용</span>
        </section>
        <section class="safety-strip">
          <div class="rail"><span>프로젝트 별칭</span><strong>{_h(output.label)}</strong></div>
          <div class="rail"><span>운영 단계</span><strong>{len(index.steps)}</strong></div>
          <div class="rail"><span>safe files</span><strong>{index.safe_file_count}/{len(SAFE_PREVIEW_FILES)}</strong></div>
          <div class="rail"><span>raw 표시</span><strong>false</strong></div>
        </section>
        <section class="grid">
          <div class="panel">
            <div class="panel-head"><h2>운영 runbook 요약</h2><span class="muted">본문 미리보기 없이 안전 metadata만 표시합니다.</span></div>
            <dl class="facts">
              <div><dt>프로젝트 별칭</dt><dd>{_h(output.label)}</dd></div>
              <div><dt>verify gate</dt><dd>{_status_badge("passed")}</dd></div>
              <div><dt>review 후보 상태</dt><dd>{_status_badge(index.review_status)}</dd></div>
              <div><dt>finding candidate count</dt><dd>{index.candidate_count}</dd></div>
              <div><dt>analysis_packet.json</dt><dd>{_status_badge(index.analysis_status)}</dd></div>
              <div><dt>report_draft.md</dt><dd>{_status_badge(index.report_status)}</dd></div>
              <div><dt>raw_data_included</dt><dd>false</dd></div>
              <div><dt>body preview</dt><dd>false</dd></div>
              <div><dt>전체 로컬 경로 표시</dt><dd>false</dd></div>
            </dl>
          </div>
          <div class="panel">
            <div class="panel-head"><h2>운영 순서</h2><span class="muted">각 단계는 실행 버튼이 아니라 조회 전용 이동 링크입니다.</span></div>
            <div class="file-grid">{step_cards}</div>
          </div>
          <div class="panel">
            <div class="panel-head"><h2>safe files 4개</h2><span class="muted">AI 후보 파일 allowlist입니다.</span></div>
            <dl class="facts">{file_rows}</dl>
            <ul class="safe-list">{safe_files}</ul>
          </div>
          <div class="panel">
            <div class="panel-head"><h2>AI 후보 입력 범위</h2><span class="muted">검증 후 사람이 다시 확인해야 하는 후보입니다.</span></div>
            <ul class="safe-list">{ai_candidate_items}</ul>
          </div>
          <div class="panel">
            <div class="panel-head"><h2>금지 데이터 경계</h2><span class="muted">분류명만 표시하고 실제 값은 표시하지 않습니다.</span></div>
            <ul class="safe-list">{forbidden_items}</ul>
          </div>
          <div class="panel">
            <div class="panel-head"><h2>해석 경계</h2><span class="muted">자동 판단으로 확정하지 않습니다.</span></div>
            <dl class="facts">
              <div><dt>finding</dt><dd>수동 검증이 끝날 때까지 candidate입니다.</dd></div>
              <div><dt>risk</dt><dd>risk rating은 draft이며 최종 심각도가 아닙니다.</dd></div>
              <div><dt>confidence</dt><dd>evidence confidence이며 severity가 아닙니다.</dd></div>
              <div><dt>최종 심각도</dt><dd>Burp 재현, 권한별 비교, 영향도 판단 후 사람이 수동 결정합니다.</dd></div>
              <div><dt>report_draft.md</dt><dd>최종 보고서가 아니라 수동 검토용 초안입니다.</dd></div>
              <div><dt>prompt/evidence/report</dt><dd>모두 AI 투입 또는 공유 전 사람 검토가 필요합니다.</dd></div>
            </dl>
          </div>
          <div class="panel">
            <div class="panel-head"><h2>관련 조회 화면</h2><span class="muted">GET 링크만 제공합니다.</span></div>
            <dl class="facts">
              <div><dt>산출물 상세</dt><dd><a href="{_output_href(output.output_id)}">검증된 산출물 상세 열기</a></dd></div>
              <div><dt>도움말</dt><dd><a href="/help">운영 도움말 열기</a></dd></div>
              <div><dt>운영 허브</dt><dd><a href="/operations">운영 허브 열기</a></dd></div>
              <div><dt>Live Capture 준비</dt><dd><a href="/live-capture">Live Capture 준비 화면 열기</a></dd></div>
              <div><dt>사전 점검</dt><dd><a href="{_preflight_href(output.output_id)}">AI 안전 사전 점검 열기</a></dd></div>
              <div><dt>핸드오프</dt><dd><a href="{_handoff_href(output.output_id)}">AI 핸드오프 인덱스 열기</a></dd></div>
              <div><dt>후보 분류</dt><dd><a href="{_triage_href(output.output_id)}">finding 후보 분류 인덱스 열기</a></dd></div>
              <div><dt>보고서 준비</dt><dd><a href="{_report_readiness_href(output.output_id)}">보고서 준비 인덱스 열기</a></dd></div>
              <div><dt>Prompt readiness</dt><dd><a href="{_prompt_readiness_href(output.output_id)}">Prompt readiness 인덱스 열기</a></dd></div>
              <div><dt>Evidence boundary</dt><dd><a href="{_evidence_boundary_href(output.output_id)}">Evidence boundary 인덱스 열기</a></dd></div>
              <div><dt>Safe file inventory</dt><dd><a href="{_safe_files_href(output.output_id)}">Safe file inventory 인덱스 열기</a></dd></div>
              <div><dt>Workflow status recap</dt><dd><a href="{_workflow_href(output.output_id)}">작업 흐름 상태 인덱스 열기</a></dd></div>
              <div><dt>경계</dt><dd>이 화면은 조회 전용이며 form, POST action, 실행 버튼, 파일 내려받기를 제공하지 않습니다.</dd></div>
            </dl>
          </div>
        </section>
        """,
    )


def render_safe_file_inventory_index(index: SafeFileInventoryIndex, alias_selector_html: str = "") -> str:
    output = index.output
    file_cards = "\n".join(_safe_file_inventory_card(file) for file in index.files)
    safe_files = "".join(f"<li>{_h(name)}</li>" for name in SAFE_PREVIEW_FILES)
    forbidden_items = "".join(
        f"<li>{_h(item)}</li>"
        for item in (
            "raw request/response body",
            "request body 또는 response body preview",
            "prompt/report/evidence body preview",
            "Cookie 값",
            "Authorization 값",
            "token/JWT/session 값",
            "실제 URL/도메인/IP",
            "개인정보",
            "무결성 검증 비밀값",
            "요청 위조 방지 값",
            "전체 로컬 경로",
            "local_only/, raw/, raw_vault/, verify 전 out/, out/.audit 산출물",
        )
    )
    related_links = "".join(
        f'<div><dt>{_h(label)}</dt><dd><a href="{_h(href)}">{_h(text)}</a></dd></div>'
        for label, href, text in (
            ("사전 점검", _preflight_href(output.output_id), "AI 안전 사전 점검 열기"),
            ("핸드오프", _handoff_href(output.output_id), "AI 핸드오프 인덱스 열기"),
            ("Prompt readiness", _prompt_readiness_href(output.output_id), "Prompt readiness 인덱스 열기"),
            ("Evidence boundary", _evidence_boundary_href(output.output_id), "Evidence boundary 인덱스 열기"),
            ("후보 분류", _triage_href(output.output_id), "finding 후보 분류 인덱스 열기"),
            ("보고서 준비", _report_readiness_href(output.output_id), "보고서 준비 인덱스 열기"),
            ("Workflow", _workflow_href(output.output_id), "작업 흐름 상태 인덱스 열기"),
            ("Operator runbook", _operator_runbook_href(output.output_id), "Operator runbook 인덱스 열기"),
        )
    )
    return _page(
        f"Safe file inventory 인덱스 {output.label}",
        f"""
        <section class="topbar">
          <div>
            <a class="back" href="{_output_href(output.output_id)}">검증된 산출물 상세</a>
            <h1>Safe file inventory 인덱스</h1>
            <p class="subtitle">AI 투입 후보 파일 4개의 존재 여부와 안전 메타데이터를 보여주는 조회 전용 safe file inventory checklist입니다.</p>
          </div>
          <span class="badge good">조회 전용</span>
        </section>
        <section class="safety-strip">
          <div class="rail"><span>프로젝트 별칭</span><strong>{_h(output.label)}</strong></div>
          <div class="rail"><span>safe files</span><strong>{index.safe_file_count}/{len(SAFE_PREVIEW_FILES)}</strong></div>
          <div class="rail"><span>finding 후보 수</span><strong>{index.candidate_count}</strong></div>
          <div class="rail"><span>raw 표시</span><strong>false</strong></div>
        </section>
        {alias_selector_html}
        <section class="grid">
          <div class="panel">
            <div class="panel-head"><h2>Inventory 요약</h2><span class="muted">본문 preview 없이 파일 메타데이터만 표시합니다.</span></div>
            <dl class="facts">
              <div><dt>프로젝트 별칭</dt><dd>{_h(output.label)}</dd></div>
              <div><dt>verify gate</dt><dd>{_status_badge("passed")}</dd></div>
              <div><dt>finding candidate count</dt><dd>{index.candidate_count}</dd></div>
              <div><dt>analysis_packet.json</dt><dd>{_status_badge(index.analysis_status)}</dd></div>
              <div><dt>report_draft.md</dt><dd>{_status_badge(index.report_status)}</dd></div>
              <div><dt>final severity</dt><dd>수동 결정입니다.</dd></div>
              <div><dt>file body preview</dt><dd>false</dd></div>
              <div><dt>download action</dt><dd>false</dd></div>
              <div><dt>전체 로컬 경로 표시</dt><dd>false</dd></div>
            </dl>
          </div>
          <div class="panel">
            <div class="panel-head"><h2>safe files 4개</h2><span class="muted">AI 후보 파일 allowlist입니다.</span></div>
            <ul class="safe-list">{safe_files}</ul>
            <p class="muted">각 파일은 verify 통과 후에도 사람이 직접 검토해야 합니다.</p>
          </div>
          <div class="panel wide">
            <div class="panel-head"><h2>파일 inventory</h2><span class="muted">exists/missing, size, modified UTC, SHA-256 fingerprint만 표시합니다.</span></div>
            <div class="file-grid">{file_cards}</div>
          </div>
          <div class="panel">
            <div class="panel-head"><h2>AI 투입 해석 경계</h2><span class="muted">사람 검토 전 확정 상태가 아닙니다.</span></div>
            <dl class="facts">
              <div><dt>finding</dt><dd>수동 검증이 끝날 때까지 candidate입니다.</dd></div>
              <div><dt>risk</dt><dd>risk rating은 초안이며 최종 심각도가 아닙니다.</dd></div>
              <div><dt>confidence</dt><dd>evidence confidence이며 severity가 아닙니다.</dd></div>
              <div><dt>final severity</dt><dd>Burp 재현, 권한별 비교, 영향도 판단 후 사람이 수동 결정합니다.</dd></div>
              <div><dt>report_draft.md</dt><dd>final report가 아니라 수동 검토용 보고서 초안입니다.</dd></div>
            </dl>
          </div>
          <div class="panel">
            <div class="panel-head"><h2>금지 데이터 경계</h2><span class="muted">분류명만 표시하며 실제 값은 표시하지 않습니다.</span></div>
            <ul class="safe-list">{forbidden_items}</ul>
          </div>
          <div class="panel">
            <div class="panel-head"><h2>관련 조회 전용 인덱스</h2><span class="muted">GET 링크만 제공합니다.</span></div>
            <dl class="facts">
              {related_links}
              <div><dt>경계</dt><dd>이 화면은 조회 전용이며 form, POST action, 실행 버튼, 파일 내려받기를 제공하지 않습니다.</dd></div>
            </dl>
          </div>
        </section>
        """,
    )


def render_workflow_status_index(index: WorkflowStatusIndex, alias_selector_html: str = "") -> str:
    output = index.output
    step_cards = "\n".join(_workflow_step_card(step) for step in index.steps)
    file_rows = "\n".join(
        f"<div><dt>{_h(name)}</dt><dd>{_status_badge(status)}</dd></div>"
        for name, status in index.file_statuses
    )
    safe_files = "".join(f"<li>{_h(name)}</li>" for name in SAFE_PREVIEW_FILES)
    forbidden_items = "".join(
        f"<li>{_h(item)}</li>"
        for item in (
            "raw 요청/응답",
            "raw 감사 row body",
            "Cookie 또는 Authorization 값",
            "token, JWT, session 값",
            "실제 도메인, URL, IP 값",
            "개인정보",
            "무결성 검증 비밀값 또는 요청 위조 방지 값",
            "전체 로컬 경로",
            "local_only/, raw/, raw_vault/, 검증 전 out/, out/.audit 산출물",
        )
    )
    return _page(
        f"작업 흐름 상태 인덱스 {output.label}",
        f"""
        <section class="topbar">
          <div>
            <a class="back" href="{_output_href(output.output_id)}">검증된 산출물 상세</a>
            <h1>작업 흐름 상태 인덱스</h1>
            <p class="subtitle">검증된 산출물 리뷰를 위한 조회 전용 작업 흐름 점검입니다. 실행 없이 안전한 대시보드 순서만 연결합니다.</p>
          </div>
          <span class="badge good">조회 전용</span>
        </section>
        <section class="safety-strip">
          <div class="rail"><span>프로젝트 별칭</span><strong>{_h(output.label)}</strong></div>
          <div class="rail"><span>검증 상태 요약</span><strong>통과</strong></div>
          <div class="rail"><span>finding 후보 수</span><strong>{index.candidate_count}</strong></div>
          <div class="rail"><span>심각도 결정</span><strong>수동 검토 필요</strong></div>
        </section>
        {alias_selector_html}
        <section class="grid">
          <div class="panel">
            <div class="panel-head"><h2>조회 전용 작업 흐름 점검</h2><span class="muted">안전 메타데이터만 표시합니다.</span></div>
            <dl class="facts">
              <div><dt>프로젝트 별칭</dt><dd>{_h(output.label)}</dd></div>
              <div><dt>검증 상태 요약</dt><dd>{_status_badge("passed")}</dd></div>
              <div><dt>리뷰 상태 요약</dt><dd>{_status_badge(index.review_status)}</dd></div>
              <div><dt>finding 후보 수</dt><dd>{index.candidate_count}</dd></div>
              <div><dt>report_draft.md</dt><dd>{_status_badge(index.report_status)}</dd></div>
              <div><dt>analysis_packet.json</dt><dd>{_status_badge(index.analysis_status)}</dd></div>
              <div><dt>raw_data_included</dt><dd>false</dd></div>
              <div><dt>파일 경로 표시</dt><dd>false</dd></div>
            </dl>
          </div>
          <div class="panel">
            <div class="panel-head"><h2>작업 흐름 단계</h2><span class="muted">조회 전용 링크입니다.</span></div>
            <div class="file-grid">{step_cards}</div>
          </div>
          <div class="panel">
            <div class="panel-head"><h2>안전 파일 상태</h2><span class="muted">4개 allowlist만 표시합니다.</span></div>
            <dl class="facts">{file_rows}</dl>
            <ul class="safe-list">{safe_files}</ul>
          </div>
          <div class="panel">
            <div class="panel-head"><h2>관련 인덱스</h2><span class="muted">GET 이동만 제공합니다.</span></div>
            <dl class="facts">
              <div><dt>사전 점검</dt><dd><a href="{_preflight_href(output.output_id)}">AI 안전 사전 점검 열기</a></dd></div>
              <div><dt>핸드오프</dt><dd><a href="{_handoff_href(output.output_id)}">AI 핸드오프 인덱스 열기</a></dd></div>
              <div><dt>Prompt readiness</dt><dd><a href="{_prompt_readiness_href(output.output_id)}">Prompt readiness 인덱스 열기</a></dd></div>
              <div><dt>Safe file inventory</dt><dd><a href="{_safe_files_href(output.output_id)}">Safe file inventory 인덱스 열기</a></dd></div>
              <div><dt>후보 분류</dt><dd><a href="{_triage_href(output.output_id)}">finding 후보 분류 인덱스 열기</a></dd></div>
              <div><dt>보고서 준비</dt><dd><a href="{_report_readiness_href(output.output_id)}">보고서 준비 인덱스 열기</a></dd></div>
              <div><dt>운영 runbook</dt><dd><a href="{_operator_runbook_href(output.output_id)}">Operator runbook 인덱스 열기</a></dd></div>
              <div><dt>리뷰/보고서/내보내기 흐름</dt><dd><a href="{_output_href(output.output_id)}">검증된 산출물 상세로 돌아가기</a></dd></div>
              <div><dt>Live Capture 준비</dt><dd><a href="/live-capture">Live Capture 준비 화면 열기</a></dd></div>
              <div><dt>경계</dt><dd>조회 전용 작업 흐름 점검이며 form 또는 POST action이 없습니다.</dd></div>
            </dl>
          </div>
          <div class="panel">
            <div class="panel-head"><h2>해석 경계</h2><span class="muted">후보와 초안으로만 봅니다.</span></div>
            <dl class="facts">
              <div><dt>finding</dt><dd>수동 검증이 끝날 때까지 후보입니다.</dd></div>
              <div><dt>risk</dt><dd>초안이며 별도 검토가 필요합니다.</dd></div>
              <div><dt>confidence</dt><dd>증거 신뢰도이며 심각도가 아닙니다.</dd></div>
              <div><dt>report draft</dt><dd>report_draft.md는 제출용 보고서가 아니라 초안입니다.</dd></div>
              <div><dt>최종 심각도</dt><dd>최종 심각도는 수동 결정입니다.</dd></div>
              <div><dt>안전 파일</dt><dd>검토 후 검증된 안전 파일만 사용합니다.</dd></div>
            </dl>
          </div>
          <div class="panel">
            <div class="panel-head"><h2>금지 데이터</h2><span class="muted">분류만 표시하고 실제 값은 표시하지 않습니다.</span></div>
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
            "raw 요청/응답",
            "Cookie 또는 Authorization 값",
            "token, JWT, session 값",
            "실제 도메인, URL, IP 값",
            "개인정보",
            "무결성 검증 비밀값 또는 요청 위조 방지 값",
            "로컬 전용 raw 저장소 또는 검증 전 산출물",
            "감사 로그, 압축 archive, manifest",
        )
    )
    return _page(
        f"AI 안전 사전 점검 {output.label}",
        f"""
        <section class="topbar">
          <div>
            <a class="back" href="{_output_href(output.output_id)}">산출물로 돌아가기</a>
            <h1>AI 안전 사전 점검</h1>
            <p class="subtitle">ChatGPT 또는 Codex 핸드오프 전 조회 전용 점검입니다. 별칭과 상태 메타데이터만 표시합니다.</p>
          </div>
          <span class="badge good">조회 전용</span>
        </section>
        <section class="safety-strip">
          <div class="rail"><span>검증</span><strong>{_h(_status_label("passed"))}</strong></div>
          <div class="rail"><span>핸드오프</span><strong>{_h(_status_label(preflight.ready_status))}</strong></div>
          <div class="rail"><span>raw 데이터 포함</span><strong>false</strong></div>
          <div class="rail"><span>최종 심각도</span><strong>수동 결정</strong></div>
        </section>
        <section class="grid">
          <div class="panel">
            <div class="panel-head"><h2>사전 점검 요약</h2><span class="muted">안전 메타데이터만 표시합니다.</span></div>
            {_preflight_summary(preflight)}
          </div>
          <div class="panel">
            <div class="panel-head"><h2>AI용 안전 파일</h2><span class="muted">먼저 검증하고 수동 검토해야 합니다.</span></div>
            <dl class="facts">{file_rows}</dl>
            <ul class="safe-list">{safe_files}</ul>
          </div>
          <div class="panel">
            <div class="panel-head"><h2>전송 금지 항목</h2><span class="muted">분류만 표시하고 실제 값은 표시하지 않습니다.</span></div>
            <ul class="safe-list">{forbidden_items}</ul>
          </div>
          <div class="panel">
            <div class="panel-head"><h2>해석 경계</h2><span class="muted">후보와 초안으로만 봅니다.</span></div>
            <dl class="facts">
              <div><dt>finding</dt><dd>수동 검증이 끝날 때까지 후보입니다.</dd></div>
              <div><dt>위험도</dt><dd>초안이며 최종 심각도가 아닙니다.</dd></div>
              <div><dt>confidence</dt><dd>증거 신뢰도이며 심각도가 아닙니다.</dd></div>
              <div><dt>CVSS</dt><dd>별도 산정 범위입니다.</dd></div>
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


def _render_output_alias_selector(
    root: Path,
    policy: RedactionPolicy,
    current_output_id: str = "",
    outputs: list[DashboardOutput] | None = None,
) -> str:
    verified_outputs = outputs if outputs is not None else _discover_outputs(root, policy)[0]
    if not verified_outputs:
        return """
        <section class="panel output-alias-selector" aria-label="검증된 output 산출물 선택">
          <div class="panel-head">
            <h2>검증된 output 산출물 선택</h2>
            <span class="muted">검증을 통과한 output 별칭이 아직 없습니다.</span>
          </div>
          <p class="muted">먼저 Burp export 또는 receiver output을 redaction/verify한 뒤 이 화면에서 별칭을 선택하세요. Output alias는 안전한 표시용 이름이며 전체 로컬 경로나 실제 target을 표시하지 않습니다. Raw traffic은 표시하지 않습니다.</p>
          <a class="button secondary" href="/help">운영 가이드 보기</a>
        </section>
        """

    cards = "\n".join(
        _output_alias_selector_card(output, current_output_id)
        for output in verified_outputs
    )
    return f"""
        <section class="panel output-alias-selector" aria-label="검증된 output 산출물 선택">
          <div class="panel-head">
            <h2>검증된 output 산출물 선택</h2>
            <span class="muted">verify를 통과한 별칭만 표시합니다.</span>
          </div>
          <p class="muted">Safe files는 AI 입력 후보이며 수동 검토가 필요합니다. Finding은 후보, risk는 초안입니다. Final severity와 CVSS는 사람이 수동 결정합니다. Raw traffic은 표시하지 않습니다.</p>
          <p class="muted">Output alias는 안전한 표시용 이름입니다. 전체 로컬 경로, 실제 target 식별자, raw traffic, credential 값은 표시하지 않습니다.</p>
          <div class="file-grid">{cards}</div>
        </section>
        """


def _output_alias_selector_card(output: DashboardOutput, current_output_id: str) -> str:
    selected_badge = '<span class="badge good">선택됨</span>' if output.output_id == current_output_id else ""
    safe_file_count = len(output.prompt_files)
    links = "".join(
        f'<a class="button small secondary" href="{_h(href)}">{_h(label)}</a>'
        for label, href in _output_alias_selector_links(output.output_id)
    )
    return f"""
            <div class="guide-card output-alias-card">
              <strong>{_h(output.label)}</strong>
              <span>finding 후보 {output.candidate_count}개 · safe files {safe_file_count}/{len(SAFE_PREVIEW_FILES)}</span>
              <small>별칭만 표시합니다. 로컬 경로와 target 식별자는 표시하지 않습니다. {selected_badge}</small>
              <div class="actions">{links}</div>
            </div>
    """


def _output_alias_selector_links(output_id: str) -> tuple[tuple[str, str], ...]:
    return (
        ("Safe files", _safe_files_href(output_id)),
        ("Triage", _triage_href(output_id)),
        ("Report readiness", _report_readiness_href(output_id)),
        ("Workflow", _workflow_href(output_id)),
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
            name="safe files 4개 언급",
            status="present" if _contains_all(combined_text, SAFE_PREVIEW_FILES) else "needs_manual_review",
            summary="analysis_packet.json, chatgpt_prompt.md, codex_task_prompt.md, report_draft.md가 prompt 본문에 모두 언급되는지 봅니다.",
        ),
        PromptReadinessCheck(
            name="forbidden data warning",
            status=(
                "present"
                if _contains_all(combined_text, ("raw", "Cookie", "Authorization", "token", "domain", "IP"))
                else "needs_manual_review"
            ),
            summary="원문, 인증 헤더, 토큰, 실제 도메인/IP 같은 금지 범위가 prompt에 경고되는지 봅니다.",
        ),
        PromptReadinessCheck(
            name="verify-first warning",
            status="present" if _contains_any(combined_text, ("verify", "verified")) else "needs_manual_review",
            summary="AI 투입 전 verify 통과 산출물만 사용한다는 경계가 있는지 봅니다.",
        ),
        PromptReadinessCheck(
            name="candidate/draft/manual review boundary",
            status=(
                "present"
                if _contains_all(combined_text, ("candidate", "draft", "manual"))
                else "needs_manual_review"
            ),
            summary="finding은 후보, risk는 초안, 수동 검토가 필요하다는 경계가 있는지 봅니다.",
        ),
        PromptReadinessCheck(
            name="최종 심각도 수동 결정 경고",
            status=(
                "present"
                if _contains_any(combined_text, ("severity decision", "manual-review severity draft"))
                else "needs_manual_review"
            ),
            summary="심각도 초안이 최종 결정이 아니라는 문구가 있는지 봅니다.",
        ),
        PromptReadinessCheck(
            name="raw data prohibition warning",
            status=(
                "present"
                if _contains_any(combined_text, ("raw request/response", "raw request or response", "raw HTTP"))
                else "needs_manual_review"
            ),
            summary="raw 요청/응답을 요청하거나 재구성하지 말라는 경계가 있는지 봅니다.",
        ),
        PromptReadinessCheck(
            name="Codex prompt 범위 구분",
            status=(
                "present"
                if _contains_all(codex_text, ("Hard requirements", "Do not", "manual verification"))
                else "needs_manual_review"
            ),
            summary="Codex용 prompt에 구현 보조 범위와 금지 범위가 분리되어 있는지 봅니다.",
        ),
        PromptReadinessCheck(
            name="ChatGPT prompt 분석 경계",
            status=(
                "present"
                if _contains_all(chatgpt_text, ("Analyze", "candidate", "manual verification"))
                else "needs_manual_review"
            ),
            summary="ChatGPT용 prompt에 분석 목적과 수동 검토 경계가 분리되어 있는지 봅니다.",
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
            summary="이 화면은 검증 gate를 통과한 산출물에만 표시됩니다.",
            href=_output_href(output.output_id),
        ),
        WorkflowStep(
            name="리뷰",
            status=review_status,
            summary="후보 리뷰 요약은 정제된 메타데이터로만 표시합니다.",
            href=_output_href(output.output_id),
        ),
        WorkflowStep(
            name="보고서",
            status=report_status,
            summary="report_draft.md는 수동 검토용 보고서 초안입니다.",
            href=_output_href(output.output_id),
        ),
        WorkflowStep(
            name="AI 안전 사전 점검",
            status="manual review required",
            summary="AI 핸드오프 전 안전 파일 4개가 있는지 확인합니다.",
            href=_preflight_href(output.output_id),
        ),
        WorkflowStep(
            name="Safe file inventory 인덱스",
            status="manual review required",
            summary="safe files 4개의 존재 여부, 크기, 수정 시각, SHA-256 fingerprint를 확인합니다.",
            href=_safe_files_href(output.output_id),
        ),
        WorkflowStep(
            name="AI 핸드오프 인덱스",
            status="manual review required",
            summary="안전 파일 별칭, 순서, 목적, 메타데이터를 확인합니다.",
            href=_handoff_href(output.output_id),
        ),
        WorkflowStep(
            name="Prompt readiness 인덱스",
            status="manual review required",
            summary="prompt 파일 본문을 표시하지 않고 투입 전 점검 결과만 확인합니다.",
            href=_prompt_readiness_href(output.output_id),
        ),
        WorkflowStep(
            name="Evidence boundary 인덱스",
            status="manual review required",
            summary="정제 증거와 raw 금지 범위의 조회 전용 경계를 확인합니다.",
            href=_evidence_boundary_href(output.output_id),
        ),
        WorkflowStep(
            name="Finding 후보 분류 인덱스",
            status="manual review required",
            summary="정제된 finding 후보를 심각도 확정 없이 검토합니다.",
            href=_triage_href(output.output_id),
        ),
        WorkflowStep(
            name="보고서 준비 인덱스",
            status="manual review required",
            summary="제출 승인 없이 보고서 초안 준비 상태를 확인합니다.",
            href=_report_readiness_href(output.output_id),
        ),
        WorkflowStep(
            name="리뷰/보고서/내보내기 흐름",
            status="manual review required",
            summary="CSRF 보호 action은 검증된 산출물 상세에서만 실행합니다.",
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
            name="Burp HTTP history 수집",
            status="manual review required",
            purpose="스코프가 확인된 HTTP history만 로컬 receiver로 보낼 준비를 확인합니다.",
            safe_metadata=("스코프 확인", "대상 별칭", "원문 값 미표시"),
            href="/help",
        ),
        OperatorRunbookStep(
            order=2,
            name="localhost receiver 저장",
            status="manual review required",
            purpose="127.0.0.1 receiver가 sanitized output alias를 생성했는지 확인합니다.",
            safe_metadata=("receiver 포트", "output alias", "project alias"),
            href="/operations",
        ),
        OperatorRunbookStep(
            order=3,
            name="redaction/verify",
            status="passed",
            purpose="검증 gate를 통과한 산출물만 다음 단계로 넘깁니다.",
            safe_metadata=("검증한 파일 수", "safe file 상태", "raw_data_included=false"),
            href=_output_href(output.output_id),
        ),
        OperatorRunbookStep(
            order=4,
            name="review candidate findings",
            status=review_status,
            purpose="정제된 finding candidate metadata와 후보 수를 확인합니다.",
            safe_metadata=("candidate count", "finding id", "risk draft metadata"),
            href=_triage_href(output.output_id),
        ),
        OperatorRunbookStep(
            order=5,
            name="report_draft.md 생성",
            status=report_status,
            purpose="수동 검토용 보고서 초안 존재 여부를 확인합니다.",
            safe_metadata=("report_draft.md 상태", "파일 fingerprint", "초안 경계"),
            href=_report_readiness_href(output.output_id),
        ),
        OperatorRunbookStep(
            order=6,
            name="preflight",
            status="manual review required",
            purpose="AI 투입 전 safe files 4개와 금지 마커 상태를 확인합니다.",
            safe_metadata=("safe files 4개", "금지 마커 스캔", "verify 선행 여부"),
            href=_preflight_href(output.output_id),
        ),
        OperatorRunbookStep(
            order=7,
            name="handoff",
            status="manual review required",
            purpose="AI 후보 파일의 순서, 목적, 안전 metadata를 확인합니다.",
            safe_metadata=("file alias", "purpose", "SHA-256 fingerprint"),
            href=_handoff_href(output.output_id),
        ),
        OperatorRunbookStep(
            order=8,
            name="triage",
            status="manual review required",
            purpose="finding 후보가 확정 심각도로 읽히지 않는지 확인합니다.",
            safe_metadata=("candidate status", "confidence", "severity draft"),
            href=_triage_href(output.output_id),
        ),
        OperatorRunbookStep(
            order=9,
            name="report-readiness",
            status="manual review required",
            purpose="보고서 초안과 수동 제출 전 확인 항목을 분리해 봅니다.",
            safe_metadata=("report draft status", "manual checklist", "safe file metadata"),
            href=_report_readiness_href(output.output_id),
        ),
        OperatorRunbookStep(
            order=10,
            name="prompt-readiness",
            status="manual review required",
            purpose="prompt 파일을 AI에 넣기 전 본문 없이 상태와 경계를 확인합니다.",
            safe_metadata=("prompt file status", "body preview=false", "manual review boundary"),
            href=_prompt_readiness_href(output.output_id),
        ),
        OperatorRunbookStep(
            order=11,
            name="evidence-boundary",
            status="manual review required",
            purpose="정제 evidence와 raw 금지 범위가 분리되어 있는지 확인합니다.",
            safe_metadata=("sanitized evidence status", "forbidden data categories", "full path=false"),
            href=_evidence_boundary_href(output.output_id),
        ),
        OperatorRunbookStep(
            order=12,
            name="workflow status recap",
            status="manual review required",
            purpose="전체 GUI 운영 흐름과 남은 수동 검토 지점을 다시 확인합니다.",
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
    summary = f"{title}; 정제된 endpoint 템플릿: {endpoint}"
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
    present_count = sum(1 for file in index.files if file.status == "present")
    return f"""
    <dl class="facts">
      <div><dt>핸드오프 상태</dt><dd>{_status_badge(index.preflight.ready_status)}</dd></div>
      <div><dt>안전 파일 수</dt><dd>{present_count}/{len(SAFE_PREVIEW_FILES)}</dd></div>
      <div><dt>검증 상태</dt><dd>{_status_badge("passed")}</dd></div>
      <div><dt>사전 점검 상태</dt><dd>{_status_badge(index.preflight.ready_status)}</dd></div>
      <div><dt>금지 마커 스캔</dt><dd>{_status_badge(index.preflight.marker_scan_status)}</dd></div>
      <div><dt>finding 후보 수</dt><dd>{index.preflight.candidate_count}</dd></div>
      <div><dt>raw_data_included</dt><dd>false</dd></div>
      <div><dt>파일 경로 표시</dt><dd>false</dd></div>
      <div><dt>hash 종류</dt><dd>SHA-256 파일 fingerprint이며 HMAC이 아닙니다.</dd></div>
    </dl>
    """


def _handoff_file_card(file: HandoffFile) -> str:
    size = str(file.size_bytes) if file.size_bytes is not None else "missing"
    return f"""
    <article class="file-card">
      <div>
        <span class="kicker">순서 {file.order}</span>
        <strong>{_h(file.name)}</strong>
        <span>{_status_badge(file.status)}</span>
        <small>{_h(file.purpose)}</small>
      </div>
      <dl class="facts compact">
        <div><dt>목적</dt><dd>{_h(file.purpose)}</dd></div>
        <div><dt>크기(bytes)</dt><dd>{_h(size)}</dd></div>
        <div><dt>수정 시각(UTC)</dt><dd>{_h(file.modified_utc)}</dd></div>
        <div><dt>SHA-256</dt><dd>{_h(file.sha256)}</dd></div>
      </dl>
    </article>
    """


def _report_readiness_file_card(file: ReportReadinessFile) -> str:
    size = str(file.size_bytes) if file.size_bytes is not None else "missing"
    return f"""
    <article class="file-card">
      <div>
        <span class="kicker">보고서 준비 메타데이터</span>
        <strong>{_h(file.name)}</strong>
        <span>{_status_badge(file.status)}</span>
        <small>{_h(file.purpose)}</small>
      </div>
      <dl class="facts compact">
        <div><dt>목적</dt><dd>{_h(file.purpose)}</dd></div>
        <div><dt>존재 여부</dt><dd>{_h(_status_label(file.status))}</dd></div>
        <div><dt>파일 크기(bytes)</dt><dd>{_h(size)}</dd></div>
        <div><dt>수정 시각(UTC)</dt><dd>{_h(file.modified_utc)}</dd></div>
        <div><dt>SHA-256 파일 fingerprint</dt><dd>{_h(file.sha256)}</dd></div>
      </dl>
    </article>
    """


def _prompt_readiness_file_card(file: PromptReadinessFile) -> str:
    size = str(file.size_bytes) if file.size_bytes is not None else "missing"
    return f"""
    <article class="file-card">
      <div>
        <span class="kicker">prompt readiness</span>
        <strong>{_h(file.name)}</strong>
        <span>{_status_badge(file.status)}</span>
        <small>{_h(file.purpose)}</small>
      </div>
      <dl class="facts compact">
        <div><dt>목적</dt><dd>{_h(file.purpose)}</dd></div>
        <div><dt>존재 여부</dt><dd>{_h(_status_label(file.status))}</dd></div>
        <div><dt>파일 크기(bytes)</dt><dd>{_h(size)}</dd></div>
        <div><dt>수정 시각(UTC)</dt><dd>{_h(file.modified_utc)}</dd></div>
        <div><dt>SHA-256 fingerprint</dt><dd>{_h(file.sha256)}</dd></div>
      </dl>
    </article>
    """


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
    size = str(file.size_bytes) if file.size_bytes is not None else "missing"
    return f"""
    <article class="file-card">
      <div>
        <span class="kicker">evidence boundary</span>
        <strong>{_h(file.name)}</strong>
        <span>{_status_badge(file.status)}</span>
        <small>{_h(file.purpose)}</small>
      </div>
      <dl class="facts compact">
        <div><dt>목적</dt><dd>{_h(file.purpose)}</dd></div>
        <div><dt>존재 여부</dt><dd>{_h(_status_label(file.status))}</dd></div>
        <div><dt>파일 크기(bytes)</dt><dd>{_h(size)}</dd></div>
        <div><dt>수정 시각(UTC)</dt><dd>{_h(file.modified_utc)}</dd></div>
        <div><dt>SHA-256 fingerprint</dt><dd>{_h(file.sha256)}</dd></div>
      </dl>
    </article>
    """


def _workflow_step_card(step: WorkflowStep) -> str:
    return f"""
    <article class="file-card">
      <div>
        <span class="kicker">작업 흐름 단계</span>
        <strong>{_h(step.name)}</strong>
        <span>{_status_badge(step.status)}</span>
        <small>{_h(step.summary)}</small>
      </div>
      <dl class="facts compact">
        <div><dt>상태</dt><dd>{_h(_status_label(step.status))}</dd></div>
        <div><dt>링크</dt><dd><a href="{_h(step.href)}">조회 전용 단계 열기</a></dd></div>
        <div><dt>action 표면</dt><dd>form 없음, POST action 없음, 상태 변경 버튼 없음</dd></div>
      </dl>
    </article>
    """


def _operator_runbook_step_card(step: OperatorRunbookStep) -> str:
    metadata = "".join(f"<li>{_h(item)}</li>" for item in step.safe_metadata)
    return f"""
    <article class="file-card">
      <div>
        <span class="kicker">runbook step {step.order}</span>
        <strong>{_h(step.name)}</strong>
        <span>{_status_badge(step.status)}</span>
        <small>{_h(step.purpose)}</small>
      </div>
      <dl class="facts compact">
        <div><dt>상태</dt><dd>{_h(_status_label(step.status))}</dd></div>
        <div><dt>확인 metadata</dt><dd><ul class="safe-list compact">{metadata}</ul></dd></div>
        <div><dt>관련 화면</dt><dd><a href="{_h(step.href)}">조회 전용 화면 열기</a></dd></div>
        <div><dt>action 표면</dt><dd>form 없음, POST action 없음, 상태 변경 버튼 없음</dd></div>
      </dl>
    </article>
    """


def _safe_file_inventory_card(file: SafeFileInventoryFile) -> str:
    size = str(file.size_bytes) if file.size_bytes is not None else "missing"
    verify_required = "true" if file.verify_required else "false"
    return f"""
    <article class="file-card">
      <div>
        <span class="kicker">safe file</span>
        <strong>{_h(file.name)}</strong>
        <span>{_status_badge(file.status)}</span>
        <small>{_h(file.purpose)}</small>
      </div>
      <dl class="facts compact">
        <div><dt>exists</dt><dd>{_h(file.status)}</dd></div>
        <div><dt>파일 목적</dt><dd>{_h(file.purpose)}</dd></div>
        <div><dt>권장 사용 위치</dt><dd>{_h(file.recommended_use)}</dd></div>
        <div><dt>verify 선행 필요</dt><dd>{verify_required}</dd></div>
        <div><dt>file size</dt><dd>{_h(size)}</dd></div>
        <div><dt>modified UTC</dt><dd>{_h(file.modified_utc)}</dd></div>
        <div><dt>SHA-256 fingerprint</dt><dd>{_h(file.sha256)}</dd></div>
        <div><dt>사람 수동 검토</dt><dd>필수</dd></div>
        <div><dt>body preview</dt><dd>false</dd></div>
      </dl>
    </article>
    """


def _triage_candidate_card(candidate: TriageCandidate) -> str:
    manual_required = "예" if candidate.manual_required else "아니오"
    return f"""
    <article class="candidate">
      <div class="candidate-head">
        <div>
          <span class="kicker">후보 #{candidate.index}</span>
          <h3>{_h(candidate.candidate_id)} - {_h(candidate.title)}</h3>
          <p>{_h(candidate.category)}</p>
        </div>
        <div class="status-stack">
          <span class="badge neutral">신뢰도: {_h(candidate.confidence)}</span>
          <span class="badge warning">수동 검토 필요</span>
        </div>
      </div>
      <dl class="facts compact">
        <div><dt>안정 ID</dt><dd>{_h(candidate.candidate_id)}</dd></div>
        <div><dt>분류/type</dt><dd>{_h(candidate.category)}</dd></div>
        <div><dt>정제된 요약</dt><dd>{_h(candidate.summary)}</dd></div>
        <div><dt>위험도 초안</dt><dd>profile: {_h(candidate.risk_profile)}; 심각도 초안: {_h(candidate.severity_draft)}; 가능성 초안: {_h(candidate.likelihood_draft)}; 영향도 초안: {_h(candidate.impact_draft)}</dd></div>
        <div><dt>confidence</dt><dd>{_h(candidate.confidence)} 증거 신뢰도이며 심각도가 아닙니다.</dd></div>
        <div><dt>수동 검증 필요</dt><dd>{_h(manual_required)}</dd></div>
        <div><dt>최종 심각도</dt><dd>최종 심각도는 수동 결정이 필요합니다.</dd></div>
      </dl>
    </article>
    """


def _preflight_summary(preflight: AiSafePreflight) -> str:
    missing = ", ".join(preflight.missing_files) if preflight.missing_files else "none"
    report_status = "present" if preflight.report_available else "missing"
    return f"""
    <dl class="facts">
      <div><dt>사전 점검 상태</dt><dd>{_status_badge(preflight.ready_status)}</dd></div>
      <div><dt>검증 상태</dt><dd>{_status_badge("passed")}</dd></div>
      <div><dt>검증한 파일 수</dt><dd>{preflight.files_checked}</dd></div>
      <div><dt>finding 후보 수</dt><dd>{preflight.candidate_count}</dd></div>
      <div><dt>report_draft.md</dt><dd>{_status_badge(report_status)}</dd></div>
      <div><dt>금지 마커 스캔</dt><dd>{_status_badge(preflight.marker_scan_status)}</dd></div>
      <div><dt>스캔한 안전 파일 수</dt><dd>{preflight.marker_scan_files}</dd></div>
      <div><dt>누락된 안전 파일</dt><dd>{_h(missing)}</dd></div>
      <div><dt>raw_data_included</dt><dd>false</dd></div>
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
    file_count = len(output.prompt_files)
    return f"""
    <tr>
      <td><span class="output-label">{_h(output.label)}</span></td>
      <td>{output.candidate_count}</td>
      <td>{file_count}</td>
      <td>{'있음' if output.report_available else '없음'}</td>
      <td><span class="badge good">검증 통과</span></td>
      <td>
        <a class="button small" href="{_simple_dashboard_href(output.output_id)}">간단 보기</a>
        <a class="button small secondary" href="{_output_href(output.output_id)}">상세</a>
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
    status = "exists" if (output.path / file_name).is_file() else "missing"
    return f"""
    <tr>
      <td>{_h(file_name)}</td>
      <td>{_h(status)}</td>
    </tr>
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
      <div><dt>압축 archive</dt><dd>{_status_badge(status["archive_status"])}</dd></div>
      <div><dt>압축 archive 검증</dt><dd>{_status_badge(status["archive_verify_status"])}</dd></div>
      <div><dt>압축 archive HMAC manifest</dt><dd>{_status_badge(status["archive_hmac_manifest_status"])}</dd></div>
      <div><dt>압축 archive HMAC 검증</dt><dd>{_status_badge(status["archive_hmac_status"])}</dd></div>
      <div><dt>표시 내용</dt><dd>메타데이터만</dd></div>
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
        "present": "있음",
        "missing": "없음",
        "ready_candidate": "후보 준비됨",
        "missing_safe_files": "안전 파일 누락",
        "needs_manual_review": "수동 검토 필요",
        "forbidden_marker_found": "금지 마커 발견",
        "candidate available": "후보 있음",
        "draft available": "초안 있음",
        "manual review required": "수동 검토 필요",
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
