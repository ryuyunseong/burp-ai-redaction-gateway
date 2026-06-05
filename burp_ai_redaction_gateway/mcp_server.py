from __future__ import annotations

import hashlib
import json
import sys
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, TextIO

from . import __version__
from .policy import RedactionPolicy
from .scanner import assert_no_sensitive_text
from .verifier import verify_path


MCP_PROTOCOL_VERSION = "2025-06-18"
SERVER_NAME = "burp-ai-redaction-gateway-readonly"
FORBIDDEN_PATH_PARTS = {"local_only", "raw", "raw_vault", "build", ".gradle"}
PROMPT_FILES = ("analysis_packet.json", "chatgpt_prompt.md", "codex_task_prompt.md")
FINDINGS_FILE = "finding_candidates.json"
ANALYSIS_PACKET_FILE = "analysis_packet.json"
DEFAULT_REPORT_FILE = "report_draft.md"
AUDIT_DIR_NAME = ".audit"
AUDIT_FILE_NAME = "mcp_audit.jsonl"
AUDIT_SCHEMA_VERSION = "1.1"
AUDIT_HASH_ALGORITHM = "SHA-256"
DEFAULT_AUDIT_MAX_BYTES = 10 * 1024 * 1024
DEFAULT_AUDIT_MAX_ROTATED_FILES = 20
TOOL_RESPONSE_CLASSES = {
    "list_findings": "finding_summary",
    "get_finding": "finding_detail",
    "get_analysis_packet": "analysis_packet",
    "get_report_draft": "report_draft",
    "list_prompt_files": "prompt_file_list",
}


@dataclass(frozen=True)
class McpToolResult:
    structured_content: dict[str, Any]
    text: str
    is_error: bool = False

    def to_protocol_result(self) -> dict[str, Any]:
        return {
            "content": [{"type": "text", "text": self.text}],
            "structuredContent": self.structured_content,
            "isError": self.is_error,
        }


class ReadOnlyMcpGateway:
    def __init__(self, root: Path, policy: RedactionPolicy) -> None:
        self.root = _validated_root(root)
        self.policy = policy

    def list_findings(self, project: str) -> McpToolResult:
        project_dir = self._verified_project_dir(project)
        findings = _load_json_file(project_dir / FINDINGS_FILE)
        candidates = _candidate_list(findings)
        summaries = [
            {
                "finding_id": _safe_text(candidate.get("finding_id")),
                "type": _safe_text(candidate.get("type")),
                "title": _safe_text(candidate.get("title")),
                "confidence": _safe_text(candidate.get("confidence")),
                "confidence_rationale": _safe_list(candidate.get("confidence_rationale")),
                "manual_verification_required": bool(candidate.get("manual_verification_required", True)),
                "affected_endpoint": _safe_text(candidate.get("affected_endpoint")),
                "evidence_ids": _safe_list(candidate.get("evidence_ids")),
            }
            for candidate in candidates
        ]
        return self._result(
            {
                "project": _safe_project_label(project),
                "raw_data_included": False,
                "candidate_count": len(summaries),
                "findings": summaries,
            }
        )

    def get_finding(self, project: str, finding_id: str) -> McpToolResult:
        project_dir = self._verified_project_dir(project)
        findings = _load_json_file(project_dir / FINDINGS_FILE)
        for candidate in _candidate_list(findings):
            if str(candidate.get("finding_id", "")) == finding_id:
                return self._result(
                    {
                        "project": _safe_project_label(project),
                        "raw_data_included": False,
                        "finding": candidate,
                    }
                )
        raise ValueError("finding_not_found")

    def get_analysis_packet(self, project: str) -> McpToolResult:
        project_dir = self._verified_project_dir(project)
        packet = _load_json_file(project_dir / ANALYSIS_PACKET_FILE)
        if packet.get("raw_data_included") is not False:
            raise ValueError("raw_data_marker_not_false")
        return self._result({"project": _safe_project_label(project), "raw_data_included": False, "analysis_packet": packet})

    def get_report_draft(self, project: str, report_name: str = DEFAULT_REPORT_FILE) -> McpToolResult:
        project_dir = self._verified_project_dir(project)
        safe_name = _safe_report_name(report_name)
        path = project_dir / safe_name
        if not path.is_file():
            raise ValueError("missing_report_draft")
        text = path.read_text(encoding="utf-8")
        assert_no_sensitive_text(text)
        return self._result(
            {
                "project": _safe_project_label(project),
                "raw_data_included": False,
                "report_name": safe_name,
                "report_draft": text,
            }
        )

    def list_prompt_files(self, project: str) -> McpToolResult:
        project_dir = self._verified_project_dir(project)
        files = []
        for name in PROMPT_FILES:
            path = project_dir / name
            if path.is_file():
                text = path.read_text(encoding="utf-8")
                assert_no_sensitive_text(text)
                files.append({"name": name, "bytes": len(text.encode("utf-8"))})
        return self._result({"project": _safe_project_label(project), "raw_data_included": False, "prompt_files": files})

    def call_tool(self, name: str, arguments: dict[str, Any] | None) -> McpToolResult:
        args = arguments or {}
        project = _required_string(args, "project")
        if name == "list_findings":
            return self.list_findings(project)
        if name == "get_finding":
            return self.get_finding(project, _required_string(args, "finding_id"))
        if name == "get_analysis_packet":
            return self.get_analysis_packet(project)
        if name == "get_report_draft":
            report_name = str(args.get("report_name", DEFAULT_REPORT_FILE))
            return self.get_report_draft(project, report_name)
        if name == "list_prompt_files":
            return self.list_prompt_files(project)
        raise ValueError("unknown_tool")

    def _verified_project_dir(self, project: str) -> Path:
        project_dir = _resolve_project_dir(self.root, project)
        verification = verify_path(project_dir, self.policy)
        if not verification.passed:
            raise ValueError("verification_failed")
        return project_dir

    def _result(self, structured_content: dict[str, Any]) -> McpToolResult:
        text = json.dumps(structured_content, ensure_ascii=True, sort_keys=True)
        assert_no_sensitive_text(text)
        return McpToolResult(structured_content=structured_content, text=text)


class ReadOnlyMcpServer:
    def __init__(
        self,
        gateway: ReadOnlyMcpGateway,
        audit_stream: TextIO | None = None,
        *,
        audit_max_bytes: int = DEFAULT_AUDIT_MAX_BYTES,
        audit_max_rotated_files: int = DEFAULT_AUDIT_MAX_ROTATED_FILES,
    ) -> None:
        self.gateway = gateway
        self.audit_stream = audit_stream if audit_stream is not None else sys.stderr
        self.audit_log_path = gateway.root / AUDIT_DIR_NAME / AUDIT_FILE_NAME
        self.audit_max_bytes = audit_max_bytes
        self.audit_max_rotated_files = audit_max_rotated_files

    def handle_message(self, message: Any) -> dict[str, Any] | list[dict[str, Any]] | None:
        if isinstance(message, list):
            responses = [response for item in message if (response := self.handle_message(item)) is not None]
            return responses or None
        if not isinstance(message, dict):
            return _error_response(None, -32600, "Invalid Request")

        request_id = message.get("id")
        method = message.get("method")
        if request_id is None:
            self._handle_notification(method)
            return None
        if method == "initialize":
            return _success_response(request_id, _initialize_result())
        if method == "tools/list":
            return _success_response(request_id, {"tools": tool_definitions()})
        if method == "tools/call":
            return self._handle_tool_call(request_id, message.get("params"))
        if method == "shutdown":
            return _success_response(request_id, {})
        return _error_response(request_id, -32601, "Method not found")

    def _handle_notification(self, method: Any) -> None:
        if method:
            self._audit_stream(str(method), "<notification>")

    def _handle_tool_call(self, request_id: Any, params: Any) -> dict[str, Any]:
        if not isinstance(params, dict):
            return _error_response(request_id, -32602, "Invalid params")
        name = params.get("name")
        arguments = params.get("arguments", {})
        if not isinstance(name, str) or not isinstance(arguments, dict):
            return _error_response(request_id, -32602, "Invalid params")
        project = _safe_project_label(str(arguments.get("project", "")))
        finding_id = _safe_optional_id(arguments.get("finding_id"))
        self._audit_stream(name, project)
        try:
            result = self.gateway.call_tool(name, arguments)
        except ValueError as error:
            error_type = str(error)
            error_result = _tool_error_result(error_type)
            self._write_audit_event(
                tool_name=name,
                output_id=project,
                finding_id=finding_id,
                result_status=_status_for_error(error_type),
                blocked_reason=_blocked_reason(error_type),
                response_class=_response_class(name),
                error_type=error_type,
            )
            return _success_response(request_id, error_result.to_protocol_result())
        self._write_audit_event(
            tool_name=name,
            output_id=project,
            finding_id=finding_id,
            result_status="success",
            blocked_reason="",
            response_class=_response_class(name),
            error_type="",
        )
        return _success_response(request_id, result.to_protocol_result())

    def _audit_stream(self, tool_name: str, project: str) -> None:
        timestamp = datetime.now(UTC).isoformat()
        safe_tool = tool_name.replace("\r", " ").replace("\n", " ")[:80]
        safe_project = project.replace("\r", " ").replace("\n", " ")[:120]
        print(f"mcp_audit timestamp={timestamp} tool={safe_tool} project={safe_project}", file=self.audit_stream)

    def _write_audit_event(
        self,
        *,
        tool_name: str,
        output_id: str,
        finding_id: str,
        result_status: str,
        blocked_reason: str,
        response_class: str,
        error_type: str,
    ) -> None:
        event = {
            "timestamp_utc": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            "event_type": "mcp_tool_call",
            "tool_name": _safe_identifier(tool_name, "unknown_tool"),
            "output_id": _safe_output_id(output_id),
            "result_status": _safe_status(result_status),
            "response_class": _safe_identifier(response_class, "unknown_response"),
            "raw_data_included": False,
        }
        if finding_id:
            event["finding_id"] = finding_id
        if blocked_reason:
            event["blocked_reason"] = _safe_identifier(blocked_reason, "blocked")
        if error_type:
            event["error_type"] = _safe_identifier(error_type, "error")
        _append_audit_event(
            self.audit_log_path,
            event,
            max_bytes=self.audit_max_bytes,
            max_rotated_files=self.audit_max_rotated_files,
        )


def serve_mcp_stdio(root: Path, policy: RedactionPolicy) -> None:
    server = ReadOnlyMcpServer(ReadOnlyMcpGateway(root, policy))
    for line in sys.stdin:
        text = line.strip()
        if not text:
            continue
        try:
            message = json.loads(text)
            response = server.handle_message(message)
        except json.JSONDecodeError:
            response = _error_response(None, -32700, "Parse error")
        if response is None:
            continue
        print(json.dumps(response, ensure_ascii=True), flush=True)


def tool_definitions() -> list[dict[str, Any]]:
    project_property = {
        "type": "string",
        "description": "Verified output directory relative to the configured root.",
    }
    read_only_annotations = {"readOnlyHint": True, "destructiveHint": False, "openWorldHint": False}
    return [
        {
            "name": "list_findings",
            "title": "List sanitized finding candidates",
            "description": "Return sanitized finding candidate summaries from a verified output directory.",
            "inputSchema": {"type": "object", "properties": {"project": project_property}, "required": ["project"]},
            "annotations": read_only_annotations,
        },
        {
            "name": "get_finding",
            "title": "Get sanitized finding candidate",
            "description": "Return one sanitized finding candidate by finding_id.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "project": project_property,
                    "finding_id": {"type": "string", "description": "Finding candidate id such as FC-0001."},
                },
                "required": ["project", "finding_id"],
            },
            "annotations": read_only_annotations,
        },
        {
            "name": "get_analysis_packet",
            "title": "Get sanitized analysis packet",
            "description": "Return analysis_packet.json from a verified output directory.",
            "inputSchema": {"type": "object", "properties": {"project": project_property}, "required": ["project"]},
            "annotations": read_only_annotations,
        },
        {
            "name": "get_report_draft",
            "title": "Get sanitized report draft",
            "description": "Return a sanitized report draft markdown file from a verified output directory.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "project": project_property,
                    "report_name": {
                        "type": "string",
                        "description": "Report markdown filename. Defaults to report_draft.md.",
                    },
                },
                "required": ["project"],
            },
            "annotations": read_only_annotations,
        },
        {
            "name": "list_prompt_files",
            "title": "List sanitized prompt files",
            "description": "List safe prompt packet files available in a verified output directory.",
            "inputSchema": {"type": "object", "properties": {"project": project_property}, "required": ["project"]},
            "annotations": read_only_annotations,
        },
    ]


def _initialize_result() -> dict[str, Any]:
    return {
        "protocolVersion": MCP_PROTOCOL_VERSION,
        "capabilities": {"tools": {"listChanged": False}},
        "serverInfo": {"name": SERVER_NAME, "version": __version__},
    }


def _success_response(request_id: Any, result: dict[str, Any]) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def _error_response(request_id: Any, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}


def _tool_error_result(error_type: str) -> McpToolResult:
    structured = {"error_type": error_type, "raw_data_included": False}
    text = json.dumps(structured, ensure_ascii=True, sort_keys=True)
    assert_no_sensitive_text(text)
    return McpToolResult(structured_content=structured, text=text, is_error=True)


def _append_audit_event(path: Path, event: dict[str, Any], *, max_bytes: int, max_rotated_files: int) -> None:
    event = _audit_event_with_chain_fields(path, event)
    text = json.dumps(event, ensure_ascii=True, sort_keys=True)
    assert_no_sensitive_text(text)
    path.parent.mkdir(parents=True, exist_ok=True)
    line = text + "\n"
    if _should_rotate_audit_file(path, line, max_bytes):
        _rotate_audit_file(path, max_rotated_files)
    with path.open("a", encoding="utf-8") as file:
        file.write(line)


def _audit_event_with_chain_fields(path: Path, event: dict[str, Any]) -> dict[str, Any]:
    timestamp = _safe_text(event.get("timestamp_utc"))
    previous = _last_chained_audit_event(path)
    if previous:
        sequence_no = int(previous["sequence_no"]) + 1
        previous_hash = previous["event_hash"]
        chain_id = previous["chain_id"]
    else:
        sequence_no = 1
        previous_hash = None
        chain_id = _new_chain_id(timestamp)
    chained = {
        "audit_schema_version": AUDIT_SCHEMA_VERSION,
        "event_id": str(uuid.uuid4()),
        "sequence_no": sequence_no,
        "chain_id": chain_id,
        "prev_event_hash": previous_hash,
        "hash_algorithm": AUDIT_HASH_ALGORITHM,
        **event,
    }
    chained["event_hash"] = _audit_event_hash(chained)
    return chained


def _last_chained_audit_event(path: Path) -> dict[str, Any] | None:
    last_event: dict[str, Any] | None = None
    for audit_file in _audit_log_files(path):
        for line in audit_file.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if _is_chained_audit_event(event):
                last_event = event
    return last_event


def _should_rotate_audit_file(path: Path, next_line: str, max_bytes: int) -> bool:
    if max_bytes <= 0 or not path.is_file():
        return False
    current_size = path.stat().st_size
    if current_size <= 0:
        return False
    return current_size + len(next_line.encode("utf-8")) > max_bytes


def _rotate_audit_file(path: Path, max_rotated_files: int) -> None:
    if not path.is_file() or path.stat().st_size <= 0:
        return
    target = _next_rotated_audit_path(path)
    path.replace(target)
    _prune_rotated_audit_files(path, max_rotated_files)


def _next_rotated_audit_path(path: Path) -> Path:
    rotated = _rotated_audit_files(path)
    next_index = rotated[-1][0] + 1 if rotated else 1
    return path.with_name(f"{path.stem}.{next_index:06d}{path.suffix}")


def _prune_rotated_audit_files(path: Path, max_rotated_files: int) -> None:
    rotated = _rotated_audit_files(path)
    if max_rotated_files < 0:
        return
    for _, file_path in rotated[: max(0, len(rotated) - max_rotated_files)]:
        file_path.unlink(missing_ok=True)


def _audit_log_files(path: Path) -> list[Path]:
    files = [file_path for _, file_path in _rotated_audit_files(path)]
    if path.is_file():
        files.append(path)
    return files


def _rotated_audit_files(path: Path) -> list[tuple[int, Path]]:
    if not path.parent.is_dir():
        return []
    prefix = f"{path.stem}."
    suffix = path.suffix
    rotated: list[tuple[int, Path]] = []
    for file_path in path.parent.glob(f"{path.stem}.*{path.suffix}"):
        name = file_path.name
        if not name.startswith(prefix) or not name.endswith(suffix):
            continue
        index_text = name[len(prefix) : -len(suffix)]
        if len(index_text) != 6 or not index_text.isdigit():
            continue
        rotated.append((int(index_text), file_path))
    return sorted(rotated, key=lambda item: item[0])


def _is_chained_audit_event(event: Any) -> bool:
    return (
        isinstance(event, dict)
        and event.get("audit_schema_version") == AUDIT_SCHEMA_VERSION
        and isinstance(event.get("chain_id"), str)
        and isinstance(event.get("sequence_no"), int)
        and _is_standard_uuid(str(event.get("event_id", "")))
        and _is_sha256_hash(str(event.get("event_hash", "")))
        and (
            event.get("prev_event_hash") is None
            or _is_sha256_hash(str(event.get("prev_event_hash", "")))
        )
    )


def _new_chain_id(timestamp_utc: str) -> str:
    date_part = timestamp_utc.split("T", 1)[0].replace("-", "")
    if len(date_part) != 8 or not date_part.isdigit():
        date_part = datetime.now(UTC).strftime("%Y%m%d")
    return f"mcp-audit-{date_part}"


def _audit_event_hash(event: dict[str, Any]) -> str:
    canonical = _canonical_audit_event_text(event)
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return f"sha256:{digest}"


def _canonical_audit_event_text(event: dict[str, Any]) -> str:
    body = {key: value for key, value in event.items() if key != "event_hash"}
    return json.dumps(body, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def _is_standard_uuid(value: str) -> bool:
    try:
        parsed = uuid.UUID(value)
    except ValueError:
        return False
    return str(parsed) == value.lower()


def _is_sha256_hash(value: str) -> bool:
    prefix = "sha256:"
    digest = value[len(prefix) :] if value.startswith(prefix) else ""
    return len(digest) == 64 and all(char in "0123456789abcdef" for char in digest)


def _validated_root(root: Path) -> Path:
    resolved = root.resolve()
    if not resolved.is_dir():
        raise ValueError("invalid_root")
    _reject_forbidden_parts(resolved.parts)
    return resolved


def _resolve_project_dir(root: Path, project: str) -> Path:
    if not project or project.strip() in {"", "."}:
        relative = Path(".")
    else:
        relative = Path(project)
    if relative.is_absolute():
        raise ValueError("absolute_project_path_forbidden")
    _reject_forbidden_parts(relative.parts)
    candidate = (root / relative).resolve()
    if not _is_relative_to(candidate, root):
        raise ValueError("path_traversal_forbidden")
    if not candidate.is_dir():
        raise ValueError("missing_project")
    return candidate


def _reject_forbidden_parts(parts: tuple[str, ...]) -> None:
    lowered = {part.lower() for part in parts}
    if lowered & FORBIDDEN_PATH_PARTS:
        raise ValueError("forbidden_directory")


def _is_relative_to(candidate: Path, root: Path) -> bool:
    return candidate == root or root in candidate.parents


def _load_json_file(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise ValueError("missing_output_file")
    text = path.read_text(encoding="utf-8")
    assert_no_sensitive_text(text)
    data = json.loads(text)
    if not isinstance(data, dict):
        raise ValueError("invalid_output_file")
    return data


def _candidate_list(findings: dict[str, Any]) -> list[dict[str, Any]]:
    candidates = findings.get("finding_candidates")
    if not isinstance(candidates, list):
        raise ValueError("invalid_findings_file")
    return [candidate for candidate in candidates if isinstance(candidate, dict)]


def _required_string(args: dict[str, Any], name: str) -> str:
    value = args.get(name)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"missing_argument:{name}")
    return value


def _safe_report_name(report_name: str) -> str:
    path = Path(report_name)
    if path.name != report_name or path.suffix.lower() != ".md" or not path.name.startswith("report"):
        raise ValueError("invalid_report_name")
    return path.name


def _safe_project_label(project: str) -> str:
    text = str(project).replace("\\", "/").replace("\r", " ").replace("\n", " ").strip()
    return text[:160] if text else "."


def _safe_output_id(value: str) -> str:
    text = _safe_project_label(value)
    parts = [part for part in text.split("/") if part and part not in {".", ".."}]
    if not parts:
        return "."
    return "/".join(_safe_identifier(part, "output") for part in parts)[:160]


def _safe_optional_id(value: Any) -> str:
    if not isinstance(value, str):
        return ""
    text = value.strip()
    if not text:
        return ""
    return _safe_identifier(text, "id")


def _safe_identifier(value: str, fallback: str) -> str:
    text = str(value).replace("\r", " ").replace("\n", " ").strip()
    result = []
    for char in text[:120]:
        if char.isalnum() or char in {"_", "-", ".", ":"}:
            result.append(char)
        else:
            result.append("_")
    safe = "".join(result).strip("._-")
    return safe or fallback


def _safe_status(value: str) -> str:
    return value if value in {"success", "blocked", "error"} else "error"


def _response_class(tool_name: str) -> str:
    return TOOL_RESPONSE_CLASSES.get(tool_name, "unknown_response")


def _status_for_error(error_type: str) -> str:
    if _blocked_reason(error_type):
        return "blocked"
    return "error"


def _blocked_reason(error_type: str) -> str:
    reasons = {
        "path_traversal_forbidden": "path_traversal",
        "absolute_project_path_forbidden": "path_traversal",
        "forbidden_directory": "forbidden_directory",
        "verification_failed": "verify_failed",
    }
    return reasons.get(error_type, "")


def _safe_text(value: Any) -> str:
    if value is None:
        return ""
    return str(value).replace("\r", " ").replace("\n", " ").strip()


def _safe_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [_safe_text(item) for item in value if _safe_text(item)]
