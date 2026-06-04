from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from .findings import build_finding_candidates
from .output import write_outputs
from .parser import event_from_montoya_handoff
from .policy import load_policy
from .redaction import Redactor
from .verifier import verify_path

INGEST_PATH = "/ingest/burp-history"
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8765
DEFAULT_MAX_BYTES = 1_048_576
SAFE_OUTPUT_NAME_RE = re.compile(r"[^A-Za-z0-9_.-]+")


@dataclass(frozen=True)
class ReceiverConfig:
    output_dir: Path
    project: str
    policy_path: Path | None = None
    max_body_bytes: int = DEFAULT_MAX_BYTES


@dataclass(frozen=True)
class IngestResult:
    status: str
    evidence_id: str
    output_name: str
    files_written: int
    raw_data_included: bool


class ReceiverError(ValueError):
    def __init__(self, error_type: str, status: HTTPStatus) -> None:
        super().__init__(error_type)
        self.error_type = error_type
        self.status = status


def validate_host(host: str) -> None:
    if host != DEFAULT_HOST:
        raise ReceiverError("non_loopback_bind_rejected", HTTPStatus.BAD_REQUEST)


def ingest_montoya_payload(payload: dict[str, Any], config: ReceiverConfig) -> IngestResult:
    _validate_payload_schema(payload)
    policy = load_policy(config.policy_path)
    event = event_from_montoya_handoff(payload)
    redactor = Redactor(policy)
    sanitized = [redactor.sanitize_event(event, 1)]
    findings = build_finding_candidates(sanitized)
    output_dir = config.output_dir / _safe_output_name(str(payload["source_event_id"]))
    written = write_outputs(config.project, output_dir, sanitized, findings, policy)
    verification = verify_path(output_dir, policy)
    if not verification.passed:
        raise ReceiverError("verification_failed", HTTPStatus.INTERNAL_SERVER_ERROR)
    return IngestResult(
        status="accepted",
        evidence_id=sanitized[0].evidence_id,
        output_name=output_dir.name,
        files_written=len(written),
        raw_data_included=False,
    )


def create_server(host: str, port: int, config: ReceiverConfig) -> ThreadingHTTPServer:
    validate_host(host)

    class Handler(_IngestHandler):
        receiver_config = config

    return ThreadingHTTPServer((host, port), Handler)


def _validate_payload_schema(payload: dict[str, Any]) -> None:
    if payload.get("schema_version") != "montoya-handoff-v1":
        raise ReceiverError("invalid_schema", HTTPStatus.BAD_REQUEST)
    if payload.get("source") != "burp_proxy_history":
        raise ReceiverError("invalid_source", HTTPStatus.BAD_REQUEST)
    if payload.get("in_scope") is not True:
        raise ReceiverError("out_of_scope_rejected", HTTPStatus.BAD_REQUEST)
    if payload.get("raw_transport") != "loopback_localhost":
        raise ReceiverError("invalid_transport", HTTPStatus.BAD_REQUEST)
    if payload.get("raw_values_included") is not True:
        raise ReceiverError("invalid_raw_marker", HTTPStatus.BAD_REQUEST)
    if not isinstance(payload.get("source_event_id"), str):
        raise ReceiverError("invalid_source_event_id", HTTPStatus.BAD_REQUEST)
    if not isinstance(payload.get("request"), str) or not payload["request"].strip():
        raise ReceiverError("invalid_request", HTTPStatus.BAD_REQUEST)
    response = payload.get("response")
    if response is not None and not isinstance(response, str):
        raise ReceiverError("invalid_response", HTTPStatus.BAD_REQUEST)


def _safe_output_name(value: str) -> str:
    name = SAFE_OUTPUT_NAME_RE.sub("-", value).strip(".-")
    return name[:80] or "montoya-event"


class _IngestHandler(BaseHTTPRequestHandler):
    receiver_config: ReceiverConfig

    def do_POST(self) -> None:
        try:
            self._handle_post()
        except ReceiverError as error:
            self._write_json(error.status, {"status": "error", "error_type": error.error_type})
        except (json.JSONDecodeError, UnicodeDecodeError):
            self._write_json(HTTPStatus.BAD_REQUEST, {"status": "error", "error_type": "invalid_json"})
        except Exception:
            self._write_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"status": "error", "error_type": "internal_error"})

    def do_GET(self) -> None:
        if self.path == "/health":
            self._write_json(HTTPStatus.OK, {"status": "ok"})
            return
        self._write_json(HTTPStatus.NOT_FOUND, {"status": "error", "error_type": "not_found"})

    def log_message(self, format: str, *args: object) -> None:
        return

    def _handle_post(self) -> None:
        if self.path != INGEST_PATH:
            raise ReceiverError("not_found", HTTPStatus.NOT_FOUND)
        if not _is_loopback_client(self.client_address[0]):
            raise ReceiverError("non_loopback_client_rejected", HTTPStatus.FORBIDDEN)
        content_type = self.headers.get("Content-Type", "")
        if not content_type.lower().startswith("application/json"):
            raise ReceiverError("invalid_content_type", HTTPStatus.UNSUPPORTED_MEDIA_TYPE)
        content_length = self.headers.get("Content-Length")
        if content_length is None or not content_length.isdigit():
            raise ReceiverError("invalid_content_length", HTTPStatus.BAD_REQUEST)
        size = int(content_length)
        if size > self.receiver_config.max_body_bytes:
            raise ReceiverError("payload_too_large", HTTPStatus.REQUEST_ENTITY_TOO_LARGE)
        payload = json.loads(self.rfile.read(size).decode("utf-8"))
        if not isinstance(payload, dict):
            raise ReceiverError("invalid_json_root", HTTPStatus.BAD_REQUEST)
        result = ingest_montoya_payload(payload, self.receiver_config)
        self._write_json(
            HTTPStatus.ACCEPTED,
            {
                "status": result.status,
                "evidence_id": result.evidence_id,
                "output_name": result.output_name,
                "files_written": result.files_written,
                "raw_data_included": result.raw_data_included,
            },
        )

    def _write_json(self, status: HTTPStatus, payload: dict[str, Any]) -> None:
        data = json.dumps(payload, sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def _is_loopback_client(host: str) -> bool:
    return host in {"127.0.0.1", "::1", "localhost"}
