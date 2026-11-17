"""One confirmed, passive review using the locally installed Codex CLI."""
from __future__ import annotations

import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
import threading
from pathlib import Path
from typing import Any

from .ai_review import AiReviewError, CANDIDATE_LABELS, MAX_RESPONSE_BYTES, ReviewDraft, review_schema
from .findings import SECURITY_HEADERS_TO_CHECK
from .report import _report_text


REVIEW_TASK = (
    "제공된 마스킹 자료만 읽고 후보별 근거, 기존 설정에서 확인할 사항, 정상·의심 기준과 권고 조치를 한국어로 정리하세요. "
    "summary에는 '검토 후보'를 넣으세요. manual_checks는 기록이나 설정 검토에만 한정합니다. "
    "도구 사용, 파일 조회, 추가 요청 전송, 공격 재현, 명령 실행은 하지 마세요. 식별자나 원문을 추측하지 마세요. "
    "관찰하지 않은 항목은 미확인입니다. SameSite=None은 누락이 아닙니다. 제공된 VA 분류를 바꾸지 마세요."
)
_OFF = ("shell_tool", "unified_exec", "code_mode", "code_mode_host", "apps", "plugins", "hooks",
        "browser_use", "browser_use_external", "in_app_browser", "computer_use", "image_generation",
        "multi_agent", "multi_agent_v2", "memories", "goals", "remote_control", "workspace_dependencies",
        "skill_mcp_dependency_install", "request_permissions_tool", "tool_suggest")
_OBSERVATIONS = {
    "Identifier parameter observed in path or query.", "Authenticated-looking request returned HTTP 2xx.",
    "Response body shape contains user-specific fields.", "Response schema contains fields that required redaction.",
    "Response indicates a server error or includes a sanitized error snippet.",
    "CORS response allows a wildcard origin or credentialed cross-origin access.",
    "Request appears authenticated and response did not include no-store, no-cache, or private Cache-Control policy.",
}


def candidate_metadata(item: dict[str, Any]) -> dict[str, Any]:
    kind = item["type"] if item["type"] in CANDIDATE_LABELS else "unmapped"
    observations = []
    for line in item["rationale"]:
        if line in _OBSERVATIONS:
            observations.append(_report_text(line))
        elif kind == "weak_cookie_attributes":
            missing = re.fullmatch(r"Set-Cookie for .+ is missing: (.+)\.", line)
            if missing and all(x in {"Secure", "HttpOnly", "SameSite"} for x in missing[1].split(", ")):
                observations.append("쿠키에 없는 속성: " + missing[1])
            elif re.fullmatch(r"Set-Cookie for .+ uses SameSite=None without Secure\.", line):
                observations.append("SameSite=None이지만 Secure가 없습니다.")
        elif kind == "missing_security_headers":
            headers = re.fullmatch(r"Response did not include: (.+)\.", line)
            if headers and set(headers[1].split(", ")) <= SECURITY_HEADERS_TO_CHECK:
                observations.append("응답에 없는 헤더: " + headers[1])
        elif kind == "sensitive_data_exposure_candidate":
            count = re.fullmatch(r"Redacted field count: ([0-9]{1,5})\.", line)
            if count:
                observations.append(f"마스킹한 항목: {count[1]}개")
    return {"finding_id": item["finding_id"], "type": kind, "title": CANDIDATE_LABELS.get(kind, "미분류"),
            "confidence": item["confidence"], "rationale": observations}


def _command() -> str:
    # Do not launch scripts or search the working directory for a program.
    name = "codex.exe" if os.name == "nt" else "codex"
    for entry in os.get_exec_path():
        path = Path(entry)
        if not path.is_absolute() or path.resolve().is_relative_to(Path.cwd().resolve()):
            continue
        executable = shutil.which(str(path / name))
        if executable and Path(executable).is_file():
            return executable
    raise AiReviewError("codex_not_available")


def _run(args: list[str], cwd: Path, env: dict[str, str], data: bytes, *, status: bool = False) -> bytes:
    try:
        with subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, cwd=cwd, env=env,
                              stderr=subprocess.STDOUT if status else subprocess.DEVNULL,
                              creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0)) as process:
            expired = threading.Event()

            def stop() -> None:
                expired.set()
                process.kill()

            timer = threading.Timer(10 if status else 120, stop)
            timer.start()
            try:
                try:
                    process.stdin.write(data)
                    process.stdin.close()
                except BrokenPipeError:
                    pass
                result = process.stdout.read(MAX_RESPONSE_BYTES + 1)
                if len(result) > MAX_RESPONSE_BYTES:
                    process.kill()
                    raise AiReviewError("ai_response_too_large")
                process.wait()
            finally:
                timer.cancel()
                timer.join()
            if expired.is_set():
                raise AiReviewError("codex_timeout")
            if process.returncode:
                raise AiReviewError("codex_login_required" if status else "codex_request_failed")
            return result
    except OSError:
        raise AiReviewError("codex_not_available") from None


def _answer(events: bytes) -> str:
    messages = []
    complete = False
    try:
        for line in events.decode("utf-8").splitlines():
            event = json.loads(line)
            kind = event["type"]
            if complete:
                raise ValueError()
            if kind == "turn.completed":
                complete = True
            elif kind == "item.completed" and event["item"]["type"] == "agent_message":
                messages.append(event["item"]["text"])
            elif kind not in ("thread.started", "turn.started"):
                raise ValueError()
        if not complete or len(messages) != 1 or not isinstance(messages[0], str):
            raise ValueError()
        return messages[0]
    except (KeyError, ValueError, TypeError, RecursionError):
        raise AiReviewError("invalid_ai_response") from None


def _review_home() -> Path:
    # Codex reads home-level AGENTS files even with --ignore-user-config.
    home = Path.home() / ".burp-review-codex"
    try:
        attributes = home.lstat()
        if not stat.S_ISDIR(attributes.st_mode) or getattr(attributes, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT:
            raise AiReviewError("codex_home_not_isolated")
        for name in ("AGENTS.md", "AGENTS.override.md"):
            try:
                (home / name).lstat()
            except FileNotFoundError:
                continue
            raise AiReviewError("codex_home_not_isolated")
    except FileNotFoundError:
        raise AiReviewError("codex_login_required") from None
    except OSError:
        raise AiReviewError("codex_home_not_isolated") from None
    return home


def request_review(draft: ReviewDraft) -> dict[str, Any]:
    executable = _command()
    env = {key: os.environ[key] for key in ("HOME", "USERPROFILE", "LOCALAPPDATA", "APPDATA", "SYSTEMROOT",
                                           "PATH", "TEMP", "TMP") if key in os.environ}
    env["CODEX_HOME"] = str(_review_home())
    with tempfile.TemporaryDirectory(prefix="masked-review-") as tmp:
        cwd = Path(tmp)
        if _run([executable, "login", "status"], cwd, env, b"", status=True).strip() != b"Logged in using ChatGPT":
            raise AiReviewError("codex_login_required")
        schema = cwd / "response-schema.json"
        schema.write_text(json.dumps(review_schema(draft)), encoding="utf-8")
        args = [executable, "exec", "--ignore-user-config", "--ignore-rules", "--ephemeral", "--strict-config",
                "--skip-git-repo-check", "--json", "--output-schema", str(schema)]
        for feature in _OFF:
            args.extend(("--disable", feature))
        for setting in ('forced_login_method="chatgpt"', 'model_provider="openai"', 'approval_policy="never"',
                        'default_permissions="review"', 'permissions.review.filesystem={ ":root" = "deny" }',
                        'web_search="disabled"', 'mcp_servers={}', 'history.persistence="none"',
                        'project_doc_max_bytes=0', 'skills.include_instructions=false',
                        'include_environment_context=false', 'include_apps_instructions=false', 'include_permissions_instructions=false',
                        'model_reasoning_effort="low"', 'analytics.enabled=false',
                        'log_dir=' + json.dumps(tmp), 'sqlite_home=' + json.dumps(tmp)):
            args.extend(("-c", setting))
        _review_home()
        raw = _run([*args, "-"], cwd, env, draft.input_json.encode("utf-8"))
    return {"status": "completed", "output": [{"type": "message", "role": "assistant",
            "content": [{"type": "output_text", "text": _answer(raw)}]}]}
