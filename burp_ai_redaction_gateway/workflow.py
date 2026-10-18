from __future__ import annotations

import re
import tempfile
from dataclasses import dataclass
from pathlib import Path

from .findings import build_finding_candidates
from .output import write_outputs
from .parser import load_events
from .policy import RedactionPolicy
from .redaction import Redactor
from .report import DEFAULT_REPORT_PROFILE, write_report_draft
from .review import build_review
from .risk import DEFAULT_RISK_RATING_PROFILE
from .verifier import verify_path
from .viewer import SAFE_FILE_ALLOWLIST


MAX_INPUT_BYTES = 16 * 1024 * 1024


class WorkflowError(ValueError):
    def __init__(self, error_type: str) -> None:
        super().__init__(error_type)
        self.error_type = error_type


@dataclass(frozen=True)
class WorkflowResult:
    event_count: int
    candidate_count: int
    export_dir: Path
    exported_files: tuple[str, ...]


def process_export(
    input_path: Path,
    output_dir: Path,
    project: str,
    policy: RedactionPolicy,
) -> WorkflowResult:
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", project):
        raise WorkflowError("invalid_project_alias")
    if output_dir.exists() or output_dir.is_symlink():
        raise WorkflowError("output_already_exists")
    if input_path.suffix.lower() not in {".xml", ".json", ".har"}:
        raise WorkflowError("unsupported_input_format")
    try:
        if input_path.stat().st_size > MAX_INPUT_BYTES:
            raise WorkflowError("input_too_large")
        events = load_events(input_path)
    except WorkflowError:
        raise
    except (OSError, ValueError, SyntaxError, TypeError, AttributeError, KeyError):
        raise WorkflowError("input_not_readable_or_invalid") from None
    if not events:
        raise WorkflowError("no_http_events")

    try:
        # Reserve a new output directory so a failed run cannot reuse older results.
        output_dir.mkdir(parents=True, exist_ok=False)
        redactor = Redactor(policy)
        sanitized = [redactor.sanitize_event(event, i) for i, event in enumerate(events, start=1)]
        findings = build_finding_candidates(sanitized, DEFAULT_RISK_RATING_PROFILE)
        write_outputs(project, output_dir, sanitized, findings, policy)
        if not verify_path(output_dir, policy).passed:
            raise WorkflowError("verification_failed")
        report = write_report_draft(output_dir, None, policy, DEFAULT_REPORT_PROFILE)
        build_review(output_dir, policy)

        export_dir = output_dir / "ai_candidates"
        # Publish the four files together only after verifying the complete copy.
        with tempfile.TemporaryDirectory(prefix=".candidates-", dir=output_dir) as temporary:
            staged = Path(temporary) / "ai_candidates"
            staged.mkdir()
            for name in SAFE_FILE_ALLOWLIST:
                text = (output_dir / name).read_text(encoding="utf-8")
                (staged / name).write_text(text, encoding="utf-8")
            if not verify_path(staged, policy).passed:
                raise WorkflowError("export_verification_failed")
            staged.rename(export_dir)
    except WorkflowError:
        raise
    except FileExistsError:
        raise WorkflowError("output_already_exists") from None
    except (OSError, ValueError, TypeError, KeyError):
        raise WorkflowError("processing_failed") from None

    return WorkflowResult(len(events), report.candidate_count, export_dir, SAFE_FILE_ALLOWLIST)
