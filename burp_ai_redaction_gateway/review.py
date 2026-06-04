from __future__ import annotations

import json
import shutil
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .policy import RedactionPolicy
from .scanner import assert_no_sensitive_text
from .verifier import verify_path


REVIEW_FILES = {
    "analysis_packet.json",
    "chatgpt_prompt.md",
    "codex_task_prompt.md",
}


@dataclass(frozen=True)
class ReviewResult:
    input_dir: Path
    candidate_count: int
    type_counts: dict[str, int]
    prompt_files: list[str]
    do_not_claim: list[str]
    export_dir: Path | None = None
    exported_files: list[str] | None = None


def build_review(input_dir: Path, policy: RedactionPolicy, export_dir: Path | None = None) -> ReviewResult:
    verification = verify_path(input_dir, policy)
    if not verification.passed:
        raise ValueError("verification_failed")

    contents = _read_review_files(input_dir)
    for content in contents.values():
        assert_no_sensitive_text(content)

    packet = json.loads(contents["analysis_packet.json"])
    if packet.get("raw_data_included") is not False:
        raise ValueError("raw_data_marker_not_false")

    candidates = _candidate_list(packet)
    type_counts = Counter(str(candidate.get("type", "unknown")) for candidate in candidates)
    do_not_claim = sorted(
        {
            str(item)
            for candidate in candidates
            for item in candidate.get("do_not_claim", [])
            if item
        }
    )
    exported_files = _export_review_files(input_dir, export_dir, contents) if export_dir else None
    return ReviewResult(
        input_dir=input_dir,
        candidate_count=len(candidates),
        type_counts=dict(sorted(type_counts.items())),
        prompt_files=sorted(contents),
        do_not_claim=do_not_claim,
        export_dir=export_dir,
        exported_files=exported_files,
    )


def render_review_summary(result: ReviewResult) -> str:
    lines = [
        "Review summary",
        "Verification: passed",
        "Raw data included: false",
        "Input: <verified_output_dir>",
        f"Candidate count: {result.candidate_count}",
        "Candidate types:",
    ]
    if result.type_counts:
        lines.extend(f"- {kind}: {count}" for kind, count in result.type_counts.items())
    else:
        lines.append("- none: 0")

    lines.append("Prompt files:")
    lines.extend(f"- {name}" for name in result.prompt_files)

    lines.append("do_not_claim:")
    if result.do_not_claim:
        lines.extend(f"- {item}" for item in result.do_not_claim)
    else:
        lines.append("- none")

    if result.export_dir:
        lines.append("Export directory: <safe_export_dir>")
        for name in result.exported_files or []:
            lines.append(f"- exported: {name}")
    return "\n".join(lines) + "\n"


def _read_review_files(input_dir: Path) -> dict[str, str]:
    contents: dict[str, str] = {}
    for name in sorted(REVIEW_FILES):
        path = input_dir / name
        if not path.is_file():
            raise ValueError(f"missing_review_file:{name}")
        contents[name] = path.read_text(encoding="utf-8")
    return contents


def _candidate_list(packet: dict[str, Any]) -> list[dict[str, Any]]:
    candidates = packet.get("finding_candidates")
    if not isinstance(candidates, list):
        raise ValueError("invalid_analysis_packet")
    return [candidate for candidate in candidates if isinstance(candidate, dict)]


def _export_review_files(input_dir: Path, export_dir: Path, contents: dict[str, str]) -> list[str]:
    export_dir.mkdir(parents=True, exist_ok=True)
    exported: list[str] = []
    for name, content in sorted(contents.items()):
        assert_no_sensitive_text(content)
        source = input_dir / name
        target = export_dir / name
        shutil.copyfile(source, target)
        exported.append(name)
    return exported
