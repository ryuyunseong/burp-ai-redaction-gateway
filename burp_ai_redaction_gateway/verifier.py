from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .policy import RedactionPolicy
from .scanner import SensitiveMatch, scan_text


@dataclass(frozen=True)
class FileFinding:
    path: Path
    match: SensitiveMatch


@dataclass(frozen=True)
class VerificationResult:
    files_checked: int
    findings: list[FileFinding]

    @property
    def passed(self) -> bool:
        return not self.findings

    def to_metadata(self) -> dict[str, object]:
        return {
            "status": "passed" if self.passed else "failed",
            "files_checked": self.files_checked,
            "finding_count": len(self.findings),
        }


def verify_path(path: Path, policy: RedactionPolicy) -> VerificationResult:
    files = _iter_verifiable_files(path, policy.verify_extensions)
    findings: list[FileFinding] = []
    for file_path in files:
        text = file_path.read_text(encoding="utf-8", errors="replace")
        for match in scan_text(_apply_literal_allowlist(text, policy.allowlisted_literals)):
            findings.append(FileFinding(file_path, match))
    return VerificationResult(files_checked=len(files), findings=findings)


def assert_verification_passed(path: Path, policy: RedactionPolicy) -> VerificationResult:
    result = verify_path(path, policy)
    if not result.passed:
        summary = ", ".join(
            f"{finding.path}:{finding.match.kind}:{finding.match.excerpt}" for finding in result.findings[:5]
        )
        raise ValueError(f"Verification failed: {summary}")
    return result


def _iter_verifiable_files(path: Path, extensions: tuple[str, ...]) -> list[Path]:
    if path.is_file():
        return [path] if path.suffix.lower() in extensions else []
    if not path.is_dir():
        raise FileNotFoundError(path)
    return sorted(file_path for file_path in path.rglob("*") if file_path.is_file() and file_path.suffix.lower() in extensions)


def _apply_literal_allowlist(text: str, allowlisted_literals: tuple[str, ...]) -> str:
    result = text
    for literal in allowlisted_literals:
        result = result.replace(literal, "<ALLOWLISTED_LITERAL>")
    return result

