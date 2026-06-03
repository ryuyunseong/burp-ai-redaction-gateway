from __future__ import annotations

import argparse
from pathlib import Path

from .findings import build_finding_candidates
from .output import write_outputs
from .parser import load_events
from .policy import load_policy
from .redaction import Redactor
from .verifier import verify_path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="burp-ai-redaction-gateway")
    subparsers = parser.add_subparsers(dest="command", required=True)

    generate = subparsers.add_parser("generate", help="Generate sanitized prompt packet output.")
    generate.add_argument("--input", required=True, type=Path, help="Burp export, HAR, or fixture JSON path.")
    generate.add_argument("--output", required=True, type=Path, help="Output directory.")
    generate.add_argument("--project", required=True, help="Project alias. Do not use a real customer name.")
    generate.add_argument("--policy", type=Path, help="Optional policy.json path.")

    verify = subparsers.add_parser("verify", help="Verify generated output files for remaining sensitive values.")
    verify.add_argument("--input", required=True, type=Path, help="Output file or directory to scan.")
    verify.add_argument("--policy", type=Path, help="Optional policy.json path.")

    args = parser.parse_args(argv)
    if args.command == "generate":
        return _generate(args.input, args.output, args.project, args.policy)
    if args.command == "verify":
        return _verify(args.input, args.policy)
    parser.error("Unknown command")
    return 2


def _generate(input_path: Path, output_dir: Path, project: str, policy_path: Path | None) -> int:
    policy = load_policy(policy_path)
    raw_events = load_events(input_path)
    redactor = Redactor(policy)
    sanitized = [redactor.sanitize_event(event, index) for index, event in enumerate(raw_events, start=1)]
    findings = build_finding_candidates(sanitized)
    written = write_outputs(project, output_dir, sanitized, findings, policy)
    print(f"Generated {len(written)} files in {output_dir}")
    for name in sorted(written):
        print(f"- {name}")
    return 0


def _verify(input_path: Path, policy_path: Path | None) -> int:
    policy = load_policy(policy_path)
    result = verify_path(input_path, policy)
    if result.passed:
        print(f"Verification passed: {result.files_checked} files checked")
        return 0

    print(f"Verification failed: {len(result.findings)} findings in {result.files_checked} files")
    for finding in result.findings[:20]:
        print(f"- {finding.path}: {finding.match.kind}: {finding.match.excerpt}")
    if len(result.findings) > 20:
        print(f"- ... {len(result.findings) - 20} additional findings omitted")
    return 1
