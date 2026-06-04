from __future__ import annotations

import argparse
from pathlib import Path

from .findings import build_finding_candidates
from .output import write_outputs
from .parser import load_events
from .policy import load_policy
from .receiver import DEFAULT_HOST, DEFAULT_MAX_BYTES, DEFAULT_PORT, ReceiverConfig, ReceiverError, create_server
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

    serve = subparsers.add_parser("serve", help="Run the loopback-only Montoya handoff receiver.")
    serve.add_argument("--host", default=DEFAULT_HOST, help="Bind host. Only 127.0.0.1 is allowed.")
    serve.add_argument("--port", default=DEFAULT_PORT, type=int, help="Bind port.")
    serve.add_argument("--output", default=Path("out") / "receiver", type=Path, help="Sanitized output root.")
    serve.add_argument("--project", default="montoya_receiver_alias", help="Project alias. Do not use a real name.")
    serve.add_argument("--policy", type=Path, help="Optional policy.json path.")
    serve.add_argument("--max-bytes", default=DEFAULT_MAX_BYTES, type=int, help="Maximum accepted JSON payload bytes.")

    args = parser.parse_args(argv)
    if args.command == "generate":
        return _generate(args.input, args.output, args.project, args.policy)
    if args.command == "verify":
        return _verify(args.input, args.policy)
    if args.command == "serve":
        return _serve(args.host, args.port, args.output, args.project, args.policy, args.max_bytes)
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
        print(f"- {finding.path}: {finding.match.kind}: <REDACTED>")
    if len(result.findings) > 20:
        print(f"- ... {len(result.findings) - 20} additional findings omitted")
    return 1


def _serve(host: str, port: int, output_dir: Path, project: str, policy_path: Path | None, max_bytes: int) -> int:
    try:
        config = ReceiverConfig(output_dir=output_dir, project=project, policy_path=policy_path, max_body_bytes=max_bytes)
        server = create_server(host, port, config)
    except ReceiverError as error:
        print(f"Receiver startup failed: {error.error_type}")
        return 1

    print(f"Receiver listening on {host}:{port}")
    print("Raw HTTP is accepted only over loopback and is not logged.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("Receiver stopped")
    finally:
        server.server_close()
    return 0
