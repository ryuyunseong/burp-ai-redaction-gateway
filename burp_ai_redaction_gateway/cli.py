from __future__ import annotations

import argparse
import json
from pathlib import Path

from .audit_hmac import (
    DEFAULT_HMAC_ENV_VAR,
    AuditHmacError,
    create_audit_hmac_manifest,
    load_hmac_secret,
    render_audit_hmac_summary,
    render_audit_hmac_verify_summary,
    verify_audit_hmac_manifest,
)
from .audit_retention import AuditRetentionError, apply_audit_retention, render_audit_retention_summary
from .audit_review import render_audit_review_summary, review_audit_path
from .dashboard import (
    DEFAULT_DASHBOARD_HOST,
    DEFAULT_DASHBOARD_PORT,
    DashboardConfig,
    DashboardError,
    create_dashboard_server,
)
from .findings import build_finding_candidates
from .mcp_server import serve_mcp_stdio
from .output import write_outputs
from .parser import load_events
from .policy import load_policy
from .receiver import DEFAULT_HOST, DEFAULT_MAX_BYTES, DEFAULT_PORT, ReceiverConfig, ReceiverError, create_server
from .redaction import Redactor
from .report import DEFAULT_REPORT_PROFILE, REPORT_PROFILE_NAMES, write_report_draft
from .review import build_review, render_review_summary
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

    review_audit = subparsers.add_parser("review-audit", help="Review MCP audit logs without printing raw data.")
    review_audit.add_argument("--input", required=True, type=Path, help="Audit directory or audit JSONL file.")
    review_audit.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="Output format. Defaults to text.",
    )

    audit_retention = subparsers.add_parser(
        "audit-retention",
        help="Write a retained MCP audit JSONL file without modifying the input.",
    )
    audit_retention.add_argument("--input", required=True, type=Path, help="Audit JSONL file to filter.")
    audit_retention.add_argument("--output", required=True, type=Path, help="Retained audit JSONL output path.")
    audit_retention.add_argument("--retention-days", required=True, type=int, help="Number of days to retain.")
    audit_retention.add_argument("--dry-run", action="store_true", help="Print counts without writing the output file.")

    audit_hmac = subparsers.add_parser(
        "audit-hmac",
        help="Write a raw-free HMAC manifest for a reviewed MCP audit JSONL file.",
    )
    audit_hmac.add_argument("--input", required=True, type=Path, help="Reviewed audit JSONL file.")
    audit_hmac.add_argument("--manifest", required=True, type=Path, help="Manifest JSON output path.")
    audit_hmac.add_argument("--key-file", type=Path, help="Local HMAC secret file. Do not commit this file.")
    audit_hmac.add_argument(
        "--env-var",
        default=DEFAULT_HMAC_ENV_VAR,
        help=f"Environment variable containing the HMAC secret. Defaults to {DEFAULT_HMAC_ENV_VAR}.",
    )

    audit_hmac_verify = subparsers.add_parser(
        "audit-hmac-verify",
        help="Verify a raw-free HMAC manifest for a reviewed MCP audit JSONL file.",
    )
    audit_hmac_verify.add_argument("--input", required=True, type=Path, help="Reviewed audit JSONL file.")
    audit_hmac_verify.add_argument("--manifest", required=True, type=Path, help="Manifest JSON path.")
    audit_hmac_verify.add_argument("--key-file", type=Path, help="Local HMAC secret file. Do not commit this file.")
    audit_hmac_verify.add_argument(
        "--env-var",
        default=DEFAULT_HMAC_ENV_VAR,
        help=f"Environment variable containing the HMAC secret. Defaults to {DEFAULT_HMAC_ENV_VAR}.",
    )

    review = subparsers.add_parser("review", help="Review verified analysis packet output without printing raw data.")
    review.add_argument("--input", required=True, type=Path, help="Verified generated output directory.")
    review.add_argument("--export-dir", type=Path, help="Optional directory for safe prompt packet copies.")
    review.add_argument("--policy", type=Path, help="Optional policy.json path.")

    report = subparsers.add_parser("report", help="Generate a cautious report draft from verified analysis packets.")
    report.add_argument("--input", required=True, type=Path, help="Verified generated output directory.")
    report.add_argument("--output", type=Path, help="Report draft path. Defaults to report_draft.md under input.")
    report.add_argument(
        "--profile",
        default=DEFAULT_REPORT_PROFILE,
        choices=REPORT_PROFILE_NAMES,
        help="Report wording profile. Defaults to conservative.",
    )
    report.add_argument("--policy", type=Path, help="Optional policy.json path.")

    mcp = subparsers.add_parser("mcp", help="Run the read-only MCP server over stdio.")
    mcp.add_argument("--root", required=True, type=Path, help="Allowed verified output root.")
    mcp.add_argument("--policy", type=Path, help="Optional policy.json path.")

    dashboard = subparsers.add_parser("dashboard", help="Run the local read-only dashboard for verified output.")
    dashboard.add_argument("--host", default=DEFAULT_DASHBOARD_HOST, help="Bind host. Only 127.0.0.1 is allowed.")
    dashboard.add_argument("--port", default=DEFAULT_DASHBOARD_PORT, type=int, help="Bind port.")
    dashboard.add_argument("--root", required=True, type=Path, help="Verified output root, for example out.")
    dashboard.add_argument("--policy", type=Path, help="Optional policy.json path.")

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
    if args.command == "review-audit":
        return _review_audit(args.input, args.format)
    if args.command == "audit-retention":
        return _audit_retention(args.input, args.output, args.retention_days, args.dry_run)
    if args.command == "audit-hmac":
        return _audit_hmac(args.input, args.manifest, args.env_var, args.key_file)
    if args.command == "audit-hmac-verify":
        return _audit_hmac_verify(args.input, args.manifest, args.env_var, args.key_file)
    if args.command == "review":
        return _review(args.input, args.export_dir, args.policy)
    if args.command == "report":
        return _report(args.input, args.output, args.profile, args.policy)
    if args.command == "mcp":
        return _mcp(args.root, args.policy)
    if args.command == "dashboard":
        return _dashboard(args.host, args.port, args.root, args.policy)
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


def _review_audit(input_path: Path, output_format: str) -> int:
    result = review_audit_path(input_path)
    if output_format == "json":
        print(json.dumps(result.to_json(), ensure_ascii=True, sort_keys=True))
    else:
        print(render_audit_review_summary(result), end="")
    return 0 if result.passed else 1


def _audit_retention(input_path: Path, output_path: Path, retention_days: int, dry_run: bool) -> int:
    try:
        result = apply_audit_retention(input_path, output_path, retention_days=retention_days, dry_run=dry_run)
    except AuditRetentionError as error:
        print(f"Audit retention failed: {error.error_type}")
        return 1
    print(render_audit_retention_summary(result), end="")
    return 0


def _audit_hmac(input_path: Path, manifest_path: Path, env_var: str, key_file: Path | None) -> int:
    try:
        secret = load_hmac_secret(env_var=env_var, key_file=key_file)
        result = create_audit_hmac_manifest(input_path, manifest_path, secret=secret)
    except AuditHmacError as error:
        print(f"Audit HMAC failed: {error.error_type}")
        return 1
    print(render_audit_hmac_summary(result), end="")
    return 0


def _audit_hmac_verify(input_path: Path, manifest_path: Path, env_var: str, key_file: Path | None) -> int:
    try:
        secret = load_hmac_secret(env_var=env_var, key_file=key_file)
        result = verify_audit_hmac_manifest(input_path, manifest_path, secret=secret)
    except AuditHmacError as error:
        print(f"Audit HMAC verification failed: {error.error_type}")
        return 1
    print(render_audit_hmac_verify_summary(result), end="")
    return 0


def _review(input_dir: Path, export_dir: Path | None, policy_path: Path | None) -> int:
    policy = load_policy(policy_path)
    try:
        result = build_review(input_dir, policy, export_dir)
    except ValueError as error:
        print(f"Review failed: {error}")
        return 1
    print(render_review_summary(result), end="")
    return 0


def _report(input_dir: Path, output_path: Path | None, profile: str, policy_path: Path | None) -> int:
    policy = load_policy(policy_path)
    try:
        result = write_report_draft(input_dir, output_path, policy, profile)
    except ValueError as error:
        print(f"Report draft failed: {error}")
        return 1
    print("Report draft written: <report_draft_path>")
    print(f"Profile: {result.profile}")
    print(f"Candidate count: {result.candidate_count}")
    print("Raw data included: false")
    return 0


def _mcp(root: Path, policy_path: Path | None) -> int:
    policy = load_policy(policy_path)
    try:
        serve_mcp_stdio(root, policy)
    except ValueError as error:
        print(f"MCP server failed: {error}")
        return 1
    return 0


def _dashboard(host: str, port: int, root: Path, policy_path: Path | None) -> int:
    try:
        server = create_dashboard_server(host, port, DashboardConfig(root=root, policy_path=policy_path))
        print(f"Dashboard listening on http://{host}:{port}")
        print("Raw HTTP viewing and replay are unavailable. Dashboard actions require CSRF protection.")
    except DashboardError as error:
        print(f"Dashboard startup failed: {error.error_type}")
        return 1
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("Dashboard stopped")
    finally:
        server.server_close()
    return 0


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
