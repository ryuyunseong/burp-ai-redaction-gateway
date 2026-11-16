from __future__ import annotations

import argparse
import json
import sys
import webbrowser
from pathlib import Path

from . import ai_review
from .audit_compressed_hmac import (
    AuditCompressedHmacError,
    create_compressed_audit_hmac_manifest,
    render_compressed_audit_hmac_summary,
    render_compressed_audit_hmac_verify_summary,
    verify_compressed_audit_hmac_manifest,
)
from .audit_compression import (
    AuditCompressionError,
    compress_audit_jsonl,
    render_audit_compression_summary,
    render_audit_compression_verify_summary,
    verify_compressed_audit_jsonl,
)
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
from .risk import DEFAULT_RISK_RATING_PROFILE, RISK_RATING_PROFILE_NAMES
from .verifier import verify_path
from .viewer import RedactedStaticViewerError, render_static_viewer_summary, write_static_viewer_html
from .workflow import WorkflowError, process_export


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="burp-ai-redaction-gateway")
    subparsers = parser.add_subparsers(dest="command", required=True)

    process = subparsers.add_parser("process", help="민감정보 제거, 검증, 보고서와 AI 전달 후보 4개를 한 번에 생성합니다.")
    process.add_argument("--input", required=True, type=Path, help="Burp XML, HAR 또는 JSON 파일.")
    process.add_argument("--output", required=True, type=Path, help="새 결과 폴더. 기존 폴더는 덮어쓰지 않습니다.")
    process.add_argument("--project", required=True, help="실제 고객명 대신 사용할 영문 별칭.")
    process.add_argument("--policy", type=Path, help="선택할 policy.json 경로.")

    generate = subparsers.add_parser("generate", help="Generate sanitized prompt packet output.")
    generate.add_argument("--input", required=True, type=Path, help="Burp export, HAR, or fixture JSON path.")
    generate.add_argument("--output", required=True, type=Path, help="Output directory.")
    generate.add_argument("--project", required=True, help="Project alias. Do not use a real customer name.")
    generate.add_argument("--policy", type=Path, help="Optional policy.json path.")
    generate.add_argument(
        "--risk-profile",
        default=DEFAULT_RISK_RATING_PROFILE,
        choices=RISK_RATING_PROFILE_NAMES,
        help="Draft risk rating profile. Defaults to conservative.",
    )

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

    audit_compress = subparsers.add_parser(
        "audit-compress",
        help="Write a gzip package for a reviewed MCP audit JSONL file.",
    )
    audit_compress.add_argument("--input", required=True, type=Path, help="Reviewed audit JSONL file.")
    audit_compress.add_argument("--output", required=True, type=Path, help="Compressed .jsonl.gz output path.")

    audit_compress_verify = subparsers.add_parser(
        "audit-compress-verify",
        help="Verify a gzip-packaged MCP audit JSONL file without printing raw data.",
    )
    audit_compress_verify.add_argument("--input", required=True, type=Path, help="Compressed .jsonl.gz audit file.")

    audit_compressed_hmac = subparsers.add_parser(
        "audit-compressed-hmac",
        help="Write a raw-free HMAC manifest for a verified compressed audit archive.",
    )
    audit_compressed_hmac.add_argument("--input", required=True, type=Path, help="Compressed .jsonl.gz audit file.")
    audit_compressed_hmac.add_argument("--manifest", required=True, type=Path, help="Manifest JSON output path.")
    audit_compressed_hmac.add_argument("--key-file", type=Path, help="Local HMAC secret file. Do not commit this file.")
    audit_compressed_hmac.add_argument(
        "--env-var",
        default=DEFAULT_HMAC_ENV_VAR,
        help=f"Environment variable containing the HMAC secret. Defaults to {DEFAULT_HMAC_ENV_VAR}.",
    )

    audit_compressed_hmac_verify = subparsers.add_parser(
        "audit-compressed-hmac-verify",
        help="Verify a raw-free HMAC manifest for a compressed audit archive.",
    )
    audit_compressed_hmac_verify.add_argument("--input", required=True, type=Path, help="Compressed .jsonl.gz audit file.")
    audit_compressed_hmac_verify.add_argument("--manifest", required=True, type=Path, help="Manifest JSON path.")
    audit_compressed_hmac_verify.add_argument(
        "--key-file",
        type=Path,
        help="Local HMAC secret file. Do not commit this file.",
    )
    audit_compressed_hmac_verify.add_argument(
        "--env-var",
        default=DEFAULT_HMAC_ENV_VAR,
        help=f"Environment variable containing the HMAC secret. Defaults to {DEFAULT_HMAC_ENV_VAR}.",
    )

    review = subparsers.add_parser("review", help="Review verified analysis packet output without printing raw data.")
    review.add_argument("--input", required=True, type=Path, help="Verified generated output directory.")
    review.add_argument("--export-dir", type=Path, help="Optional directory for safe prompt packet copies.")
    review.add_argument("--policy", type=Path, help="Optional policy.json path.")

    ai = subparsers.add_parser("ai-review", help="마스킹된 점검 후보를 미리 보고, 동의 후 AI 점검 가이드를 받습니다.")
    ai.add_argument("--input", required=True, type=Path, help="검증된 결과 폴더.")
    ai.add_argument("--candidate", action="append", default=[], help="후보 번호. 최대 5개까지 반복 지정합니다.")
    ai.add_argument("--model", default=ai_review.MODEL, help="gpt-6-luna(기본). 필요하면 gpt-6.1-terra를 지정합니다.")
    ai.add_argument("--send", action="store_true", help="전체 전송 내용을 표시하고 터미널에서 동의를 받습니다.")
    ai.add_argument("--policy", type=Path, help="선택할 policy.json 경로.")

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

    viewer = subparsers.add_parser("viewer", help="Generate a static local HTML viewer for a redacted artifact.")
    viewer.add_argument("--input", required=True, type=Path, help="Redacted viewer JSON artifact.")
    viewer.add_argument("--output", required=True, type=Path, help="Static HTML output path.")

    mcp = subparsers.add_parser("mcp", help="Run the read-only MCP server over stdio.")
    mcp.add_argument("--root", required=True, type=Path, help="Allowed verified output root.")
    mcp.add_argument("--policy", type=Path, help="Optional policy.json path.")

    dashboard = subparsers.add_parser("dashboard", help="Run the local read-only dashboard for verified output.")
    dashboard.add_argument("--host", default=DEFAULT_DASHBOARD_HOST, help="Bind host. Only 127.0.0.1 is allowed.")
    dashboard.add_argument("--port", default=DEFAULT_DASHBOARD_PORT, type=int, help="Bind port.")
    dashboard.add_argument("--root", required=True, type=Path, help="Verified output root, for example out.")
    dashboard.add_argument("--policy", type=Path, help="Optional policy.json path.")
    dashboard.add_argument("--open", action="store_true", help="서버가 열린 뒤 브라우저를 자동으로 엽니다.")

    serve = subparsers.add_parser("serve", help="Run the loopback-only Montoya handoff receiver.")
    serve.add_argument("--host", default=DEFAULT_HOST, help="Bind host. Only 127.0.0.1 is allowed.")
    serve.add_argument("--port", default=DEFAULT_PORT, type=int, help="Bind port.")
    serve.add_argument("--output", default=Path("out") / "receiver", type=Path, help="Sanitized output root.")
    serve.add_argument("--project", default="montoya_receiver_alias", help="Project alias. Do not use a real name.")
    serve.add_argument("--policy", type=Path, help="Optional policy.json path.")
    serve.add_argument("--max-bytes", default=DEFAULT_MAX_BYTES, type=int, help="Maximum accepted JSON payload bytes.")

    args = parser.parse_args(argv)
    if args.command == "process":
        return _process(args.input, args.output, args.project, args.policy)
    if args.command == "generate":
        return _generate(args.input, args.output, args.project, args.policy, args.risk_profile)
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
    if args.command == "audit-compress":
        return _audit_compress(args.input, args.output)
    if args.command == "audit-compress-verify":
        return _audit_compress_verify(args.input)
    if args.command == "audit-compressed-hmac":
        return _audit_compressed_hmac(args.input, args.manifest, args.env_var, args.key_file)
    if args.command == "audit-compressed-hmac-verify":
        return _audit_compressed_hmac_verify(args.input, args.manifest, args.env_var, args.key_file)
    if args.command == "review":
        return _review(args.input, args.export_dir, args.policy)
    if args.command == "ai-review":
        return _ai_review_command(args.input, args.candidate, args.model, args.send, args.policy)
    if args.command == "report":
        return _report(args.input, args.output, args.profile, args.policy)
    if args.command == "viewer":
        return _viewer(args.input, args.output)
    if args.command == "mcp":
        return _mcp(args.root, args.policy)
    if args.command == "dashboard":
        return _dashboard(args.host, args.port, args.root, args.policy, open_browser=args.open)
    if args.command == "serve":
        return _serve(args.host, args.port, args.output, args.project, args.policy, args.max_bytes)
    parser.error("Unknown command")
    return 2


def _process(input_path: Path, output_dir: Path, project: str, policy_path: Path | None) -> int:
    try:
        policy = load_policy(policy_path)
        result = process_export(input_path, output_dir, project, policy)
    except (OSError, ValueError, TypeError, AttributeError) as error:
        reason = error.error_type if isinstance(error, WorkflowError) else "invalid_policy"
        print(f"처리를 완료하지 못했습니다: {reason}")
        print("새 결과 폴더와 입력 형식을 확인하세요. 실패한 결과는 AI에 전달하지 마세요.")
        return 1
    print("민감정보 제거, 검증, 검토 및 보고서 초안 생성 완료")
    print(f"처리한 요청: {result.event_count}개 / 수동 검토할 후보: {result.candidate_count}개")
    print("AI 전달 후보: 결과 폴더의 ai_candidates 아래 파일 4개")
    for name in result.exported_files:
        print(f"- {name}")
    print("자동 전송하지 않습니다. 파일 내용을 직접 확인한 뒤 사용하세요.")
    return 0


def _generate(
    input_path: Path,
    output_dir: Path,
    project: str,
    policy_path: Path | None,
    risk_profile: str,
) -> int:
    policy = load_policy(policy_path)
    raw_events = load_events(input_path)
    redactor = Redactor(policy)
    sanitized = [redactor.sanitize_event(event, index) for index, event in enumerate(raw_events, start=1)]
    findings = build_finding_candidates(sanitized, risk_profile)
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


def _audit_compress(input_path: Path, output_path: Path) -> int:
    try:
        result = compress_audit_jsonl(input_path, output_path)
    except AuditCompressionError as error:
        print(f"Audit compression failed: {error.error_type}")
        return 1
    print(render_audit_compression_summary(result), end="")
    return 0


def _audit_compress_verify(input_path: Path) -> int:
    try:
        result = verify_compressed_audit_jsonl(input_path)
    except AuditCompressionError as error:
        print(f"Audit compression verification failed: {error.error_type}")
        return 1
    print(render_audit_compression_verify_summary(result), end="")
    return 0


def _audit_compressed_hmac(input_path: Path, manifest_path: Path, env_var: str, key_file: Path | None) -> int:
    try:
        secret = load_hmac_secret(env_var=env_var, key_file=key_file)
        result = create_compressed_audit_hmac_manifest(input_path, manifest_path, secret=secret)
    except (AuditCompressedHmacError, AuditHmacError) as error:
        print(f"Compressed audit HMAC failed: {error.error_type}")
        return 1
    print(render_compressed_audit_hmac_summary(result), end="")
    return 0


def _audit_compressed_hmac_verify(input_path: Path, manifest_path: Path, env_var: str, key_file: Path | None) -> int:
    try:
        secret = load_hmac_secret(env_var=env_var, key_file=key_file)
        result = verify_compressed_audit_hmac_manifest(input_path, manifest_path, secret=secret)
    except (AuditCompressedHmacError, AuditHmacError) as error:
        print(f"Compressed audit HMAC verification failed: {error.error_type}")
        return 1
    print(render_compressed_audit_hmac_verify_summary(result), end="")
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


def _ai_review_command(input_dir: Path, candidate_ids: list[str], model: str, send: bool, policy_path: Path | None) -> int:
    try:
        policy = load_policy(policy_path)
        if model not in ai_review.MODELS:
            raise ai_review.AiReviewError("unsupported_ai_model")
        verification = verify_path(input_dir, policy)
        if not verification.passed or verification.files_checked == 0:
            raise ai_review.AiReviewError("verification_failed")
        if not candidate_ids:
            if send:
                raise ai_review.AiReviewError("select_one_to_five_candidates")
            candidates = ai_review.list_review_candidates(input_dir)
            print(f"점검 후보 {len(candidates)}개 · 외부 전송 없음")
            for candidate in candidates:
                label = ai_review.CANDIDATE_LABELS.get(candidate["type"], "점검 항목")
                print(ai_review.terminal_text(f"{candidate['finding_id']} · {label} · {candidate['affected_endpoint']}"))
            return 0
        session = ai_review.ReviewSession()
        token, draft = session.prepare("cli_review", input_dir, candidate_ids, model=model)
        print(f"모델: {draft.model}\n실제로 전송할 자료 전체:")
        if ai_review.terminal_text(draft.input_json) != draft.input_json:
            raise ai_review.AiReviewError("invalid_analysis_packet")
        print(draft.input_json)
        if not send:
            print("외부로 전송하지 않았습니다. 요청하려면 같은 명령에 --send를 추가하세요.")
            return 0
        if not sys.stdin.isatty():
            print("직접 연 터미널에서 실행하고 전송 내용을 확인해야 합니다. 전송하지 않았습니다.")
            return 1
        print("OpenAI로 전송하면 API 요금이 발생할 수 있습니다. 응답 저장은 꺼도 제공자의 보안 점검용 보관까지 없애지는 않습니다.")
        if input("외부 전송에 동의하면 SEND를 입력하세요: ").strip() != "SEND":
            print("전송을 취소했습니다.")
            return 0
        if not verify_path(input_dir, policy).passed:
            raise ai_review.AiReviewError("verification_failed")
        result_id = session.send(token, input_dir, True)
        _, result = session.result(result_id)
        print(ai_review.render_text_review(result), end="")
        return 0
    except ai_review.AiReviewError as error:
        print(f"AI 검토를 중단했습니다. 후보·모델·검증 상태·API 연결을 확인하세요. 안내 코드: {error.code}")
        return 1
    except (EOFError, KeyboardInterrupt):
        print("\n사용자가 확인을 중단했습니다. 자동으로 재전송하지 않습니다.")
        return 1
    except (OSError, ValueError):
        print("분석 자료나 설정을 읽지 못했습니다. 파일 위치와 검증 상태를 확인하세요.")
        return 1


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


def _viewer(input_path: Path, output_path: Path) -> int:
    try:
        result = write_static_viewer_html(input_path, output_path)
    except RedactedStaticViewerError as error:
        print(f"Static viewer failed: {error.error_type}")
        return 1
    print(render_static_viewer_summary(result), end="")
    return 0


def _mcp(root: Path, policy_path: Path | None) -> int:
    policy = load_policy(policy_path)
    try:
        serve_mcp_stdio(root, policy)
    except ValueError as error:
        print(f"MCP server failed: {error}")
        return 1
    return 0


def _dashboard(host: str, port: int, root: Path, policy_path: Path | None, *, open_browser: bool = False) -> int:
    try:
        server = create_dashboard_server(host, port, DashboardConfig(root=root, policy_path=policy_path))
        url = f"http://{host}:{server.server_address[1]}/"
        print(f"대시보드: {url}")
        print("원본 HTTP 조회·재전송은 지원하지 않습니다. 상태 변경 요청은 CSRF 검사를 거칩니다.")
    except DashboardError as error:
        print(f"Dashboard startup failed: {error.error_type}")
        if error.error_type == "port_unavailable":
            print("포트를 열 수 없습니다. 이미 사용 중이라면 --port에 다른 번호를 지정하세요.")
        return 1
    try:
        if open_browser:
            try:
                if not webbrowser.open(url, new=2):
                    print("브라우저를 열지 못했습니다. 위 주소를 직접 여세요.")
            except (OSError, webbrowser.Error):
                print("브라우저를 열지 못했습니다. 위 주소를 직접 여세요.")
        server.serve_forever()
    except KeyboardInterrupt:
        print("대시보드를 종료했습니다.")
    finally:
        server.server_close()
    return 0


def _serve(host: str, port: int, output_dir: Path, project: str, policy_path: Path | None, max_bytes: int) -> int:
    try:
        config = ReceiverConfig(output_dir=output_dir, project=project, policy_path=policy_path, max_body_bytes=max_bytes)
        server = create_server(host, port, config)
    except ReceiverError as error:
        print(f"Receiver startup failed: {error.error_type}")
        if error.error_type == "port_unavailable":
            print("포트를 열 수 없습니다. 이미 사용 중이라면 --port와 Burp 수집기의 전송 포트를 함께 바꾸세요.")
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
