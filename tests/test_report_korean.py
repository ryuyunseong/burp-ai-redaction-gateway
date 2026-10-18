from __future__ import annotations

import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from copy import deepcopy
from pathlib import Path
from unittest.mock import patch

from burp_ai_redaction_gateway.cli import main
from burp_ai_redaction_gateway.policy import load_policy
from burp_ai_redaction_gateway.report import _report_text, render_report_draft, write_report_draft
from burp_ai_redaction_gateway.risk import RULE_RISK_BASELINES, build_risk_rating_draft
from burp_ai_redaction_gateway.scanner import assert_no_sensitive_text


SAMPLE = Path(__file__).resolve().parents[1] / "samples" / "synthetic_burp_history.json"


class KoreanReportTests(unittest.TestCase):
    def _generate(self, root: Path) -> list[dict]:
        with redirect_stdout(io.StringIO()):
            self.assertEqual(main([
                "generate", "--input", str(SAMPLE), "--output", str(root), "--project", "demo_check",
            ]), 0)
        packet = json.loads((root / "analysis_packet.json").read_text(encoding="utf-8"))
        return packet["finding_candidates"]

    def test_report_translates_generated_candidates_without_changing_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "result"
            candidates = self._generate(root)
            before = deepcopy(candidates)
            packet_before = (root / "analysis_packet.json").read_bytes()
            self.assertEqual({item["type"] for item in candidates}, set(RULE_RISK_BASELINES))
            for profile in ("conservative", "consultant"):
                with self.subTest(profile=profile):
                    result = write_report_draft(root, None, load_policy(), profile)
                    report = result.output_path.read_text(encoding="utf-8")
                    self.assertEqual(result.profile, profile)
                    self.assertEqual(result.candidate_count, len(candidates))
                    self.assertIn("취약점 확정 보고서가 아닙니다", report)
                    self.assertIn("근거 신뢰도와는 다릅니다", report)
                    self.assertIn("위험도 확정: 아니요", report)
                    self.assertIn("확인 전 단정하면 안 되는 내용", report)
                    for candidate in candidates:
                        self.assertIn(candidate["finding_id"], report)
                        self.assertIn(candidate["affected_endpoint"], report)
                        for evidence_id in candidate["evidence_ids"]:
                            self.assertIn(evidence_id, report)
                        text_values = [candidate["title"], candidate["type"]]
                        for field in ("rationale", "confidence_rationale", "recommended_manual_tests", "do_not_claim"):
                            text_values.extend(candidate[field])
                        text_values.extend(candidate["risk_rating_draft"]["severity_basis"])
                        for text in text_values:
                            self.assertNotIn(text, report, text)
                    assert_no_sensitive_text(report)
            self.assertEqual(candidates, before)
            self.assertEqual((root / "analysis_packet.json").read_bytes(), packet_before)

    def test_report_translates_variable_observations_without_losing_values(self) -> None:
        examples = {
            "Response did not include: Secure-Header.": "응답에 없는 보안 헤더: Secure-Header",
            "Set-Cookie for demo_cookie is missing: Secure, HttpOnly.": "쿠키 demo_cookie에 없는 보호 속성: Secure, HttpOnly",
            "Set-Cookie for low is missing: Secure.": "쿠키 low에 없는 보호 속성: Secure",
            "Response did not include: high.": "응답에 없는 보안 헤더: high",
            "Redacted field count: 12.": "민감정보 제거 대상 항목 수: 12개",
        }
        for source, expected in examples.items():
            self.assertEqual(_report_text(source), expected)
        for level, translated in (("low", "낮음"), ("medium", "보통"), ("high", "높음")):
            self.assertEqual(
                _report_text(f"Confidence remains {level} until cookie purpose is manually confirmed."),
                f"쿠키 용도를 직접 확인하기 전의 근거 신뢰도: {translated}",
            )
        for label in (
            "Credentialed CORS marker observed", "User-specific response signal observed",
            "Authenticated or user-specific context observed", "Session-like cookie name signal observed",
            "Missing high-impact attributes observed",
        ):
            for value, translated in (("True", "있음"), ("False", "없음")):
                self.assertTrue(_report_text(f"{label}: {value}.").endswith(f": {translated}"))

    def test_report_translates_all_risk_profiles_without_changing_ratings(self) -> None:
        for profile in ("conservative", "consultant", "strict"):
            rating = build_risk_rating_draft("idor_candidate", "medium", profile)
            before = deepcopy(rating)
            report = render_report_draft([{"risk_rating_draft": rating}])
            for basis in rating["severity_basis"]:
                self.assertNotIn(basis, report)
            self.assertIn("근거 신뢰도를 심각도로 사용: 아니요", report)
            self.assertIn("위험도 확정: 아니요", report)
            self.assertEqual(rating, before)

    def test_report_handles_empty_and_unknown_candidates_without_claiming_safety(self) -> None:
        for profile in ("conservative", "consultant"):
            empty = render_report_draft([], profile)
            self.assertIn("검토 후보 없음", empty)
            self.assertIn("취약점이 없다는 뜻은 아닙니다", empty)
            report = render_report_draft([{
                "title": "Custom observation",
                "rationale": ["Unrecognized evidence stays intact.", "직접 기록한 점검 근거"],
            }], profile)
            for text in ("Custom observation", "Unrecognized evidence stays intact.", "직접 기록한 점검 근거"):
                self.assertIn(text, report)
            self.assertIn("실제 영향은 직접 확인해야 합니다", report)
            assert_no_sensitive_text(report)
        with self.assertRaisesRegex(ValueError, "invalid_report_profile"):
            render_report_draft([], "unsupported")

    def test_report_blocks_sensitive_packet_before_translation_or_write(self) -> None:
        probes = [
            "Cookie: demo_cookie=demo_value",
            "raw_" + "request",
            "Response did not include: service.internal.",
        ]
        for probe in probes:
            with self.subTest(probe_class=probes.index(probe)), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary) / "result"
                self._generate(root)
                packet_path = root / "analysis_packet.json"
                packet = json.loads(packet_path.read_text(encoding="utf-8"))
                packet["finding_candidates"][0]["rationale"] = [probe]
                packet_path.write_text(json.dumps(packet, ensure_ascii=False), encoding="utf-8")
                target = Path(temporary) / "report_draft.md"
                with self.assertRaisesRegex(ValueError, "verification_failed"):
                    write_report_draft(root, target, load_policy())
                self.assertFalse(target.exists())

    def test_report_scans_rendered_text_before_writing_and_preserves_existing_file(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "result"
            self._generate(root)
            target = Path(temporary) / "report_draft.md"
            target.write_text("기존 초안", encoding="utf-8")
            with patch("burp_ai_redaction_gateway.report.render_report_draft", return_value="Cookie: demo_cookie=demo_value"):
                with self.assertRaisesRegex(ValueError, "fail-closed"):
                    write_report_draft(root, target, load_policy())
            self.assertEqual(target.read_text(encoding="utf-8"), "기존 초안")

    def test_report_still_rejects_raw_data_marker(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "result"
            self._generate(root)
            packet_path = root / "analysis_packet.json"
            packet = json.loads(packet_path.read_text(encoding="utf-8"))
            packet["raw_data_included"] = True
            packet_path.write_text(json.dumps(packet), encoding="utf-8")
            with self.assertRaises(ValueError):
                write_report_draft(root, None, load_policy())
            self.assertFalse((root / "report_draft.md").exists())
