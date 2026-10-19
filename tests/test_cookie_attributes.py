from __future__ import annotations

import unittest
from collections import Counter
from copy import deepcopy
from pathlib import Path

from burp_ai_redaction_gateway.analysis import (
    build_analysis_packet,
    render_chatgpt_analysis_prompt,
    render_codex_analysis_prompt,
)
from burp_ai_redaction_gateway.findings import build_finding_candidates
from burp_ai_redaction_gateway.models import HttpRequest, HttpResponse, RawEvent
from burp_ai_redaction_gateway.parser import load_events
from burp_ai_redaction_gateway.policy import load_policy
from burp_ai_redaction_gateway.redaction import Redactor, _redact_set_cookie
from burp_ai_redaction_gateway.report import render_report_draft
from burp_ai_redaction_gateway.scanner import assert_no_sensitive_text


SAMPLE = Path(__file__).resolve().parents[1] / "samples" / "synthetic_burp_history.json"


class CookieAttributeTests(unittest.TestCase):
    def _findings(self, attributes: str) -> dict:
        event = RawEvent(
            raw_id="cookie_case",
            request=HttpRequest(method="GET", url="https://service.example/profile"),
            response=HttpResponse(status=200, headers={"Set-Cookie": f"sid=synthetic; {attributes}"}),
        )
        sanitized = Redactor(load_policy()).sanitize_event(event, 1)
        return build_finding_candidates([sanitized])

    def test_redaction_keeps_absent_samesite_distinct_from_none(self) -> None:
        for redact in (Redactor(load_policy())._redact_set_cookie, _redact_set_cookie):
            for attributes, expected in (
                ("Secure; HttpOnly", ""),
                ("HttpOnly; SameSite=None", "None"),
                ("Secure; HttpOnly; sAmEsItE=nOnE", "nOnE"),
                ("Secure; HttpOnly; SameSite= None ", "None"),
                ("Secure; HttpOnly; SameSite=Lax", "Lax"),
                ("Secure; HttpOnly; SameSite=Strict", "Strict"),
            ):
                with self.subTest(helper=redact.__qualname__, attributes=attributes):
                    counters = Counter()
                    result = redact(f"sid=synthetic; {attributes}", counters)
                    self.assertEqual(result["security"]["samesite"], expected)
                    self.assertIn(f"samesite {expected or 'missing'}", result["summary"])
                    self.assertEqual(counters["set_cookie_value"], 1)
                    self.assertNotIn("synthetic", str(result))
                    assert_no_sensitive_text(str(result))

    def test_candidates_distinguish_missing_attributes_from_none_without_secure(self) -> None:
        for attributes, missing, none_without_secure in (
            ("Secure; HttpOnly", ["SameSite"], False),
            ("HttpOnly", ["Secure", "SameSite"], False),
            ("SameSite=None", ["Secure", "HttpOnly"], True),
            ("HttpOnly; SameSite=None", ["Secure"], True),
            ("HttpOnly; sAmEsItE=nOnE", ["Secure"], True),
            ("HttpOnly; SameSite= None ", ["Secure"], True),
            ("Secure; SameSite=None", ["HttpOnly"], False),
            ("Secure; HttpOnly; SameSite=None", [], False),
            ("Secure; HttpOnly; SameSite=Lax", [], False),
            ("Secure; HttpOnly; SameSite=Strict", [], False),
        ):
            with self.subTest(attributes=attributes):
                findings = self._findings(attributes)
                cookies = [item for item in findings["finding_candidates"] if item["type"] == "weak_cookie_attributes"]
                if not missing:
                    self.assertEqual(cookies, [])
                    continue
                self.assertEqual(len(cookies), 1)
                expected = [f"Set-Cookie for sid is missing: {', '.join(missing)}."]
                if none_without_secure:
                    expected.append("Set-Cookie for sid uses SameSite=None without Secure.")
                self.assertEqual(cookies[0]["rationale"], expected)
                self.assertTrue(cookies[0]["manual_verification_required"])
                self.assertFalse(cookies[0]["risk_rating_draft"]["risk_rating_finalized"])
                self.assertNotIn("synthetic", str(findings))
                assert_no_sensitive_text(str(findings))

    def test_report_and_prompts_show_both_cases_in_korean_without_mutating_data(self) -> None:
        for attributes, expected, absent in (
            ("Secure; HttpOnly", ["쿠키 sid에 없는 보호 속성: SameSite"], ["SameSite=None"]),
            ("SameSite=None", [
                "쿠키 sid에 없는 보호 속성: Secure, HttpOnly",
                "쿠키 sid는 SameSite=None이지만 Secure가 없습니다",
            ], ["없는 보호 속성: Secure, HttpOnly, SameSite"]),
        ):
            findings = self._findings(attributes)
            packet = build_analysis_packet(findings)
            before = deepcopy(packet)
            reports = [render_report_draft(packet["finding_candidates"], profile) for profile in ("conservative", "consultant")]
            prompts = [renderer(packet) for renderer in (render_chatgpt_analysis_prompt, render_codex_analysis_prompt)]
            for document in reports + prompts:
                with self.subTest(attributes=attributes, title=document.splitlines()[0]):
                    for text in expected:
                        self.assertIn(text, document)
                    for text in absent:
                        self.assertNotIn(text, document)
                    self.assertIn("검토 후보", document)
                    self.assertNotIn("synthetic", document)
                    assert_no_sensitive_text(document)
            self.assertEqual(packet, before)

    def test_sample_preserves_candidate_ids_and_corrects_cookie_reasons(self) -> None:
        redactor = Redactor(load_policy())
        events = [redactor.sanitize_event(event, index) for index, event in enumerate(load_events(SAMPLE), start=1)]
        findings = build_finding_candidates(events)
        self.assertEqual(len(findings["finding_candidates"]), 22)
        cookies = {item["finding_id"]: item["rationale"] for item in findings["finding_candidates"] if item["type"] == "weak_cookie_attributes"}
        self.assertEqual(cookies, {
            "FC-0002": ["Set-Cookie for session is missing: Secure."],
            "FC-0010": [
                "Set-Cookie for sid is missing: Secure, HttpOnly.",
                "Set-Cookie for sid uses SameSite=None without Secure.",
            ],
        })


if __name__ == "__main__":
    unittest.main()
