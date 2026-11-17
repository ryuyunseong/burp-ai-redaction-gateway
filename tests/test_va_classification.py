from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from burp_ai_redaction_gateway import ai_review
from burp_ai_redaction_gateway.analysis import render_chatgpt_analysis_prompt, render_codex_analysis_prompt
from burp_ai_redaction_gateway.dashboard import render_ai_review_result, render_ai_review_selection
from burp_ai_redaction_gateway.policy import load_policy
from burp_ai_redaction_gateway.report import render_report_draft
from burp_ai_redaction_gateway.scanner import assert_no_sensitive_text
from burp_ai_redaction_gateway.va_classification import VA_BY_CODE, VA_CATALOG, catalog_scope, classify_candidate, va_label
from burp_ai_redaction_gateway.workflow import process_export


ROOT = Path(__file__).resolve().parents[1]


class VaClassificationTests(unittest.TestCase):
    def test_catalog_preserves_all_thirty_codes_and_supplied_subcategories(self):
        self.assertEqual([item.code for item in VA_CATALOG], [f"VA-{number:02d}" for number in range(1, 31)])
        self.assertEqual(VA_BY_CODE["VA-05"].subcategories, (
            "불필요한 파일 노출", "서버정보 노출", "Front-End/API 응답 범위 설계 오류", "Config / Secret 정보 노출",
        ))
        self.assertEqual(VA_BY_CODE["VA-06"].subcategories, ("저장형 XSS", "반사형 XSS", "DOM 기반 XSS", "설정 미흡 기반 XSS"))
        self.assertEqual(VA_BY_CODE["VA-16"].subcategories, ("부적절한 중요정보 저장", "세션 쿠키 보안 헤더 설정 미흡", "세션 유효성 관리 미흡"))
        for item in VA_CATALOG:
            self.assertRegex(item.title, "[가-힣]")
            self.assertIsInstance(item.subcategories, tuple)
            assert_no_sensitive_text(item.title + " ".join(item.subcategories))

    def test_passive_candidate_mapping_does_not_confirm_a_vulnerability(self):
        for kind, code, subcategory in (
            ("idor_candidate", "VA-11", "수평/수직 권한 이동"),
            ("weak_cookie_attributes", "VA-16", "세션 쿠키 보안 헤더 설정 미흡"),
            ("error_exposure", "VA-04", "에러정보 노출"),
            ("sensitive_data_exposure_candidate", "VA-05", None),
        ):
            result = classify_candidate(kind)
            self.assertEqual((result["code"], result["subcategory"], result["relation"]), (code, subcategory, "candidate"))
            self.assertIn("검토 후보", va_label(kind))
        self.assertIn("누락과 설정값을 구분", classify_candidate("weak_cookie_attributes")["reason"])

    def test_cors_and_cache_are_references_and_headers_do_not_imply_xss_or_csrf(self):
        for kind in ("cors_candidate", "cache_control_on_authenticated_response"):
            result = classify_candidate(kind)
            self.assertEqual((result["code"], result["relation"], result["subcategory"]), ("VA-05", "reference", None))
            self.assertIn("참고 분류", va_label(kind))
        for kind in ("missing_security_headers", "custom_check", "VA-02", None, []):
            result = classify_candidate(kind)
            self.assertIsNone(result["code"])
            self.assertEqual(result["relation"], "unmapped")

    def test_scope_never_marks_unobserved_categories_as_passed(self):
        scope = catalog_scope(["idor_candidate", "weak_cookie_attributes", "error_exposure", "cors_candidate"])
        self.assertEqual(scope["VA-05"], "reference")
        self.assertEqual(scope["VA-11"], "candidate")
        for code in ("VA-01", "VA-02", "VA-06", "VA-07", "VA-22", "VA-23", "VA-30"):
            self.assertEqual(scope[code], "not_assessed")
        self.assertNotIn("passed", scope.values())
        self.assertTrue(all(value == "not_assessed" for value in catalog_scope([]).values()))
        self.assertEqual(catalog_scope(["sensitive_data_exposure_candidate", "cors_candidate"])["VA-05"], "candidate")

    def test_classification_returns_detached_metadata_and_documented_definitions(self):
        first = classify_candidate("idor_candidate")
        first["code"] = "VA-01"
        self.assertEqual(classify_candidate("idor_candidate")["code"], "VA-11")
        guide = (ROOT / "docs" / "VA_CHECKLIST.md").read_text(encoding="utf-8")
        for item in VA_CATALOG:
            self.assertIn(item.code, guide)
            self.assertIn(item.title, guide)
            for subcategory in item.subcategories:
                self.assertIn(subcategory, guide)
        self.assertNotIn("**", guide)
        self.assertNotRegex(guide, "[\ufeff\ufffd\u200b-\u200d]")
        for name in ("README.md", "docs/AI_REVIEW.md"):
            self.assertIn("VA_CHECKLIST.md", (ROOT / name).read_text(encoding="utf-8"))


class VaOutputTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temp.cleanup)
        cls.result = process_export(ROOT / "samples/synthetic_burp_history.json", Path(cls.temp.name) / "demo", "demo", load_policy())
        cls.directory = cls.result.export_dir
        cls.packet = json.loads((cls.directory / "analysis_packet.json").read_text(encoding="utf-8"))

    def response(self, summary, finding_id="FC-0004"):
        result = {"reviews": [{
            "finding_id": finding_id, "assessment": "needs_check", "summary": summary,
            "evidence_notes": ["제공된 근거만으로 교차 접근 여부는 알 수 없습니다."],
            "manual_checks": ["허가된 계정의 소유권과 역할을 비교하세요."],
            "normal_result": "권한 없는 자료를 거부합니다.", "issue_result": "권한 없는 계정에 보호된 내용이 반환됩니다.",
            "remediation": ["서버에서 소유권을 확인합니다."],
        }]}
        return {"status": "completed", "output": [{"type": "message", "role": "assistant", "content": [{
            "type": "output_text", "text": json.dumps(result, ensure_ascii=False),
        }]}]}

    def test_ai_input_classifications_are_selected_only_and_do_not_change_source(self):
        before = (self.directory / "analysis_packet.json").read_bytes()
        draft = ai_review.prepare_review("demo", self.directory, ["FC-0004", "FC-0010"])
        payload = json.loads(draft.input_json)
        self.assertEqual(set(payload["va_classifications"]), {"FC-0004", "FC-0010"})
        self.assertEqual(payload["va_classifications"]["FC-0004"]["code"], "VA-11")
        self.assertEqual(payload["va_classifications"]["FC-0010"]["code"], "VA-16")
        self.assertEqual(before, (self.directory / "analysis_packet.json").read_bytes())
        self.assertEqual(len(self.packet["finding_candidates"]), 22)
        self.assertEqual(len(self.result.exported_files), 4)
        self.assertTrue(all("va_classification" not in item for item in self.packet["finding_candidates"]))

    def test_ai_rejects_wrong_or_unknown_va_codes_without_echo(self):
        draft = ai_review.prepare_review("demo", self.directory, ["FC-0004"])
        for code in ("VA-01", "VA-02", "VA-16", "VA-31", "va05"):
            with self.subTest(code=code), self.assertRaisesRegex(ai_review.AiReviewError, "ai_response_va_mismatch"):
                ai_review.validate_response(self.response(f"{code} 검토 후보입니다."), draft)
        for summary in ("VA-11 검토 후보입니다.", "추가 확인이 필요한 검토 후보입니다."):
            self.assertEqual(ai_review.validate_response(self.response(summary), draft)["reviews"][0]["summary"], summary)
        unmapped = ai_review.prepare_review("demo", self.directory, ["FC-0001"])
        with self.assertRaisesRegex(ai_review.AiReviewError, "ai_response_va_mismatch"):
            ai_review.validate_response(self.response("VA-06 검토 후보입니다.", "FC-0001"), unmapped)

    def test_source_cannot_override_locally_derived_classification(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            packet = copy.deepcopy(self.packet)
            packet["va_classifications"] = {"FC-0004": {"code": "VA-01"}}
            packet["finding_candidates"][3]["va_code"] = "VA-02"
            (directory / "analysis_packet.json").write_text(json.dumps(packet, ensure_ascii=False), encoding="utf-8")
            payload = json.loads(ai_review.prepare_review("demo", directory, ["FC-0004"]).input_json)
            self.assertEqual(payload["va_classifications"]["FC-0004"]["code"], "VA-11")
            self.assertNotIn("va_code", payload["candidates"][0])

    def test_human_outputs_share_classification_without_mutating_analysis(self):
        before = copy.deepcopy(self.packet)
        for renderer in (render_chatgpt_analysis_prompt, render_codex_analysis_prompt):
            text = renderer(self.packet)
            for phrase in ("VA-11", "VA-16", "VA-04", "VA-05", "참고 분류", "분류 미정", "미점검"):
                self.assertIn(phrase, text)
            assert_no_sensitive_text(text)
        report = render_report_draft(self.packet["finding_candidates"])
        for phrase in ("VA-11", "VA-16", "VA-04", "VA-05", "참고 분류", "분류 미정", "미점검"):
            self.assertIn(phrase, report)
        self.assertEqual(before, self.packet)

    def test_gui_shows_full_catalog_without_marking_missing_categories_safe(self):
        output = SimpleNamespace(path=self.directory, output_id="demo")
        html = render_ai_review_selection(output, "DUMMY_CSRF")
        for item in VA_CATALOG:
            self.assertIn(item.code, html)
        self.assertIn("VA-01</code> 코드 인젝션 (Code Injection) · 미점검", html)
        self.assertIn("VA-11</code> 불충분한 권한 검증 · 관련 후보 있음", html)
        self.assertIn("VA 분류 미정", html)
        self.assertNotIn("진단 완료", html)

    def test_gui_and_terminal_result_use_server_classification(self):
        review = json.loads(self.response("VA-11 검토 후보입니다.")["output"][0]["content"][0]["text"])
        review.update(candidate_types={"FC-0004": "idor_candidate"}, model=ai_review.MODEL)
        for text in (ai_review.render_text_review(review), render_ai_review_result("demo", review)):
            self.assertIn("VA-11 불충분한 권한 검증", text)
            self.assertIn("수평/수직 권한 이동", text)
            self.assertIn("검토 후보", text)


if __name__ == "__main__":
    unittest.main()
