import contextlib
import io
import json
import os
import unittest
from unittest.mock import patch

from scripts.check_ci_results import all_checks_passed, main


class CiGateTests(unittest.TestCase):
    def test_all_required_jobs_must_succeed(self) -> None:
        self.assertTrue(all_checks_passed({
            "python-tests": {"result": "success"},
            "collector": {"result": "success"},
        }))

    def test_unsuccessful_job_blocks_merging(self) -> None:
        for job in ["python-tests", "collector"]:
            for status in ["failure", "cancelled", "skipped", "neutral", "pending", "", None]:
                with self.subTest(job=job, status=status):
                    results = {
                        "python-tests": {"result": "success"},
                        "collector": {"result": "success"},
                    }
                    results[job]["result"] = status
                    self.assertFalse(all_checks_passed(results))

    def test_missing_or_extra_job_blocks_merging(self) -> None:
        for results in [{}, {"python-tests": {"result": "success"}}, {
            "python-tests": {"result": "success"},
            "collector": {"result": "success"},
            "unexpected": {"result": "success"},
        }]:
            with self.subTest(results=results):
                self.assertFalse(all_checks_passed(results))

    def test_invalid_result_shape_blocks_merging(self) -> None:
        for results in [None, [], "success", {
            "python-tests": "success", "collector": {"result": "success"},
        }, {"python-tests": {"result": "success"}, "collector": {}}]:
            with self.subTest(results=results):
                self.assertFalse(all_checks_passed(results))

    def test_cli_rejects_invalid_or_failed_results(self) -> None:
        for value in ["", "not-json", "null", "{}", json.dumps({
            "python-tests": {"result": "failure"},
            "collector": {"result": "success"},
        })]:
            with self.subTest(value=value), patch.dict(os.environ, {"CI_RESULTS": value}):
                with contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(main(), 1)

    def test_cli_accepts_successful_results(self) -> None:
        value = json.dumps({
            "python-tests": {"result": "success"},
            "collector": {"result": "success"},
        })
        with patch.dict(os.environ, {"CI_RESULTS": value}):
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main(), 0)


if __name__ == "__main__":
    unittest.main()
