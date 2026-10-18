"""Fail the required PR check unless every upstream job succeeded."""

import json
import os


REQUIRED_JOBS = {"python-tests", "collector"}


def all_checks_passed(results: object) -> bool:
    return (
        isinstance(results, dict)
        and set(results) == REQUIRED_JOBS
        and all(
            isinstance(results[job], dict)
            and results[job].get("result") == "success"
            for job in REQUIRED_JOBS
        )
    )


def main() -> int:
    try:
        results = json.loads(os.environ.get("CI_RESULTS", ""))
    except ValueError:
        print("CI results are missing or invalid.")
        return 1
    if not all_checks_passed(results):
        print("All required jobs must succeed before merging.")
        return 1
    print("All required jobs passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
