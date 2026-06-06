from __future__ import annotations

import json
from copy import deepcopy
from typing import Any


ANALYSIS_CANDIDATE_FIELDS = [
    "finding_id",
    "type",
    "title",
    "confidence",
    "confidence_rationale",
    "risk_rating_draft",
    "manual_verification_required",
    "affected_endpoint",
    "evidence_ids",
    "rationale",
    "recommended_manual_tests",
    "do_not_claim",
]

ANALYSIS_CONSTRAINTS = [
    "Use only verified sanitized output files.",
    "Do not request or infer raw request or response values.",
    "Do not include Cookie, Authorization, token, real domain, IP, or personal data values.",
    "Keep every issue as a candidate until manual verification is complete.",
    "Treat risk_rating_draft as a manual-review severity draft, not a severity decision.",
    "Do not claim privilege escalation, data breach, or exploitation without separate proof.",
]

REPORT_DRAFT_REQUESTS = [
    "Assess whether each candidate is plausible from the sanitized evidence.",
    "Review risk_rating_draft separately from evidence confidence and keep it draft-only.",
    "List missing evidence and safe manual verification steps.",
    "Draft cautious report wording that preserves candidate status.",
    "Suggest likely OWASP Top 10 or CWE mappings as references only.",
]


def build_analysis_packet(findings: dict[str, Any]) -> dict[str, Any]:
    candidates = [_analysis_candidate(candidate) for candidate in findings.get("finding_candidates", [])]
    packet: dict[str, Any] = {
        "schema_version": "analysis-prompt-packet-v1",
        "source": "finding_candidates.json",
        "raw_data_included": False,
        "use_only_after_verify_passed": True,
        "candidate_count": len(candidates),
        "analysis_constraints": ANALYSIS_CONSTRAINTS,
        "report_draft_requests": REPORT_DRAFT_REQUESTS,
        "finding_candidates": candidates,
    }
    if "risk_rating_profile" in findings:
        packet["risk_rating_profile"] = deepcopy(findings["risk_rating_profile"])
    if "metadata" in findings:
        packet["metadata"] = deepcopy(findings["metadata"])
    return packet


def render_chatgpt_analysis_prompt(packet: dict[str, Any]) -> str:
    data = json.dumps(packet, indent=2, sort_keys=True)
    return f"""# Sanitized Finding Candidate Analysis

Use this only after the generated output directory has passed `python -m burp_ai_redaction_gateway verify`.

Boundaries:
- Analyze only the sanitized finding candidate packet below.
- Treat every item as a candidate, not as a confirmed vulnerability.
- Do not ask for or reconstruct raw request/response values, cookies, tokens, real domains, IPs, or personal data.
- Keep `do_not_claim` limits in the final wording.

Tasks:
1. Summarize each finding candidate.
2. Assess plausibility and confidence without over-claiming.
3. Review `risk_rating_draft` separately from evidence confidence; keep severity draft-only.
4. Identify evidence gaps.
5. Provide safe manual verification steps for Burp.
6. Draft cautious report language for candidates that remain plausible.
7. Suggest likely OWASP Top 10 or CWE mappings as references only.

Analysis packet:

```json
{data}
```
"""


def render_codex_analysis_prompt(packet: dict[str, Any]) -> str:
    data = json.dumps(packet, indent=2, sort_keys=True)
    return f"""# Codex Analysis Task

Project: burp-ai-redaction-gateway

Goal:
Review sanitized finding candidates and produce safe analysis guidance without handling raw HTTP data.

Hard requirements:
1. Use only the analysis packet below.
2. Do not request, print, store, or infer raw request/response values.
3. Do not log Cookie, Authorization, token, real domain, IP, or personal data values.
4. Keep every issue as a candidate until manual reproduction proves it.
5. Preserve `finding_id`, `evidence_ids`, `affected_endpoint`, `confidence`, `confidence_rationale`, `risk_rating_draft`, `manual_verification_required`, `rationale`, `recommended_manual_tests`, and `do_not_claim` in any derived output.
6. Treat `risk_rating_draft` as draft-only; do not treat evidence confidence as severity.
7. Include cautious report draft wording and explicit manual verification steps.
8. Do not make any claim listed in `do_not_claim`.

Analysis packet:

```json
{data}
```
"""


def _analysis_candidate(candidate: dict[str, Any]) -> dict[str, Any]:
    item = {field: deepcopy(candidate.get(field)) for field in ANALYSIS_CANDIDATE_FIELDS}
    item["summary"] = _candidate_summary(item)
    return item


def _candidate_summary(candidate: dict[str, Any]) -> str:
    finding_id = candidate.get("finding_id") or "candidate"
    rule_type = candidate.get("type") or "unknown_type"
    endpoint = candidate.get("affected_endpoint") or "unknown_endpoint"
    confidence = candidate.get("confidence") or "unknown_confidence"
    return f"{finding_id}: {rule_type} candidate on {endpoint} with {confidence} confidence."
