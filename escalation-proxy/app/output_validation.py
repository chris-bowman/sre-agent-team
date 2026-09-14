import json
import re
from typing import Any, Callable

from pydantic import ValidationError

from contracts import LiaisonFinalReport

DEFAULT_FINALIZATION_TOKEN = "ESCALATION_FINAL_V1"
DEFAULT_REQUIRE_FINALIZATION_TOKEN = True

EventSink = Callable[..., None]

_SENSITIVE_VALUE_PATTERN = re.compile(
    r"(?i)(bearer\s+|(?:api[_-]?key|access[_-]?token|client[_-]?secret|password|secret|connection[_-]?string|account[_-]?key|sharedaccesskey|platform[_-]?thread[_-]?id)\s*[:=]\s*)([^\s,;]+)"
)
_SENSITIVE_JSON_FIELD_PATTERN = re.compile(
    r"""(?is)(["']?(?:api[_-]?key|access[_-]?token|client[_-]?secret|password|secret|connection[_-]?string|account[_-]?key|sharedaccesskey|platform[_-]?thread[_-]?id)["']?\s*:\s*)(?:"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|[^,}\]\s]+)"""
)
_SENSITIVE_QUERY_PATTERN = re.compile(r"(?i)([?&](?:sig|token|access_token|api_key|client_secret)=)[^&#\s]+")


def redact_sensitive_text(text: str, event_sink: EventSink | None = None) -> str:
    """Remove credential-shaped values from output text."""
    original = text or ""
    redacted = _SENSITIVE_JSON_FIELD_PATTERN.sub(r"\1[REDACTED]", original)
    redacted = _SENSITIVE_VALUE_PATTERN.sub(r"\1[REDACTED]", redacted)
    redacted = _SENSITIVE_QUERY_PATTERN.sub(r"\1[REDACTED]", redacted)
    if redacted != original and event_sink is not None:
        event_sink("findings_redacted")
    return redacted


def normalize_status_value(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip().lower().replace("-", "").replace("_", "")


def summary_candidate_score(
    text: str,
    finalization_token: str = DEFAULT_FINALIZATION_TOKEN,
) -> int:
    """Heuristic score for selecting the best investigation summary message."""
    content = (text or "").strip()
    if not content:
        return -1

    try:
        report = LiaisonFinalReport.model_validate_json(content)
        if report.finalization_token == finalization_token:
            return 600
    except (ValidationError, ValueError, TypeError):
        pass

    lower = content.lower()
    score = 0

    if finalization_token.lower() in lower:
        score += 500
    if "## escalation response" in lower:
        score += 100
    if "## platform investigation findings" in lower:
        score += 90

    if "### root cause" in lower:
        score += 30
    if "### evidence" in lower:
        score += 25
    if "### recommended actions" in lower:
        score += 25
    if "### verdict" in lower:
        score += 20

    if "escalated by:" in lower:
        score += 10
    if "reported symptom:" in lower:
        score += 10

    if len(content) >= 1200:
        score += 15
    elif len(content) >= 600:
        score += 8
    elif len(content) < 160:
        score -= 10

    return score


def select_best_summary_text(
    agent_texts: list[str],
    finalization_token: str = DEFAULT_FINALIZATION_TOKEN,
) -> tuple[int, str, str]:
    """Choose the best summary and return its score, text, and strategy."""
    if not agent_texts:
        return (-1, "", "none")

    ranked = [
        (summary_candidate_score(text, finalization_token), index, text) for index, text in enumerate(agent_texts)
    ]
    ranked.sort(key=lambda candidate: (candidate[0], candidate[1]), reverse=True)
    best_score, _best_index, best_text = ranked[0]

    if best_score >= 40:
        return (best_score, best_text, "best_structured_message")

    recent = agent_texts[-3:]
    return (best_score, "\n\n---\n\n".join(recent), "recent_composite")


def is_finalized_summary(
    best_score: int,
    selected_text: str,
    require_finalization_token: bool = DEFAULT_REQUIRE_FINALIZATION_TOKEN,
    finalization_token: str = DEFAULT_FINALIZATION_TOKEN,
) -> bool:
    try:
        report = LiaisonFinalReport.model_validate_json(selected_text)
        return report.finalization_token == finalization_token
    except (ValidationError, ValueError, TypeError):
        pass
    if require_finalization_token:
        return bool(
            re.search(
                rf"(?i)(?:^|\n)FINALIZATION_TOKEN:\s*{re.escape(finalization_token)}\s*\Z",
                (selected_text or "").strip(),
            )
        )
    return best_score >= 40


def parse_finalized_findings(
    report: str,
    finalization_token: str = DEFAULT_FINALIZATION_TOKEN,
) -> dict[str, Any] | None:
    """Parse a final JSON liaison report, with Markdown migration fallback."""
    json_findings = parse_json_finalized_findings(report, finalization_token)
    if json_findings is not None:
        return json_findings

    return _parse_markdown_finalized_findings(report, finalization_token)


def parse_json_finalized_findings(
    report: str,
    finalization_token: str = DEFAULT_FINALIZATION_TOKEN,
) -> dict[str, Any] | None:
    """Validate the private liaison JSON and project it to the public findings shape."""
    try:
        liaison_report = LiaisonFinalReport.model_validate_json(report.strip())
    except (ValidationError, ValueError, TypeError, json.JSONDecodeError):
        return None
    if liaison_report.finalization_token != finalization_token:
        return None
    verdict = liaison_report.verdict.replace("_", " ")
    return {
        "summary": liaison_report.root_cause,
        "impact": verdict,
        "evidence": liaison_report.evidence,
        "likely_causes": [liaison_report.root_cause],
        "recommended_actions": liaison_report.recommended_actions,
        "limitations": liaison_report.limitations
        or ["Findings are investigation guidance; the proxy performed no remediation."],
    }


def _parse_markdown_finalized_findings(
    report: str,
    finalization_token: str,
) -> dict[str, Any] | None:
    """Temporary v1 migration parser for reports produced before JSON rollout."""
    if not re.search(
        rf"(?i)(?:^|\n)FINALIZATION_TOKEN:\s*{re.escape(finalization_token)}\s*\Z",
        report.strip(),
    ):
        return None

    sections = {}
    section_pattern = re.compile(
        r"^### (Root Cause|Evidence|Recommended Actions|Verdict)\s*$\n(.*?)(?=^### |\Z)",
        re.MULTILINE | re.DOTALL,
    )
    for heading, content in section_pattern.findall(report):
        sections[heading] = content.strip()

    required = {"Root Cause", "Evidence", "Recommended Actions", "Verdict"}
    if set(sections) != required:
        return None

    def lines(value: str) -> list[str]:
        return [
            re.sub(r"^(?:[-*]|\d+\.)\s*", "", line).strip()
            for line in value.splitlines()
            if line.strip() and not line.startswith("FINALIZATION_TOKEN:")
        ]

    root_cause = " ".join(lines(sections["Root Cause"]))
    evidence = lines(sections["Evidence"])
    actions = lines(sections["Recommended Actions"])
    verdict = " ".join(lines(sections["Verdict"]))
    if not root_cause or not evidence or not actions or not verdict:
        return None
    verdict = verdict.strip().upper()
    if verdict not in {"PLATFORM ISSUE", "APPLICATION ISSUE", "INCONCLUSIVE"}:
        return None

    return {
        "summary": root_cause,
        "impact": verdict,
        "evidence": evidence,
        "likely_causes": [root_cause],
        "recommended_actions": actions,
        "limitations": ["Findings are investigation guidance; the proxy performed no remediation."],
    }
