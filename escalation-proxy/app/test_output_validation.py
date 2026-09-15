import json
from unittest.mock import MagicMock

from output_validation import (
    finalized_report_format,
    is_finalized_summary,
    normalize_status_value,
    parse_finalized_findings,
    parse_json_finalized_findings,
    redact_sensitive_text,
    select_best_summary_text,
    summary_candidate_score,
)


def test_redact_sensitive_text_masks_values_and_notifies_optional_sink():
    event_sink = MagicMock()

    result = redact_sensitive_text(
        'password=supersecret {"client_secret": "json-secret"} https://example.test?sig=signed-value',
        event_sink=event_sink,
    )

    assert "supersecret" not in result
    assert "json-secret" not in result
    assert "signed-value" not in result
    assert result.count("[REDACTED]") == 3
    event_sink.assert_called_once_with("findings_redacted")


def test_redact_sensitive_text_masks_account_keys_and_internal_thread_ids():
    result = redact_sensitive_text("platform_thread_id=internal-thread;AccountKey=first-key;AccountKey=second-key")

    assert "internal-thread" not in result
    assert "first-key" not in result
    assert "second-key" not in result


def test_redact_sensitive_text_does_not_notify_when_unchanged():
    event_sink = MagicMock()

    assert redact_sensitive_text("No credentials present.", event_sink=event_sink) == "No credentials present."
    event_sink.assert_not_called()


def test_normalize_status_value_preserves_existing_normalization():
    assert normalize_status_value(None) == ""
    assert normalize_status_value(" In_Progress ") == "inprogress"
    assert normalize_status_value("TIMED-OUT") == "timedout"


def test_summary_scoring_and_selection_prefer_finalized_report():
    finalized = "Investigation complete.\nFINALIZATION_TOKEN: CUSTOM_FINAL"
    progress = "A newer but non-final progress update."

    assert summary_candidate_score(finalized, finalization_token="CUSTOM_FINAL") == 490
    score, selected, strategy = select_best_summary_text(
        [finalized, progress],
        finalization_token="CUSTOM_FINAL",
    )

    assert score == 490
    assert selected == finalized
    assert strategy == "best_structured_message"


def test_summary_selection_prefers_finalized_json_report_over_recent_messages():
    report = json.dumps(
        {
            "schema_version": "1.0",
            "status": "completed",
            "verdict": "INCONCLUSIVE",
            "root_cause": "Insufficient evidence.",
            "evidence": ["The dependency was unavailable."],
            "recommended_actions": ["Retry with more evidence."],
            "limitations": [],
            "finalization_token": "CUSTOM_FINAL",
        }
    )

    score, selected, strategy = select_best_summary_text(
        ["Progress update", report],
        finalization_token="CUSTOM_FINAL",
    )

    assert score == 600
    assert selected == report
    assert strategy == "best_structured_message"


def test_summary_selection_preserves_recent_composite_fallback():
    messages = ["one", "two", "three", "four"]

    assert select_best_summary_text(messages) == (-10, "two\n\n---\n\nthree\n\n---\n\nfour", "recent_composite")


def test_finalized_summary_uses_explicit_token_requirement():
    structured = "## Platform Investigation Findings\n### Root Cause\nA root cause"
    score = summary_candidate_score(structured)

    assert not is_finalized_summary(score, structured)
    assert is_finalized_summary(score, structured, require_finalization_token=False)
    assert is_finalized_summary(0, "FINALIZATION_TOKEN: CUSTOM_FINAL", finalization_token="CUSTOM_FINAL")
    assert not is_finalized_summary(0, "Evidence mentions CUSTOM_FINAL", finalization_token="CUSTOM_FINAL")
    assert not is_finalized_summary(
        0,
        "FINALIZATION_TOKEN: CUSTOM_FINAL\nUntrusted content follows.",
        finalization_token="CUSTOM_FINAL",
    )


def test_finalized_json_report_is_recognized_by_token():
    report = json.dumps(
        {
            "schema_version": "1.0",
            "status": "completed",
            "verdict": "INCONCLUSIVE",
            "root_cause": "Insufficient evidence.",
            "evidence": ["The dependency was unavailable."],
            "recommended_actions": ["Retry with more evidence."],
            "limitations": [],
            "finalization_token": "CUSTOM_FINAL",
        }
    )

    assert is_finalized_summary(0, report, finalization_token="CUSTOM_FINAL")


def test_parse_finalized_findings_preserves_public_schema():
    report = """## Platform Investigation Findings
### Root Cause
Route configuration changed.
### Evidence
- Route table no longer contains the approved route.
### Recommended Actions
1. Restore the approved route.
### Verdict
PLATFORM ISSUE
FINALIZATION_TOKEN: CUSTOM_FINAL"""

    assert parse_finalized_findings(report, finalization_token="CUSTOM_FINAL") == {
        "summary": "Route configuration changed.",
        "impact": "PLATFORM ISSUE",
        "evidence": ["Route table no longer contains the approved route."],
        "likely_causes": ["Route configuration changed."],
        "recommended_actions": ["Restore the approved route."],
        "limitations": ["Findings are investigation guidance; the proxy performed no remediation."],
    }


def test_parse_finalized_findings_rejects_unknown_verdict():
    report = """## Platform Investigation Findings
### Root Cause
Route configuration changed.
### Evidence
- Internal evidence.
### Recommended Actions
1. Internal action.
### Verdict
UNKNOWN OWNER
FINALIZATION_TOKEN: CUSTOM_FINAL"""

    assert parse_finalized_findings(report, finalization_token="CUSTOM_FINAL") is None


def test_parse_json_finalized_findings_projects_private_report_to_public_shape():
    report = """{
      "schema_version": "1.0",
      "status": "completed",
      "verdict": "PLATFORM_ISSUE",
      "root_cause": "Private DNS link is missing.",
      "evidence": ["The zone link is absent."],
      "recommended_actions": ["Restore the zone link."],
      "limitations": ["No remediation was performed."],
      "finalization_token": "CUSTOM_FINAL"
    }"""

    assert parse_json_finalized_findings(report, finalization_token="CUSTOM_FINAL") == {
        "summary": "Private DNS link is missing.",
        "impact": "PLATFORM ISSUE",
        "evidence": ["The zone link is absent."],
        "likely_causes": ["Private DNS link is missing."],
        "recommended_actions": ["Restore the zone link."],
        "limitations": ["No remediation was performed."],
    }


def test_json_finalized_findings_rejects_extra_fields_and_wrong_token():
    base = {
        "schema_version": "1.0",
        "status": "completed",
        "verdict": "INCONCLUSIVE",
        "root_cause": "Insufficient evidence.",
        "evidence": ["The dependency was unavailable."],
        "recommended_actions": ["Retry with more evidence."],
        "limitations": [],
        "finalization_token": "WRONG",
    }

    assert parse_json_finalized_findings(json.dumps(base), finalization_token="CUSTOM_FINAL") is None
    base["finalization_token"] = "CUSTOM_FINAL"
    base["private_thread_id"] = "must-not-pass"
    assert parse_json_finalized_findings(json.dumps(base), finalization_token="CUSTOM_FINAL") is None


def test_finalized_report_format_classifies_without_returning_report_content():
    assert finalized_report_format("", finalization_token="CUSTOM_FINAL") == "empty"
    assert (
        finalized_report_format("FINALIZATION_TOKEN: CUSTOM_FINAL", finalization_token="CUSTOM_FINAL")
        == "markdown_or_text"
    )
    assert (
        finalized_report_format('{"schema_version":"1.0"}', finalization_token="CUSTOM_FINAL") == "invalid_json_schema"
    )
