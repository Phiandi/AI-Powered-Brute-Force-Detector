
from ai_investigation import is_successful_analysis
from investigation_history import add_investigation_history


def process_ai_result(history, alert, ai_result):
    """Save an investigation only when the AI result is successful."""
    if not is_successful_analysis(ai_result):
        return False

    add_investigation_history(
        history=history,
        alert_id=alert["alert_id"],
        result=ai_result,
        severity=alert.get("severity", "UNKNOWN"),
        investigation_id="TEST-001",
        timestamp="2026-10-27T08:00:00",
        notes="",
    )
    return True


def test_successful_ai_result_is_saved():
    history = []
    alert = {
        "alert_id": "ALERT-001",
        "severity": "HIGH",
    }

    saved = process_ai_result(
        history,
        alert,
        "Repeated failed login attempts detected.",
    )

    assert saved is True
    assert len(history) == 1
    assert history[0]["alert_id"] == "ALERT-001"


def test_failed_ai_result_is_not_saved():
    history = []
    alert = {
        "alert_id": "ALERT-002",
        "severity": "MEDIUM",
    }

    saved = process_ai_result(
        history,
        alert,
        "AI analysis failed: request error.",
    )

    assert saved is False
    assert history == []
