
import pandas as pd
import pytest

from alert_detection import detect_alerts


def test_detects_failed_logins_at_threshold():
    logs = pd.DataFrame({
        "login_status": ["Failed", "Failed", "Failed"],
        "failed_attempts": [4, 5, 6],
    })

    alerts = detect_alerts(logs)

    assert len(alerts) == 2
    assert sorted(alerts["failed_attempts"].tolist()) == [5, 6]


def test_ignores_successful_logins():
    logs = pd.DataFrame({
        "login_status": ["Success", "Failed"],
        "failed_attempts": [7, 5],
    })

    alerts = detect_alerts(logs)

    assert len(alerts) == 1
    assert alerts.iloc[0]["login_status"] == "Failed"


def test_assigns_expected_severity():
    logs = pd.DataFrame({
        "login_status": ["Failed", "Failed", "Failed"],
        "failed_attempts": [5, 6, 7],
    })

    alerts = detect_alerts(logs)

    severity_by_attempts = dict(
        zip(alerts["failed_attempts"], alerts["severity"])
    )

    assert severity_by_attempts == {
        5: "LOW",
        6: "MEDIUM",
        7: "HIGH",
    }


def test_rejects_missing_required_columns():
    logs = pd.DataFrame({
        "login_status": ["Failed"],
    })

    with pytest.raises(ValueError, match="Missing required columns"):
        detect_alerts(logs)


def test_returns_empty_alerts_when_nothing_meets_threshold():
    logs = pd.DataFrame({
        "login_status": ["Failed", "Success"],
        "failed_attempts": [2, 7],
    })

    alerts = detect_alerts(logs)

    assert alerts.empty
    assert "severity" in alerts.columns


def test_handles_empty_dataset():
    logs = pd.DataFrame({
        "login_status": pd.Series(dtype="str"),
        "failed_attempts": pd.Series(dtype="int64"),
    })

    alerts = detect_alerts(logs)

    assert alerts.empty
    assert "severity" in alerts.columns


def test_supports_custom_threshold():
    logs = pd.DataFrame({
        "login_status": ["Failed", "Failed", "Failed"],
        "failed_attempts": [3, 4, 5],
    })

    alerts = detect_alerts(logs, threshold=4)

    assert sorted(alerts["failed_attempts"].tolist()) == [4, 5]


def test_rejects_invalid_threshold():
    logs = pd.DataFrame({
        "login_status": ["Failed"],
        "failed_attempts": [5],
    })

    with pytest.raises(ValueError, match="threshold"):
        detect_alerts(logs, threshold=0)

def test_rejects_missing_login_status():
    logs = pd.DataFrame({
        "login_status": ["Failed", None],
        "failed_attempts": [5, 6],
    })

    with pytest.raises(ValueError, match="login_status contains missing values"):
        detect_alerts(logs)


def test_rejects_missing_failed_attempts():
    logs = pd.DataFrame({
        "login_status": ["Failed", "Failed"],
        "failed_attempts": [5, None],
    })

    with pytest.raises(ValueError, match="failed_attempts contains missing values"):
        detect_alerts(logs)


def test_rejects_negative_failed_attempts():
    logs = pd.DataFrame({
        "login_status": ["Failed"],
        "failed_attempts": [-1],
    })

    with pytest.raises(ValueError, match="cannot be negative"):
        detect_alerts(logs)
def test_rejects_non_numeric_failed_attempts():
    logs = pd.DataFrame({
        "login_status": ["Failed"],
        "failed_attempts": ["five"],
    })

    with pytest.raises(
        ValueError,
        match="failed_attempts must contain numeric values"
    ):
        detect_alerts(logs)