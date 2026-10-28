
import pandas as pd

from severity import assign_severity


def detect_alerts(logs, threshold=5):
    """Return failed-login records that meet the alert threshold."""

    if (
        not isinstance(threshold, int)
        or isinstance(threshold, bool)
        or threshold < 1
    ):
        raise ValueError("threshold must be a positive integer")

    required_columns = {"login_status", "failed_attempts"}
    missing_columns = required_columns - set(logs.columns)

    if missing_columns:
        raise ValueError(
            f"Missing required columns: {sorted(missing_columns)}"
        )

    if logs["login_status"].isna().any():
        raise ValueError("login_status contains missing values")

    if logs["failed_attempts"].isna().any():
        raise ValueError("failed_attempts contains missing values")

    if not pd.api.types.is_numeric_dtype(logs["failed_attempts"]):
        raise ValueError("failed_attempts must contain numeric values")

    if (logs["failed_attempts"] < 0).any():
        raise ValueError("failed_attempts cannot be negative")

    failed_logins = logs[
        logs["login_status"] == "Failed"
    ].copy()

    alerts = failed_logins[
        failed_logins["failed_attempts"] >= threshold
    ].copy()

    alerts["severity"] = alerts["failed_attempts"].apply(
        assign_severity
    )

    return alerts
