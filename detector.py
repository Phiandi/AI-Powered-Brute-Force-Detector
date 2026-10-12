import pandas as pd

# Load authentication logs
log_file = "data/authentication_logs.csv"
logs = pd.read_csv(log_file)

print("Dataset loaded successfully!\n")

# Keep only failed login events
failed_logins = logs[logs["login_status"] == "Failed"].copy()

# Detect suspicious logins (5 or more failed attempts)
alerts = failed_logins[failed_logins["failed_attempts"] >= 5].copy()

# Assign severity levels
def assign_severity(attempts):
    if attempts == 7:
        return "HIGH"
    elif attempts == 6:
        return "MEDIUM"
    else:   # 5 failed attempts
        return "LOW"

alerts["severity"] = alerts["failed_attempts"].apply(assign_severity)

# Count alerts by severity level
severity_summary = alerts["severity"].value_counts().rename("count")

print("SOC ALERTS")
print("-----------")
print(f"Detection Rule: 5 or more failed attempts")
print(f"Total Alerts Detected: {len(alerts)}")

print("\nFirst 10 Suspicious Authentication Events")
print("------------------------------------------")
print(
    alerts[
        [
            "auth_event_id",
            "user_id",
            "login_status",
            "failed_attempts",
            "timestamp"
        ]
    ].head(10).to_string(index=False)
)

# Count failed login attempts per user
user_summary = (
    failed_logins.groupby("user_id")
    .size()
    .reset_index(name="failed_login_events")
    .sort_values(by="failed_login_events", ascending=False)
)

print("\nTop 10 Targeted User Accounts")
print("-----------------------------")
print(user_summary.head(10))

# Convert timestamp to datetime
logs["timestamp"] = pd.to_datetime(logs["timestamp"])

# Keep failed logins only
failed_logins = logs[logs["login_status"] == "Failed"].copy()

# Count failed logins per hour
hourly_attacks = (
    failed_logins.groupby(failed_logins["timestamp"].dt.hour)
    .size()
    .reset_index(name="failed_login_events")
)

print("\nFailed Login Attempts by Hour")
print("------------------------------")
print(hourly_attacks)

import plotly.express as px

# Create a bar chart
hour_chart = px.bar(
    hourly_attacks,
    x="timestamp",
    y="failed_login_events",
    title="Failed Login Attempts by Hour",
    labels={
        "timestamp": "Hour of Day",
        "failed_login_events": "Failed Login Events"
    }
)

# Display chart in browser
hour_chart.show()

# Create Risk Level Distribution chart
severity_chart = px.bar(
    severity_summary.reset_index(),
    x="severity",
    y="count",
    title="Risk Level Distribution",
    labels={
        "severity": "Risk Level",
        "count": "Number of Alerts"
    }
)

severity_chart.show()

