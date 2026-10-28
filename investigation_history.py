
def add_investigation_history(
    history,
    alert_id,
    result,
    severity="UNKNOWN",
    investigation_id="N/A",
    timestamp="N/A",
    notes="",
):
    """Add an investigation using the app's existing history structure."""
    investigation = {
        "alert_id": str(alert_id),
        "severity": severity,
        "investigation_id": investigation_id,
        "timestamp": timestamp,
        "result": result,
        "analyst_notes": notes,
    }

    history.append(investigation)
    return investigation
