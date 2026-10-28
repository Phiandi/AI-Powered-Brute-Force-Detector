 
import sqlite3
from pathlib import Path
from datetime import datetime, timezone

DATA_DIR = Path(__file__).resolve().parent / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)

DB_PATH = DATA_DIR / "investigation_statuses.db"

VALID_STATUSES = {"New", "In Progress", "Escalated", "Closed"}


def get_connection():
    return sqlite3.connect(DB_PATH)


def initialise_database():
    """Create the current-status and audit-history tables."""
    with get_connection() as connection:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS investigation_statuses (
                alert_id TEXT PRIMARY KEY,
                status TEXT NOT NULL DEFAULT 'New',
                updated_at TEXT NOT NULL
            )
        """)

        connection.execute("""
            CREATE TABLE IF NOT EXISTS investigation_status_history (
                history_id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_id TEXT NOT NULL,
                old_status TEXT,
                new_status TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
        """)


def get_all_statuses():
    """Return the latest saved status for each alert."""
    with get_connection() as connection:
        rows = connection.execute("""
            SELECT alert_id, status
            FROM investigation_statuses
        """).fetchall()

    return {alert_id: status for alert_id, status in rows}


def save_status(alert_id, status):
    """Save the current status and record the status change."""
    if status not in VALID_STATUSES:
        raise ValueError("Invalid investigation status.")

    alert_id = str(alert_id)
    timestamp = datetime.now(timezone.utc).isoformat(timespec="seconds")

    with get_connection() as connection:
        existing = connection.execute("""
            SELECT status
            FROM investigation_statuses
            WHERE alert_id = ?
        """, (alert_id,)).fetchone()

        old_status = existing[0] if existing else None

        connection.execute("""
            INSERT INTO investigation_statuses
                (alert_id, status, updated_at)
            VALUES (?, ?, ?)
            ON CONFLICT(alert_id) DO UPDATE SET
                status = excluded.status,
                updated_at = excluded.updated_at
        """, (alert_id, status, timestamp))

        # Record only actual changes, not repeated saves of the same status.
        if old_status != status:
            connection.execute("""
                INSERT INTO investigation_status_history
                    (alert_id, old_status, new_status, updated_at)
                VALUES (?, ?, ?, ?)
            """, (alert_id, old_status, status, timestamp))


def get_status_history(alert_id):
    """Return the current status and its last update time."""
    with get_connection() as connection:
        row = connection.execute("""
            SELECT alert_id, status, updated_at
            FROM investigation_statuses
            WHERE alert_id = ?
        """, (str(alert_id),)).fetchone()

    if row is None:
        return None

    return {
        "alert_id": row[0],
        "status": row[1],
        "updated_at": row[2]
    }



def get_audit_history(alert_id=None, limit=500):
    """Return audit history, newest first, optionally filtered by alert."""
    with get_connection() as connection:
        if alert_id:
            rows = connection.execute("""
                SELECT history_id, alert_id, old_status, new_status, updated_at
                FROM investigation_status_history
                WHERE alert_id = ?
                ORDER BY history_id DESC
                LIMIT ?
            """, (str(alert_id), limit)).fetchall()
        else:
            rows = connection.execute("""
                SELECT history_id, alert_id, old_status, new_status, updated_at
                FROM investigation_status_history
                ORDER BY history_id DESC
                LIMIT ?
            """, (limit,)).fetchall()

    return [
        {
            "history_id": row[0],
            "alert_id": row[1],
            "old_status": row[2] or "—",
            "new_status": row[3],
            "updated_at": row[4],
        }
        for row in rows
    ]


initialise_database()
