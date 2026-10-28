
import sqlite3
import pytest

import database


@pytest.fixture
def test_db(tmp_path, monkeypatch):
    test_db_path = tmp_path / "test_investigations.db"

    monkeypatch.setattr(database, "DB_PATH", test_db_path)

    database.initialise_database()

    yield test_db_path


def test_save_status_and_retrieve_it(test_db):
    database.save_status("ALERT-001", "In Progress")

    statuses = database.get_all_statuses()

    assert statuses["ALERT-001"] == "In Progress"


def test_status_change_is_recorded_in_audit_history(test_db):
    database.save_status("ALERT-002", "New")
    database.save_status("ALERT-002", "Escalated")

    history = database.get_audit_history(
        alert_id="ALERT-002",
        limit=500,
    )

    assert len(history) == 2
    assert history[0]["new_status"] == "Escalated"
    assert history[1]["new_status"] == "New"


def test_invalid_status_is_rejected(test_db):
    with pytest.raises(ValueError):
        database.save_status("ALERT-003", "Unknown Status")
