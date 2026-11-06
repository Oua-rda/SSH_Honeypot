from database.db import init_db, insert_events, count_rows, get_connection


def make_event(n, etype="login_failed", session="s1", ip="10.0.0.5", **extra):
    base = {
        "event_id": f"id-{n}", "event_type": etype, "timestamp": f"2026-11-05T00:00:{n:02d}Z",
        "source_ip": ip, "session_id": session, "username": "root",
        "password_masked": "1*****", "password_hash": "abc", "command": None,
        "duration_s": None,
    }
    base.update(extra)
    return base


def test_insert_and_duplicates(tmp_path):
    db = tmp_path / "t.db"
    init_db(db)
    events = [make_event(1), make_event(2)]
    assert insert_events(events, db) == {"new": 2, "duplicates": 0}
    assert insert_events(events, db) == {"new": 0, "duplicates": 2}
    assert count_rows(db)["attacks"] == 2


def test_session_tracking(tmp_path):
    db = tmp_path / "t.db"
    init_db(db)
    insert_events([
        make_event(1, "connect", username=None),
        make_event(2, "command", command="ls"),
        make_event(3, "command", command="pwd"),
        make_event(4, "session_closed", duration_s=12.5),
    ], db)
    conn = get_connection(db)
    row = conn.execute("SELECT * FROM sessions WHERE id = 's1'").fetchone()
    assert row["commands_count"] == 2
    assert row["duration_s"] == 12.5
    assert row["end_time"] is not None