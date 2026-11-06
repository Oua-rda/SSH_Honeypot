from database.db import init_db, insert_events
from analysis.statistics import summary

_n = iter(range(10_000))


def ev(ts, etype="login_failed", ip="10.0.0.1", user="root", pw_hash="h1", masked="p***"):
    return {
        "event_id": f"e{next(_n)}", "event_type": etype, "timestamp": ts,
        "source_ip": ip, "session_id": f"s-{ip}", "username": user,
        "password_masked": masked, "password_hash": pw_hash,
        "command": None, "duration_s": None,
    }


def test_empty_database_does_not_crash(tmp_path):
    db = tmp_path / "t.db"
    init_db(db)
    s = summary(db)
    assert s["overview"]["total_alerts"] == 0
    assert s["top_ips"] == [] and s["hourly"]["labels"] == []


def test_overview_and_ranking(tmp_path):
    db = tmp_path / "t.db"
    init_db(db)
    insert_events(
        [ev("2026-11-05T10:00:00Z", "connect", user=None, pw_hash=None, masked=None)]
        + [ev(f"2026-11-05T10:00:0{i}Z") for i in range(3)]
        + [ev("2026-11-05T10:01:00Z", ip="10.0.0.2")]
        + [ev("2026-11-05T10:02:00Z", "login_success")], db)
    s = summary(db)
    assert s["overview"]["total_connections"] == 1
    assert s["overview"]["failed_logins"] == 4
    assert s["overview"]["successful_logins"] == 1
    assert s["overview"]["unique_ips"] == 2
    assert s["top_ips"][0]["source_ip"] == "10.0.0.1"      


def test_ip_and_date_filters(tmp_path):
    db = tmp_path / "t.db"
    init_db(db)
    insert_events([ev("2026-11-04T10:00:00Z"), ev("2026-11-05T10:00:00Z"),
                   ev("2026-11-05T11:00:00Z", ip="10.0.0.2")], db)
    assert summary(db, start="2026-11-05")["overview"]["failed_logins"] == 2
    assert summary(db, end="2026-11-04")["overview"]["failed_logins"] == 1
    assert summary(db, ip="10.0.0.2")["overview"]["failed_logins"] == 1


def test_hourly_fills_empty_hours(tmp_path):
    db = tmp_path / "t.db"
    init_db(db)
    insert_events([ev("2026-11-05T00:10:00Z"), ev("2026-11-05T02:10:00Z")], db)
    h = summary(db)["hourly"]
    assert h["failed"] == [1, 0, 1] and len(h["labels"]) == 3


def test_passwords_are_masked_only(tmp_path):
    db = tmp_path / "t.db"
    init_db(db)
    insert_events([ev("2026-11-05T10:00:00Z", masked="s*****")], db)
    tp = summary(db)["top_passwords"]
    assert tp == [{"password_masked": "s*****", "count": 1}]