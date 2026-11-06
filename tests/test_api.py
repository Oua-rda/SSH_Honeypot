import itertools

import pytest

from backend.app import create_app
from database.db import insert_events
from detection.detector import run_detection

_n = itertools.count()


def ev(ts, etype="login_failed", ip="10.0.0.1", user="root", cmd=None, session="s1"):
    return {
        "event_id": f"e{next(_n)}", "event_type": etype, "timestamp": ts,
        "source_ip": ip, "session_id": session, "username": user,
        "password_masked": "p***", "password_hash": "secrethash", "command": cmd,
        "duration_s": None,
    }


@pytest.fixture
def client(tmp_path):
    db = tmp_path / "t.db"
    app = create_app(db)
    insert_events(
        [ev(f"2026-11-05T10:00:0{i}Z") for i in range(6)]
        + [ev("2026-11-04T09:00:00Z", ip="10.0.0.2", session="s2")]
        + [ev("2026-11-05T10:05:00Z", "command", user=None, cmd="=cmd|' /C calc'!A0")], db)
    run_detection(db)
    return app.test_client()


def test_health(client):
    r = client.get("/api/health")
    assert r.status_code == 200 and r.json["status"] == "ok"


def test_honeypot_status_shape(client):
    j = client.get("/api/honeypot/status").get_json()
    assert j["port"] == 2222 and isinstance(j["listening"], bool)


def test_summary(client):
    j = client.get("/api/summary").get_json()
    assert j["overview"]["failed_logins"] == 7
    assert j["overview"]["unique_ips"] == 2
    assert j["overview"]["total_alerts"] >= 1


def test_attack_filters_and_pagination(client):
    j = client.get("/api/attacks?ip=10.0.0.2").get_json()
    assert j["total"] == 1
    j = client.get("/api/attacks?start=2026-11-05&event_type=login_failed&limit=2").get_json()
    assert j["total"] == 6 and len(j["items"]) == 2


def test_invalid_parameters_return_400(client):
    assert client.get("/api/attacks?start=garbage").status_code == 400
    assert client.get("/api/attacks?ip=999.1.1.1").status_code == 400
    assert client.get("/api/attacks?event_type=DROP").status_code == 400
    assert client.get("/api/attacks?limit=abc").status_code == 400


def test_attack_detail_and_missing(client):
    first = client.get("/api/attacks?limit=1").get_json()["items"][0]["id"]
    j = client.get(f"/api/attacks/{first}").get_json()
    assert "session_events" in j and "ip_alerts" in j
    assert client.get("/api/attacks/99999").status_code == 404


def test_alert_status_update(client):
    alert_id = client.get("/api/alerts").get_json()[0]["id"]
    ok = client.patch(f"/api/alerts/{alert_id}", json={"status": "investigating"})
    assert ok.status_code == 200
    assert client.get("/api/alerts?status=investigating").get_json()[0]["id"] == alert_id
    assert client.patch(f"/api/alerts/{alert_id}", json={"status": "hacked"}).status_code == 400
    assert client.patch("/api/alerts/99999", json={"status": "closed"}).status_code == 404


def test_csv_export_is_safe(client):
    r = client.get("/api/export/attacks.csv")
    text = r.get_data(as_text=True)
    assert r.mimetype == "text/csv"
    assert text.splitlines()[0].startswith("id,timestamp,source_ip")
    assert "secrethash" not in text            
    assert "'=cmd" in text                    


def test_report(client):
    r = client.get("/api/report")
    assert r.status_code == 200
    body = r.get_data(as_text=True)
    assert "# SSH Sentinel - Summary Report" in body
    assert "not proof of compromise" in body
    
def test_dashboard_page_and_csp(client):
    r = client.get("/")
    assert r.status_code == 200 and b"SSH" in r.data
    assert "script-src 'self'" in r.headers["Content-Security-Policy"]
    assert client.get("/static/css/style.css").status_code == 200
    assert client.get("/static/js/app.js").status_code == 200