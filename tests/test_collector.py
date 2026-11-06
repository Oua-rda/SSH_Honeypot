import json
from collector.log_collector import parse_line, LogReader

GOOD = json.dumps({
    "eventid": "cowrie.login.failed", "timestamp": "2026-11-04T23:50:01Z",
    "src_ip": "10.0.0.5", "session": "abc", "username": "root", "password": "secret",
})

def test_valid_line():
    e = parse_line(GOOD)
    assert e["event_type"] == "login_failed"
    assert e["password_masked"] == "s*****"
    assert "secret" not in json.dumps(e)

def test_malformed_and_empty():
    assert parse_line("{not json") is None
    assert parse_line("") is None

def test_missing_field():
    assert parse_line(json.dumps({"eventid": "cowrie.login.failed"})) is None

def test_same_line_same_id():
    assert parse_line(GOOD)["event_id"] == parse_line(GOOD)["event_id"]

def test_partial_line_and_resume(tmp_path):
    log, state = tmp_path / "c.json", tmp_path / "state.json"
    log.write_text(GOOD + "\n" + GOOD[:20])            
    reader = LogReader(log, state)
    assert len(reader.read_new_events()) == 1
    assert len(reader.read_new_events()) == 0           
    log.write_text(GOOD + "\n" + GOOD + "\n")           
    assert len(reader.read_new_events()) == 1