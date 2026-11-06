import csv
import io
import ipaddress
from datetime import datetime, timezone

from flask import Blueprint, Response, current_app, jsonify, render_template, request

from analysis import statistics as st
from analysis.report import build_report
from database.db import get_connection, transaction

bp = Blueprint("api", __name__)

EVENT_TYPES = {"connect", "login_failed", "login_success", "command", "session_closed"}
ALERT_STATUSES = {"open", "investigating", "closed", "false_positive"}
SEVERITIES = {"low", "medium", "high", "critical"}
CSV_COLUMNS = ["id", "timestamp", "source_ip", "event_type", "username",
               "password_masked", "command", "session_id"]   # no password_hash
HONEYPOT_PORT = int(__import__("os").environ.get("SENTINEL_HONEYPOT_PORT", "2222"))


class ApiError(Exception):
    def __init__(self, message, status=400):
        super().__init__(message)
        self.message, self.status = message, status


# ------------------------------------------------------------- helpers
def _db():
    return current_app.config["DB_PATH"]


def _query(sql, params=()):
    conn = get_connection(_db())
    try:
        return [dict(r) for r in conn.execute(sql, params).fetchall()]
    finally:
        conn.close()


def _date(name):
    value = request.args.get(name)
    if not value:
        return None
    try:
        datetime.strptime(value, "%Y-%m-%d")
    except ValueError:
        raise ApiError(f"'{name}' must be a valid date in YYYY-MM-DD format")
    return value


def _ip():
    value = request.args.get("ip")
    if not value:
        return None
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        raise ApiError("'ip' is not a valid IP address")


def _choice(name, allowed):
    value = request.args.get(name)
    if not value:
        return None
    if value not in allowed:
        raise ApiError(f"'{name}' must be one of: {', '.join(sorted(allowed))}")
    return value


def _int(name, default, low, high):
    try:
        n = int(request.args.get(name, default))
    except ValueError:
        raise ApiError(f"'{name}' must be an integer")
    return max(low, min(high, n))


def _filters():
    return {"start": _date("start"), "end": _date("end"), "ip": _ip()}


def _attack_where(f, event_type=None):
    sql, params = " WHERE 1=1", []
    if f["start"]:
        sql += " AND substr(timestamp,1,10) >= ?"
        params.append(f["start"])
    if f["end"]:
        sql += " AND substr(timestamp,1,10) <= ?"
        params.append(f["end"])
    if f["ip"]:
        sql += " AND source_ip = ?"
        params.append(f["ip"])
    if event_type:
        sql += " AND event_type = ?"
        params.append(event_type)
    return sql, params


def _port_listening(port):
    """Reads the kernel's socket table; never connects (so no fake events)."""
    wanted = f"{port:04X}"
    for path in ("/proc/net/tcp", "/proc/net/tcp6"):
        try:
            with open(path) as f:
                next(f)
                for line in f:
                    parts = line.split()
                    if parts[3] == "0A" and parts[1].rsplit(":", 1)[1] == wanted:
                        return True
        except OSError:
            continue
    return False


def _safe_cell(value):
    """Neutralise spreadsheet formulas in attacker-controlled text."""
    if isinstance(value, str) and value[:1] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + value
    return value


def _csv_response(rows, columns, filename):
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(columns)
    for r in rows:
        writer.writerow([_safe_cell(r.get(c)) for c in columns])
    return Response(buf.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": f"attachment; filename={filename}"})


# ------------------------------------------------------------- pages
@bp.get("/")
def index():
    return render_template("index.html")


# ------------------------------------------------------------- status
@bp.get("/api/health")
def health():
    return jsonify(status="ok", time=datetime.now(timezone.utc).isoformat())


@bp.get("/api/honeypot/status")
def honeypot_status():
    last = _query("SELECT MAX(timestamp) AS t FROM attacks")[0]["t"]
    return jsonify(port=HONEYPOT_PORT, listening=_port_listening(HONEYPOT_PORT),
                   last_event=last)


# ------------------------------------------------------------- statistics
@bp.get("/api/summary")
def summary():
    f = _filters()
    return jsonify(st.summary(_db(), f["start"], f["end"], f["ip"]))


@bp.get("/api/attackers")
def attackers():
    f = _filters()
    attacks = st.load_attacks(_db(), f["start"], f["end"], f["ip"])
    alerts = st.load_alerts(_db(), f["ip"])
    return jsonify(st.top_ips(attacks, alerts, _int("limit", 10, 1, 100)))


@bp.get("/api/credentials")
def credentials():
    f = _filters()
    attacks = st.load_attacks(_db(), f["start"], f["end"], f["ip"])
    limit = _int("limit", 10, 1, 100)
    return jsonify(usernames=st.top_usernames(attacks, limit),
                   passwords=st.top_passwords(attacks, limit))


@bp.get("/api/timeline")
def timeline():
    f = _filters()
    freq = {"hour": "h", "day": "D"}[_choice("by", {"hour", "day"}) or "hour"]
    attacks = st.load_attacks(_db(), f["start"], f["end"], f["ip"])
    return jsonify(st.attempts_over_time(attacks, freq))


@bp.get("/api/sessions")
def sessions():
    f = _filters()
    return jsonify(st.session_stats(st.load_sessions(_db(), f["ip"])))


# ------------------------------------------------------------- alerts
@bp.get("/api/alerts")
def alerts():
    ip = _ip()
    status = _choice("status", ALERT_STATUSES)
    severity = _choice("severity", SEVERITIES)
    sql, params = "SELECT id, source_ip, alert_type, severity, description, created_at, status " \
                  "FROM alerts WHERE 1=1", []
    for col, val in (("source_ip", ip), ("status", status), ("severity", severity)):
        if val:
            sql += f" AND {col} = ?"
            params.append(val)
    sql += " ORDER BY created_at DESC LIMIT ?"
    params.append(_int("limit", 100, 1, 500))
    return jsonify(_query(sql, params))


@bp.patch("/api/alerts/<int:alert_id>")
def update_alert(alert_id):
    body = request.get_json(silent=True) or {}
    status = body.get("status")
    if status not in ALERT_STATUSES:
        raise ApiError(f"'status' must be one of: {', '.join(sorted(ALERT_STATUSES))}")
    with transaction(_db()) as conn:
        changed = conn.execute("UPDATE alerts SET status = ? WHERE id = ?",
                               (status, alert_id)).rowcount
    if changed == 0:
        raise ApiError("alert not found", 404)
    return jsonify(id=alert_id, status=status)


# ------------------------------------------------------------- attacks
@bp.get("/api/attacks")
def attacks_list():
    f = _filters()
    where, params = _attack_where(f, _choice("event_type", EVENT_TYPES))
    limit, offset = _int("limit", 50, 1, 500), _int("offset", 0, 0, 10**9)
    total = _query(f"SELECT COUNT(*) AS n FROM attacks{where}", params)[0]["n"]
    items = _query(
        "SELECT id, timestamp, source_ip, event_type, username, password_masked, "
        f"command, session_id FROM attacks{where} ORDER BY timestamp DESC LIMIT ? OFFSET ?",
        params + [limit, offset])
    return jsonify(total=total, limit=limit, offset=offset, items=items)


@bp.get("/api/attacks/<int:attack_id>")
def attack_detail(attack_id):
    rows = _query("SELECT id, timestamp, source_ip, event_type, username, password_masked, "
                  "command, session_id FROM attacks WHERE id = ?", (attack_id,))
    if not rows:
        raise ApiError("attack not found", 404)
    a = rows[0]
    return jsonify(
        event=a,
        session=(_query("SELECT * FROM sessions WHERE id = ?", (a["session_id"],)) or [None])[0],
        session_events=_query(
            "SELECT id, timestamp, event_type, username, password_masked, command "
            "FROM attacks WHERE session_id = ? ORDER BY timestamp LIMIT 200", (a["session_id"],)),
        ip_alerts=_query(
            "SELECT id, alert_type, severity, created_at, status FROM alerts "
            "WHERE source_ip = ? ORDER BY created_at DESC LIMIT 20", (a["source_ip"],)),
    )


# ------------------------------------------------------------- export & report
@bp.get("/api/export/attacks.csv")
def export_attacks():
    f = _filters()
    where, params = _attack_where(f, _choice("event_type", EVENT_TYPES))
    rows = _query(f"SELECT {', '.join(CSV_COLUMNS)} FROM attacks{where} "
                  "ORDER BY timestamp LIMIT 100000", params)
    return _csv_response(rows, CSV_COLUMNS, "attacks.csv")


@bp.get("/api/export/alerts.csv")
def export_alerts():
    cols = ["id", "source_ip", "alert_type", "severity", "description", "created_at", "status"]
    rows = _query(f"SELECT {', '.join(cols)} FROM alerts ORDER BY created_at LIMIT 100000")
    return _csv_response(rows, cols, "alerts.csv")


@bp.get("/api/report")
def report():
    f = _filters()
    s = st.summary(_db(), f["start"], f["end"], f["ip"])
    latest = _query("SELECT source_ip, alert_type, severity, created_at, status FROM alerts "
                    "ORDER BY created_at DESC LIMIT 10")
    text = build_report(s, f, latest)
    headers = {"Content-Disposition": "attachment; filename=report.md"} \
        if request.args.get("download") else {}
    return Response(text, mimetype="text/markdown", headers=headers)