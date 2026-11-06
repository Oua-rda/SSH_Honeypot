
import pandas as pd

from database.db import DEFAULT_DB, get_connection

SEV_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}
SEV_NAME = {v: k for k, v in SEV_RANK.items()}
LOGIN_TYPES = ["login_failed", "login_success"]


def _read(sql, params, db_path):
    conn = get_connection(db_path)
    try:
        return pd.read_sql_query(sql, conn, params=params)
    finally:
        conn.close()


def load_attacks(db_path=DEFAULT_DB, start=None, end=None, ip=None) -> pd.DataFrame:
    """Events, optionally filtered. start/end are 'YYYY-MM-DD' (inclusive)."""
    sql, params = "SELECT * FROM attacks WHERE 1=1", []
    if start:
        sql += " AND substr(timestamp,1,10) >= ?"
        params.append(start)
    if end:
        sql += " AND substr(timestamp,1,10) <= ?"
        params.append(end)
    if ip:
        sql += " AND source_ip = ?"
        params.append(ip)
    df = _read(sql, params, db_path)
    df["ts"] = pd.to_datetime(df["timestamp"], utc=True, format="ISO8601")
    return df


def load_alerts(db_path=DEFAULT_DB, ip=None) -> pd.DataFrame:
    sql, params = "SELECT * FROM alerts WHERE 1=1", []
    if ip:
        sql += " AND source_ip = ?"
        params.append(ip)
    return _read(sql, params, db_path)


def load_sessions(db_path=DEFAULT_DB, ip=None) -> pd.DataFrame:
    sql, params = "SELECT * FROM sessions WHERE 1=1", []
    if ip:
        sql += " AND source_ip = ?"
        params.append(ip)
    return _read(sql, params, db_path)


def _iso(series):
    return series.dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def overview(attacks, alerts) -> dict:
    et = attacks["event_type"]
    return {
        "total_connections": int((et == "connect").sum()),
        "failed_logins": int((et == "login_failed").sum()),
        "successful_logins": int((et == "login_success").sum()),
        "unique_ips": int(attacks["source_ip"].nunique()),
        "detected_attacks": int(alerts["source_ip"].nunique()),  # IPs with >= 1 alert
        "total_alerts": int(len(alerts)),
    }


def top_ips(attacks, alerts, limit=10) -> list:
    if attacks.empty:
        return []
    g = attacks.groupby("source_ip").agg(
        events=("event_id", "count"),
        first_seen=("ts", "min"),
        last_seen=("ts", "max"),
    )
    counts = attacks[attacks["event_type"].isin(LOGIN_TYPES)].groupby("source_ip").size()
    failed = attacks[attacks["event_type"] == "login_failed"].groupby("source_ip").size()
    g["login_attempts"] = counts.reindex(g.index, fill_value=0).astype(int)
    g["failed_logins"] = failed.reindex(g.index, fill_value=0).astype(int)

    if alerts.empty:
        g["alerts"], g["max_severity"] = 0, "none"
    else:
        rank = alerts["severity"].map(SEV_RANK)
        top = rank.groupby(alerts["source_ip"]).max().map(SEV_NAME)
        g["max_severity"] = top.reindex(g.index).fillna("none")
        g["alerts"] = alerts.groupby("source_ip").size().reindex(g.index, fill_value=0)

    g = g.sort_values(["failed_logins", "events"], ascending=False).head(limit).reset_index()
    g["first_seen"], g["last_seen"] = _iso(g["first_seen"]), _iso(g["last_seen"])
    return g.to_dict("records")


def top_usernames(attacks, limit=10) -> list:
    logins = attacks[attacks["event_type"].isin(LOGIN_TYPES) & attacks["username"].notna()]
    vc = logins["username"].value_counts().head(limit)
    return [{"username": k, "count": int(v)} for k, v in vc.items()]


def top_passwords(attacks, limit=10) -> list:
    """Most common passwords, shown ONLY in masked form (e.g. '1*****')."""
    pw = attacks[attacks["password_hash"].notna()]
    if pw.empty:
        return []
    g = (pw.groupby("password_hash")
           .agg(password_masked=("password_masked", "first"), count=("event_id", "count"))
           .sort_values("count", ascending=False).head(limit))
    return [{"password_masked": r.password_masked, "count": int(r.count)}
            for r in g.itertuples()]


def attempts_over_time(attacks, freq="h") -> dict:
    """Login attempts per hour ('h') or per day ('D'), zero-filled."""
    empty = {"labels": [], "failed": [], "success": []}
    logins = attacks[attacks["event_type"].isin(LOGIN_TYPES)]
    if logins.empty:
        return empty
    counts = (logins.groupby([pd.Grouper(key="ts", freq=freq), "event_type"])
                    .size().unstack(fill_value=0))
    full = pd.date_range(counts.index.min(), counts.index.max(), freq=freq)
    counts = counts.reindex(full, fill_value=0)
    for col in LOGIN_TYPES:
        if col not in counts:
            counts[col] = 0
    fmt = "%Y-%m-%d %H:00" if freq == "h" else "%Y-%m-%d"
    return {
        "labels": list(counts.index.strftime(fmt)),
        "failed": [int(x) for x in counts["login_failed"]],
        "success": [int(x) for x in counts["login_success"]],
    }


def session_stats(sessions) -> dict:
    if sessions.empty:
        return {"total": 0, "avg_duration_s": 0, "max_duration_s": 0,
                "total_commands": 0, "recent": []}
    dur = sessions["duration_s"].dropna()
    recent = sessions.sort_values("start_time", ascending=False).head(10)
    return {
        "total": int(len(sessions)),
        "avg_duration_s": round(float(dur.mean()), 2) if len(dur) else 0,
        "max_duration_s": round(float(dur.max()), 2) if len(dur) else 0,
        "total_commands": int(sessions["commands_count"].sum()),
        "recent": recent[["id", "source_ip", "start_time", "duration_s",
                          "commands_count"]].fillna("").to_dict("records"),
    }


def alert_breakdown(alerts) -> dict:
    return {
        "by_severity": {k: int(v) for k, v in alerts["severity"].value_counts().items()},
        "by_type": {k: int(v) for k, v in alerts["alert_type"].value_counts().items()},
    }


def summary(db_path=DEFAULT_DB, start=None, end=None, ip=None) -> dict:
    """Everything the dashboard needs, in one call."""
    attacks = load_attacks(db_path, start, end, ip)
    alerts = load_alerts(db_path, ip)
    sessions = load_sessions(db_path, ip)
    return {
        "overview": overview(attacks, alerts),
        "top_ips": top_ips(attacks, alerts),
        "top_usernames": top_usernames(attacks),
        "top_passwords": top_passwords(attacks),
        "hourly": attempts_over_time(attacks, "h"),
        "daily": attempts_over_time(attacks, "D"),
        "sessions": session_stats(sessions),
        "alerts": alert_breakdown(alerts),
    }