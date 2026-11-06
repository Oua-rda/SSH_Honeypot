"""
database/db.py
SQLite access layer for SSH Sentinel.
"""
import os
import sqlite3
from contextlib import contextmanager
from pathlib import Path

DEFAULT_DB = Path(os.environ.get("SENTINEL_DB", "data/sentinel.db"))
SCHEMA_FILE = Path(__file__).with_name("schema.sql")


def get_connection(db_path=DEFAULT_DB) -> sqlite3.Connection:
    db_path = Path(db_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row          # rows behave like dicts
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


@contextmanager
def transaction(db_path=DEFAULT_DB):
    """Commit on success, roll back on any error."""
    conn = get_connection(db_path)
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db(db_path=DEFAULT_DB) -> None:
    db_path = Path(db_path)
    with transaction(db_path) as conn:
        conn.executescript(SCHEMA_FILE.read_text())
    try:
        os.chmod(db_path, 0o600)            # owner-only: protect attacker data
    except OSError:
        pass


def insert_events(events: list, db_path=DEFAULT_DB) -> dict:
    """Store events. Returns counts of new and duplicate events."""
    new = dup = 0
    with transaction(db_path) as conn:
        for e in events:
            cur = conn.execute(
                """INSERT OR IGNORE INTO attacks
                   (event_id, source_ip, username, password_masked, password_hash,
                    command, timestamp, event_type, session_id)
                   VALUES (?,?,?,?,?,?,?,?,?)""",
                (e["event_id"], e["source_ip"], e["username"], e["password_masked"],
                 e["password_hash"], e["command"], e["timestamp"], e["event_type"],
                 e["session_id"]),
            )
            if cur.rowcount == 0:
                dup += 1
                continue
            new += 1
            _update_session(conn, e)
    return {"new": new, "duplicates": dup}


def _update_session(conn, e: dict) -> None:
    sid, ip, ts, etype = e["session_id"], e["source_ip"], e["timestamp"], e["event_type"]

    conn.execute(
        "INSERT OR IGNORE INTO sessions (id, source_ip, start_time) VALUES (?,?,?)",
        (sid, ip, ts),
    )
    if etype == "connect":
        conn.execute("UPDATE sessions SET start_time = ? WHERE id = ?", (ts, sid))
    elif etype == "command":
        conn.execute(
            "UPDATE sessions SET commands_count = commands_count + 1 WHERE id = ?", (sid,)
        )
    elif etype == "session_closed":
        conn.execute(
            "UPDATE sessions SET end_time = ?, duration_s = ? WHERE id = ?",
            (ts, e["duration_s"], sid),
        )


def count_rows(db_path=DEFAULT_DB) -> dict:
    with transaction(db_path) as conn:
        return {
            t: conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
            for t in ("attacks", "sessions", "alerts")
        }