PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS attacks (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id        TEXT NOT NULL UNIQUE,
    source_ip       TEXT NOT NULL,
    username        TEXT,
    password_masked TEXT,
    password_hash   TEXT,
    command         TEXT,
    timestamp       TEXT NOT NULL,
    event_type      TEXT NOT NULL,
    session_id      TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_attacks_ip_time ON attacks (source_ip, timestamp);
CREATE INDEX IF NOT EXISTS idx_attacks_type    ON attacks (event_type);
CREATE INDEX IF NOT EXISTS idx_attacks_session ON attacks (session_id);

CREATE TABLE IF NOT EXISTS sessions (
    id             TEXT PRIMARY KEY,
    source_ip      TEXT NOT NULL,
    start_time     TEXT,
    end_time       TEXT,
    duration_s     REAL,
    commands_count INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_sessions_ip ON sessions (source_ip);

CREATE TABLE IF NOT EXISTS alerts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    source_ip   TEXT NOT NULL,
    alert_type  TEXT NOT NULL,
    severity    TEXT NOT NULL CHECK (severity IN ('low','medium','high','critical')),
    description TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'open'
                CHECK (status IN ('open','investigating','closed','false_positive')),
    dedup_key   TEXT UNIQUE
);

CREATE INDEX IF NOT EXISTS idx_alerts_ip ON alerts (source_ip);