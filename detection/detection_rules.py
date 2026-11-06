import re
from collections import defaultdict, deque
from datetime import datetime, timezone

DEFAULT_CONFIG = {
    "brute_force":            {"enabled": True, "max_failures": 5, "window_s": 60, "severity": "medium"},
    "rapid_attack":           {"enabled": True, "max_failures": 10, "window_s": 30, "severity": "high"},
    "username_enumeration":   {"enabled": True, "distinct_usernames": 5, "window_s": 60, "severity": "medium"},
    "password_spraying":      {"enabled": True, "distinct_usernames": 3, "window_s": 300, "severity": "high"},
    "repeated_attacks":       {"enabled": True, "min_periods": 3, "period_s": 3600,
                               "min_failures_per_period": 3, "severity": "medium"},
    "success_after_failures": {"enabled": True, "min_failures": 5, "lookback_s": 600, "severity": "critical"},
    "suspicious_commands":    {"enabled": True},
}

DISCLAIMER = "This is a threshold-based signal, not proof of compromise."

COMMAND_PATTERNS = {
    "reconnaissance": ("low", [r"\b(uname|whoami|id|ifconfig|netstat|lscpu|hostname)\b",
                               r"\bip\s+a\b", r"\bps\s+aux", r"/proc/(cpuinfo|meminfo)"]),
    "credential_access": ("medium", [r"/etc/(passwd|shadow)"]),
    "download": ("high", [r"\b(wget|curl|tftp|ftpget)\b"]),
    "execution": ("high", [r"\bchmod\s+\+?[0-7x]+", r"\bbash\s+-i\b", r"/dev/tcp/",
                           r"\b(nc|ncat|netcat)\b.*\s-e\b"]),
    "persistence": ("high", [r"\bcrontab\b", r"authorized_keys"]),
}
_COMPILED = {cat: (sev, [re.compile(p, re.IGNORECASE) for p in pats])
             for cat, (sev, pats) in COMMAND_PATTERNS.items()}
_SEV_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def parse_ts(value: str) -> datetime:
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _alert(ip, atype, severity, description, created_at, key):
    return {"source_ip": ip, "alert_type": atype, "severity": severity,
            "description": f"{description} {DISCLAIMER}",
            "created_at": created_at, "dedup_key": key}


def _failures(events):
    return [e for e in events if e["event_type"] == "login_failed"]


def rule_failure_burst(ip, events, cfg, atype):
    alerts, window = [], deque()
    for e in _failures(events):
        window.append(e)
        while (e["dt"] - window[0]["dt"]).total_seconds() > cfg["window_s"]:
            window.popleft()
        if len(window) >= cfg["max_failures"]:
            first = window[0]
            span = (e["dt"] - first["dt"]).total_seconds()
            alerts.append(_alert(
                ip, atype, cfg["severity"],
                f"{len(window)} failed logins in {span:.0f}s "
                f"(threshold: {cfg['max_failures']} in {cfg['window_s']}s). "
                f"Possible brute-force activity.",
                e["timestamp"], f"{atype}:{ip}:{first['timestamp']}"))
            window.clear()          # one alert per burst
    return alerts


def rule_username_enumeration(ip, events, cfg):
    alerts, window = [], deque()
    for e in _failures(events):
        window.append(e)
        while (e["dt"] - window[0]["dt"]).total_seconds() > cfg["window_s"]:
            window.popleft()
        names = {w["username"] for w in window if w["username"]}
        if len(names) >= cfg["distinct_usernames"]:
            alerts.append(_alert(
                ip, "username_enumeration", cfg["severity"],
                f"{len(names)} different usernames tried within {cfg['window_s']}s.",
                e["timestamp"], f"username_enumeration:{ip}:{window[0]['timestamp']}"))
            window.clear()
    return alerts


def rule_password_spraying(ip, events, cfg):
    by_hash = defaultdict(list)
    for e in _failures(events):
        if e["password_hash"]:
            by_hash[e["password_hash"]].append(e)

    alerts = []
    for pw_hash, evs in by_hash.items():
        window = deque()
        for e in evs:
            window.append(e)
            while (e["dt"] - window[0]["dt"]).total_seconds() > cfg["window_s"]:
                window.popleft()
            names = {w["username"] for w in window if w["username"]}
            if len(names) >= cfg["distinct_usernames"]:
                alerts.append(_alert(
                    ip, "password_spraying", cfg["severity"],
                    f"The same password ({e['password_masked']}) was tried against "
                    f"{len(names)} usernames within {cfg['window_s']}s.",
                    e["timestamp"], f"password_spraying:{ip}:{pw_hash}:{window[0]['timestamp']}"))
                window.clear()
    return alerts


def rule_repeated_attacks(ip, events, cfg):
    buckets = defaultdict(int)
    fails = _failures(events)
    for e in fails:
        buckets[int(e["dt"].timestamp() // cfg["period_s"])] += 1
    active = [b for b, n in buckets.items() if n >= cfg["min_failures_per_period"]]
    if len(active) >= cfg["min_periods"]:
        return [_alert(
            ip, "repeated_attacks", cfg["severity"],
            f"Failed logins in {len(active)} separate {cfg['period_s']}s periods "
            f"(at least {cfg['min_failures_per_period']} each). Persistent source.",
            fails[-1]["timestamp"], f"repeated_attacks:{ip}")]
    return []


def rule_success_after_failures(ip, events, cfg):
    fails = _failures(events)
    alerts = []
    for e in events:
        if e["event_type"] != "login_success":
            continue
        prior = [f for f in fails
                 if 0 <= (e["dt"] - f["dt"]).total_seconds() <= cfg["lookback_s"]]
        if len(prior) >= cfg["min_failures"]:
            alerts.append(_alert(
                ip, "success_after_failures", cfg["severity"],
                f"Simulated login succeeded for '{e['username']}' after {len(prior)} "
                f"failures in the previous {cfg['lookback_s']}s. High-priority investigation.",
                e["timestamp"], f"success_after_failures:{ip}:{e['session_id']}"))
    return alerts


def rule_suspicious_commands(ip, events, cfg):
    sessions = {}
    for e in events:
        if e["event_type"] != "command" or not e["command"]:
            continue
        for cat, (sev, patterns) in _COMPILED.items():
            if any(p.search(e["command"]) for p in patterns):
                s = sessions.setdefault(e["session_id"], {
                    "cats": set(), "sev": "low", "first_ts": e["timestamp"],
                    "example": e["command"][:80]})
                s["cats"].add(cat)
                if _SEV_ORDER[sev] > _SEV_ORDER[s["sev"]]:
                    s["sev"], s["example"] = sev, e["command"][:80]
    return [_alert(
        ip, "suspicious_commands", s["sev"],
        f"Session {sid} ran commands in categories: {', '.join(sorted(s['cats']))}. "
        f"Example: {s['example']!r}.",
        s["first_ts"], f"suspicious_commands:{sid}")
        for sid, s in sessions.items()]


def merged_config(overrides=None) -> dict:
    cfg = {k: dict(v) for k, v in DEFAULT_CONFIG.items()}
    for k, v in (overrides or {}).items():
        cfg.setdefault(k, {}).update(v)
    return cfg


def run_rules(ip, events, config=None) -> list:
    """Run every enabled rule on one IP's events."""
    cfg = merged_config(config)
    events = sorted(({**e, "dt": parse_ts(e["timestamp"])} for e in events),
                    key=lambda e: e["dt"])
    alerts = []
    if cfg["brute_force"]["enabled"]:
        alerts += rule_failure_burst(ip, events, cfg["brute_force"], "brute_force")
    if cfg["rapid_attack"]["enabled"]:
        alerts += rule_failure_burst(ip, events, cfg["rapid_attack"], "rapid_attack")
    if cfg["username_enumeration"]["enabled"]:
        alerts += rule_username_enumeration(ip, events, cfg["username_enumeration"])
    if cfg["password_spraying"]["enabled"]:
        alerts += rule_password_spraying(ip, events, cfg["password_spraying"])
    if cfg["repeated_attacks"]["enabled"]:
        alerts += rule_repeated_attacks(ip, events, cfg["repeated_attacks"])
    if cfg["success_after_failures"]["enabled"]:
        alerts += rule_success_after_failures(ip, events, cfg["success_after_failures"])
    if cfg["suspicious_commands"]["enabled"]:
        alerts += rule_suspicious_commands(ip, events, cfg["suspicious_commands"])
    return alerts