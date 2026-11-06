
import argparse
import json
from collections import Counter, defaultdict

from database.db import DEFAULT_DB, init_db, transaction
from detection.detection_rules import run_rules

EVENT_COLUMNS = ("event_id, source_ip, username, password_masked, password_hash, "
                 "command, timestamp, event_type, session_id")


def run_detection(db_path=DEFAULT_DB, config=None) -> dict:
    init_db(db_path)
    with transaction(db_path) as conn:
        rows = conn.execute(f"SELECT {EVENT_COLUMNS} FROM attacks ORDER BY timestamp").fetchall()

    by_ip = defaultdict(list)
    for r in rows:
        by_ip[r["source_ip"]].append(dict(r))

    found, new = [], 0
    for ip, events in by_ip.items():
        found += run_rules(ip, events, config)

    with transaction(db_path) as conn:
        for a in found:
            cur = conn.execute(
                """INSERT OR IGNORE INTO alerts
                   (source_ip, alert_type, severity, description, created_at, dedup_key)
                   VALUES (?,?,?,?,?,?)""",
                (a["source_ip"], a["alert_type"], a["severity"], a["description"],
                 a["created_at"], a["dedup_key"]))
            new += cur.rowcount
    return {"alerts_found": len(found), "new_alerts": new}


def main():
    parser = argparse.ArgumentParser(description="SSH Sentinel detection engine")
    parser.add_argument("--config", help="JSON file with threshold overrides")
    args = parser.parse_args()
    config = json.load(open(args.config)) if args.config else None

    result = run_detection(config=config)
    print(f"Alerts found: {result['alerts_found']}  (new: {result['new_alerts']})")

    with transaction(DEFAULT_DB) as conn:
        rows = conn.execute(
            "SELECT alert_type, severity, source_ip, created_at FROM alerts "
            "ORDER BY created_at DESC LIMIT 10").fetchall()
        by_type = Counter(r[0] for r in conn.execute("SELECT alert_type FROM alerts"))
    print("Totals by type:", dict(by_type))
    print("\nLatest alerts:")
    for r in rows:
        print(f"  {r['created_at']}  {r['severity']:<8} {r['alert_type']:<24} {r['source_ip']}")


if __name__ == "__main__":
    main()