
import argparse
import logging
from pathlib import Path

from collector.log_collector import LogReader, DEFAULT_LOG, DEFAULT_STATE
from database.db import init_db, insert_events, count_rows, DEFAULT_DB


def run(log_path=DEFAULT_LOG, state_path=DEFAULT_STATE, db_path=DEFAULT_DB) -> dict:
    init_db(db_path)
    events = LogReader(log_path, state_path).read_new_events()
    result = insert_events(events, db_path)
    result["read"] = len(events)
    return result


def main():
    parser = argparse.ArgumentParser(description="Ingest Cowrie events into SQLite")
    parser.add_argument("--reset", action="store_true", help="re-read the log from the start")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    if args.reset and Path(DEFAULT_STATE).exists():
        Path(DEFAULT_STATE).unlink()

    r = run()
    print(f"Read {r['read']} events: {r['new']} new, {r['duplicates']} duplicates")
    print("Database totals:", count_rows())


if __name__ == "__main__":
    main()