
import argparse
import hashlib
import json
import logging
import os
from collections import Counter
from pathlib import Path
from typing import Optional

log = logging.getLogger("collector")

DEFAULT_LOG = os.environ.get(
    "SENTINEL_COWRIE_LOG",
    "/home/cowrie/Honeypot/var/log/cowrie/cowrie.json",
)
DEFAULT_STATE = Path("data/collector_state.json")

# Cowrie eventid -> our simplified event type
RELEVANT_EVENTS = {
    "cowrie.session.connect": "connect",
    "cowrie.login.failed": "login_failed",
    "cowrie.login.success": "login_success",
    "cowrie.command.input": "command",
    "cowrie.session.closed": "session_closed",
}
REQUIRED_FIELDS = ("eventid", "timestamp", "src_ip", "session")


def mask_password(password: str) -> str:
    """Keep only the first character: 'hunter2' -> 'h******'."""
    if not password:
        return ""
    return password[0] + "*" * (len(password) - 1)


def hash_password(password: str) -> str:
    """Short SHA-256 fingerprint, so equal passwords can be compared safely."""
    if not password:
        return ""
    return hashlib.sha256(password.encode("utf-8")).hexdigest()[:16]


def parse_line(raw: str) -> Optional[dict]:
    """Turn one raw log line into an event dict, or None if unusable."""
    raw = raw.strip()
    if not raw:
        return None

    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        log.warning("Skipping malformed JSON line: %.60s", raw)
        return None

    if not isinstance(data, dict):
        log.warning("Skipping non-object JSON line")
        return None

    event_type = RELEVANT_EVENTS.get(data.get("eventid"))
    if event_type is None:
        return None  # valid Cowrie event we don't need (e.g. client.version)

    missing = [f for f in REQUIRED_FIELDS if not data.get(f)]
    if missing:
        log.warning("Skipping %s event, missing fields: %s", data["eventid"], missing)
        return None

    password = data.get("password", "")
    duration_ms = data.get("duration_ms")

    return {
        "event_id": hashlib.sha256(raw.encode("utf-8")).hexdigest(),
        "event_type": event_type,
        "timestamp": data["timestamp"],            # ISO 8601, UTC
        "source_ip": data["src_ip"],
        "session_id": data["session"],
        "username": data.get("username"),
        "password_masked": mask_password(password) if password else None,
        "password_hash": hash_password(password) if password else None,
        "command": data.get("input"),
        "duration_s": round(duration_ms / 1000, 3) if isinstance(duration_ms, (int, float)) else None,
    }


class LogReader:
    """Reads only NEW lines since the last run and remembers its position."""

    def __init__(self, log_path=DEFAULT_LOG, state_path=DEFAULT_STATE):
        self.log_path = Path(log_path)
        self.state_path = Path(state_path)

    def _load_state(self) -> dict:
        try:
            return json.loads(self.state_path.read_text())
        except (FileNotFoundError, json.JSONDecodeError):
            return {"inode": None, "offset": 0}

    def _save_state(self, state: dict) -> None:
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.state_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(state))
        tmp.replace(self.state_path)  # atomic swap

    def read_new_events(self) -> list:
        state = self._load_state()
        stat = self.log_path.stat()

        # Rotation or truncation: new file (different inode) or file got smaller
        if state["inode"] != stat.st_ino or stat.st_size < state["offset"]:
            if state["inode"] is not None:
                log.info("Log rotation/truncation detected, restarting at offset 0")
            state = {"inode": stat.st_ino, "offset": 0}

        events = []
        with open(self.log_path, "rb") as f:
            f.seek(state["offset"])
            while True:
                line = f.readline()
                if not line:
                    break
                if not line.endswith(b"\n"):
                    break  # partial line still being written; retry next run
                state["offset"] = f.tell()
                event = parse_line(line.decode("utf-8", errors="replace"))
                if event:
                    events.append(event)

        self._save_state(state)
        return events


def main():
    parser = argparse.ArgumentParser(description="SSH Sentinel log collector")
    parser.add_argument("--path", default=DEFAULT_LOG)
    parser.add_argument("--state", default=str(DEFAULT_STATE))
    parser.add_argument("--reset", action="store_true", help="re-read from the start")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    if args.reset and Path(args.state).exists():
        Path(args.state).unlink()

    events = LogReader(args.path, args.state).read_new_events()

    print(f"\nCollected {len(events)} new events")
    for etype, n in Counter(e["event_type"] for e in events).most_common():
        print(f"  {n:4d}  {etype}")

    print("\nLast 5 events:")
    for e in events[-5:]:
        print(f"  {e['timestamp']}  {e['event_type']:<14} ip={e['source_ip']} "
              f"user={e['username']} pw={e['password_masked']} cmd={e['command']}")


if __name__ == "__main__":
    main()