
import argparse
import json
from pathlib import Path

import matplotlib
matplotlib.use("Agg")               
import matplotlib.pyplot as plt

from analysis.statistics import summary

REPORTS = Path("reports")


def save_plots(s: dict) -> list:
    REPORTS.mkdir(exist_ok=True)
    saved = []

    h = s["hourly"]
    if h["labels"]:
        fig, ax = plt.subplots(figsize=(10, 4))
        ax.bar(h["labels"], h["failed"], label="Failed", color="#d9534f")
        ax.bar(h["labels"], h["success"], bottom=h["failed"], label="Success", color="#5cb85c")
        ax.set_title("Login attempts per hour")
        ax.set_ylabel("Attempts")
        ax.legend()
        plt.xticks(rotation=45, ha="right")
        fig.tight_layout()
        path = REPORTS / "attempts_per_hour.png"
        fig.savefig(path, dpi=120)
        plt.close(fig)
        saved.append(path)

    ips = s["top_ips"]
    if ips:
        fig, ax = plt.subplots(figsize=(8, 4))
        ax.barh([i["source_ip"] for i in ips][::-1],
                [i["failed_logins"] for i in ips][::-1], color="#f0ad4e")
        ax.set_title("Top source IPs (failed logins)")
        fig.tight_layout()
        path = REPORTS / "top_ips.png"
        fig.savefig(path, dpi=120)
        plt.close(fig)
        saved.append(path)
    return saved


def main():
    p = argparse.ArgumentParser(description="SSH Sentinel analysis report")
    p.add_argument("--start", help="YYYY-MM-DD")
    p.add_argument("--end", help="YYYY-MM-DD")
    p.add_argument("--ip")
    p.add_argument("--plots", action="store_true", help="save PNG graphs to reports/")
    p.add_argument("--json", action="store_true", help="print the full result as JSON")
    a = p.parse_args()

    s = summary(start=a.start, end=a.end, ip=a.ip)
    if a.json:
        print(json.dumps(s, indent=2))
    else:
        print("== Overview ==")
        for k, v in s["overview"].items():
            print(f"  {k:<20} {v}")
        print("\n== Top IPs ==")
        for i in s["top_ips"]:
            print(f"  {i['source_ip']:<16} failed={i['failed_logins']:<4} "
                  f"events={i['events']:<4} severity={i['max_severity']}")
        print("\n== Top usernames ==", s["top_usernames"])
        print("== Top passwords (masked) ==", s["top_passwords"])
        print("== Sessions ==", {k: v for k, v in s["sessions"].items() if k != "recent"})
        print("== Alerts ==", s["alerts"])
    if a.plots:
        for path in save_plots(s):
            print("Saved", path)


if __name__ == "__main__":
    main()