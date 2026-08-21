#!/usr/bin/env python3
"""Mark a message as triaged in data/triage.csv -- the record of which
likely_scam/review messages you've actually looked at.

build_master_report.py's Triage Queue sheet is a full rebuild from
master_iocs.csv every run (like every other sheet), but this CSV is never
rebuilt, only appended to -- so marking something triaged here sticks
across report regenerations. Any likely_scam/review message whose id has
no row in this CSV is still "new" and shows up in the queue.

Usage:
    python scripts/mark_triage.py <message_id> reviewed --notes "just a coupon blast, ignore"
    python scripts/mark_triage.py <message_id> escalated --notes "active BTC wallet, filing IC3"
    python scripts/mark_triage.py --list          # show the log

Suggested status values: reviewed, dismissed, escalated. Free text is
accepted -- these are just what the report groups nicely.
"""

import argparse
import csv
import os
from datetime import date

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TRIAGE_CSV = os.path.join(BASE, "data", "triage.csv")
FIELDNAMES = ["id", "status", "date", "notes"]


def load_rows():
    if not os.path.exists(TRIAGE_CSV):
        return []
    with open(TRIAGE_CSV, encoding="utf-8") as f:
        return list(csv.DictReader(f))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("id", nargs="?", help="Message id (from the Emails sheet / master_iocs.csv).")
    parser.add_argument("status", nargs="?", default="reviewed",
                        help="reviewed (default), dismissed, escalated...")
    parser.add_argument("--notes", default="", help="Anything future-you needs to know.")
    parser.add_argument("--date", default=date.today().isoformat(),
                        help="Triage date, YYYY-MM-DD (default today).")
    parser.add_argument("--list", action="store_true", help="Print the log and exit.")
    args = parser.parse_args(argv)

    if args.list:
        rows = load_rows()
        if not rows:
            print(f"No messages triaged yet ({TRIAGE_CSV} doesn't exist).")
            return
        for r in rows:
            print(f"{r['date']}  {r['status']:<10} {r['id']}")
            if r.get("notes"):
                print(f"{'':12}{r['notes']}")
        print(f"\n{len(rows)} message(s) triaged in {TRIAGE_CSV}")
        return

    if not args.id:
        parser.error("id is required (or use --list).")

    file_exists = os.path.exists(TRIAGE_CSV)
    with open(TRIAGE_CSV, "a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDNAMES)
        if not file_exists:
            writer.writeheader()
        writer.writerow({"id": args.id, "status": args.status,
                         "date": args.date, "notes": args.notes})
    print(f"Marked {args.id} -> {args.status}")
    print("Rebuild the report (or run publish.ps1) to see it reflected.")


if __name__ == "__main__":
    main()
