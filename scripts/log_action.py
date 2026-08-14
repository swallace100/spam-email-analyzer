#!/usr/bin/env python3
"""Log an enforcement action you've taken against a bad actor into
data/actions.csv -- the record of what you DID with the intelligence
(IC3 complaints, registrar/hosting abuse reports, Chainabuse filings).

The dashboard's Actions tab lists this log, and any indicator you've
acted on (a wallet, a domain, an IP) gets a "reported" badge in its own
table. The xlsx gets an Actions sheet. The CSV is also fine to edit by
hand in Excel -- this script is just the quick path.

Usage:
    python scripts/log_action.py ic3_report wallet 1AbC... --ref "IC3 #I26..." --notes "full tx list attached"
    python scripts/log_action.py registrar_abuse domain evil.top --ref "GoDaddy ticket 123" --status acknowledged
    python scripts/log_action.py --list          # show the log

Suggested action values: ic3_report, registrar_abuse, hosting_abuse,
chainabuse_report, phishing_report, ftc_report, other. Free text is
accepted -- these are just what the dashboard groups nicely.
Suggested status values: submitted, acknowledged, actioned, no_response.
"""

import argparse
import csv
import os
import sys
from datetime import date

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ACTIONS_CSV = os.path.join(BASE, "data", "actions.csv")
FIELDNAMES = ["date", "action", "target_type", "target", "reference", "status", "notes"]

TARGET_TYPES = ["wallet", "domain", "ip", "asn", "url", "email", "phone", "other"]


def load_rows():
    if not os.path.exists(ACTIONS_CSV):
        return []
    with open(ACTIONS_CSV, encoding="utf-8") as f:
        return list(csv.DictReader(f))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("action", nargs="?", help="What you did (e.g. ic3_report, registrar_abuse).")
    parser.add_argument("target_type", nargs="?", choices=TARGET_TYPES,
                        help="What kind of indicator the action targets.")
    parser.add_argument("target", nargs="?",
                        help="The indicator itself, un-defanged (wallet address, domain, IP...).")
    parser.add_argument("--ref", default="", help="Case/ticket/complaint number to find it again.")
    parser.add_argument("--status", default="submitted",
                        help="submitted (default), acknowledged, actioned, no_response...")
    parser.add_argument("--notes", default="", help="Anything future-you needs to know.")
    parser.add_argument("--date", default=date.today().isoformat(),
                        help="Action date, YYYY-MM-DD (default today).")
    parser.add_argument("--list", action="store_true", help="Print the log and exit.")
    args = parser.parse_args(argv)

    if args.list:
        rows = load_rows()
        if not rows:
            print(f"No actions logged yet ({ACTIONS_CSV} doesn't exist).")
            return
        for r in rows:
            ref = f"  [{r['reference']}]" if r.get("reference") else ""
            print(f"{r['date']}  {r['action']:<18} {r['target_type']:<7} {r['target']}"
                  f"  ({r['status']}){ref}")
            if r.get("notes"):
                print(f"{'':12}{r['notes']}")
        print(f"\n{len(rows)} action(s) in {ACTIONS_CSV}")
        return

    if not (args.action and args.target_type and args.target):
        parser.error("action, target_type, and target are required (or use --list).")

    file_exists = os.path.exists(ACTIONS_CSV)
    with open(ACTIONS_CSV, "a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDNAMES)
        if not file_exists:
            writer.writeheader()
        writer.writerow({"date": args.date, "action": args.action,
                         "target_type": args.target_type, "target": args.target,
                         "reference": args.ref, "status": args.status,
                         "notes": args.notes})
    print(f"Logged: {args.date} {args.action} -> {args.target_type} {args.target}")
    print("Rebuild the report/dashboard (or run publish.ps1) to see it reflected.")


if __name__ == "__main__":
    main()
