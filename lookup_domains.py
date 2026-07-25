#!/usr/bin/env python3
"""Look up WHOIS registration info for scam sender domains and append the
results to data/domain_enrichment.csv, skipping domains already recorded
there. By default this only looks at domains that showed up in 2+
messages (the same threshold "Domain Clusters" uses) -- one-off senders
usually aren't worth a lookup, and every skipped domain is one less
request against a WHOIS server.

Waits between each lookup (default 8s) so as not to hammer WHOIS servers,
which commonly rate-limit or temporarily block IPs that query too fast.

Usage:
    python3 lookup_domains.py                  # 2+ message domains, 8s delay
    python3 lookup_domains.py --all            # every sender domain
    python3 lookup_domains.py --delay 15       # slower, more polite
    python3 lookup_domains.py --limit 20       # only do 20 this run
"""

import argparse
import csv
import os
import time
from collections import Counter

import whois

BASE = os.path.dirname(os.path.abspath(__file__))
MASTER_CSV = os.path.join(BASE, "data", "master_iocs.csv")
ENRICHMENT_CSV = os.path.join(BASE, "data", "domain_enrichment.csv")
ENRICHMENT_FIELDNAMES = ["domain", "registered_date", "registrar", "notes"]

DEFAULT_DELAY_SECONDS = 8
MIN_MESSAGES = 2


def load_candidate_domains(min_messages):
    with open(MASTER_CSV, encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    counts = Counter(r["from_domain"] for r in rows if r["from_domain"])
    return sorted(d for d, c in counts.items() if c >= min_messages)


def load_already_enriched():
    if not os.path.exists(ENRICHMENT_CSV):
        return set()
    with open(ENRICHMENT_CSV, encoding="utf-8") as f:
        return {r["domain"] for r in csv.DictReader(f)}


def append_enrichment(rows):
    file_exists = os.path.exists(ENRICHMENT_CSV)
    with open(ENRICHMENT_CSV, "a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=ENRICHMENT_FIELDNAMES)
        if not file_exists:
            writer.writeheader()
        writer.writerows(rows)


def format_date(value):
    # python-whois sometimes returns a list when multiple WHOIS records
    # disagree (e.g. registry vs. registrar) -- just take the first.
    if isinstance(value, list):
        value = value[0] if value else None
    if value is None:
        return ""
    return str(value.date()) if hasattr(value, "date") else str(value)


def lookup_one(domain):
    result = whois.whois(domain)
    return format_date(result.creation_date), (result.registrar or "")


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                      formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--all", action="store_true",
                        help="Look up every sender domain, not just ones seen 2+ times.")
    parser.add_argument("--delay", type=float, default=DEFAULT_DELAY_SECONDS,
                        help=f"Seconds to wait between lookups (default {DEFAULT_DELAY_SECONDS}).")
    parser.add_argument("--limit", type=int, default=None,
                        help="Look up at most N domains this run.")
    args = parser.parse_args()

    if not os.path.exists(MASTER_CSV):
        print(f"No {MASTER_CSV} yet -- nothing to look up.")
        return

    candidates = load_candidate_domains(1 if args.all else MIN_MESSAGES)
    already = load_already_enriched()
    todo = [d for d in candidates if d not in already]
    if args.limit:
        todo = todo[:args.limit]

    if not todo:
        print("Nothing new to look up.")
        return

    print(f"Looking up {len(todo)} domain(s), waiting {args.delay}s between each...")
    new_rows = []
    for i, domain in enumerate(todo):
        try:
            registered, registrar = lookup_one(domain)
            print(f"  [{i + 1}/{len(todo)}] {domain}: registered={registered!r} registrar={registrar!r}")
            new_rows.append({"domain": domain, "registered_date": registered,
                              "registrar": registrar, "notes": ""})
        except Exception as e:
            print(f"  [{i + 1}/{len(todo)}] {domain}: lookup failed ({e})")
        if i < len(todo) - 1:
            time.sleep(args.delay)

    if new_rows:
        append_enrichment(new_rows)
        print(f"Added {len(new_rows)} row(s) to {ENRICHMENT_CSV}")
    else:
        print("No successful lookups to add.")


if __name__ == "__main__":
    main()
