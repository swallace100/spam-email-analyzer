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
# nameservers/registrant fields exist so the report can correlate burner
# domains that were bought together: same registrar + same nameservers +
# registered within days of each other = one operator's shopping trip.
ENRICHMENT_FIELDNAMES = ["domain", "registered_date", "registrar",
                         "nameservers", "registrant_org", "registrant_country",
                         "notes"]

DEFAULT_DELAY_SECONDS = 8
MIN_MESSAGES = 2


def migrate_schema():
    """Rewrite domain_enrichment.csv with the current columns if it predates
    them (new columns blank for old rows). Same idea as process_mail.py's
    master-CSV migration."""
    if not os.path.exists(ENRICHMENT_CSV):
        return
    with open(ENRICHMENT_CSV, encoding="utf-8") as f:
        reader = csv.DictReader(f)
        if reader.fieldnames == ENRICHMENT_FIELDNAMES:
            return
        old_rows = list(reader)
    tmp = ENRICHMENT_CSV + ".tmp"
    with open(tmp, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=ENRICHMENT_FIELDNAMES)
        writer.writeheader()
        for r in old_rows:
            writer.writerow({k: r.get(k, "") for k in ENRICHMENT_FIELDNAMES})
    os.replace(tmp, ENRICHMENT_CSV)
    print(f"Migrated {ENRICHMENT_CSV} to the current schema ({len(old_rows)} rows kept).")


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


def _as_str(value):
    if isinstance(value, list):
        value = value[0] if value else ""
    return str(value or "")


def format_nameservers(value):
    if value is None:
        return ""
    if isinstance(value, str):
        value = [value]
    # normalize: lowercase, strip trailing dots, dedupe
    return "; ".join(sorted({ns.lower().rstrip(".") for ns in value if ns}))


def lookup_one(domain):
    result = whois.whois(domain)
    return {
        "registered_date": format_date(result.creation_date),
        "registrar": _as_str(result.registrar),
        "nameservers": format_nameservers(result.name_servers),
        "registrant_org": _as_str(getattr(result, "org", "")),
        "registrant_country": _as_str(getattr(result, "country", "")),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                      formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--all", action="store_true",
                        help="Look up every sender domain, not just ones seen 2+ times.")
    parser.add_argument("--delay", type=float, default=DEFAULT_DELAY_SECONDS,
                        help=f"Seconds to wait between lookups (default {DEFAULT_DELAY_SECONDS}).")
    parser.add_argument("--limit", type=int, default=None,
                        help="Look up at most N domains this run.")
    parser.add_argument("--refill-missing", action="store_true",
                        help="Re-query already-enriched domains whose nameservers "
                             "column is blank (rows recorded before that column "
                             "existed). Their rows are updated in place.")
    args = parser.parse_args()

    if not os.path.exists(MASTER_CSV):
        print(f"No {MASTER_CSV} yet -- nothing to look up.")
        return

    migrate_schema()
    candidates = load_candidate_domains(1 if args.all else MIN_MESSAGES)
    existing_rows = []
    if os.path.exists(ENRICHMENT_CSV):
        with open(ENRICHMENT_CSV, encoding="utf-8") as f:
            existing_rows = list(csv.DictReader(f))
    already = {r["domain"] for r in existing_rows}
    todo = [d for d in candidates if d not in already]
    refill = []
    if args.refill_missing:
        refill = [r["domain"] for r in existing_rows if not (r.get("nameservers") or "").strip()]
    todo += refill
    if args.limit:
        todo = todo[:args.limit]

    if not todo:
        print("Nothing new to look up.")
        return

    print(f"Looking up {len(todo)} domain(s), waiting {args.delay}s between each...")
    new_rows, updated = [], {}
    for i, domain in enumerate(todo):
        try:
            info = lookup_one(domain)
            print(f"  [{i + 1}/{len(todo)}] {domain}: registered={info['registered_date']!r} "
                  f"registrar={info['registrar']!r} ns={info['nameservers']!r}")
            if domain in already:
                updated[domain] = info
            else:
                new_rows.append({"domain": domain, "notes": "", **info})
        except Exception as e:
            print(f"  [{i + 1}/{len(todo)}] {domain}: lookup failed ({e})")
        if i < len(todo) - 1:
            time.sleep(args.delay)

    if updated:
        for r in existing_rows:
            if r["domain"] in updated:
                # keep existing registered_date/registrar/notes if the new
                # lookup came back blank for them
                for k, v in updated[r["domain"]].items():
                    if v:
                        r[k] = v
        tmp = ENRICHMENT_CSV + ".tmp"
        with open(tmp, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=ENRICHMENT_FIELDNAMES)
            writer.writeheader()
            for r in existing_rows:
                writer.writerow({k: r.get(k, "") for k in ENRICHMENT_FIELDNAMES})
        os.replace(tmp, ENRICHMENT_CSV)
        print(f"Updated {len(updated)} existing row(s) in {ENRICHMENT_CSV}")
    if new_rows:
        append_enrichment(new_rows)
        print(f"Added {len(new_rows)} row(s) to {ENRICHMENT_CSV}")
    elif not updated:
        print("No successful lookups to add.")


if __name__ == "__main__":
    main()
