#!/usr/bin/env python3
"""Look up ASN / hosting-provider / country info for the originating IPs
extracted from scam emails and write data/ip_enrichment.csv.

Why: sender domains are $2 burners, but the machines the mail actually
transits are rented from real hosting providers. Aggregating your spam by
ASN (see the report's "Origin ASNs" tab) surfaces patterns like "60% of my
likely_scam volume originates from one bulletproof hoster" -- which is a
reportable finding for that provider's abuse desk and for law enforcement.

Uses ip-api.com's free batch endpoint (no API key, up to 100 IPs per
request, rate-limited to 15 requests/minute -- this script stays under
that). Free tier is HTTP-only and for non-commercial use, which personal
abuse-reporting research is. Only valid, public (globally routable) IPs
are queried; private relay hops and regex false-positives in older rows
are skipped.

Usage:
    python3 lookup_ips.py              # all new public IPs
    python3 lookup_ips.py --limit 200  # at most 200 this run
    python3 lookup_ips.py --recheck    # re-query everything already enriched
"""

import argparse
import csv
import ipaddress
import json
import os
import time
import urllib.request
from datetime import date

BASE = os.path.dirname(os.path.abspath(__file__))
MASTER_CSV = os.path.join(BASE, "data", "master_iocs.csv")
ENRICHMENT_CSV = os.path.join(BASE, "data", "ip_enrichment.csv")
ENRICHMENT_FIELDNAMES = ["ip", "asn", "as_name", "isp", "org", "country",
                         "country_code", "reverse_dns", "checked_date", "notes"]

BATCH_URL = "http://ip-api.com/batch"
BATCH_SIZE = 100
BATCH_DELAY_SECONDS = 4.5   # 15 requests/min allowed; stay comfortably under
FIELDS = "status,message,country,countryCode,isp,org,as,asname,reverse,query"
USER_AGENT = "scam-email-tracker (personal abuse-reporting research)"


def load_candidate_ips():
    """Distinct valid public IPs from originating_ips, insertion-ordered."""
    ips, seen = [], set()
    with open(MASTER_CSV, encoding="utf-8") as f:
        for r in csv.DictReader(f):
            for ip in (r.get("originating_ips") or "").split(";"):
                ip = ip.strip()
                if not ip or ip in seen:
                    continue
                seen.add(ip)
                try:
                    if ipaddress.ip_address(ip).is_global:
                        ips.append(ip)
                except ValueError:
                    continue  # regex false positive from an older row
    return ips


def load_enrichment_rows():
    if not os.path.exists(ENRICHMENT_CSV):
        return []
    with open(ENRICHMENT_CSV, encoding="utf-8") as f:
        return list(csv.DictReader(f))


def lookup_batch(ips):
    # payload is a plain JSON array of IPs; the field list goes in the query
    # string (a per-object "fields" key makes the server drop the connection)
    payload = json.dumps(ips).encode("utf-8")
    req = urllib.request.Request(
        f"{BATCH_URL}?fields={FIELDS}", data=payload,
        headers={"User-Agent": USER_AGENT, "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode("utf-8"))


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                      formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--limit", type=int, default=None,
                        help="Look up at most N IPs this run.")
    parser.add_argument("--recheck", action="store_true",
                        help="Re-query IPs already enriched (replaces their rows).")
    args = parser.parse_args()

    if not os.path.exists(MASTER_CSV):
        print(f"No {MASTER_CSV} yet -- nothing to look up.")
        return

    candidates = load_candidate_ips()
    existing = load_enrichment_rows()
    already = {r["ip"] for r in existing}
    todo = [ip for ip in candidates if args.recheck or ip not in already]
    if args.limit:
        todo = todo[:args.limit]

    if not todo:
        print("Nothing new to look up.")
        return

    batches = [todo[i:i + BATCH_SIZE] for i in range(0, len(todo), BATCH_SIZE)]
    print(f"Looking up {len(todo)} IP(s) in {len(batches)} batch(es)...")

    results = {r["ip"]: r for r in existing}
    ok = failed = 0
    for b_idx, batch in enumerate(batches):
        try:
            answers = lookup_batch(batch)
        except Exception as e:
            print(f"  batch {b_idx + 1}/{len(batches)} failed ({e}); "
                  "stopping -- already-fetched results will still be written")
            break
        for a in answers:
            ip = a.get("query", "")
            if a.get("status") != "success":
                failed += 1
                continue
            as_field = a.get("as") or ""          # e.g. "AS15169 Google LLC"
            asn = as_field.split()[0] if as_field else ""
            prior = results.get(ip, {})
            results[ip] = {
                "ip": ip,
                "asn": asn,
                "as_name": a.get("asname") or as_field.partition(" ")[2],
                "isp": a.get("isp", ""),
                "org": a.get("org", ""),
                "country": a.get("country", ""),
                "country_code": a.get("countryCode", ""),
                "reverse_dns": a.get("reverse", ""),
                "checked_date": date.today().isoformat(),
                "notes": prior.get("notes", ""),
            }
            ok += 1
        print(f"  batch {b_idx + 1}/{len(batches)}: {len(answers)} answer(s)")
        if b_idx < len(batches) - 1:
            time.sleep(BATCH_DELAY_SECONDS)

    if ok:
        ordered = [results[ip] for ip in candidates if ip in results]
        with open(ENRICHMENT_CSV, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=ENRICHMENT_FIELDNAMES)
            writer.writeheader()
            for r in ordered:
                writer.writerow({k: r.get(k, "") for k in ENRICHMENT_FIELDNAMES})
        print(f"Wrote {len(ordered)} row(s) to {ENRICHMENT_CSV} "
              f"({ok} looked up this run, {failed} failed)")
        print("Run build_master_report.py to pull this into the Origin ASNs tab.")
    else:
        print("No successful lookups to write.")


if __name__ == "__main__":
    main()
