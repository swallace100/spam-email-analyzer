#!/usr/bin/env python3
"""Ingest every .eml and .mbox file sitting in data/input/, append new rows
to the master CSV, then move each processed file into a dated folder under
data/scanned/ (e.g. data/scanned/2026-07-25/) so it isn't re-ingested next
run. That dated folder is then zipped into data/scanned/2026-07-25.zip and
the unzipped copy is deleted -- data/scanned/ ends up holding one zip per
day, not a growing pile of loose files.

Files can sit directly in data/input/, or be organized into subfolders
(e.g. data/input/work_gmail/, data/input/personal_outlook/) -- the
subfolder name becomes each row's "source" tag, so a report built later
can tell which mailbox a message came from. That subfolder structure is
preserved inside the dated folder (and therefore inside the zip).

Run this after dropping in new exports, then run build_master_report.py
to refresh the .xlsx report.
"""

import argparse
import mailbox
import email
import csv
import os
import re
import shutil
from datetime import date

import ioc_lib

# scripts/ lives one level below the repo root that data/, output/, and
# dashboard/ hang off of.
BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
INPUT_DIR = os.path.join(BASE, "data", "input")
SCANNED_DIR = os.path.join(BASE, "data", "scanned")
MASTER_CSV = os.path.join(BASE, "data", "master_iocs.csv")
MASTER_URLS_CSV = os.path.join(BASE, "data", "master_urls.csv")

DATE_DIR_RE = re.compile(r'^\d{4}-\d{2}-\d{2}$')

FIELDNAMES = [
    "id", "source", "category", "scam_score", "scam_signals", "date",
    "date_iso", "subject", "from_name", "from_addr",
    "from_domain", "return_path", "reply_to_addr", "list_unsubscribe",
    "dkim", "spf", "dmarc", "originating_ips", "url_count", "url_domains",
    "phone_numbers", "btc_addresses", "eth_addresses",
    "contact_emails_in_body", "contacts_functional", "contacts_filler",
    "phones_functional", "phones_filler", "first_url",
    "impersonated_brands", "body_template_fingerprint",
    "link_mismatches", "url_flags", "remote_image_domains",
    "image_count", "image_hashes", "image_phashes", "image_filenames",
    "image_ocr_chars",
]

DEFAULT_SOURCE = "input"


def migrate_schema():
    """If master_iocs.csv predates a column addition, rewrite it once with
    the current FIELDNAMES (new columns blank for old rows). Rows ingested
    before a feature existed simply have no data for it."""
    if not os.path.exists(MASTER_CSV):
        return
    with open(MASTER_CSV, encoding="utf-8") as f:
        reader = csv.DictReader(f)
        if reader.fieldnames == FIELDNAMES:
            return
        old_rows = list(reader)
        old_fields = reader.fieldnames or []
    dropped = [c for c in old_fields if c not in FIELDNAMES]
    if dropped:
        raise SystemExit(
            f"{MASTER_CSV} has columns not in the current schema ({dropped}); "
            "refusing to migrate automatically."
        )
    tmp = MASTER_CSV + ".tmp"
    with open(tmp, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDNAMES)
        writer.writeheader()
        for r in old_rows:
            writer.writerow({k: r.get(k, "") for k in FIELDNAMES})
    os.replace(tmp, MASTER_CSV)
    print(f"Migrated {MASTER_CSV} to the current schema "
          f"({len(old_fields)} -> {len(FIELDNAMES)} columns, {len(old_rows)} rows kept).")


def load_existing_ids():
    if not os.path.exists(MASTER_CSV):
        return set()
    with open(MASTER_CSV, encoding="utf-8") as f:
        return {row["id"] for row in csv.DictReader(f)}


def source_tag_for(path):
    rel = os.path.relpath(path, INPUT_DIR)
    parts = rel.split(os.sep)
    return parts[0] if len(parts) > 1 else DEFAULT_SOURCE


def scanned_path_for(path, date_str):
    """Mirror the file's path (including any subfolder) into
    data/scanned/<date_str>/, adding a numeric suffix if something with
    that name was already scanned today."""
    rel = os.path.relpath(path, INPUT_DIR)
    dest = os.path.join(SCANNED_DIR, date_str, rel)
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    base, ext = os.path.splitext(dest)
    n = 1
    while os.path.exists(dest):
        dest = f"{base}_{n}{ext}"
        n += 1
    return dest


def _unique_zip_base(base):
    """base + '.zip' if free, otherwise base + '_2.zip', '_3.zip', etc. --
    covers running process_mail.py more than once on the same day."""
    if not os.path.exists(base + ".zip"):
        return base
    n = 2
    while os.path.exists(f"{base}_{n}.zip"):
        n += 1
    return f"{base}_{n}"


def zip_dated_folders():
    """Zip up every unzipped dated folder under data/scanned/ and remove
    the unzipped copy. Normally that's just the folder this run created,
    but it also sweeps up a folder left behind by a run that crashed
    before reaching this step."""
    if not os.path.isdir(SCANNED_DIR):
        return
    for name in sorted(os.listdir(SCANNED_DIR)):
        full = os.path.join(SCANNED_DIR, name)
        if not os.path.isdir(full) or not DATE_DIR_RE.match(name):
            continue
        zip_base = _unique_zip_base(os.path.join(SCANNED_DIR, name))
        shutil.make_archive(zip_base, "zip", root_dir=SCANNED_DIR, base_dir=name)
        shutil.rmtree(full)
        print(f"Zipped {name}/ -> {os.path.basename(zip_base)}.zip")


def process_eml(path, existing_ids):
    source = source_tag_for(path)
    with open(path, "rb") as f:
        msg = email.message_from_bytes(f.read())
    row, urls = ioc_lib.extract_row(msg, source=source)
    if row["id"] in existing_ids:
        return [], [], 1
    existing_ids.add(row["id"])
    url_rows = [{"id": row["id"], "url": u, "domain": ioc_lib.domain_of(u)} for u in urls]
    return [row], url_rows, 0


def process_mbox(path, existing_ids):
    source = source_tag_for(path)
    rows, url_rows = [], []
    dupes = 0
    mbox = mailbox.mbox(path)
    try:
        for msg in mbox:
            row, urls = ioc_lib.extract_row(msg, source=source)
            if row["id"] in existing_ids:
                dupes += 1
                continue
            existing_ids.add(row["id"])
            rows.append(row)
            url_rows += [{"id": row["id"], "url": u, "domain": ioc_lib.domain_of(u)} for u in urls]
    finally:
        mbox.close()  # release the file handle before we move it
    return rows, url_rows, dupes


def append_rows(rows, url_rows):
    if not rows:
        return
    file_exists = os.path.exists(MASTER_CSV)
    with open(MASTER_CSV, "a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDNAMES)
        if not file_exists:
            writer.writeheader()
        writer.writerows(rows)

    file_exists = os.path.exists(MASTER_URLS_CSV)
    with open(MASTER_URLS_CSV, "a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["id", "url", "domain"])
        if not file_exists:
            writer.writeheader()
        writer.writerows(url_rows)


def run_lookups():
    """Run the three enrichment lookups with their default (new-IOCs-only)
    behavior, so a normal ingest leaves the enrichment CSVs current without
    a separate manual step. Each is independent and network-bound, so one
    failing (WHOIS rate limit, API hiccup) shouldn't stop the others -- or
    the ingest itself, which already succeeded by this point. All three
    no-op quickly when there's nothing new."""
    import lookup_ips
    import lookup_domains
    import lookup_wallets
    for name, mod in (("lookup_ips", lookup_ips),
                      ("lookup_domains", lookup_domains),
                      ("lookup_wallets", lookup_wallets)):
        print(f"\n--- {name} ---")
        try:
            mod.main([])
        except KeyboardInterrupt:
            raise
        except Exception as e:
            print(f"{name} failed ({e}); continuing -- "
                  f"run 'python {name}.py' manually to retry.")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--skip-lookups", action="store_true",
                        help="Don't run the WHOIS/IP/wallet enrichment lookups "
                             "after ingesting (they run automatically by default; "
                             "each only queries IOCs it hasn't seen before).")
    args = parser.parse_args(argv)

    os.makedirs(INPUT_DIR, exist_ok=True)
    os.makedirs(SCANNED_DIR, exist_ok=True)
    migrate_schema()

    files = []
    for root, _dirs, names in os.walk(INPUT_DIR):
        for name in names:
            if name.lower().endswith((".eml", ".mbox")):
                files.append(os.path.join(root, name))

    if not files:
        print(f"No .eml or .mbox files found in {INPUT_DIR}.")
    else:
        date_str = date.today().isoformat()
        existing_ids = load_existing_ids()
        all_rows, all_url_rows = [], []
        total_dupes = 0
        scanned_count = 0

        for path in sorted(files):
            try:
                if path.lower().endswith(".mbox"):
                    rows, url_rows, dupes = process_mbox(path, existing_ids)
                else:
                    rows, url_rows, dupes = process_eml(path, existing_ids)
            except Exception as e:
                print(f"Skipping {path}: failed to parse ({e})")
                continue

            all_rows += rows
            all_url_rows += url_rows
            total_dupes += dupes

            shutil.move(path, scanned_path_for(path, date_str))
            scanned_count += 1

        append_rows(all_rows, all_url_rows)

        by_cat = {}
        for r in all_rows:
            by_cat[r["category"]] = by_cat.get(r["category"], 0) + 1
        print(f"Scanned {scanned_count} file(s)")
        print(f"Added {len(all_rows)} new row(s): {by_cat}")
        if total_dupes:
            print(f"Skipped {total_dupes} duplicate message(s) already in {MASTER_CSV}")

    zip_dated_folders()
    if not args.skip_lookups:
        run_lookups()
    print("\nRun build_master_report.py to refresh the .xlsx report.")


if __name__ == "__main__":
    main()
