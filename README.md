# Scam Email Tracker

A toolkit for extracting indicators of compromise (IOCs) from spam/scam
emails, triaging them, and compiling them into a running spreadsheet report.

## How it works

This is a batch tool, not a live service. Drop email files into
`data/input/`, run `process_mail.py`, then `build_master_report.py`.

`process_mail.py`:

- Extracts IOCs from every `.eml`/`.mbox` file in `data/input/`.
- appends new rows to `data/master_iocs.csv` / `data/master_urls.csv`,
  deduping by a hash of each message's `Message-ID`. Re-running
  against an export that overlaps with what you've already ingested (e.g.
  a mailbox export that always includes everything, not just what's new)
  is safe.
- Moves processed files into a dated, zipped archive under
  `data/scanned/` (e.g. `data/scanned/2026-07-25.zip`). Running the tool
  more than once in a day adds a `_2`, `_3`, etc. suffix instead of
  overwriting that day's zip.

`build_master_report.py` rebuilds `output/master_report.xlsx` from those
CSVs. A full rebuild every time, not an append, so the CSVs are always
the source of truth.

Getting mail into `data/input/` in the first place is up to you. A manual
download/export is enough. If you want it automated (an IMAP poller, a
cron job, a scheduled export), that's a separate concern this repo
doesn't try to solve. Any process that drops `.eml`/`.mbox` files into
`data/input/` works.

## Where data lives

`data/master_iocs.csv` and `data/master_urls.csv` are the source of truth
for everything downstream. `build_master_report.py` reads only from
them, never the original emails. You don't need to keep the raw
`.eml`/`.mbox` files after ingesting them unless you want to re-pull full
original headers later (e.g. for an abuse report). They're preserved,
zipped by day, in `data/scanned/` either way.

## What it does

1. **Extract**: Sender info, SPF/DKIM/DMARC, originating IPs, URLs,
   phone numbers, crypto wallet addresses, and contact emails from the
   body. This includes ones hidden with cheap obfuscation tricks like
   `name (at) domain (dot) com`, zero-width characters, HTML entities,
   fullwidth/stylized Unicode, or Cyrillic look-alike letters
   (`ioc_lib.deobfuscate`). HTML bodies are parsed properly (not
   tag-stripped), which recovers `<a href>` URLs, remote image domains,
   and anchor-text-vs-href mismatches (`<a href="evil.top">paypal.com</a>`),
   while excluding `display:none` word-salad blocks.
2. **Triage**: Rule-based and no LLM/API calls. Each email gets a weighted
   `scam_score` from stacked signals -- urgent keywords, a brand name in the
   From display name sent from a non-official domain, Reply-To diverted to
   freemail, DKIM/SPF/DMARC failures, recently registered sender domains
   (from your WHOIS enrichment), deceptive links, punycode/shortener URLs,
   wallet addresses -- which maps to `likely_scam`, `review`, or
   `bulk_marketing`. The contributing signals are kept per-row in
   `scam_signals` so every score can be audited and tuned. It also tags
   which brand or institution the mail appears to be impersonating
   (`ioc_lib.IMPERSONATED_BRANDS`); keyword phrases match flexibly
   ("verify your account" also catches "verify your Amazon account").
3. **Analyze images**: Every inline/attached image is hashed (sha256), so a
   reused image is an operator fingerprint just like a reused phone number.
   With `Pillow`+`imagehash` installed, a perceptual hash also links
   recompressed/resized variants of the same artwork. With `pytesseract`
   (plus the Tesseract binary) installed, image-only spam is OCR'd and the
   recovered text flows through the normal keyword/extraction pipeline.
   All of this is local -- no LLM/API calls -- and each tier degrades
   gracefully if its dependency isn't installed.
4. **Classify confidence**: Phone numbers and contact emails are split
   into `functional` (real call-to-action language) vs `filler`
   (word-salad/camouflage noise). See `ioc_lib.classify_contacts` and
   `classify_phones`.
5. **Fingerprint the body template**: A SimHash of the body with the
   parts that vary per-blast (URLs, contacts, wallets) stripped out, so
   campaigns sharing a template get linked even across different senders
   with different contact info (`ioc_lib.body_template_fingerprint`).
6. **Report**: A formatted `.xlsx` with tabs for the full email list,
   domain clustering, WHOIS enrichment, a brand-impersonation breakdown,
   template clusters, image reuse, "Operator Fingerprints" (any contact
   email, phone number, crypto wallet, or image that repeats across 2+
   sender domains -- the strongest signal this dataset can surface that
   messages trace back to the same operator), and a per-month "Trends"
   tab: volume by category, top impersonated brands, and burner-domain
   churn over time.

## Files

| File                     | Purpose                                                                                                                                                        |
| ------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `ioc_lib.py`             | Shared extraction + triage logic. Everything else imports this.                                                                                                |
| `process_mail.py`        | Main entry point. Ingests every `.eml`/`.mbox` file in `data/input/` and moves it into a dated, zipped archive under `data/scanned/` once it's been processed. |
| `build_master_report.py` | Rebuilds the formatted `.xlsx` report from the running CSV. Safe to re-run any time -- a full rebuild, not an append.                                          |
| `lookup_domains.py`      | Optional. Runs WHOIS lookups for sender domains (registration date, registrar, nameservers, registrant) into `data/domain_enrichment.csv`, with a delay between requests. |
| `lookup_wallets.py`      | Optional. Looks up on-chain activity for extracted crypto wallets (free public APIs, no key) and writes `data/wallet_enrichment.csv` for the Wallets tab.      |
| `lookup_ips.py`          | Optional. Maps originating IPs to ASN/hosting provider/country via ip-api.com's free batch endpoint, into `data/ip_enrichment.csv` for the Origin ASNs tab.   |

## Setup

```bash
pip install -r requirements.txt
```

For OCR of image-only spam (optional), also install the
[Tesseract binary](https://github.com/tesseract-ocr/tesseract) and
`pip install pytesseract`. Without it, images are still hashed and
perceptually fingerprinted -- their text just isn't read.

Note on schemas: when a new version adds columns, `process_mail.py`
migrates `data/master_iocs.csv` in place on its next run (old rows keep
blank values for the new columns).

### Analyze emails

Put email files into `data/input/`. They can be individual `.eml` files, a `.mbox`
export, or both. Then run:

```bash
python3 process_mail.py
```

This extracts IOCs from every file in `data/input/`, appends new rows to
the master CSVs, and moves each processed file into
`data/scanned/<today's date>/`, which then gets zipped and removed.
`data/input/` and the day's raw files are both empty/gone by the time the
run finishes.

If you're monitoring more than one mailbox, drop each one's exports into
its own subfolder (e.g. `data/input/work/`, `data/input/personal/`).
The subfolder name is recorded as that row's `source`, so the report can
tell them apart later. Files placed directly in `data/input/` get a
default `source` of `input`.

Once the CSVs are updated, build the report:

```bash
python3 build_master_report.py
```

Outputs `output/master_report.xlsx`.

### Excluding your own addresses (recommended)

`ioc_lib.py` excludes your own email addresses from
`contact_emails_in_body` -- otherwise every "Dear you@example.com" salutation
gets extracted as if it were an attacker-controlled contact. Copy
`data/self_addresses_example.txt` to `data/self_addresses.txt` (gitignored)
and list your own addresses, one per line:

```
you@example.com
you@your-other-provider.example
```

If `data/self_addresses.txt` doesn't exist, nothing gets excluded this
way -- it just means your own addresses may show up as false-positive
"contacts found in body."

### Domain enrichment (optional)

`data/domain_enrichment.csv` holds WHOIS notes per domain (registration
date, registrar, anything else worth noting) that `build_master_report.py`
picks up automatically, highlighting matches in "Domain Clusters" and
listing everything in its own "Domain Enrichment" tab. Copy
`data/domain_enrichment_example.csv` to `data/domain_enrichment.csv`
(gitignored -- it's your own research) to get started, same format as the
example:

```csv
domain,registered_date,registrar,notes
```

You can fill it in by hand, or run `lookup_domains.py` to do it via WHOIS:

```bash
python3 lookup_domains.py
```

By default this only looks up sender domains that showed up in 2+
messages (same threshold "Domain Clusters" uses) and skips any domain
already in `data/domain_enrichment.csv`, waiting 8 seconds between each
lookup so as not to hammer WHOIS servers (many rate-limit or temporarily
block IPs that query too fast). `--all` looks up every sender domain
instead of just repeat ones, `--delay N` changes the wait, and `--limit N`
caps how many it does in one run. The `notes` column is always left blank
for you to fill in yourself.

### IP enrichment (optional)

Sender domains are disposable, but the machines the mail transits are
rented from real hosting providers. `lookup_ips.py` maps every public
originating IP to its ASN, hosting provider, and country via ip-api.com's
free batch endpoint (no key; HTTP-only free tier, rate-limited -- the
script stays under the limit automatically):

```bash
python3 lookup_ips.py
```

The report's "Origin ASNs" tab then aggregates messages by the ASN of
their best-guess origin IP (the deepest public hop in each Received
chain). Concentration there is a reportable pattern -- a hosting provider
carrying a large share of your scam volume has an abuse desk that should
hear about it. Caveat: Received headers below the hop your own provider
recorded can be forged, so treat origins as strong hints, not proof.

The WHOIS side feeds a second correlation: `lookup_domains.py` now also
records nameservers and registrant org/country, and the "Registration
Clusters" tab groups enriched domains sharing registrar + nameserver
infrastructure. Burner domains bought at the same registrar, parked on the
same nameservers, registered within days of each other, are one operator's
shopping trip. This tab gets more useful the more domains you enrich
(consider `lookup_domains.py --all`); a cluster spanning years on a huge
shared platform (e.g. domaincontrol.com) is weak evidence, one spanning
days on an obscure one is strong. Old enrichment rows from before the
nameserver column existed can be backfilled with
`lookup_domains.py --refill-missing`.

### Wallet enrichment (optional)

The blockchain is the one part of a scam email that's public and permanent.
`lookup_wallets.py` queries free, no-API-key explorers (Blockstream for
BTC, Blockscout for ETH) for each extracted wallet's transaction count,
total received, and balance, writing `data/wallet_enrichment.csv`
(gitignored). The report's Wallets tab picks it up automatically and sorts
wallets with real on-chain activity to the top, highlighted -- a wallet
that has actually received funds proves the campaign has victims, which is
what makes an IC3 (ic3.gov) or [Chainabuse](https://chainabuse.com) report
actionable.

```bash
python3 lookup_wallets.py            # new wallets only
python3 lookup_wallets.py --recheck  # refresh previously checked ones
```

These are read-only lookups of public ledger data. No interaction with the
scammer or their wallet occurs, and none should: never reply, click,
or transact -- collect, document, and report.

For any wallet with on-chain activity, `lookup_wallets.py` also fetches
every individual transaction into `data/wallet_enrichment.csv`'s sibling
`data/wallet_transactions.csv` -- transaction ID, timestamp, amount,
direction, and the counterparty address on the other side of each
transaction. This is the level of detail a law-enforcement crypto-fraud
report (e.g. IC3) actually asks for; the summary stats in
`wallet_enrichment.csv` alone aren't enough. The report's "Wallet
Transactions" tab lists the same data, with incoming transactions
(funds received by the scam wallet) highlighted -- outgoing rows show
where the money moved on next, which is worth including in a report too
since it's the next hop in the trail.

## Known limitations

- Keyword-based triage, brand detection, and deobfuscation are all
  pattern-based, not exhaustive
  - Triage/brand tuning lives in `ioc_lib.py` (`URGENT_KEYWORDS`,
    `KNOWN_LEGIT_DOMAINS`, `IMPERSONATED_BRANDS`, `BRAND_LEGIT_DOMAINS`,
    and the signal weights in `ioc_lib.triage`) and needs occasional
    updates as new patterns show up. Deobfuscation (`ioc_lib.deobfuscate`)
    undoes NFKC-foldable Unicode tricks, `[at]`/`[dot]`, zero-width
    characters, and a small set of Cyrillic/Greek look-alikes -- wider than
    before, but still not a full Unicode-confusables solution. Text inside
    images is only visible when OCR (Tesseract) is installed, and OCR
    quality varies with the image.
- Phone/email extraction is regex-based
  - It is not a full NLP pipeline. It's tuned to reduce false positives
    (e.g. tracking/order numbers being mistaken for phone numbers)
    but won't be perfect on unusual formats.
- The functional/filler contact classifier is a heuristic, not ground truth
  - It's meant to cut down on wasted effort chasing camouflage text,
    not to make the final call for you. Double check results before filing
    an abuse report.
- Template clustering is approximate:
  - It compares SimHash fingerprints with an O(n^2) pairwise comparison,
    which is fine at personal-mailbox scale but would need banding to stay
    fast on a much larger dataset. The distance threshold
    (`build_master_report.TEMPLATE_HAMMING_THRESHOLD`) acts as a tuning knob.
    Tighten it if unrelated messages end up in the same
    cluster or loosen it if near-identical templates aren't matching.
- No built-in automation for getting mail into `data/input/`
  - This is deliberate (see "How it works" above), so live/continuous monitoring is
    something you'd need to build yourself.
- Same-day zips share an internal folder name
  - `data/scanned/2026-07-25.zip` and `data/scanned/2026-07-25_2.zip`
    (if you ran the tool twice in one day) both contain a top-level `2026-07-25/`
    folder. Extracting both into the same destination at once will collide.
    Extract them one at a time, or to separate destinations, if that ever comes up.
- `lookup_domains.py` results vary by registry/registrar
  - Some WHOIS servers rate-limit or block regardless of the delay between
    requests, some TLDs redact registrant/registrar info by default, and
    responses aren't perfectly standardized across registrars -- expect
    occasional blank or missing fields rather than a failure.

## Privacy note

This repo intentionally does not include any actual email data or
extracted IOCs. See `.gitignore`. If you fork this for your own use,
please keep it this way. `data/` and `output/` contain personal information (or,
in the report's case, indicators that could be considered evidence if
you're using this for abuse reporting) and shouldn't be committed to a
public repo. The one exception is `data/domain_enrichment_example.csv`,
which is just a format template with no personal data.
