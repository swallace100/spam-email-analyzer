#!/usr/bin/env python3
"""Look up on-chain activity for crypto wallet addresses extracted from
scam emails and append the results to data/wallet_enrichment.csv (summary
stats) and data/wallet_transactions.csv (one row per actual transaction),
skipping addresses already recorded there.

Why: everything else in a spam email is disposable, but the blockchain is
public and permanent. A wallet that has actually RECEIVED money proves the
campaign has victims, which is exactly what makes an IC3/law-enforcement
report actionable -- and IC3's crypto-fraud form specifically asks for
per-transaction metadata (transaction ID, timestamp, amount, counterparty
address), not just a summary. That's what wallet_transactions.csv holds.
This uses free, no-API-key endpoints:

  BTC: blockstream.info  (public Esplora API)
  ETH: eth.blockscout.com (public Blockscout API)

Both are read-only lookups of public ledger data -- nothing is transacted,
and no interaction with the scammer occurs. The chainabuse_url column links
to Chainabuse (community scam-address registry) for a manual check whether
others have already reported the address; consider filing yours there too.

Usage:
    python3 lookup_wallets.py              # all new wallets, 2s delay
    python3 lookup_wallets.py --delay 5    # slower
    python3 lookup_wallets.py --limit 20   # only do 20 this run
    python3 lookup_wallets.py --recheck    # re-query addresses already
                                           # enriched (activity changes over
                                           # time; old rows -- both summary
                                           # and per-transaction -- get
                                           # replaced)
"""

import argparse
import csv
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import defaultdict
from datetime import date, datetime, timezone

# scripts/ lives one level below the repo root that data/, output/, and
# dashboard/ hang off of.
BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MASTER_CSV = os.path.join(BASE, "data", "master_iocs.csv")
ENRICHMENT_CSV = os.path.join(BASE, "data", "wallet_enrichment.csv")
ENRICHMENT_FIELDNAMES = [
    "address", "chain", "tx_count", "total_received", "balance",
    "first_seen", "last_seen", "checked_date", "explorer_url",
    "chainabuse_url", "notes",
]
TRANSACTIONS_CSV = os.path.join(BASE, "data", "wallet_transactions.csv")
TRANSACTIONS_FIELDNAMES = [
    "address", "chain", "txid", "timestamp", "block_height", "direction",
    "amount", "counterparty_addresses", "confirmed", "tx_explorer_url",
]
TX_FETCH_CAP = 1000  # safety cap on how many transactions to pull per address

DEFAULT_DELAY_SECONDS = 2
USER_AGENT = "scam-email-tracker (personal abuse-reporting research)"


def _get_json(url, timeout=20):
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _ts_to_date(ts):
    return datetime.fromtimestamp(ts, tz=timezone.utc).date().isoformat()


def _ts_to_iso(ts):
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat().replace("+00:00", "Z")


def lookup_btc(addr):
    """Blockstream Esplora: totals come in satoshis. First/last seen dates
    come from the recent-transactions endpoint (25 most recent), so
    first_seen is only definitive when the address has <= 25 txs."""
    info = _get_json(f"https://blockstream.info/api/address/{addr}")
    stats = info.get("chain_stats", {})
    tx_count = stats.get("tx_count", 0)
    funded = stats.get("funded_txo_sum", 0)
    spent = stats.get("spent_txo_sum", 0)
    first_seen = last_seen = ""
    if tx_count:
        txs = _get_json(f"https://blockstream.info/api/address/{addr}/txs")
        times = [t["status"]["block_time"] for t in txs
                 if t.get("status", {}).get("confirmed")]
        if times:
            last_seen = _ts_to_date(max(times))
            first_seen = _ts_to_date(min(times)) if tx_count <= 25 else f"<= {_ts_to_date(min(times))}"
    return {
        "tx_count": tx_count,
        "total_received": f"{funded / 1e8:.8f} BTC" if funded else "0",
        "balance": f"{(funded - spent) / 1e8:.8f} BTC" if funded else "0",
        "first_seen": first_seen,
        "last_seen": last_seen,
        "explorer_url": f"https://blockstream.info/address/{addr}",
    }


def fetch_btc_txs(addr, cap=TX_FETCH_CAP):
    """All transactions touching addr, newest first. The Esplora API returns
    the most recent 50 mempool + 25 confirmed txs from /txs, then requires
    paging older confirmed ones via /txs/chain/<last_confirmed_txid>."""
    all_txs = []
    last_confirmed_txid = None
    while True:
        if last_confirmed_txid is None:
            url = f"https://blockstream.info/api/address/{addr}/txs"
        else:
            url = f"https://blockstream.info/api/address/{addr}/txs/chain/{last_confirmed_txid}"
        page = _get_json(url)
        if not page:
            break
        all_txs.extend(page)
        confirmed_in_page = [t for t in page if t.get("status", {}).get("confirmed")]
        if len(confirmed_in_page) < 25 or len(all_txs) >= cap:
            break
        last_confirmed_txid = confirmed_in_page[-1]["txid"]
        time.sleep(0.3)
    seen, deduped = set(), []
    for t in all_txs:
        if t["txid"] not in seen:
            seen.add(t["txid"])
            deduped.append(t)
    return deduped[:cap]


def parse_btc_tx(tx, addr):
    """One transaction -> a flat record from addr's point of view. UTXO
    transactions don't have a single 'from'/'to' like account-based chains,
    so direction/amount/counterparty are all computed relative to addr:
    received = addr's share of the outputs, sent = addr's share of the
    inputs, counterparty = the addresses on the other side of that net
    flow (senders for an incoming payment, recipients for an outgoing one)."""
    vins, vouts = tx.get("vin", []), tx.get("vout", [])
    received = sum(v.get("value", 0) for v in vouts
                   if v.get("scriptpubkey_address") == addr)
    sent = sum(v.get("prevout", {}).get("value", 0) for v in vins
               if v.get("prevout", {}).get("scriptpubkey_address") == addr)
    net = received - sent
    direction = "in" if net > 0 else ("out" if net < 0 else "self")
    if direction == "in":
        counterparties = sorted({
            v.get("prevout", {}).get("scriptpubkey_address") for v in vins
            if v.get("prevout", {}).get("scriptpubkey_address")
            and v["prevout"]["scriptpubkey_address"] != addr
        })
    elif direction == "out":
        counterparties = sorted({
            v.get("scriptpubkey_address") for v in vouts
            if v.get("scriptpubkey_address") and v["scriptpubkey_address"] != addr
        })
    else:
        counterparties = []
    status = tx.get("status", {})
    confirmed = bool(status.get("confirmed"))
    return {
        "txid": tx.get("txid", ""),
        "timestamp": _ts_to_iso(status["block_time"]) if confirmed else "",
        "block_height": status.get("block_height", "") if confirmed else "",
        "direction": direction,
        "amount": f"{abs(net) / 1e8:.8f} BTC",
        "counterparty_addresses": "; ".join(counterparties),
        "confirmed": confirmed,
        "tx_explorer_url": f"https://blockstream.info/tx/{tx.get('txid', '')}",
    }


def fetch_eth_txs(addr, cap=TX_FETCH_CAP):
    """All transactions for addr via Blockscout, newest first, following
    next_page_params until exhausted or cap is hit."""
    items = []
    base_url = f"https://eth.blockscout.com/api/v2/addresses/{addr}/transactions"
    url = base_url
    while True:
        page = _get_json(url)
        batch = page.get("items", [])
        items.extend(batch)
        next_params = page.get("next_page_params")
        if not next_params or len(items) >= cap:
            break
        qs = urllib.parse.urlencode(next_params)
        url = f"{base_url}?{qs}"
        time.sleep(0.3)
    return items[:cap]


def parse_eth_tx(tx, addr):
    addr_l = addr.lower()
    frm = ((tx.get("from") or {}).get("hash") or "").lower()
    to = ((tx.get("to") or {}).get("hash") or "").lower()
    value_wei = int(tx.get("value") or 0)
    if to == addr_l and frm != addr_l:
        direction, counterparty = "in", frm
    elif frm == addr_l:
        direction, counterparty = "out", to
    else:
        direction, counterparty = "self", ""
    return {
        "txid": tx.get("hash", ""),
        "timestamp": tx.get("timestamp", ""),
        "block_height": tx.get("block_number", tx.get("block", "")),
        "direction": direction,
        "amount": f"{value_wei / 1e18:.6f} ETH",
        "counterparty_addresses": counterparty,
        "confirmed": (tx.get("status") == "ok"),
        "tx_explorer_url": f"https://eth.blockscout.com/tx/{tx.get('hash', '')}",
    }


def lookup_eth(addr):
    """Blockscout: balance in wei; tx count from the counters endpoint.
    (Blockscout has no cheap 'total received' figure, so that's left blank
    for ETH -- balance + tx count still show whether the address is live.)"""
    tx_count = 0
    balance_wei = 0
    try:
        info = _get_json(f"https://eth.blockscout.com/api/v2/addresses/{addr}")
        balance_wei = int(info.get("coin_balance") or 0)
    except urllib.error.HTTPError as e:
        if e.code != 404:  # 404 = address never seen on-chain; that's data too
            raise
    else:
        counters = _get_json(f"https://eth.blockscout.com/api/v2/addresses/{addr}/counters")
        tx_count = int(counters.get("transactions_count") or 0)
    return {
        "tx_count": tx_count,
        "total_received": "",
        "balance": f"{balance_wei / 1e18:.6f} ETH" if balance_wei else "0",
        "first_seen": "",
        "last_seen": "",
        "explorer_url": f"https://eth.blockscout.com/address/{addr}",
    }


def load_candidate_wallets():
    wallets = []  # (address, chain), insertion-ordered, deduped
    seen = set()
    with open(MASTER_CSV, encoding="utf-8") as f:
        for r in csv.DictReader(f):
            for chain, col in (("BTC", "btc_addresses"), ("ETH", "eth_addresses")):
                for addr in (r.get(col) or "").split(";"):
                    addr = addr.strip()
                    if addr and addr not in seen:
                        seen.add(addr)
                        wallets.append((addr, chain))
    return wallets


def load_enrichment_rows():
    if not os.path.exists(ENRICHMENT_CSV):
        return []
    with open(ENRICHMENT_CSV, encoding="utf-8") as f:
        return list(csv.DictReader(f))


def write_enrichment(rows):
    with open(ENRICHMENT_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=ENRICHMENT_FIELDNAMES)
        writer.writeheader()
        for r in rows:
            writer.writerow({k: r.get(k, "") for k in ENRICHMENT_FIELDNAMES})


def load_transaction_rows():
    if not os.path.exists(TRANSACTIONS_CSV):
        return []
    with open(TRANSACTIONS_CSV, encoding="utf-8") as f:
        return list(csv.DictReader(f))


def write_transactions(rows):
    with open(TRANSACTIONS_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=TRANSACTIONS_FIELDNAMES)
        writer.writeheader()
        for r in rows:
            writer.writerow({k: r.get(k, "") for k in TRANSACTIONS_FIELDNAMES})


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__,
                                      formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--delay", type=float, default=DEFAULT_DELAY_SECONDS,
                        help=f"Seconds to wait between lookups (default {DEFAULT_DELAY_SECONDS}).")
    parser.add_argument("--limit", type=int, default=None,
                        help="Look up at most N addresses this run.")
    parser.add_argument("--recheck", action="store_true",
                        help="Re-query addresses already enriched (replaces their rows).")
    args = parser.parse_args(argv)

    if not os.path.exists(MASTER_CSV):
        print(f"No {MASTER_CSV} yet -- nothing to look up.")
        return

    candidates = load_candidate_wallets()
    existing = load_enrichment_rows()
    already = {r["address"] for r in existing}
    todo = [(a, c) for a, c in candidates if args.recheck or a not in already]
    if args.limit:
        todo = todo[:args.limit]

    if not todo:
        print("Nothing new to look up.")
        return

    existing_txs = load_transaction_rows()
    tx_by_addr = defaultdict(list)
    for r in existing_txs:
        tx_by_addr[r["address"]].append(r)

    print(f"Looking up {len(todo)} wallet(s), waiting {args.delay}s between each...")
    results = {r["address"]: r for r in existing}
    ok = 0
    for i, (addr, chain) in enumerate(todo):
        try:
            data = lookup_btc(addr) if chain == "BTC" else lookup_eth(addr)
            prior = results.get(addr, {})
            results[addr] = {
                "address": addr,
                "chain": chain,
                "checked_date": date.today().isoformat(),
                "chainabuse_url": f"https://www.chainabuse.com/address/{addr}",
                "notes": prior.get("notes", ""),  # keep hand-written notes on recheck
                **data,
            }
            ok += 1
            active = " *** HAS RECEIVED FUNDS ***" if data["tx_count"] else ""
            print(f"  [{i + 1}/{len(todo)}] {chain} {addr}: "
                  f"txs={data['tx_count']} received={data['total_received'] or 'n/a'} "
                  f"balance={data['balance']}{active}")

            # Per-transaction detail -- this is what IC3's crypto-fraud form
            # actually asks for (txid/timestamp/amount/counterparty), not
            # just the summary stats above.
            if data["tx_count"]:
                raw_txs = fetch_btc_txs(addr) if chain == "BTC" else fetch_eth_txs(addr)
                parse_fn = parse_btc_tx if chain == "BTC" else parse_eth_tx
                tx_records = []
                for raw in raw_txs:
                    rec = parse_fn(raw, addr)
                    tx_records.append({"address": addr, "chain": chain, **rec})
                tx_by_addr[addr] = tx_records
                print(f"      -> saved {len(tx_records)} transaction(s) to {os.path.basename(TRANSACTIONS_CSV)}")
        except Exception as e:
            print(f"  [{i + 1}/{len(todo)}] {chain} {addr}: lookup failed ({e})")
        if i < len(todo) - 1:
            time.sleep(args.delay)

    if ok:
        # full rewrite (not append) so --recheck can replace rows in place
        ordered = [results[a] for a, _ in candidates if a in results]
        ordered += [r for a, r in results.items() if a not in {c for c, _ in candidates}]
        write_enrichment(ordered)
        print(f"Wrote {len(ordered)} row(s) to {ENRICHMENT_CSV}")

        tx_ordered = []
        for a, _ in candidates:
            tx_ordered += tx_by_addr.get(a, [])
        known = {a for a, _ in candidates}
        for a, recs in tx_by_addr.items():
            if a not in known:
                tx_ordered += recs
        write_transactions(tx_ordered)
        print(f"Wrote {len(tx_ordered)} transaction row(s) to {TRANSACTIONS_CSV}")
        print("Run build_master_report.py to pull this into the Wallets / "
              "Wallet Transactions tabs.")
    else:
        print("No successful lookups to add.")


if __name__ == "__main__":
    main()
