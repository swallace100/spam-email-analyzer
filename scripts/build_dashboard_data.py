#!/usr/bin/env python3
"""Build dashboard/data/data.json from the master CSVs -- the same
aggregations as build_master_report.py's xlsx tabs, serialized for the
static web dashboard instead of openpyxl.

Like the xlsx, this is a full rebuild from the CSVs every run, never an
append. It reuses build_master_report's loaders and clustering helpers so
the two outputs can't drift apart on the underlying numbers.

Everything attacker-controlled that could render as a live link is
DEFANGED at export time (hxxps[://]evil[.]top, name[@]evil[.]top,
203[.]0[.]113[.]9), the way threat-intel platforms publish indicators.
The dashboard is meant to be hosted (behind auth) on a cloud static host,
and no raw email content leaves this machine -- only extracted indicators
and aggregate stats. Analyst-tool URLs (block explorers, Chainabuse) are
deliberately left clickable; they point at legitimate services.
"""

import csv
import json
import os
from collections import Counter, defaultdict
from datetime import datetime, timezone

import build_master_report as bmr

# scripts/ lives one level below the repo root that data/, output/, and
# dashboard/ hang off of.
BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT_JSON = os.path.join(BASE, "dashboard", "data", "data.json")
ACTIONS_CSV = os.path.join(BASE, "data", "actions.csv")


# --- Defanging (threat-intel convention) --------------------------------

def defang_domain(d):
    return (d or "").replace(".", "[.]")


def defang_ip(ip):
    ip = ip or ""
    return ip.replace(".", "[.]").replace(":", "[:]") if ip else ""


def defang_email(e):
    e = e or ""
    if "@" in e:
        local, _, dom = e.rpartition("@")
        return f"{local}[@]{defang_domain(dom)}"
    return e


def defang_url(u):
    u = u or ""
    u = u.replace("https://", "hxxps[://]").replace("http://", "hxxp[://]")
    scheme, sep, rest = u.partition("[://]")
    return scheme + sep + rest.replace(".", "[.]") if sep else u.replace(".", "[.]")


def defang_list(values, fn=defang_domain, sep=";"):
    return [fn(v.strip()) for v in (values or "").split(sep) if v.strip()]


def _split(field, sep=";"):
    return [v.strip() for v in (field or "").split(sep) if v.strip()]


def _samples(items, n_subjects=4, n_ids=6):
    return {
        "sample_subjects": [it["subject"][:80] for it in items[:n_subjects]],
        "sample_ids": [it["id"] for it in items[:n_ids]],
    }


def _domains_of(items):
    return sorted(set(defang_domain(it["from_domain"]) for it in items if it["from_domain"]))


# Targets in data/actions.csv are logged un-defanged (they're pasted from
# the CSVs); defang per type here so the exported value string-matches the
# defanged indicator it refers to in the other sections.
ACTION_DEFANG = {"domain": defang_domain, "ip": defang_ip, "email": defang_email,
                 "url": defang_url}


def load_actions():
    """Enforcement actions logged via scripts/log_action.py (or by hand)."""
    if not os.path.exists(ACTIONS_CSV):
        return []
    with open(ACTIONS_CSV, encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    out = []
    for r in rows:
        ttype = (r.get("target_type") or "other").strip()
        fn = ACTION_DEFANG.get(ttype, lambda v: v)
        out.append({
            "date": r.get("date", ""),
            "action": r.get("action", ""),
            "target_type": ttype,
            "target": fn((r.get("target") or "").strip()),
            "reference": r.get("reference", ""),
            "status": r.get("status", ""),
            "notes": r.get("notes", ""),
        })
    out.sort(key=lambda a: a["date"], reverse=True)
    return out


def main():
    if not os.path.exists(bmr.MASTER_CSV):
        print(f"No {bmr.MASTER_CSV} yet -- nothing to build.")
        return

    with open(bmr.MASTER_CSV, encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    url_rows = []
    if os.path.exists(bmr.MASTER_URLS_CSV):
        with open(bmr.MASTER_URLS_CSV, encoding="utf-8") as f:
            url_rows = list(csv.DictReader(f))
    enrichment = bmr.load_enrichment()
    ip_enrichment = bmr.load_ip_enrichment()
    wallet_enrichment = bmr.load_wallet_enrichment()
    wallet_transactions = bmr.load_wallet_transactions()

    cat_counts = Counter(r["category"] for r in rows)

    # ---- Trends (per month) ----
    by_month = defaultdict(list)
    for r in rows:
        by_month[bmr.month_of(r) or "(unknown)"].append(r)
    domain_first_month = {}
    for m in sorted(by_month):
        for r in by_month[m]:
            d = r.get("from_domain")
            if d and d not in domain_first_month:
                domain_first_month[d] = m
    trends = []
    for m in sorted(by_month):
        items = by_month[m]
        cats = Counter(it["category"] for it in items)
        brand_counts = Counter(b for it in items
                               for b in _split(it.get("impersonated_brands")))
        trends.append({
            "month": m,
            "total": len(items),
            "likely_scam": cats.get("likely_scam", 0),
            "review": cats.get("review", 0),
            "bulk_marketing": cats.get("bulk_marketing", 0),
            "new_domains": sum(1 for fm in domain_first_month.values() if fm == m),
            "top_brands": [{"brand": b, "count": n} for b, n in brand_counts.most_common(3)],
        })

    # ---- Sender domains (all -- the UI filters; xlsx only shows 2+) ----
    cluster_map = defaultdict(list)
    for r in rows:
        if r["from_domain"]:
            cluster_map[r["from_domain"]].append(r)
    domains = []
    for d, items in sorted(cluster_map.items(), key=lambda x: -len(x[1])):
        enr = enrichment.get(d, {})
        domains.append({
            "domain": defang_domain(d),
            "count": len(items),
            "categories": sorted(set(it["category"] for it in items)),
            "registered": enr.get("registered_date", ""),
            "registrar": enr.get("registrar", ""),
            "nameservers": defang_list(enr.get("nameservers", "")),
            "registrant_org": enr.get("registrant_org", ""),
            "registrant_country": enr.get("registrant_country", ""),
            "notes": enr.get("notes", ""),
            "enriched": bool(enr),
            **_samples(items),
        })

    # ---- Registration clusters (bought-together burner domains) ----
    def ns_roots(ns_field):
        roots = set()
        for ns in _split(ns_field):
            parts = ns.lower().split(".")
            if len(parts) >= 2:
                roots.add(".".join(parts[-2:]))
        return frozenset(roots)

    msg_count_by_domain = Counter(r["from_domain"] for r in rows if r["from_domain"])
    reg_groups = defaultdict(list)
    for d, enr in enrichment.items():
        registrar = (enr.get("registrar") or "").strip().lower()
        roots = ns_roots(enr.get("nameservers"))
        if registrar and roots:
            reg_groups[(registrar, roots)].append((d, enr))
    registration_clusters = []
    for (registrar, roots), members in sorted(reg_groups.items(), key=lambda x: -len(x[1])):
        if len(members) < 2:
            continue
        doms = sorted(d for d, _ in members)
        dates = sorted(e.get("registered_date", "") for _, e in members if e.get("registered_date"))
        span = None
        if len(dates) >= 2:
            try:
                from datetime import date as _date
                span = (_date.fromisoformat(dates[-1][:10])
                        - _date.fromisoformat(dates[0][:10])).days
            except ValueError:
                pass
        registration_clusters.append({
            "registrar": registrar,
            "nameserver_roots": sorted(defang_domain(x) for x in roots),
            "domains": [defang_domain(d) for d in doms],
            "registration_dates": dates,
            "span_days": span,
            "messages": sum(msg_count_by_domain.get(d, 0) for d in doms),
        })

    # ---- Origin ASNs + per-IP detail ----
    asn_map = defaultdict(list)   # asn -> [(row, ip)]
    ip_map = defaultdict(list)    # ip -> [row]
    unenriched_ips = set()
    for r in rows:
        ip = bmr.origin_ip_of(r)
        if not ip:
            continue
        ip_map[ip].append(r)
        enr = ip_enrichment.get(ip)
        if enr and enr.get("asn"):
            asn_map[enr["asn"]].append((r, ip))
        elif not enr:
            unenriched_ips.add(ip)
    asns = []
    for asn, entries in sorted(asn_map.items(), key=lambda x: -len(x[1])):
        items = [r for r, _ in entries]
        ips = sorted(set(ip for _, ip in entries))
        enr0 = ip_enrichment.get(ips[0], {})
        countries = sorted(set(
            ip_enrichment.get(ip, {}).get("country_code", "") for ip in ips) - {""})
        asns.append({
            "asn": asn,
            "as_name": enr0.get("as_name", ""),
            "isp": enr0.get("isp", ""),
            "countries": countries,
            "messages": len(items),
            "likely_scam": sum(1 for it in items if it["category"] == "likely_scam"),
            "distinct_ips": len(ips),
            "distinct_domains": len(set(it["from_domain"] for it in items if it["from_domain"])),
            **_samples(items),
        })
    ips_out = []
    for ip, items in sorted(ip_map.items(), key=lambda x: -len(x[1])):
        enr = ip_enrichment.get(ip, {})
        ips_out.append({
            "ip": defang_ip(ip),
            "asn": enr.get("asn", ""),
            "as_name": enr.get("as_name", ""),
            "isp": enr.get("isp", ""),
            "country": enr.get("country", ""),
            "times_seen": len(items),
            "distinct_domains": len(set(it["from_domain"] for it in items if it["from_domain"])),
            "artifact": bmr._is_likely_exchange_artifact(ip, enr),
            **_samples(items),
        })

    # ---- Template clusters ----
    template_clusters = []
    for num, members in enumerate(
            sorted(bmr.cluster_by_template(rows), key=lambda m: -len(m)), start=1):
        contacts = set()
        for m in members:
            contacts.update(defang_email(x) for x in _split(m.get("contacts_functional")))
            contacts.update(_split(m.get("phones_functional")))
        template_clusters.append({
            "cluster": num,
            "count": len(members),
            "distinct_domains": len(set(m["from_domain"] for m in members if m["from_domain"])),
            "categories": sorted(set(m["category"] for m in members)),
            "contacts": sorted(contacts),
            **_samples(members),
        })

    # ---- Brands ----
    brand_map = defaultdict(list)
    for r in rows:
        for b in _split(r.get("impersonated_brands")):
            brand_map[b].append(r)
    brands = []
    for b, items in sorted(brand_map.items(), key=lambda x: -len(x[1])):
        brands.append({
            "brand": b,
            "count": len(items),
            "categories": sorted(set(it["category"] for it in items)),
            "distinct_domains": len(_domains_of(items)),
            **_samples(items),
        })

    # ---- Phones / contact emails (with functional/filler confidence) ----
    def contact_indicators(value_col, functional_col, defang_fn):
        cmap = defaultdict(list)
        for r in rows:
            functional = {x.lower() for x in _split(r.get(functional_col))}
            for v in _split(r.get(value_col)):
                cmap[v].append((r, v.lower() in functional))
        out = []
        for v, entries in sorted(cmap.items(),
                                 key=lambda x: (0 if any(f for _, f in x[1]) else 1, -len(x[1]))):
            items = [r for r, _ in entries]
            out.append({
                "value": defang_fn(v),
                "confidence": "functional" if any(f for _, f in entries) else "filler",
                "times_seen": len(items),
                "distinct_domains": len(_domains_of(items)),
                **_samples(items),
            })
        return cmap, out

    phone_map, phones = contact_indicators("phone_numbers", "phones_functional", lambda v: v)
    email_map, contact_emails = contact_indicators(
        "contact_emails_in_body", "contacts_functional", defang_email)

    # ---- Wallets + transactions ----
    wallet_map = defaultdict(list)
    for r in rows:
        for chain, col in (("BTC", "btc_addresses"), ("ETH", "eth_addresses")):
            for w in _split(r.get(col)):
                wallet_map[(chain, w)].append(r)
    wallets = []
    for (chain, w), items in sorted(
            wallet_map.items(),
            key=lambda x: (0 if (wallet_enrichment.get(x[0][1], {}).get("tx_count") or "0") not in ("", "0") else 1,
                           -len(x[1]))):
        enr = wallet_enrichment.get(w, {})
        try:
            txs = int(enr.get("tx_count") or 0)
        except ValueError:
            txs = 0
        wallets.append({
            "chain": chain,
            "address": w,
            "times_seen": len(items),
            "distinct_domains": len(_domains_of(items)),
            "tx_count": txs,
            "active": txs > 0,
            "total_received": enr.get("total_received", ""),
            "balance": enr.get("balance", ""),
            "first_seen": enr.get("first_seen", ""),
            "last_seen": enr.get("last_seen", ""),
            "checked_date": enr.get("checked_date", ""),
            "explorer_url": enr.get("explorer_url", ""),
            "chainabuse_url": enr.get("chainabuse_url", ""),
            **_samples(items),
        })
    wallet_txs = []
    for recs in wallet_transactions.values():
        for t in recs:
            wallet_txs.append({
                "address": t.get("address", ""),
                "chain": t.get("chain", ""),
                "txid": t.get("txid", ""),
                "timestamp": t.get("timestamp", ""),
                "direction": t.get("direction", ""),
                "amount": t.get("amount", ""),
                "counterparty_addresses": _split(t.get("counterparty_addresses")),
                "confirmed": t.get("confirmed", ""),
                "explorer_url": t.get("tx_explorer_url", ""),
            })
    wallet_txs.sort(key=lambda t: (t["address"], t["timestamp"]))

    # ---- Images ----
    image_map = defaultdict(list)
    image_phash = {}
    image_names = defaultdict(set)
    for r in rows:
        hashes = _split(r.get("image_hashes"))
        phashes = _split(r.get("image_phashes"))
        names = _split(r.get("image_filenames"))
        for i, h in enumerate(hashes):
            image_map[h].append(r)
            if i < len(phashes) and h not in image_phash:
                image_phash[h] = phashes[i]
            if i < len(names):
                image_names[h].add(names[i])
    images = []
    for h, items in sorted(image_map.items(), key=lambda x: -len(x[1])):
        images.append({
            "hash": h,
            "phash": image_phash.get(h, ""),
            "times_seen": len(items),
            "distinct_domains": len(_domains_of(items)),
            "filenames": sorted(image_names[h])[:4],
            **_samples(items),
        })

    # ---- Operator fingerprints (indicator reused across 2+ sender domains) ----
    fingerprints = []
    def _fp(kind, value, conf, doms, rank):
        fingerprints.append({"type": kind, "value": value, "confidence": conf,
                             "domain_count": len(doms), "domains": doms[:8],
                             "_rank": rank})
    for p, entries in phone_map.items():
        doms = _domains_of([r for r, _ in entries])
        if len(doms) >= 2:
            is_f = any(f for _, f in entries)
            _fp("phone", p, "functional" if is_f else "filler", doms, 1 if is_f else 2)
    for e, entries in email_map.items():
        doms = _domains_of([r for r, _ in entries])
        if len(doms) >= 2:
            is_f = any(f for _, f in entries)
            _fp("email", defang_email(e), "functional" if is_f else "filler", doms, 1 if is_f else 2)
    for (chain, w), items in wallet_map.items():
        doms = _domains_of(items)
        if len(doms) >= 2:
            _fp(chain, w, "wallet", doms, 0)
    for h, items in image_map.items():
        doms = _domains_of(items)
        if len(doms) >= 2:
            _fp("image", h, "image", doms, 1)
    for ip, items in ip_map.items():
        if bmr._is_likely_exchange_artifact(ip, ip_enrichment.get(ip, {})):
            continue
        doms = _domains_of(items)
        if len(doms) >= 2:
            _fp("ip", defang_ip(ip), "ip", doms, 0)
    fingerprints.sort(key=lambda x: (x["_rank"], -x["domain_count"]))
    for fp in fingerprints:
        fp.pop("_rank")

    # ---- Full email list (curated columns, defanged) ----
    emails = []
    for r in rows:
        emails.append({
            "id": r["id"],
            "source": r.get("source", ""),
            "category": r.get("category", ""),
            "scam_score": r.get("scam_score", ""),
            "scam_signals": _split(r.get("scam_signals"), sep=";"),
            "date": r.get("date_iso", "") or r.get("date", ""),
            "subject": r.get("subject", ""),
            "from_name": r.get("from_name", ""),
            "from_addr": defang_email(r.get("from_addr", "")),
            "from_domain": defang_domain(r.get("from_domain", "")),
            "reply_to_addr": defang_email(r.get("reply_to_addr", "")),
            "dkim": r.get("dkim", ""),
            "spf": r.get("spf", ""),
            "dmarc": r.get("dmarc", ""),
            "origin_ip": defang_ip(bmr.origin_ip_of(r)),
            "url_count": r.get("url_count", ""),
            "url_domains": defang_list(r.get("url_domains")),
            "first_url": defang_url(r.get("first_url", "")),
            "impersonated_brands": _split(r.get("impersonated_brands")),
            "phone_numbers": _split(r.get("phone_numbers")),
            "wallets": _split(r.get("btc_addresses")) + _split(r.get("eth_addresses")),
            "contact_emails": defang_list(r.get("contact_emails_in_body"), defang_email),
            "link_mismatches": defang_list(r.get("link_mismatches")),
            "url_flags": _split(r.get("url_flags")),
            "image_count": r.get("image_count", ""),
        })

    # ---- URL list ----
    urls = [{"id": r["id"], "url": defang_url(r["url"]), "domain": defang_domain(r["domain"])}
            for r in url_rows]

    data = {
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "message_total": len(rows),
        "category_counts": dict(cat_counts),
        "unenriched_ip_count": len(unenriched_ips),
        "trends": trends,
        "domains": domains,
        "registration_clusters": registration_clusters,
        "asns": asns,
        "ips": ips_out,
        "template_clusters": template_clusters,
        "brands": brands,
        "phones": phones,
        "contact_emails": contact_emails,
        "wallets": wallets,
        "wallet_transactions": wallet_txs,
        "images": images,
        "fingerprints": fingerprints,
        "emails": emails,
        "urls": urls,
        "actions": load_actions(),
    }

    os.makedirs(os.path.dirname(OUT_JSON), exist_ok=True)
    with open(OUT_JSON, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, separators=(",", ":"))
    size_kb = os.path.getsize(OUT_JSON) / 1024
    print(f"Saved {OUT_JSON} ({len(rows)} messages, {size_kb:.0f} KB)")


if __name__ == "__main__":
    main()
