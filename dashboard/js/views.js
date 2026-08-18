import { el } from "./dom.js";
import { CAT_COLORS, CAT_LABELS } from "./state.js";
import { stackedMonthly, hbarChart, legend } from "./charts.js";
import { dataTable, badge, catBadge, iocCell, pills, colSubjects, colDomains, colSeen } from "./table.js";

/* ---------- views ---------- */

function viewOverview(d) {
  const c = d.category_counts;
  const activeWallets = d.wallets.filter((w) => w.active).length;
  const cards = el("div", { class: "cards" },
    el("div", { class: "card" }, el("div", { class: "v" }, d.message_total.toLocaleString()),
      el("div", { class: "k" }, "messages analyzed")),
    el("div", { class: "card" }, el("div", { class: "v crit" }, String(c.likely_scam || 0)),
      el("div", { class: "k" }, "likely scam")),
    el("div", { class: "card" }, el("div", { class: "v warn" }, String(c.review || 0)),
      el("div", { class: "k" }, "needs review")),
    el("div", { class: "card" }, el("div", { class: "v" }, String(d.fingerprints.length)),
      el("div", { class: "k" }, "operator fingerprints")),
    el("div", { class: "card" },
      el("div", { class: "v" + (activeWallets ? " crit" : "") }, String(activeWallets)),
      el("div", { class: "k" }, "wallets with on-chain funds")),
    el("div", { class: "card" },
      el("div", { class: "v" + (d.actions.length ? " good" : "") }, String(d.actions.length)),
      el("div", { class: "k" }, "actions taken")));

  const trendPanel = el("div", { class: "panel" },
    el("h2", {}, "Monthly volume by triage category"),
    el("div", { class: "sub" }, "Burner-domain churn shows in the per-bar tooltips (new sender domains that month)."),
    el("div", { class: "chart-wrap" }, stackedMonthly(d.trends)),
    legend(Object.keys(CAT_COLORS).map((k) => [CAT_LABELS[k], CAT_COLORS[k]])));

  const brandItems = d.brands.slice(0, 8).map((b) => ({ label: b.brand, value: b.count, row: b }));
  const brandPanel = el("div", { class: "panel" },
    el("h2", {}, "Top impersonated brands"),
    el("div", { class: "sub" }, "Messages claiming to be each brand."),
    el("div", { class: "chart-wrap" }, hbarChart(brandItems, {
      tip: (x) => `<b>${x.label}</b><br>${x.value} messages · ` +
        `${x.row.distinct_domains} sender domains`,
    })));

  const asnItems = d.asns.slice(0, 8).map((a) => ({
    label: `${a.asn} ${a.as_name || a.isp}`, value: a.messages, row: a }));
  const asnPanel = el("div", { class: "panel" },
    el("h2", {}, "Top origin ASNs"),
    el("div", { class: "sub" }, "Hosting networks the mail actually transited (best-guess deepest public hop)."),
    el("div", { class: "chart-wrap" }, hbarChart(asnItems, {
      color: "#d95926",
      tip: (x) => `<b>${x.label}</b><br>${x.value} messages, ` +
        `${x.row.likely_scam} likely scam<br>${x.row.distinct_ips} IPs · ` +
        `${x.row.distinct_domains} sender domains · ${x.row.countries.join(", ")}`,
    })));

  const fpPanel = el("div", { class: "panel" },
    el("h2", {}, "Strongest operator fingerprints"),
    el("div", { class: "sub" },
      "Indicators reused across 2+ sender domains — the best evidence that campaigns share an operator."),
    dataTable(d.fingerprints.slice(0, 12), [
      { key: "type", label: "Type", render: (r) => badge(r.type, r.confidence) },
      { key: "value", label: "Indicator", render: (r) => iocCell(r.value) },
      { key: "confidence", label: "Confidence", render: (r) => badge(r.confidence, r.confidence) },
      { key: "domain_count", label: "Domains", num: true },
      { key: "domains", label: "Example sender domains", render: (r) => pills(r.domains) },
    ]));

  return el("div", {}, cards, trendPanel,
    el("div", { class: "panel-row" }, brandPanel, asnPanel), fpPanel);
}

function emailDetail(r) {
  const rowsOut = [
    ["Message ID", r.id], ["Source mailbox", r.source], ["Date", r.date],
    ["From", `${r.from_name} <${r.from_addr}>`], ["Reply-To", r.reply_to_addr],
    ["Auth", `DKIM ${r.dkim || "—"} · SPF ${r.spf || "—"} · DMARC ${r.dmarc || "—"}`],
    ["Origin IP", r.origin_ip], ["First URL", r.first_url],
    ["URL domains", r.url_domains.join(", ")],
    ["Link mismatches", r.link_mismatches.join(", ")],
    ["URL flags", r.url_flags.join(", ")],
    ["Phones", r.phone_numbers.join(", ")], ["Wallets", r.wallets.join(", ")],
    ["Contact emails", r.contact_emails.join(", ")],
    ["Images", r.image_count], ["Scam signals", r.scam_signals.join("; ")],
  ].filter(([, v]) => v !== "" && v != null && v !== "<>" && String(v).trim() !== "<>");
  return el("dl", { class: "detail-grid" },
    rowsOut.map(([k, v]) => [el("dt", {}, k), el("dd", { class: "ioc" }, String(v))]));
}

function viewEmails(d) {
  return el("div", { class: "panel" },
    el("h2", {}, "All analyzed messages"),
    el("div", { class: "sub" }, "Click a row for full extracted indicators. Indicator values are defanged."),
    dataTable(d.emails, [
      { key: "date", label: "Date",
        // date is date_iso when available, else the raw Date header --
        // only slice the ISO form; sort chronologically for both.
        render: (r) => /^\d{4}-\d{2}-\d{2}/.test(r.date) ? r.date.slice(0, 10) : r.date,
        sortVal: (r) => Date.parse(r.date) || 0 },
      { key: "category", label: "Category", render: (r) => catBadge(r.category),
        sortVal: (r) => r.category },
      { key: "scam_score", label: "Score", num: true, sortVal: (r) => Number(r.scam_score) || 0 },
      { key: "subject", label: "Subject" },
      { key: "from_addr", label: "From", render: (r) => el("span", { class: "ioc" }, r.from_addr) },
      { key: "impersonated_brands", label: "Brand", render: (r) => r.impersonated_brands.join(", ") },
      { key: "dmarc", label: "DMARC", render: (r) =>
          badge(r.dmarc || "—", r.dmarc === "pass" ? "pass" : (r.dmarc ? "fail" : "neutral")) },
      { key: "url_count", label: "URLs", num: true, sortVal: (r) => Number(r.url_count) || 0 },
      { key: "source", label: "Source" },
    ], {
      detail: emailDetail,
      pageSize: 50,
      filters: [
        { key: "category", label: "Category",
          options: ["likely_scam", "review", "bulk_marketing"], format: (o) => CAT_LABELS[o] },
        { key: "source", label: "Source", options: [...new Set(d.emails.map((e) => e.source))].sort() },
      ],
    }));
}

function viewSenders(d) {
  const domains = el("div", { class: "panel" },
    el("h2", {}, "Sender domains"),
    el("div", { class: "sub" },
      "Highlighted rows have WHOIS enrichment. Recently registered = burner. " +
      "Gmail/iCloud/Outlook/etc. senders are broken out by full address (not lumped under the " +
      "provider's domain) since abuse reports for those go to the provider per-account, not per-domain."),
    dataTable(d.domains, [
      { key: "domain", label: "Domain / Address", render: (r) => iocCell(r.domain) },
      { key: "provider", label: "Provider", render: (r) => r.provider ? badge(r.provider, "neutral") : "" },
      { key: "count", label: "Messages", num: true },
      { key: "categories", label: "Categories", render: (r) => el("span", {}, r.categories.map(catBadge)) },
      { key: "registered", label: "Registered" },
      { key: "registrar", label: "Registrar" },
      { key: "registrant_country", label: "Country" },
      { key: "nameservers", label: "Nameservers", render: (r) => pills(r.nameservers, 3) },
      colSubjects,
    ], { filters: [
      { key: "is_freemail_address", label: "Type", options: ["true", "false"],
          match: (r, v) => String(r.is_freemail_address) === v,
          format: (o) => o === "true" ? "freemail address" : "domain" },
      { key: "enriched", label: "WHOIS", options: ["true", "false"],
          match: (r, v) => String(r.enriched) === v, format: (o) => o === "true" ? "enriched" : "not enriched" },
    ] }));

  const reg = el("div", { class: "panel" },
    el("h2", {}, "Registration clusters"),
    el("div", { class: "sub" },
      "Enriched domains sharing registrar + nameserver infrastructure. A small day-span on an obscure platform = one operator's shopping trip."),
    dataTable(d.registration_clusters, [
      { key: "registrar", label: "Registrar" },
      { key: "nameserver_roots", label: "Nameserver infra", render: (r) => pills(r.nameserver_roots, 4) },
      { key: "domains", label: "Domains", render: (r) => pills(r.domains, 8) },
      { key: "registration_dates", label: "Registered", render: (r) => r.registration_dates.join(", ") },
      { key: "span_days", label: "Span (days)", num: true },
      { key: "messages", label: "Messages", num: true },
    ]));
  return el("div", {}, domains, reg);
}

function viewInfra(d) {
  const asns = el("div", { class: "panel" },
    el("h2", {}, "Origin ASNs"),
    el("div", { class: "sub" },
      "Messages grouped by the ASN of their best-guess origin IP. Received chains can be forged below your provider's hop — strong hints, not proof." +
      (d.unenriched_ip_count ? ` ${d.unenriched_ip_count} IP(s) not yet enriched — rerun lookup_ips.py.` : "")),
    dataTable(d.asns, [
      { key: "asn", label: "ASN", render: (r) => el("span", { class: "ioc nowrap" }, r.asn) },
      { key: "as_name", label: "AS name" },
      { key: "isp", label: "ISP" },
      { key: "countries", label: "Countries", render: (r) => r.countries.join(", ") },
      { key: "messages", label: "Messages", num: true },
      { key: "likely_scam", label: "Likely scam", num: true },
      { key: "distinct_ips", label: "IPs", num: true },
      colDomains, colSubjects,
    ]));
  const ips = el("div", { class: "panel" },
    el("h2", {}, "Origin IP addresses"),
    el("div", { class: "sub" }, "Per-IP granularity — what a hosting provider's abuse desk asks for. Greyed rows are likely Microsoft Exchange version stamps misread as IPs, not real hops."),
    dataTable(d.ips, [
      { key: "ip", label: "IP", render: (r) =>
          r.artifact
            ? el("span", { class: "ioc nowrap dim" }, r.ip + " (artifact)")
            : iocCell(r.ip, "nowrap") },
      { key: "asn", label: "ASN" },
      { key: "as_name", label: "AS name" },
      { key: "isp", label: "ISP" },
      { key: "country", label: "Country" },
      colSeen, colDomains, colSubjects,
    ]));
  return el("div", {}, asns, ips);
}

function viewIndicators(d) {
  const mk = (title, sub, rows, valueLabel) => el("div", { class: "panel" },
    el("h2", {}, title), el("div", { class: "sub" }, sub),
    dataTable(rows, [
      { key: "value", label: valueLabel, render: (r) => el("span", { class: "ioc" }, r.value) },
      { key: "confidence", label: "Confidence", render: (r) => badge(r.confidence, r.confidence) },
      colSeen, colDomains, colSubjects,
    ]));
  const urls = el("div", { class: "panel" },
    el("h2", {}, "Extracted URLs"),
    el("div", { class: "sub" }, "Every URL seen in message bodies, defanged. Never visit these."),
    dataTable(d.urls, [
      { key: "url", label: "URL (defanged)", render: (r) => el("span", { class: "ioc" }, r.url) },
      { key: "domain", label: "Domain", render: (r) => el("span", { class: "ioc" }, r.domain) },
      { key: "id", label: "Message" },
    ], { pageSize: 300 }));
  const images = el("div", { class: "panel" },
    el("h2", {}, "Image fingerprints"),
    el("div", { class: "sub" }, "Hashes of inline/attached images — reused artwork is an operator fingerprint."),
    dataTable(d.images, [
      { key: "hash", label: "SHA-256", render: (r) => el("span", { class: "ioc" }, r.hash) },
      { key: "phash", label: "Perceptual hash", render: (r) => el("span", { class: "ioc" }, r.phash) },
      colSeen, colDomains,
      { key: "filenames", label: "Filenames", render: (r) => pills(r.filenames, 4) },
    ]));
  return el("div", {},
    mk("Phone numbers", "“functional” = near real call-to-action language; “filler” = word-salad camouflage.",
      d.phones, "Phone"),
    mk("Contact emails in bodies", "Attacker-controlled reply addresses planted in message text.",
      d.contact_emails, "Email (defanged)"),
    urls, images);
}

function viewWallets(d) {
  const wallets = el("div", { class: "panel" },
    el("h2", {}, "Crypto wallets"),
    el("div", { class: "sub" },
      "A wallet that has received funds proves the campaign has victims — that's what makes an IC3/Chainabuse report actionable. Explorer links go to legitimate block explorers."),
    dataTable(d.wallets, [
      { key: "chain", label: "Chain" },
      { key: "address", label: "Address", render: (r) => iocCell(r.address) },
      { key: "active", label: "Status", render: (r) =>
          r.active ? badge("HAS RECEIVED FUNDS", "active") : badge("no activity", "neutral") },
      { key: "tx_count", label: "Txs", num: true },
      { key: "total_received", label: "Received", num: true },
      { key: "balance", label: "Balance", num: true },
      colSeen, colDomains,
      { key: "explorer_url", label: "Links", render: (r) => el("span", {},
          r.explorer_url ? el("a", { href: r.explorer_url, target: "_blank", rel: "noopener noreferrer" }, "explorer") : "",
          " ",
          r.chainabuse_url ? el("a", { href: r.chainabuse_url, target: "_blank", rel: "noopener noreferrer" }, "chainabuse") : "") },
    ]));
  const txs = el("div", { class: "panel" },
    el("h2", {}, "Wallet transactions"),
    el("div", { class: "sub" },
      "Per-transaction detail (txid, timestamp, amount, counterparty) — the level IC3's crypto-fraud form asks for. “in” rows are funds received by the scam wallet."),
    dataTable(d.wallet_transactions, [
      { key: "address", label: "Address", render: (r) => el("span", { class: "ioc" }, r.address) },
      { key: "chain", label: "Chain" },
      { key: "direction", label: "Dir", render: (r) =>
          badge(r.direction, r.direction === "in" ? "functional" : "neutral") },
      { key: "amount", label: "Amount", num: true },
      { key: "timestamp", label: "Timestamp" },
      { key: "counterparty_addresses", label: "Counterparty", render: (r) => pills(r.counterparty_addresses, 3) },
      { key: "explorer_url", label: "Tx", render: (r) =>
          r.explorer_url ? el("a", { href: r.explorer_url, target: "_blank", rel: "noopener noreferrer" }, "view") : "" },
    ]));
  return el("div", {}, wallets, txs);
}

function viewCampaigns(d) {
  const templates = el("div", { class: "panel" },
    el("h2", {}, "Template clusters"),
    el("div", { class: "sub" },
      "Messages sharing a body template (SimHash with per-blast parts stripped) — the same kit reused across senders."),
    dataTable(d.template_clusters, [
      { key: "cluster", label: "#", num: true },
      { key: "count", label: "Messages", num: true },
      colDomains,
      { key: "categories", label: "Categories", render: (r) => el("span", {}, r.categories.map(catBadge)) },
      { key: "contacts", label: "Contacts seen", render: (r) => pills(r.contacts, 5) },
      colSubjects,
    ]));
  const brands = el("div", { class: "panel" },
    el("h2", {}, "Impersonated brands"),
    dataTable(d.brands, [
      { key: "brand", label: "Brand" },
      { key: "count", label: "Messages", num: true },
      { key: "categories", label: "Categories", render: (r) => el("span", {}, r.categories.map(catBadge)) },
      colDomains, colSubjects,
    ]));
  const fps = el("div", { class: "panel" },
    el("h2", {}, "All operator fingerprints"),
    el("div", { class: "sub" }, "Every indicator reused across 2+ sender domains. Wallets, images, and IPs are the strongest links; “filler” contacts may be camouflage noise."),
    dataTable(d.fingerprints, [
      { key: "type", label: "Type", render: (r) => badge(r.type, r.confidence) },
      { key: "value", label: "Indicator", render: (r) => iocCell(r.value) },
      { key: "confidence", label: "Confidence", render: (r) => badge(r.confidence, r.confidence) },
      { key: "domain_count", label: "Domains", num: true },
      { key: "domains", label: "Example sender domains", render: (r) => pills(r.domains) },
    ]));
  return el("div", {}, templates, brands, fps);
}

function viewActions(d) {
  const acted = new Set(d.actions.map((a) => a.target));
  return el("div", {},
    el("div", { class: "panel" },
      el("h2", {}, "Actions taken"),
      el("div", { class: "sub" },
        `The enforcement record — what you did with the intelligence. ${d.actions.length} action(s) ` +
        `against ${acted.size} distinct target(s). Log new ones with scripts/log_action.py ` +
        "(or edit data/actions.csv) and republish; acted-on indicators show a “reported” badge throughout the dashboard."),
      d.actions.length
        ? dataTable(d.actions, [
            { key: "date", label: "Date", render: (r) => el("span", { class: "nowrap" }, r.date) },
            { key: "action", label: "Action", render: (r) => badge(r.action, "reported") },
            { key: "target_type", label: "Target type" },
            { key: "target", label: "Target", render: (r) => el("span", { class: "ioc" }, r.target) },
            { key: "reference", label: "Reference" },
            { key: "status", label: "Status", render: (r) =>
                badge(r.status || "—", r.status === "actioned" ? "functional" : "neutral") },
            { key: "notes", label: "Notes", render: (r) => el("span", { class: "dim" }, r.notes) },
          ])
        : el("div", { class: "note" },
            "Nothing logged yet. Example: python scripts/log_action.py ic3_report wallet <address> " +
            "--ref \"IC3 #...\" --notes \"included full tx list\"")));
}

export const VIEWS = [
  ["overview", "Overview", viewOverview],
  ["emails", "Emails", viewEmails],
  ["senders", "Sender Domains", viewSenders],
  ["infra", "Infrastructure", viewInfra],
  ["indicators", "Indicators", viewIndicators],
  ["wallets", "Wallets", viewWallets],
  ["campaigns", "Campaigns", viewCampaigns],
  ["actions", "Actions Taken", viewActions],
];
