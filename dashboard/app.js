/* Scam Email Tracker dashboard.
   Reads data/data.json (built locally by build_dashboard_data.py — every
   attacker-controlled value arrives already defanged) and renders it as
   tabbed, sortable, searchable indicator tables plus overview charts.
   No dependencies, no build step. */

"use strict";

const CAT_COLORS = {
  likely_scam: "#d03b3b",
  review: "#fab219",
  bulk_marketing: "#3987e5",
};
const CAT_LABELS = {
  likely_scam: "Likely scam",
  review: "Review",
  bulk_marketing: "Bulk marketing",
};

let DATA = null;
let ACTIONS_BY_TARGET = new Map(); // defanged indicator value -> [action, ...]

const $ = (sel, root = document) => root.querySelector(sel);

function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "class") node.className = v;
    else if (k.startsWith("on")) node.addEventListener(k.slice(2), v);
    else node.setAttribute(k, v);
  }
  for (const c of children.flat()) {
    if (c == null) continue;
    node.append(c.nodeType ? c : document.createTextNode(c));
  }
  return node;
}

function svgEl(tag, attrs = {}, ...children) {
  const node = document.createElementNS("http://www.w3.org/2000/svg", tag);
  for (const [k, v] of Object.entries(attrs)) node.setAttribute(k, v);
  node.append(...children);
  return node;
}

/* ---------- tooltip ---------- */

const tooltip = () => $("#tooltip");

function showTip(evt, html) {
  const t = tooltip();
  t.innerHTML = html;
  t.style.display = "block";
  const pad = 14;
  let x = evt.clientX + pad, y = evt.clientY + pad;
  const r = t.getBoundingClientRect();
  if (x + r.width > innerWidth - 8) x = evt.clientX - r.width - pad;
  if (y + r.height > innerHeight - 8) y = evt.clientY - r.height - pad;
  t.style.left = x + "px";
  t.style.top = y + "px";
}

function hideTip() { tooltip().style.display = "none"; }

function hoverable(node, tipFn) {
  node.addEventListener("mousemove", (e) => showTip(e, tipFn()));
  node.addEventListener("mouseleave", hideTip);
}

/* ---------- charts (inline SVG) ---------- */

// Monthly stacked bars: message volume by triage category.
function stackedMonthly(trends) {
  const months = trends.filter((t) => t.month !== "(unknown)");
  const W = Math.max(420, months.length * 64 + 70), H = 240;
  const padL = 44, padB = 28, padT = 12;
  const max = Math.max(1, ...months.map((t) => t.total));
  const yScale = (v) => (H - padB) - (v / max) * (H - padB - padT);
  const svg = svgEl("svg", { width: W, height: H, role: "img",
    "aria-label": "Messages per month by category" });

  // y gridlines + ticks
  const step = max > 40 ? Math.ceil(max / 4 / 10) * 10 : Math.max(1, Math.ceil(max / 4));
  for (let v = 0; v <= max; v += step) {
    const y = yScale(v);
    svg.append(svgEl("line", { x1: padL, x2: W - 8, y1: y, y2: y, stroke: "#2c2c2a" }));
    svg.append(svgEl("text", { x: padL - 6, y: y + 4, "text-anchor": "end", class: "val" }, String(v)));
  }

  const bw = 34;
  months.forEach((t, i) => {
    const x = padL + 16 + i * ((W - padL - 24) / months.length);
    let yCursor = H - padB;
    for (const cat of ["bulk_marketing", "review", "likely_scam"]) {
      const v = t[cat];
      if (!v) continue;
      const h = Math.max(0, (H - padB) - yScale(v) - 2); // 2px spacer between segments
      const y = yCursor - h - (yCursor === H - padB ? 0 : 2);
      const seg = svgEl("rect", { x, y, width: bw, height: h, rx: 3, fill: CAT_COLORS[cat] });
      hoverable(seg, () =>
        `<b>${t.month}</b><br>${CAT_LABELS[cat]}: <b>${v}</b><br>Total: ${t.total}` +
        `<br>New sender domains: ${t.new_domains}`);
      svg.append(seg);
      yCursor = y;
    }
    svg.append(svgEl("text", { x: x + bw / 2, y: H - padB + 16, "text-anchor": "middle" }, t.month));
    svg.append(svgEl("text", { x: x + bw / 2, y: yCursor - 5, "text-anchor": "middle", class: "val" },
      String(t.total)));
  });
  svg.append(svgEl("line", { x1: padL, x2: W - 8, y1: H - padB, y2: H - padB, stroke: "#383835" }));
  return svg;
}

// Horizontal bar list: label / value pairs, single series.
function hbarChart(items, { color = "#3987e5", tip } = {}) {
  const rowH = 26, padL = 8, W = 560, labelW = 210;
  const H = items.length * rowH + 8;
  const max = Math.max(1, ...items.map((d) => d.value));
  const svg = svgEl("svg", { width: W, height: H, role: "img" });
  items.forEach((d, i) => {
    const y = i * rowH + 5;
    const w = Math.max(2, (d.value / max) * (W - labelW - 60));
    svg.append(svgEl("text", { x: padL, y: y + 13, class: "lbl" },
      d.label.length > 30 ? d.label.slice(0, 29) + "…" : d.label));
    const bar = svgEl("rect", { x: labelW, y, width: w, height: rowH - 9, rx: 3, fill: color });
    if (tip) hoverable(bar, () => tip(d));
    svg.append(bar);
    svg.append(svgEl("text", { x: labelW + w + 6, y: y + 13, class: "val" }, String(d.value)));
  });
  return svg;
}

function legend(entries) {
  return el("div", { class: "legend" },
    entries.map(([label, color]) =>
      el("span", {}, el("i", { style: `background:${color}` }), label)));
}

/* ---------- generic sortable/searchable table ---------- */

function badge(text, cls) { return el("span", { class: `badge ${cls}` }, text); }

function catBadge(c) { return badge(CAT_LABELS[c] || c, c); }

// "reported" marker for any indicator that appears as a target in the
// action log (data/actions.csv) -- hover for the what/when/reference.
function actionMark(value) {
  const acts = ACTIONS_BY_TARGET.get(value);
  if (!acts) return null;
  const b = badge("reported", "reported");
  hoverable(b, () => acts.map((a) =>
    `<b>${a.action}</b> · ${a.date} · ${a.status}` +
    (a.reference ? `<br>${a.reference}` : "") +
    (a.notes ? `<br><span style="color:#898781">${a.notes}</span>` : "")
  ).join("<hr style='border-color:#383835'>"));
  return b;
}

function iocCell(value, extraCls = "") {
  return el("span", {}, el("span", { class: `ioc ${extraCls}` }, value), " ", actionMark(value));
}

function pills(values, max = 6) {
  const shown = values.slice(0, max);
  const more = values.length - shown.length;
  return el("div", { class: "pill-list" },
    shown.map((v) => el("span", {}, v)),
    more > 0 ? el("span", { class: "dim" }, `+${more} more`) : null);
}

/* columns: [{key, label, render(row), sortVal(row), num:bool}] */
function dataTable(rows, columns, { searchKeys = null, filters = [], detail = null, pageSize = 500 } = {}) {
  const wrap = el("div");
  const state = { q: "", sortKey: null, sortDir: -1, filterVals: {} };

  const search = el("input", {
    type: "search", placeholder: "Filter rows…",
    oninput: (e) => { state.q = e.target.value.toLowerCase(); render(); },
  });
  const toolbar = el("div", { class: "toolbar" }, search);
  for (const f of filters) {
    const sel = el("select", {
      onchange: (e) => { state.filterVals[f.key] = e.target.value; render(); },
    }, el("option", { value: "" }, f.label + ": all"),
      f.options.map((o) => el("option", { value: o }, f.format ? f.format(o) : o)));
    toolbar.append(sel);
  }
  const count = el("span", { class: "count" });
  toolbar.append(count);

  const tblWrap = el("div", { class: "tbl-wrap" });
  wrap.append(toolbar, tblWrap);

  function matching() {
    let out = rows;
    for (const f of filters) {
      const v = state.filterVals[f.key];
      if (v) out = out.filter((r) => f.match ? f.match(r, v) : String(r[f.key]) === v);
    }
    if (state.q) {
      out = out.filter((r) => {
        const keys = searchKeys || Object.keys(r);
        return keys.some((k) => JSON.stringify(r[k] ?? "").toLowerCase().includes(state.q));
      });
    }
    if (state.sortKey) {
      const col = columns.find((c) => c.key === state.sortKey);
      const sv = col.sortVal || ((r) => r[col.key]);
      out = [...out].sort((a, b) => {
        const va = sv(a), vb = sv(b);
        const cmp = typeof va === "number" && typeof vb === "number"
          ? va - vb : String(va ?? "").localeCompare(String(vb ?? ""));
        return cmp * state.sortDir;
      });
    }
    return out;
  }

  function render() {
    const out = matching();
    count.textContent = `${out.length.toLocaleString()} of ${rows.length.toLocaleString()} rows` +
      (out.length > pageSize ? ` (showing first ${pageSize})` : "");
    const thead = el("thead", {}, el("tr", {},
      columns.map((c) => el("th", {
        onclick: () => {
          state.sortDir = state.sortKey === c.key ? -state.sortDir : (c.num ? -1 : 1);
          state.sortKey = c.key;
          render();
        },
      }, c.label, state.sortKey === c.key
        ? el("span", { class: "dir" }, state.sortDir > 0 ? " ↑" : " ↓") : null))));
    const tbody = el("tbody");
    for (const r of out.slice(0, pageSize)) {
      const tr = el("tr", detail ? { class: "expandable" } : {},
        columns.map((c) => el("td", { class: c.num ? "num" : "" },
          c.render ? c.render(r) : String(r[c.key] ?? ""))));
      if (detail) {
        tr.addEventListener("click", () => {
          if (tr.nextSibling && tr.nextSibling.classList.contains("detail")) {
            tr.nextSibling.remove();
            return;
          }
          tbody.querySelectorAll("tr.detail").forEach((d) => d.remove());
          tr.after(el("tr", { class: "detail" },
            el("td", { colspan: String(columns.length) }, detail(r))));
        });
      }
      tbody.append(tr);
    }
    tblWrap.replaceChildren(el("table", {}, thead, tbody));
  }

  render();
  return wrap;
}

/* shared column helpers */
const colSubjects = { key: "sample_subjects", label: "Sample subjects",
  render: (r) => el("span", { class: "dim" }, (r.sample_subjects || []).join(" | ")) };
const colDomains = { key: "distinct_domains", label: "Sender domains", num: true };
const colSeen = { key: "times_seen", label: "Seen", num: true };

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
    el("div", { class: "sub" }, "Highlighted rows have WHOIS enrichment. Recently registered = burner."),
    dataTable(d.domains, [
      { key: "domain", label: "Domain", render: (r) => iocCell(r.domain) },
      { key: "count", label: "Messages", num: true },
      { key: "categories", label: "Categories", render: (r) => el("span", {}, r.categories.map(catBadge)) },
      { key: "registered", label: "Registered" },
      { key: "registrar", label: "Registrar" },
      { key: "registrant_country", label: "Country" },
      { key: "nameservers", label: "Nameservers", render: (r) => pills(r.nameservers, 3) },
      colSubjects,
    ], { filters: [{ key: "enriched", label: "WHOIS", options: ["true", "false"],
          match: (r, v) => String(r.enriched) === v, format: (o) => o === "true" ? "enriched" : "not enriched" }] }));

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

/* ---------- boot ---------- */

const VIEWS = [
  ["overview", "Overview", viewOverview],
  ["emails", "Emails", viewEmails],
  ["senders", "Sender Domains", viewSenders],
  ["infra", "Infrastructure", viewInfra],
  ["indicators", "Indicators", viewIndicators],
  ["wallets", "Wallets", viewWallets],
  ["campaigns", "Campaigns", viewCampaigns],
  ["actions", "Actions Taken", viewActions],
];

function activate(id) {
  document.querySelectorAll("nav button").forEach((b) =>
    b.classList.toggle("active", b.dataset.view === id));
  document.querySelectorAll("section.view").forEach((s) =>
    s.classList.toggle("active", s.id === "view-" + id));
  const section = $("#view-" + id);
  if (!section.dataset.rendered) {
    section.append(VIEWS.find(([vid]) => vid === id)[2](DATA));
    section.dataset.rendered = "1";
  }
  location.hash = id;
}

async function boot() {
  const main = $("main");
  try {
    const resp = await fetch("data/data.json", { cache: "no-store" });
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    DATA = await resp.json();
    DATA.actions = DATA.actions || [];
    for (const a of DATA.actions) {
      if (!ACTIONS_BY_TARGET.has(a.target)) ACTIONS_BY_TARGET.set(a.target, []);
      ACTIONS_BY_TARGET.get(a.target).push(a);
    }
  } catch (e) {
    main.textContent = `Could not load data/data.json (${e.message}). ` +
      "Run build_dashboard_data.py and redeploy.";
    return;
  }
  $("#generated").textContent =
    `${DATA.message_total.toLocaleString()} messages · data generated ${DATA.generated_at.slice(0, 16).replace("T", " ")} UTC`;
  const nav = $("nav");
  for (const [id, label] of VIEWS) {
    nav.append(el("button", { "data-view": id, onclick: () => activate(id) }, label));
  }
  for (const [id] of VIEWS) main.append(el("section", { class: "view", id: "view-" + id }));
  const start = location.hash.slice(1);
  activate(VIEWS.some(([id]) => id === start) ? start : "overview");
}

boot();
