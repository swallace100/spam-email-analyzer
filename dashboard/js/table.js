import { el } from "./dom.js";
import { hoverable } from "./tooltip.js";
import { CAT_LABELS, ACTIONS_BY_TARGET } from "./state.js";

/* ---------- generic sortable/searchable table ---------- */

export function badge(text, cls) { return el("span", { class: `badge ${cls}` }, text); }

export function catBadge(c) { return badge(CAT_LABELS[c] || c, c); }

// "reported" marker for any indicator that appears as a target in the
// action log (data/actions.csv) -- hover for the what/when/reference.
export function actionMark(value) {
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

export function iocCell(value, extraCls = "") {
  return el("span", {}, el("span", { class: `ioc ${extraCls}` }, value), " ", actionMark(value));
}

export function pills(values, max = 6) {
  const shown = values.slice(0, max);
  const more = values.length - shown.length;
  return el("div", { class: "pill-list" },
    shown.map((v) => el("span", {}, v)),
    more > 0 ? el("span", { class: "dim" }, `+${more} more`) : null);
}

/* columns: [{key, label, render(row), sortVal(row), num:bool}] */
export function dataTable(rows, columns, { searchKeys = null, filters = [], detail = null, pageSize = 500 } = {}) {
  const wrap = el("div");
  const state = { q: "", sortKey: null, sortDir: -1, filterVals: {}, page: 0 };

  const search = el("input", {
    type: "search", placeholder: "Filter rows…",
    oninput: (e) => { state.q = e.target.value.toLowerCase(); state.page = 0; render(); },
  });
  const toolbar = el("div", { class: "toolbar" }, search);
  for (const f of filters) {
    const sel = el("select", {
      onchange: (e) => { state.filterVals[f.key] = e.target.value; state.page = 0; render(); },
    }, el("option", { value: "" }, f.label + ": all"),
      f.options.map((o) => el("option", { value: o }, f.format ? f.format(o) : o)));
    toolbar.append(sel);
  }
  const count = el("span", { class: "count" });
  toolbar.append(count);
  const pager = el("div", { class: "pager" });
  toolbar.append(pager);

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
    const pageCount = Math.max(1, Math.ceil(out.length / pageSize));
    state.page = Math.min(state.page, pageCount - 1);
    count.textContent = `${out.length.toLocaleString()} of ${rows.length.toLocaleString()} rows`;
    pager.replaceChildren();
    if (pageCount > 1) {
      const prevBtn = el("button", {
        ...(state.page === 0 ? { disabled: "" } : {}),
        onclick: () => { state.page--; render(); },
      }, "‹ Prev");
      const label = el("span", { class: "page-label" }, `Page ${state.page + 1} of ${pageCount}`);
      const nextBtn = el("button", {
        ...(state.page === pageCount - 1 ? { disabled: "" } : {}),
        onclick: () => { state.page++; render(); },
      }, "Next ›");
      pager.append(prevBtn, label, nextBtn);
    }
    const thead = el("thead", {}, el("tr", {},
      columns.map((c) => el("th", {
        onclick: () => {
          state.sortDir = state.sortKey === c.key ? -state.sortDir : (c.num ? -1 : 1);
          state.sortKey = c.key;
          state.page = 0;
          render();
        },
      }, c.label, state.sortKey === c.key
        ? el("span", { class: "dir" }, state.sortDir > 0 ? " ↑" : " ↓") : null))));
    const tbody = el("tbody");
    for (const r of out.slice(state.page * pageSize, (state.page + 1) * pageSize)) {
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
export const colSubjects = { key: "sample_subjects", label: "Sample subjects",
  render: (r) => el("span", { class: "dim" }, (r.sample_subjects || []).join(" | ")) };
export const colDomains = { key: "distinct_domains", label: "Sender domains", num: true };
export const colSeen = { key: "times_seen", label: "Seen", num: true };
