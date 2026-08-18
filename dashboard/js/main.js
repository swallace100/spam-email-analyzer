/* Scam Email Tracker dashboard.
   Reads data/data.json (built locally by build_dashboard_data.py — every
   attacker-controlled value arrives already defanged) and renders it as
   tabbed, sortable, searchable indicator tables plus overview charts.
   No dependencies, no build step (native ES modules). */

import { $, el } from "./dom.js";
import { DATA, setData, ACTIONS_BY_TARGET } from "./state.js";
import { VIEWS } from "./views.js";

/* ---------- boot ---------- */

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
  let data;
  try {
    const resp = await fetch("data/data.json", { cache: "no-store" });
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    data = await resp.json();
    data.actions = data.actions || [];
    for (const a of data.actions) {
      if (!ACTIONS_BY_TARGET.has(a.target)) ACTIONS_BY_TARGET.set(a.target, []);
      ACTIONS_BY_TARGET.get(a.target).push(a);
    }
    setData(data);
  } catch (e) {
    main.textContent = `Could not load data/data.json (${e.message}). ` +
      "Run build_dashboard_data.py and redeploy.";
    return;
  }
  $("#generated").textContent =
    `${data.message_total.toLocaleString()} messages · data generated ${data.generated_at.slice(0, 16).replace("T", " ")} UTC`;
  const nav = $("nav");
  for (const [id, label] of VIEWS) {
    nav.append(el("button", { "data-view": id, onclick: () => activate(id) }, label));
  }
  for (const [id] of VIEWS) main.append(el("section", { class: "view", id: "view-" + id }));
  const start = location.hash.slice(1);
  activate(VIEWS.some(([id]) => id === start) ? start : "overview");
}

boot();
