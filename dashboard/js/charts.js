import { el, svgEl } from "./dom.js";
import { hoverable } from "./tooltip.js";
import { CAT_COLORS, CAT_LABELS } from "./state.js";

/* ---------- charts (inline SVG) ---------- */

// Monthly stacked bars: message volume by triage category.
export function stackedMonthly(trends) {
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
export function hbarChart(items, { color = "#3987e5", tip } = {}) {
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

export function legend(entries) {
  return el("div", { class: "legend" },
    entries.map(([label, color]) =>
      el("span", {}, el("i", { style: `background:${color}` }), label)));
}
