import { $ } from "./dom.js";

/* ---------- tooltip ---------- */

const tooltip = () => $("#tooltip");

export function showTip(evt, html) {
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

export function hideTip() { tooltip().style.display = "none"; }

export function hoverable(node, tipFn) {
  node.addEventListener("mousemove", (e) => showTip(e, tipFn()));
  node.addEventListener("mouseleave", hideTip);
}
