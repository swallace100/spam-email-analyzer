/* ---------- shared app state ---------- */

export const CAT_COLORS = {
  likely_scam: "#d03b3b",
  review: "#fab219",
  bulk_marketing: "#3987e5",
};
export const CAT_LABELS = {
  likely_scam: "Likely scam",
  review: "Review",
  bulk_marketing: "Bulk marketing",
};

export let DATA = null;
export function setData(d) { DATA = d; }

export let ACTIONS_BY_TARGET = new Map(); // defanged indicator value -> [action, ...]
