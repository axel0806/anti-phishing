import type { BannerModel } from "./banner.ts";

/** Marks our banner so hosts can tell whether a message already has one. */
export const BANNER_ATTR = "data-ap-banner";

const COLORS = { phishing: { bg: "#fde8e8", border: "#c81e1e" }, suspicious: { bg: "#fef6e0", border: "#b7791f" } } as const;

/**
 * Builds the warning banner element. Everything that came from an email or a model goes in via `textContent` and never as
 * HTML, so a hostile sender or a manipulated model cannot inject markup or script into Gmail or Outlook.
 */
export function renderBanner(m: BannerModel, doc: Document = document): HTMLElement {
  const c = COLORS[m.level];
  const box = doc.createElement("div");
  box.setAttribute(BANNER_ATTR, "1");
  box.setAttribute("role", "alert");
  box.style.cssText = `background:${c.bg};border-left:4px solid ${c.border};padding:10px 14px;margin:8px 0;font:14px/1.4 Arial,sans-serif;color:#222`;
  const title = doc.createElement("strong");
  title.textContent = m.title;
  box.append(title);
  if (m.reasons.length) {
    const ul = doc.createElement("ul");
    ul.style.margin = "6px 0 0 18px";
    for (const r of m.reasons) {
      const li = doc.createElement("li");
      li.textContent = r;
      ul.append(li);
    }
    box.append(ul);
  }
  if (m.explanation) {
    const ex = doc.createElement("div");
    ex.style.cssText = "margin-top:8px;font-style:italic";
    ex.textContent = "AI assessment: " + m.explanation;
    box.append(ex);
  }
  if (m.note) {
    const n = doc.createElement("div");
    n.style.cssText = "margin-top:6px;font-size:12px;color:#555";
    n.textContent = m.note;
    box.append(n);
  }
  return box;
}
