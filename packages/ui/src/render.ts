import type { BannerModel } from "./banner.ts";
import type { FeedbackResult } from "./client.ts";

/** Marks our banner so hosts can tell whether a message already has one. */
export const BANNER_ATTR = "data-ap-banner";

const COLORS = { phishing: { bg: "#fde8e8", border: "#c81e1e" }, suspicious: { bg: "#fef6e0", border: "#b7791f" } } as const;

/**
 * Builds the warning banner element. Everything that came from an email or a model goes in via `textContent` and never as
 * HTML, so a hostile sender or a manipulated model cannot inject markup or script into Gmail or Outlook.
 */
export interface BannerOptions {
  /** When given, the banner shows "Not phishing" / "Report phishing" buttons that call this. */
  onFeedback?: (label: "not_phishing" | "phishing") => Promise<FeedbackResult>;
}

const THANKS: Record<string, string> = {
  restored: "Thanks. The email was moved back to your inbox.",
  moved: "Thanks. The email was moved to your Phishing folder.",
};

export function renderBanner(m: BannerModel, doc: Document = document, opts: BannerOptions = {}): HTMLElement {
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
  if (opts.onFeedback) {
    const send = opts.onFeedback;
    const row = doc.createElement("div");
    row.style.cssText = "margin-top:10px;display:flex;gap:8px;align-items:center;flex-wrap:wrap";
    const status = doc.createElement("span");
    status.style.cssText = "font-size:12px";
    let busy = false;
    const buttons: HTMLButtonElement[] = [];
    for (const [text, label] of [["Not phishing", "not_phishing"], ["Report phishing", "phishing"]] as const) {
      const b = doc.createElement("button");
      b.type = "button";
      b.textContent = text;
      b.style.cssText = "padding:4px 10px;font:13px Arial,sans-serif;cursor:pointer";
      b.addEventListener("click", async () => {
        if (busy) return; // a double click must not send twice
        busy = true;
        buttons.forEach((x) => (x.disabled = true));
        status.textContent = "Sending...";
        let res: FeedbackResult = { ok: false };
        try { res = await send(label); } catch { /* shown as a failure below */ }
        if (res.ok) status.textContent = (res.mailAction && THANKS[res.mailAction]) || "Thanks, your feedback was saved.";
        else {
          status.textContent = "Your feedback could not be saved. Try again.";
          buttons.forEach((x) => (x.disabled = false));
          busy = false;
        }
      });
      buttons.push(b);
      row.append(b);
    }
    row.append(status);
    box.append(row);
  }
  return box;
}
