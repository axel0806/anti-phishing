import { bannerModel, type BannerModel, type VerdictDto } from "./banner.ts";
import { BANNER_ATTR, MESSAGE_SELECTOR, messageIdOf } from "./selectors.ts";

const SERVER = "http://127.0.0.1:8787";
const COLORS = { phishing: { bg: "#fde8e8", border: "#c81e1e" }, suspicious: { bg: "#fef6e0", border: "#b7791f" } } as const;

function render(m: BannerModel): HTMLElement {
  const c = COLORS[m.level];
  const box = document.createElement("div");
  box.setAttribute(BANNER_ATTR, "1");
  box.style.cssText = `background:${c.bg};border-left:4px solid ${c.border};padding:10px 14px;margin:8px 0;font:14px/1.4 Arial,sans-serif;color:#222`;
  const title = document.createElement("strong");
  title.textContent = m.title; // textContent only: flag evidence comes from untrusted email content
  box.append(title);
  if (m.reasons.length) {
    const ul = document.createElement("ul");
    ul.style.margin = "6px 0 0 18px";
    for (const r of m.reasons) { const li = document.createElement("li"); li.textContent = r; ul.append(li); }
    box.append(ul);
  }
  if (m.note) { const n = document.createElement("div"); n.style.cssText = "margin-top:6px;font-size:12px;color:#555"; n.textContent = m.note; box.append(n); }
  return box;
}

const inFlight = new Set<string>();

async function annotate(el: Element): Promise<void> {
  const id = messageIdOf(el);
  if (!id || el.querySelector(`[${BANNER_ATTR}]`) || inFlight.has(id)) return;
  inFlight.add(id);
  try {
    const res = await fetch(`${SERVER}/v1/messages/${encodeURIComponent(id)}/verdict`);
    if (!res.ok) return;
    const model = bannerModel((await res.json()) as VerdictDto);
    if (model && !el.querySelector(`[${BANNER_ATTR}]`)) el.prepend(render(model));
  } catch {
    // Server not running: fail quietly, never break Gmail.
  } finally {
    inFlight.delete(id);
  }
}

const scan = () => document.querySelectorAll(MESSAGE_SELECTOR).forEach((el) => void annotate(el));
new MutationObserver(scan).observe(document.body, { childList: true, subtree: true });
scan();
