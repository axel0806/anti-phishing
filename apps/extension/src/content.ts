import { bannerModel, type BannerModel, type VerdictDto } from "./banner.ts";
import { VerdictCache } from "./cache.ts";
import { BANNER_ATTR, MESSAGE_SELECTOR, messageIdOf } from "./selectors.ts";

const api = (globalThis as any).browser ?? (globalThis as any).chrome;
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

const cache = new VerdictCache(async (id) => ((await api.runtime.sendMessage({ type: "verdict", id })) as VerdictDto | null) ?? null);
const done = new WeakSet<Element>();
// Direct children only: the email body is untrusted and could contain a lookalike attribute.
const hasBanner = (el: Element) => Array.from(el.children).some((c) => c.hasAttribute(BANNER_ATTR));
async function annotate(el: Element): Promise<void> {
  const id = messageIdOf(el);
  if (!id || done.has(el) || hasBanner(el)) return;
  done.add(el);
  try {
    const dto = await cache.get(id);
    const model = dto ? bannerModel(dto) : null;
    if (model && !hasBanner(el)) el.prepend(render(model));
  } catch {
    // Server not running: fail quietly, never break Gmail.
  }
  // Messages with no verdict yet may be re-checked later (the cache limits how often it hits the server).
  if (!hasBanner(el)) setTimeout(() => done.delete(el), 30_000);
}

const scan = () => document.querySelectorAll(MESSAGE_SELECTOR).forEach((el) => void annotate(el));
let timer: ReturnType<typeof setTimeout> | undefined;
const debounced = () => { clearTimeout(timer); timer = setTimeout(scan, 300); };
new MutationObserver(debounced).observe(document.body, { childList: true, subtree: true });
scan();
