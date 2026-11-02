import { BANNER_ATTR, bannerModel, renderBanner, VerdictCache, type VerdictDto } from "@ap/ui";
import { MESSAGE_SELECTOR, messageIdOf } from "./selectors.ts";

const api = (globalThis as any).browser ?? (globalThis as any).chrome;
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
    if (model && !hasBanner(el)) el.prepend(renderBanner(model));
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
