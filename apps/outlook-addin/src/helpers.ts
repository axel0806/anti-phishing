import type { Connection } from "@ap/ui";

interface KeyValueStore { getItem(k: string): string | null; setItem(k: string, v: string): void; removeItem(k: string): void }
const KEY = "ap_token";

/** The add-in is served by the API itself, so the server is always the page's own origin; only the token is stored. */
export function connectionFromStorage(storage: KeyValueStore, origin: string): Connection {
  let token = "";
  try { token = storage.getItem(KEY) ?? ""; } catch { /* storage can be blocked: behave as signed out */ }
  return { serverUrl: origin, serverId: null, token };
}
export function saveToken(storage: KeyValueStore, token: string): void {
  try { storage.setItem(KEY, token.trim()); } catch { /* nothing to do */ }
}
export function clearToken(storage: KeyValueStore): void {
  try { storage.removeItem(KEY); } catch { /* nothing to do */ }
}

/** Outlook gives add-ins an EWS-style item id; the server needs the REST id (it then translates that to the id it scans under). */
export function restIdFor(itemId: string | undefined, convert: (id: string, version: string) => string, version = "v2.0"): string | null {
  if (!itemId) return null;
  try { return convert(itemId, version); } catch { return null; }
}

/**
 * The task pane stays open while the user clicks through messages, and replies can arrive out of order.
 * Call `next()` at the start of each refresh; the function it returns says whether that refresh is still the newest.
 * A stale reply must not render, or its feedback buttons would act on a message the user is no longer looking at.
 */
export function latestOnly(): () => () => boolean {
  let n = 0;
  return () => { const mine = ++n; return () => mine === n; };
}
