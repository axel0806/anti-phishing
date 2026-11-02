import type { VerdictDto } from "./banner.ts";

const SERVER = "http://127.0.0.1:8787";

/** Fetches a verdict from the local server; null when not scanned or the server is down. */
export async function fetchVerdict(id: string, f: typeof fetch = fetch): Promise<VerdictDto | null> {
  try {
    const res = await f(`${SERVER}/v1/messages/${encodeURIComponent(id)}/verdict`);
    return res.ok ? ((await res.json()) as VerdictDto) : null;
  } catch {
    return null;
  }
}

// `browser` exists in Firefox, `chrome` in Chrome; both accept sendResponse + `return true`.
const api = (globalThis as any).browser ?? (globalThis as any).chrome;
api?.runtime?.onMessage.addListener((msg: any, _sender: unknown, sendResponse: (r: VerdictDto | null) => void) => {
  if (msg?.type !== "verdict" || typeof msg.id !== "string") return false;
  void fetchVerdict(msg.id).then(sendResponse);
  return true;
});
