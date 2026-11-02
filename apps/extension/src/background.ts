import type { VerdictDto } from "./banner.ts";
import { normalizeVerdict, resolveConnection, type Connection, type ManagedPolicy } from "./connection.ts";

/**
 * Fetches a verdict from the configured server. If the message has not been scanned yet and we hold a session token,
 * asks the server for a dry-run scan (the extension never moves mail itself). Null on any failure: Gmail must never break.
 */
export async function fetchVerdict(id: string, conn: Connection, f: typeof fetch = fetch): Promise<VerdictDto | null> {
  const headers: Record<string, string> = conn.token ? { Authorization: `Bearer ${conn.token}` } : {};
  try {
    const res = await f(`${conn.serverUrl}/v1/messages/${encodeURIComponent(id)}/verdict`, { headers });
    if (res.ok) return normalizeVerdict(await res.json());
    if (res.status === 404 && conn.token) {
      const scan = await f(`${conn.serverUrl}/v1/scan`, {
        method: "POST", headers: { ...headers, "Content-Type": "application/json" },
        body: JSON.stringify({ providerMessageId: id, mode: "dry_run" }),
      });
      return scan.ok ? normalizeVerdict(await scan.json()) : null;
    }
    return null;
  } catch {
    return null;
  }
}

// `browser` exists in Firefox, `chrome` in Chrome; both accept sendResponse + `return true`.
const api = (globalThis as any).browser ?? (globalThis as any).chrome;

async function currentConnection(): Promise<Connection> {
  const [local, managed] = await Promise.all([
    api.storage.local.get("connection").then((r: any) => (r.connection as Connection | undefined) ?? null),
    api.storage.managed.get(["serverUrl", "lockServerUrl", "certFingerprint"]).then((r: any) => r as ManagedPolicy, () => undefined),
  ]);
  return resolveConnection(local, managed).connection;
}

api?.runtime?.onMessage.addListener((msg: any, _sender: unknown, sendResponse: (r: VerdictDto | null) => void) => {
  if (msg?.type !== "verdict" || typeof msg.id !== "string") return false;
  void currentConnection().then((c) => fetchVerdict(msg.id, c)).then(sendResponse, () => sendResponse(null));
  return true;
});
