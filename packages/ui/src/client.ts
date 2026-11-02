import type { VerdictDto } from "./banner.ts";
import { normalizeVerdict, type Connection } from "./connection.ts";

/**
 * Fetches a verdict from the configured server. If the message has not been scanned yet and we hold a session token,
 * asks the server for a dry-run scan (UI surfaces never move mail themselves). Null on any failure: the host app must never break.
 */
export async function fetchVerdict(id: string, conn: Connection, f: typeof fetch = fetch, opts: { idFormat?: string } = {}): Promise<VerdictDto | null> {
  if (!conn.serverUrl) return null;
  const headers: Record<string, string> = conn.token ? { Authorization: `Bearer ${conn.token}` } : {};
  try {
    const q = opts.idFormat ? `?idFormat=${encodeURIComponent(opts.idFormat)}` : "";
    const res = await f(`${conn.serverUrl}/v1/messages/${encodeURIComponent(id)}/verdict${q}`, { headers });
    if (res.ok) return normalizeVerdict(await res.json());
    if (res.status === 404 && conn.token) {
      const scan = await f(`${conn.serverUrl}/v1/scan`, {
        method: "POST", headers: { ...headers, "Content-Type": "application/json" },
        body: JSON.stringify({ providerMessageId: id, mode: "dry_run", ...(opts.idFormat ? { idFormat: opts.idFormat } : {}) }),
      });
      return scan.ok ? normalizeVerdict(await scan.json()) : null;
    }
    return null;
  } catch {
    return null;
  }
}
