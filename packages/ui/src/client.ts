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

export type FeedbackResult = { ok: true; mailAction?: string } | { ok: false };

/** "Not phishing" / "Report phishing". The server records it, pins the verdict and puts the mailbox in line (restore or move). */
export async function sendFeedback(
  id: string, conn: Connection, label: "not_phishing" | "phishing", f: typeof fetch = fetch, opts: { idFormat?: string; updateList?: boolean } = {},
): Promise<FeedbackResult> {
  if (!conn.serverUrl || !conn.token) return { ok: false };
  try {
    const q = opts.idFormat ? `?idFormat=${encodeURIComponent(opts.idFormat)}` : "";
    const res = await f(`${conn.serverUrl}/v1/messages/${encodeURIComponent(id)}/feedback${q}`, {
      method: "POST", headers: { Authorization: `Bearer ${conn.token}`, "Content-Type": "application/json" },
      body: JSON.stringify({ label, updateList: opts.updateList ?? false }),
    });
    if (!res.ok) return { ok: false };
    const j = (await res.json()) as { mailAction?: unknown };
    return { ok: true, mailAction: typeof j.mailAction === "string" ? j.mailAction : undefined };
  } catch {
    return { ok: false };
  }
}
