import type { VerdictDto } from "./banner.ts";

export interface Connection { serverUrl: string; serverId: string | null; token: string }
export interface ManagedPolicy { serverUrl?: string; lockServerUrl?: boolean; certFingerprint?: string }

/** The Phase 1 local runner, so the extension still works with no setup. */
export const DEFAULT_CONNECTION: Connection = { serverUrl: "http://127.0.0.1:8787", serverId: null, token: "" };

const LOCAL_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]"]);

export type UrlCheck = { ok: true; url: string } | { ok: false; error: string };

/** HTTPS is required except for loopback hosts. Returns the origin only (no path, query or credentials). */
export function normalizeServerUrl(input: string): UrlCheck {
  let u: URL;
  try { u = new URL(input.trim()); } catch { return { ok: false, error: "Not a valid URL" }; }
  if (u.protocol !== "https:" && u.protocol !== "http:") return { ok: false, error: "Use an https:// URL" };
  if (u.username || u.password) return { ok: false, error: "Do not put credentials in the URL" };
  if (u.protocol === "http:" && !LOCAL_HOSTS.has(u.hostname)) return { ok: false, error: "HTTPS is required unless the server is on localhost" };
  return { ok: true, url: u.origin };
}

export type Handshake = { ok: true; serverId: string | null; version: string } | { ok: false; error: string };

/** GET /v1/health: confirms the server speaks API v1 and learns its ID. */
export async function handshake(serverUrl: string, f: typeof fetch = fetch): Promise<Handshake> {
  try {
    const res = await f(serverUrl + "/v1/health");
    if (!res.ok) return { ok: false, error: `Server answered ${(res as { status?: number }).status ?? "an error"}` };
    const j = (await res.json()) as { version?: unknown; serverId?: unknown; apiVersions?: unknown };
    if (!j || typeof j !== "object" || !Array.isArray(j.apiVersions) || !j.apiVersions.includes("v1")) {
      return { ok: false, error: "This server does not speak API v1" };
    }
    return { ok: true, serverId: typeof j.serverId === "string" ? j.serverId : null, version: String(j.version ?? "") };
  } catch (e) {
    return { ok: false, error: "Could not reach the server: " + (e as Error).message };
  }
}

/** A session token is scoped to one server, so changing the URL or server ID drops it (and the caller must drop cached verdicts). */
export function applyConnection(current: Connection | null, next: { serverUrl: string; serverId: string | null; token?: string }): { connection: Connection; cleared: boolean } {
  const changed = !current || current.serverUrl !== next.serverUrl || current.serverId !== next.serverId;
  let token = next.token ?? (changed ? "" : current!.token);
  // The options form is pre-filled with the old token: a token that merely echoes the previous server's must never follow us to a new one.
  if (changed && current && token === current.token) token = "";
  return { connection: { serverUrl: next.serverUrl, serverId: next.serverId, token }, cleared: changed && !!current && current.token !== "" };
}

/** Managed (enterprise policy) settings beat local ones when the URL is locked. An insecure managed URL is ignored. */
export function resolveConnection(local: Connection | null, managed: ManagedPolicy | undefined): { connection: Connection; locked: boolean; error?: string } {
  if (managed?.serverUrl) {
    const m = normalizeServerUrl(managed.serverUrl);
    if (!m.ok) {
      // An admin asked for a lock but gave an unusable URL: stay locked and unusable so the problem is visible, never fall back to a local server.
      if (managed.lockServerUrl) return { connection: { serverUrl: "", serverId: null, token: "" }, locked: true, error: `The managed server URL is invalid: ${m.error}` };
    } else if (managed.lockServerUrl) {
      const same = local?.serverUrl === m.url;
      return { connection: { serverUrl: m.url, serverId: same ? local!.serverId : null, token: same ? local!.token : "" }, locked: true };
    } else if (!local) return { connection: { ...DEFAULT_CONNECTION, serverUrl: m.url }, locked: false };
  }
  return { connection: local ?? DEFAULT_CONNECTION, locked: false };
}

/** Accepts both server shapes: the cloud API (flat verdict) and the Phase 1 local runner (wrapped). */
export function normalizeVerdict(j: unknown): VerdictDto | null {
  if (!j || typeof j !== "object") return null;
  const o = j as Record<string, unknown>;
  if (o.verdict && typeof o.verdict === "object") return j as VerdictDto;
  if (typeof o.verdict === "string" && typeof o.score === "number" && Array.isArray(o.flags)) {
    return { verdict: o as unknown as VerdictDto["verdict"], action: typeof o.action === "string" ? o.action : "none", shadow: false };
  }
  return null;
}

/** Why the extension cannot work yet, or null if it can. Shown as a badge so a managed install is never silently dead. */
export function setupProblem(r: { connection: Connection; error?: string }, hasPermission: boolean): string | null {
  if (r.error) return r.error;
  if (!r.connection.serverUrl) return "No server configured";
  if (!hasPermission) return "Click to allow access to " + r.connection.serverUrl;
  return null;
}
