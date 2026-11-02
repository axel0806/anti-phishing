import { createHash, randomBytes } from "node:crypto";
import { createServer, type Server } from "node:http";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import type { FetchLike } from "./gmail.ts";

export const GMAIL_SCOPE = "https://www.googleapis.com/auth/gmail.modify";
export const MICROSOFT_SCOPE = "offline_access Mail.ReadWrite";
const GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth";
const GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token";
const SIGN_IN_TIMEOUT_MS = 5 * 60_000;

export interface OAuthConfig {
  clientId: string;
  /** Absent for public clients (the usual Microsoft desktop registration). */
  clientSecret?: string;
  redirectPort?: number;
  /** Host in the redirect URI: 127.0.0.1 for Google, `localhost` for Microsoft (which ignores the port for it). */
  redirectHost?: string;
  /** Default to Google's endpoints and Gmail scope. */
  authUrl?: string;
  tokenUrl?: string;
  scope?: string;
}
export interface Tokens { refresh_token: string; access_token?: string; expires_at?: number }

export const microsoftEndpoints = (tenant = "common") => ({
  authUrl: `https://login.microsoftonline.com/${tenant}/oauth2/v2.0/authorize`,
  tokenUrl: `https://login.microsoftonline.com/${tenant}/oauth2/v2.0/token`,
});

const redirectUri = (c: OAuthConfig) => `http://${c.redirectHost ?? "127.0.0.1"}:${c.redirectPort ?? 53682}/callback`;

export function buildAuthUrl(c: OAuthConfig, state: string, challenge: string): string {
  const p = new URLSearchParams({
    client_id: c.clientId, redirect_uri: redirectUri(c), response_type: "code", scope: c.scope ?? GMAIL_SCOPE,
    state, code_challenge: challenge, code_challenge_method: "S256",
    ...(c.authUrl ? { prompt: "select_account" } : { access_type: "offline", prompt: "consent" }),
  });
  return `${c.authUrl ?? GOOGLE_AUTH_URL}?${p}`;
}

async function tokenRequest(c: OAuthConfig, params: Record<string, string>, f: FetchLike): Promise<any> {
  const body = new URLSearchParams({ ...params, client_id: c.clientId, ...(c.clientSecret ? { client_secret: c.clientSecret } : {}) });
  const res = await f(c.tokenUrl ?? GOOGLE_TOKEN_URL, { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: body.toString() });
  if (!res.ok) throw new Error(`Token endpoint failed: ${res.status} ${await res.text()}`);
  return res.json();
}

/**
 * Opens one-shot loopback listeners, waits for the provider to redirect back, and exchanges the code (PKCE).
 * A request with the wrong state is answered with 400 but does NOT abort the sign-in, and the wait is bounded.
 */
export async function signIn(c: OAuthConfig, openUrl: (url: string) => void, f: FetchLike = fetch as unknown as FetchLike): Promise<Tokens> {
  const verifier = randomBytes(32).toString("base64url");
  const challenge = createHash("sha256").update(verifier).digest("base64url");
  const state = randomBytes(16).toString("hex");
  const port = c.redirectPort ?? 53682;

  const code = await new Promise<string>((resolve, reject) => {
    const servers: Server[] = [];
    const finish = (fn: () => void) => { clearTimeout(timer); servers.forEach((s) => s.close()); fn(); };
    const timer = setTimeout(() => finish(() => reject(new Error("Sign-in timed out after 5 minutes"))), SIGN_IN_TIMEOUT_MS);
    const handler: Parameters<typeof createServer>[1] = (req, res) => {
      const u = new URL(req.url ?? "/", "http://127.0.0.1");
      if (u.pathname !== "/callback") { res.writeHead(404).end(); return; }
      if (u.searchParams.get("state") !== state) { res.writeHead(400, { "Content-Type": "text/plain" }).end("Unexpected sign-in response."); return; }
      const err = u.searchParams.get("error"), got = u.searchParams.get("code");
      res.writeHead(got ? 200 : 400, { "Content-Type": "text/plain" }).end(got ? "Signed in. You can close this tab." : "Sign-in failed.");
      finish(() => (got ? resolve(got) : reject(new Error(err ?? "no code returned"))));
    };
    // `localhost` may resolve to IPv4 or IPv6 depending on the browser, so listen on both loopback addresses.
    const hosts = (c.redirectHost ?? "127.0.0.1") === "localhost" ? ["127.0.0.1", "::1"] : ["127.0.0.1"];
    let ready = 0;
    hosts.forEach((h) => {
      const s = createServer(handler);
      servers.push(s);
      s.on("error", (e) => { if (h === "127.0.0.1") finish(() => reject(e)); /* ::1 may simply not exist on this machine */ });
      s.listen(port, h, () => { if (++ready === 1) openUrl(buildAuthUrl(c, state, challenge)); });
    });
  });

  const t = await tokenRequest(c, {
    code, redirect_uri: redirectUri(c), grant_type: "authorization_code", code_verifier: verifier, ...(c.scope && c.authUrl ? { scope: c.scope } : {}),
  }, f);
  if (!t.refresh_token) throw new Error("The provider returned no refresh token; revoke the app's access and sign in again.");
  return { refresh_token: t.refresh_token, access_token: t.access_token, expires_at: Date.now() + t.expires_in * 1000 };
}

/**
 * Returns a function that always yields a valid access token. A rotated refresh token (Microsoft issues one on every refresh)
 * replaces the old one and is passed to `save`; if the grant has been revoked, `onRevoked` is called once so the caller can stop retrying.
 */
export function tokenSource(
  c: OAuthConfig, tokens: Tokens, save: (t: Tokens) => void, f: FetchLike = fetch as unknown as FetchLike, onRevoked?: () => void,
) {
  return async (): Promise<string> => {
    if (tokens.access_token && tokens.expires_at && tokens.expires_at - 60_000 > Date.now()) return tokens.access_token;
    let t;
    try {
      t = await tokenRequest(c, { refresh_token: tokens.refresh_token, grant_type: "refresh_token", ...(c.scope && c.authUrl ? { scope: c.scope } : {}) }, f);
    } catch (e) {
      if (/invalid_grant/.test((e as Error).message)) onRevoked?.();
      throw e;
    }
    tokens.access_token = t.access_token;
    tokens.expires_at = Date.now() + t.expires_in * 1000;
    if (t.refresh_token) tokens.refresh_token = t.refresh_token;
    save(tokens);
    return tokens.access_token!;
  };
}

export const loadTokens = (path: string): Tokens | null => (existsSync(path) ? JSON.parse(readFileSync(path, "utf8")) : null);
export const saveTokens = (path: string, t: Tokens) => writeFileSync(path, JSON.stringify(t), { mode: 0o600 });
