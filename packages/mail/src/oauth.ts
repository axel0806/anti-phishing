import { createHash, randomBytes } from "node:crypto";
import { createServer } from "node:http";
import { readFileSync, writeFileSync, existsSync } from "node:fs";
import type { FetchLike } from "./gmail.ts";

export const GMAIL_SCOPE = "https://www.googleapis.com/auth/gmail.modify";
const AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth";
const TOKEN_URL = "https://oauth2.googleapis.com/token";

export interface OAuthConfig { clientId: string; clientSecret: string; redirectPort?: number }
export interface Tokens { refresh_token: string; access_token?: string; expires_at?: number }

const redirectUri = (c: OAuthConfig) => `http://127.0.0.1:${c.redirectPort ?? 53682}/callback`;

export function buildAuthUrl(c: OAuthConfig, state: string, challenge: string): string {
  const p = new URLSearchParams({
    client_id: c.clientId, redirect_uri: redirectUri(c), response_type: "code", scope: GMAIL_SCOPE,
    access_type: "offline", prompt: "consent", state, code_challenge: challenge, code_challenge_method: "S256",
  });
  return `${AUTH_URL}?${p}`;
}

async function tokenRequest(params: Record<string, string>, f: FetchLike): Promise<any> {
  const res = await f(TOKEN_URL, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams(params).toString(),
  });
  if (!res.ok) throw new Error(`Token endpoint failed: ${res.status} ${await res.text()}`);
  return res.json();
}

/** Opens a one-shot loopback server, waits for Google to redirect back, and exchanges the code (PKCE). */
export async function signIn(c: OAuthConfig, openUrl: (url: string) => void, f: FetchLike = fetch as unknown as FetchLike): Promise<Tokens> {
  const verifier = randomBytes(32).toString("base64url");
  const challenge = createHash("sha256").update(verifier).digest("base64url");
  const state = randomBytes(16).toString("hex");

  const code = await new Promise<string>((resolve, reject) => {
    const server = createServer((req, res) => {
      const u = new URL(req.url ?? "/", "http://127.0.0.1");
      if (u.pathname !== "/callback") { res.writeHead(404).end(); return; }
      const ok = u.searchParams.get("state") === state && u.searchParams.get("code");
      res.writeHead(ok ? 200 : 400, { "Content-Type": "text/plain" }).end(ok ? "Signed in. You can close this tab." : "Sign-in failed.");
      server.close();
      ok ? resolve(u.searchParams.get("code")!) : reject(new Error(u.searchParams.get("error") ?? "state mismatch"));
    });
    server.listen(c.redirectPort ?? 53682, "127.0.0.1", () => openUrl(buildAuthUrl(c, state, challenge)));
  });

  const t = await tokenRequest({
    code, client_id: c.clientId, client_secret: c.clientSecret, redirect_uri: redirectUri(c),
    grant_type: "authorization_code", code_verifier: verifier,
  }, f);
  if (!t.refresh_token) throw new Error("Google returned no refresh token; revoke the app's access and sign in again.");
  return { refresh_token: t.refresh_token, access_token: t.access_token, expires_at: Date.now() + t.expires_in * 1000 };
}

/** Returns a function that always yields a valid access token, refreshing and persisting as needed. */
export function tokenSource(c: OAuthConfig, tokens: Tokens, save: (t: Tokens) => void, f: FetchLike = fetch as unknown as FetchLike) {
  return async (): Promise<string> => {
    if (tokens.access_token && tokens.expires_at && tokens.expires_at - 60_000 > Date.now()) return tokens.access_token;
    const t = await tokenRequest({
      client_id: c.clientId, client_secret: c.clientSecret, refresh_token: tokens.refresh_token, grant_type: "refresh_token",
    }, f);
    tokens.access_token = t.access_token;
    tokens.expires_at = Date.now() + t.expires_in * 1000;
    save(tokens);
    return tokens.access_token!;
  };
}

export const loadTokens = (path: string): Tokens | null => (existsSync(path) ? JSON.parse(readFileSync(path, "utf8")) : null);
export const saveTokens = (path: string, t: Tokens) => writeFileSync(path, JSON.stringify(t), { mode: 0o600 });
