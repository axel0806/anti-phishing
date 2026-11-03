import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { signBlob, verifyBlob } from "./auth.ts";

export type MailProviderName = "gmail" | "outlook";

export interface ConnectResult {
  provider: MailProviderName;
  /** The mailbox's verified address, read from the ID token the provider issued to us. */
  email: string;
  refreshToken: string;
  /** Whatever the caller attached in `start()` (what this sign-in is for). Round-trips inside the signed cookie. */
  purpose: string;
}

/** What the onboarding routes need from a mailbox-connect flow. Tests substitute a fake. */
export interface ConnectFlow {
  providers: MailProviderName[];
  start(provider: MailProviderName, purpose: string): { url: string; cookie: string; maxAge: number };
  finish(query: { code?: string; state?: string }, cookie: string | undefined): Promise<ConnectResult>;
  readonly secureCookie: boolean;
}

export class ConnectError extends Error {}

export interface ConnectConfig {
  secret: string;
  /** https address users reach this server at. The provider redirects back to `${publicUrl}/connect/callback`. */
  publicUrl: string;
  google?: { clientId: string; clientSecret: string } | null;
  microsoft?: { clientId: string; clientSecret?: string; tenant: string } | null;
  fetch?: typeof fetch;
}

const TTL_SECONDS = 600;
const b64u = (b: Buffer) => b.toString("base64url");
const GOOGLE = { auth: "https://accounts.google.com/o/oauth2/v2/auth", token: "https://oauth2.googleapis.com/token", scope: "openid email https://www.googleapis.com/auth/gmail.modify" };
const MICROSOFT_SCOPE = "openid email offline_access Mail.ReadWrite";

/**
 * Browser-based mailbox connection (authorization code + PKCE) for web onboarding. Stateless: the PKCE verifier, anti-forgery state and
 * the purpose of the sign-in live in one short-lived signed cookie, like the dashboard's SSO login.
 */
export class Connect implements ConnectFlow {
  readonly providers: MailProviderName[];
  readonly secureCookie: boolean;
  private f: typeof fetch;

  constructor(private cfg: ConnectConfig) {
    this.f = cfg.fetch ?? fetch;
    // Microsoft identities are only trustworthy within one known tenant: in "common"/"organizations" anyone can run their own tenant and put any address
    // in the email claim. So web sign-in for Outlook needs MICROSOFT_TENANT set to a tenant id; other setups use the command line.
    const singleTenant = !!cfg.microsoft && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(cfg.microsoft.tenant);
    this.providers = [...(cfg.google ? (["gmail"] as const) : []), ...(singleTenant ? (["outlook"] as const) : [])];
    this.secureCookie = cfg.publicUrl.startsWith("https:");
  }

  private get redirectUri() { return `${this.cfg.publicUrl.replace(/\/+$/, "")}/connect/callback`; }

  private endpoints(p: MailProviderName) {
    if (p === "gmail") {
      const g = this.cfg.google;
      if (!g) throw new ConnectError("Gmail is not configured on this server");
      return { auth: GOOGLE.auth, token: GOOGLE.token, scope: GOOGLE.scope, clientId: g.clientId, clientSecret: g.clientSecret as string | undefined };
    }
    const m = this.cfg.microsoft;
    if (!m) throw new ConnectError("Outlook is not configured on this server");
    const base = `https://login.microsoftonline.com/${m.tenant}/oauth2/v2.0`;
    return { auth: `${base}/authorize`, token: `${base}/token`, scope: MICROSOFT_SCOPE, clientId: m.clientId, clientSecret: m.clientSecret };
  }

  start(provider: MailProviderName, purpose: string) {
    const e = this.endpoints(provider);
    const state = b64u(randomBytes(24)), verifier = b64u(randomBytes(32));
    const u = new URL(e.auth);
    u.search = new URLSearchParams({
      client_id: e.clientId, redirect_uri: this.redirectUri, response_type: "code", scope: e.scope, state,
      code_challenge: b64u(createHash("sha256").update(verifier).digest()), code_challenge_method: "S256",
      ...(provider === "gmail" ? { access_type: "offline", prompt: "consent" } : { prompt: "select_account" }),
    }).toString();
    const exp = Math.floor(Date.now() / 1000) + TTL_SECONDS;
    return { url: u.toString(), cookie: signBlob(this.cfg.secret, JSON.stringify({ k: "connect", p: provider, s: state, v: verifier, u: purpose, e: exp })), maxAge: TTL_SECONDS };
  }

  async finish(query: { code?: string; state?: string }, cookie: string | undefined): Promise<ConnectResult> {
    const raw = cookie ? verifyBlob(this.cfg.secret, cookie) : null;
    if (!raw) throw new ConnectError("Missing or invalid connect cookie");
    let c: { k?: string; p?: MailProviderName; s: string; v: string; u: string; e: number };
    try { c = JSON.parse(raw); } catch { throw new ConnectError("Malformed connect cookie"); }
    if (c.k !== "connect" || (c.p !== "gmail" && c.p !== "outlook")) throw new ConnectError("Not a connect cookie"); // e.g. an SSO login cookie
    if (c.e * 1000 < Date.now()) throw new ConnectError("Connect link expired");
    const given = Buffer.from(query.state ?? ""), want = Buffer.from(c.s);
    if (!query.code || given.length !== want.length || !timingSafeEqual(given, want)) throw new ConnectError("State mismatch");

    const e = this.endpoints(c.p);
    const res = await this.f(e.token, {
      method: "POST", signal: AbortSignal.timeout(8000), headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "authorization_code", code: query.code, redirect_uri: this.redirectUri, client_id: e.clientId,
        code_verifier: c.v, ...(e.clientSecret ? { client_secret: e.clientSecret } : {}),
      }).toString(),
    });
    if (!res.ok) throw new ConnectError(`Token exchange failed (${res.status})`);
    const t = (await res.json()) as { refresh_token?: string; id_token?: string; scope?: string };
    if (!t.refresh_token) throw new ConnectError("The provider returned no refresh token; remove this app from the account's connected apps and try again");
    const claims = decodeClaims(t.id_token);
    // The ID token came straight from the token endpoint over TLS, so it needs no signature check (OIDC Core 3.1.3.7).
    const email = (typeof claims.email === "string" ? claims.email : c.p === "outlook" && typeof claims.preferred_username === "string" ? claims.preferred_username : "").toLowerCase();
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) throw new ConnectError("The provider did not return an email address");
    if (c.p === "gmail" && claims.email_verified !== true) throw new ConnectError("The Google account's email is not verified");
    if (c.p === "gmail" && !(t.scope ?? "").includes("gmail.modify")) throw new ConnectError("The mail permission was not granted; connect again and allow access to Gmail");
    if (c.p === "outlook" && String(claims.tid ?? "").toLowerCase() !== (this.cfg.microsoft?.tenant ?? "").toLowerCase()) throw new ConnectError("The Microsoft account is not from this organization's tenant");
    return { provider: c.p, email, refreshToken: t.refresh_token, purpose: c.u };
  }
}

function decodeClaims(idToken: string | undefined): Record<string, unknown> {
  try { return JSON.parse(Buffer.from(idToken!.split(".")[1]!, "base64url").toString("utf8")); } catch { return {}; }
}

// ---- invites: signed, expiring, bound to one org, one role and one mailbox address ----
export interface Invite { id: string; orgId: string; email: string; role: "user" | "viewer" | "analyst" | "admin"; exp: number }
const INVITE_DAYS = 7;

export function makeInvite(secret: string, i: Omit<Invite, "exp" | "id">, now = Date.now()): { token: string; exp: number } {
  const exp = Math.floor(now / 1000) + INVITE_DAYS * 86400;
  return { token: signBlob(secret, JSON.stringify({ k: "invite", j: randomBytes(12).toString("base64url"), o: i.orgId, e: i.email.toLowerCase(), r: i.role, x: exp })), exp };
}

export function readInvite(secret: string, token: string, now = Date.now()): Invite | null {
  const raw = verifyBlob(secret, token);
  if (!raw) return null;
  try {
    const c = JSON.parse(raw) as { k?: string; j?: string; o?: string; e?: string; r?: Invite["role"]; x?: number };
    if (c.k !== "invite" || !c.j || !c.o || !c.e || !c.r || typeof c.x !== "number" || c.x * 1000 < now) return null;
    return { id: c.j, orgId: c.o, email: c.e, role: c.r, exp: c.x };
  } catch { return null; }
}
