import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { createRemoteJWKSet, jwtVerify, type JWTPayload } from "jose";
import { signBlob, verifyBlob } from "./auth.ts";

export interface OidcConfig {
  issuer: string;
  clientId: string;
  clientSecret: string;
  /** Must exactly match what is registered with the IdP, e.g. https://phish.example/admin/callback. */
  redirectUri: string;
  /** Server secret: signs the short-lived login cookie. */
  secret: string;
  /** Entra ID omits `email_verified`. Set this to accept a MISSING claim (an explicit false is always refused). */
  trustMissingEmailVerified?: boolean;
  fetch?: typeof fetch;
}

export class OidcError extends Error {}

const LOGIN_TTL_SECONDS = 600;
const b64u = (b: Buffer) => b.toString("base64url");
const ALGS = ["RS256", "ES256", "PS256"]; // never "none", never HMAC with a public key

interface Discovery { issuer: string; authorization_endpoint: string; token_endpoint: string; jwks_uri: string }

/** Authorization-code + PKCE login for the admin dashboard. Stateless: all in-flight state lives in one signed cookie. */
export class Oidc {
  private disc?: Promise<Discovery>;
  private jwks?: ReturnType<typeof createRemoteJWKSet>;
  private f: typeof fetch;
  readonly secureCookie: boolean;

  constructor(private cfg: OidcConfig) {
    this.f = cfg.fetch ?? fetch;
    this.secureCookie = cfg.redirectUri.startsWith("https:");
  }

  private discovery(): Promise<Discovery> {
    this.disc ??= (async () => {
      const res = await this.f(this.cfg.issuer.replace(/\/+$/, "") + "/.well-known/openid-configuration", { signal: AbortSignal.timeout(5000) });
      if (!res.ok) throw new OidcError(`Discovery failed (${res.status})`);
      const d = (await res.json()) as Discovery;
      if (d.issuer !== this.cfg.issuer) throw new OidcError("Issuer in discovery document does not match configuration");
      return d;
    })();
    this.disc.catch(() => { this.disc = undefined; }); // retry on the next login instead of caching a failure
    return this.disc;
  }

  /** Returns where to send the browser and the cookie value to keep (valid for 10 minutes). */
  async start(): Promise<{ url: string; cookie: string; maxAge: number }> {
    const d = await this.discovery();
    const state = b64u(randomBytes(24)), nonce = b64u(randomBytes(24)), verifier = b64u(randomBytes(32));
    const u = new URL(d.authorization_endpoint);
    u.search = new URLSearchParams({
      response_type: "code", client_id: this.cfg.clientId, redirect_uri: this.cfg.redirectUri, scope: "openid email",
      state, nonce, code_challenge: b64u(createHash("sha256").update(verifier).digest()), code_challenge_method: "S256",
    }).toString();
    const exp = Math.floor(Date.now() / 1000) + LOGIN_TTL_SECONDS;
    return { url: u.toString(), cookie: signBlob(this.cfg.secret, JSON.stringify({ s: state, n: nonce, v: verifier, e: exp })), maxAge: LOGIN_TTL_SECONDS };
  }

  async verifyIdToken(idToken: string, nonce: string): Promise<JWTPayload> {
    const d = await this.discovery();
    this.jwks ??= createRemoteJWKSet(new URL(d.jwks_uri));
    const { payload } = await jwtVerify(idToken, this.jwks, { issuer: this.cfg.issuer, audience: this.cfg.clientId, algorithms: ALGS });
    if (payload.nonce !== nonce) throw new OidcError("Nonce mismatch");
    return payload;
  }

  /** Completes the login. Throws OidcError (safe to show as "sign-in failed") for anything wrong; returns the verified email. */
  async finish(query: { code?: string; state?: string }, cookieValue: string | undefined): Promise<{ email: string }> {
    const raw = cookieValue ? verifyBlob(this.cfg.secret, cookieValue) : null;
    if (!raw) throw new OidcError("Missing or invalid login cookie");
    let c: { s: string; n: string; v: string; e: number };
    try { c = JSON.parse(raw); } catch { throw new OidcError("Malformed login cookie"); }
    if (c.e * 1000 < Date.now()) throw new OidcError("Login expired");
    const given = Buffer.from(query.state ?? ""), want = Buffer.from(c.s);
    if (!query.code || given.length !== want.length || !timingSafeEqual(given, want)) throw new OidcError("State mismatch");

    const d = await this.discovery();
    const res = await this.f(d.token_endpoint, {
      method: "POST",
      signal: AbortSignal.timeout(5000), // a hanging identity provider must not hang the login request
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "authorization_code", code: query.code, redirect_uri: this.cfg.redirectUri,
        client_id: this.cfg.clientId, client_secret: this.cfg.clientSecret, code_verifier: c.v,
      }).toString(),
    });
    if (!res.ok) throw new OidcError(`Token exchange failed (${res.status})`);
    const tok = (await res.json()) as { id_token?: string };
    if (!tok.id_token) throw new OidcError("No id_token in response");

    let claims: JWTPayload;
    try { claims = await this.verifyIdToken(tok.id_token, c.n); } catch (e) { throw new OidcError("ID token rejected: " + (e as Error).message); }
    const email = typeof claims.email === "string" ? claims.email.toLowerCase() : "";
    if (!email) throw new OidcError("No email in ID token");
    const verified = claims.email_verified;
    if (verified === false || (verified === undefined && !this.cfg.trustMissingEmailVerified)) throw new OidcError("Email address is not verified");
    return { email };
  }
}
