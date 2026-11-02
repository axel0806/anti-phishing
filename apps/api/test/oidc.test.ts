import { createHash } from "node:crypto";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { exportJWK, generateKeyPair, SignJWT, type JWK } from "jose";
import type { FastifyInstance } from "fastify";
import { connect, Store, type Connection } from "@ap/db";
import { buildApp } from "../src/app.ts";
import { Oidc } from "../src/oidc.ts";
import { ScanService } from "../src/service.ts";

const SECRET = "oidc-test-secret-oidc-test-secret", SID = "srv-oidc", CLIENT_ID = "dash-client", CLIENT_SECRET = "dash-secret";
let conn: Connection, store: Store, app: FastifyInstance, idp: Server, issuer: string, privateKey: CryptoKey, jwk: JWK;
let redirectUri = "";

// What the fake IdP will put into the next id_token, and what it saw at /token.
let claims: Record<string, unknown> = {};
let signWith: CryptoKey | null = null;
let seen: { verifier?: string; challenge?: string; secret?: string; code?: string } = {};
let expectedChallenge = "";

const b64u = (b: Buffer) => b.toString("base64url");

beforeAll(async () => {
  const kp = await generateKeyPair("RS256", { extractable: true });
  privateKey = kp.privateKey as CryptoKey;
  jwk = { ...(await exportJWK(kp.publicKey)), kid: "k1", alg: "RS256", use: "sig" };
  idp = createServer((req, res) => {
    const url = new URL(req.url ?? "/", "http://x");
    const json = (o: unknown, code = 200) => { res.writeHead(code, { "content-type": "application/json" }).end(JSON.stringify(o)); };
    if (url.pathname === "/.well-known/openid-configuration") {
      return json({ issuer, authorization_endpoint: issuer + "/authorize", token_endpoint: issuer + "/token", jwks_uri: issuer + "/jwks" });
    }
    if (url.pathname === "/jwks") return json({ keys: [jwk] });
    if (url.pathname === "/token" && req.method === "POST") {
      let body = "";
      req.on("data", (d) => (body += d));
      req.on("end", async () => {
        const p = new URLSearchParams(body);
        seen = { verifier: p.get("code_verifier") ?? undefined, secret: p.get("client_secret") ?? undefined, code: p.get("code") ?? undefined };
        const pkceOk = !!seen.verifier && b64u(createHash("sha256").update(seen.verifier).digest()) === expectedChallenge;
        if (p.get("code") !== "good-code" || !pkceOk || p.get("client_secret") !== CLIENT_SECRET || p.get("redirect_uri") !== redirectUri) return json({ error: "invalid_grant" }, 400);
        const jwt = await new SignJWT(claims).setProtectedHeader({ alg: "RS256", kid: "k1" }).sign(signWith ?? privateKey);
        return json({ id_token: jwt, access_token: "unused", token_type: "Bearer" });
      });
      return;
    }
    res.writeHead(404).end();
  });
  await new Promise<void>((r) => idp.listen(0, "127.0.0.1", r));
  issuer = `http://127.0.0.1:${(idp.address() as AddressInfo).port}`;
  redirectUri = "https://phish.example/admin/callback";

  conn = await connect(); store = new Store(conn.db);
  const org = await store.createOrg("SSO Co");
  await store.createUser({ email: "boss@sso.example", orgId: org.id, role: "admin" });
  await store.createUser({ email: "viewer@sso.example", orgId: org.id, role: "viewer" });
  await store.createUser({ email: "plain@sso.example", orgId: org.id, role: "user" });
  app = buildApp({
    store, secret: SECRET, serverId: SID, service: new ScanService({ store, mailFor: () => null }),
    oidc: new Oidc({ issuer, clientId: CLIENT_ID, clientSecret: CLIENT_SECRET, redirectUri, secret: SECRET }),
  });
  await app.ready();
});
afterAll(async () => { await app.close(); await conn.close(); idp.close(); });

/** Runs /admin/login, returns what the IdP would see and the cookie the browser keeps. */
async function startLogin() {
  const r = await app.inject({ method: "GET", url: "/admin/login" });
  expect(r.statusCode).toBe(302);
  const loc = new URL(r.headers.location as string);
  const cookie = String(r.headers["set-cookie"]).split(";")[0]!;
  expectedChallenge = loc.searchParams.get("code_challenge")!;
  return { loc, cookie, state: loc.searchParams.get("state")!, nonce: loc.searchParams.get("nonce")!, setCookie: String(r.headers["set-cookie"]) };
}
const baseClaims = (nonce: string, over: Record<string, unknown> = {}) => ({
  iss: issuer, aud: CLIENT_ID, sub: "u-1", email: "boss@sso.example", email_verified: true, nonce,
  iat: Math.floor(Date.now() / 1000), exp: Math.floor(Date.now() / 1000) + 300, ...over,
});
const callback = (cookie: string, state: string, code = "good-code") =>
  app.inject({ method: "GET", url: `/admin/callback?code=${code}&state=${state}`, headers: { cookie } });

describe("login redirect", () => {
  it("sends the browser to the IdP with PKCE, state, nonce and a short-lived HttpOnly cookie", async () => {
    const { loc, setCookie } = await startLogin();
    expect(loc.origin + loc.pathname).toBe(issuer + "/authorize");
    expect(loc.searchParams.get("client_id")).toBe(CLIENT_ID);
    expect(loc.searchParams.get("redirect_uri")).toBe(redirectUri);
    expect(loc.searchParams.get("response_type")).toBe("code");
    expect(loc.searchParams.get("scope")).toBe("openid email");
    expect(loc.searchParams.get("code_challenge_method")).toBe("S256");
    expect(loc.searchParams.get("state")!.length).toBeGreaterThan(20);
    expect(setCookie).toMatch(/HttpOnly/i);
    expect(setCookie).toMatch(/SameSite=Lax/i);
    expect(setCookie).toMatch(/Max-Age=600/);
  });
  it("is 404 when SSO is not configured", async () => {
    const plain = buildApp({ store, secret: SECRET, serverId: SID, service: new ScanService({ store, mailFor: () => null }) });
    expect((await plain.inject({ method: "GET", url: "/admin/login" })).statusCode).toBe(404);
    await plain.close();
  });
});

describe("callback", () => {
  it("signs in an existing admin and hands the dashboard a working session token in the URL fragment", async () => {
    const s = await startLogin();
    claims = baseClaims(s.nonce);
    const r = await callback(s.cookie, s.state);
    expect(r.statusCode).toBe(302);
    const loc = r.headers.location as string;
    expect(loc).toMatch(/^\/admin\/#token=v1\./); // fragment: never sent to a server or logged
    expect(String(r.headers["set-cookie"])).toMatch(/Max-Age=0/); // the login cookie is consumed
    const token = loc.split("#token=")[1]!;
    const me = await app.inject({ method: "GET", url: "/v1/settings", headers: { authorization: "Bearer " + token } });
    expect(me.statusCode).toBe(200);
    expect(seen.secret).toBe(CLIENT_SECRET);
  });
  it("lets a viewer in too (the dashboard then limits what they see)", async () => {
    const s = await startLogin();
    claims = baseClaims(s.nonce, { email: "viewer@sso.example" });
    expect((await callback(s.cookie, s.state)).statusCode).toBe(302);
  });
  it("refuses people who have no account or no dashboard role, without creating accounts", async () => {
    for (const email of ["stranger@sso.example", "plain@sso.example"]) {
      const s = await startLogin();
      claims = baseClaims(s.nonce, { email });
      const r = await callback(s.cookie, s.state);
      expect(r.statusCode, email).toBe(403);
      expect(r.body).not.toContain("token=");
    }
    expect(await store.getUserByEmail("stranger@sso.example")).toBeNull();
  });
  it("matches the email case-insensitively", async () => {
    const s = await startLogin();
    claims = baseClaims(s.nonce, { email: "BOSS@SSO.example" });
    expect((await callback(s.cookie, s.state)).statusCode).toBe(302);
  });
});

describe("callback rejects forged or stale logins", () => {
  const expectRefused = async (mutate: (s: Awaited<ReturnType<typeof startLogin>>) => { claims?: Record<string, unknown>; cookie?: string; state?: string; code?: string }, label: string) => {
    const s = await startLogin();
    const m = mutate(s);
    claims = m.claims ?? baseClaims(s.nonce);
    const r = await callback(m.cookie ?? s.cookie, m.state ?? s.state, m.code);
    expect(r.statusCode, label).toBeGreaterThanOrEqual(400);
    expect(r.statusCode, label).toBeLessThan(500);
    expect(r.headers.location ?? "", label).not.toContain("token=");
  };
  it("wrong state (CSRF)", () => expectRefused(() => ({ state: "attacker-state" }), "state"));
  it("missing or tampered cookie", async () => {
    await expectRefused(() => ({ cookie: "ap_oidc=garbage" }), "garbage cookie");
    await expectRefused((s) => ({ cookie: s.cookie.slice(0, -3) + "xyz" }), "tampered cookie");
  });
  it("wrong nonce", () => expectRefused((s) => ({ claims: baseClaims("not-" + s.nonce) }), "nonce"));
  it("wrong audience", () => expectRefused((s) => ({ claims: baseClaims(s.nonce, { aud: "someone-else" }) }), "aud"));
  it("wrong issuer", () => expectRefused((s) => ({ claims: baseClaims(s.nonce, { iss: "https://evil.example" }) }), "iss"));
  it("expired id_token", () => expectRefused((s) => ({ claims: baseClaims(s.nonce, { exp: Math.floor(Date.now() / 1000) - 3600 }) }), "exp"));
  it("unverified email", () => expectRefused((s) => ({ claims: baseClaims(s.nonce, { email_verified: false }) }), "email_verified"));
  it("missing email", () => expectRefused((s) => ({ claims: baseClaims(s.nonce, { email: undefined }) }), "no email"));
  it("IdP rejects the code", () => expectRefused(() => ({ code: "bad-code" }), "bad code"));
  it("a token signed by some other key", async () => {
    const other = await generateKeyPair("RS256");
    signWith = other.privateKey as CryptoKey;
    try { await expectRefused((s) => ({ claims: baseClaims(s.nonce) }), "wrong key"); } finally { signWith = null; }
  });
  it("an unsigned (alg=none) token", async () => {
    const s = await startLogin();
    const none = `${b64u(Buffer.from('{"alg":"none"}'))}.${b64u(Buffer.from(JSON.stringify(baseClaims(s.nonce))))}.`;
    // Exercise the verifier directly: an alg=none token must never verify.
    const oidc = new Oidc({ issuer, clientId: CLIENT_ID, clientSecret: CLIENT_SECRET, redirectUri, secret: SECRET });
    await expect(oidc.verifyIdToken(none, s.nonce)).rejects.toThrow();
  });
});
