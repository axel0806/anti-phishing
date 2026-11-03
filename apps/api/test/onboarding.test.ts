import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { FastifyInstance } from "fastify";
import type { MailProvider } from "@ap/mail";
import { AdminQueries, connect, Store, type Connection, type User } from "@ap/db";
import { buildApp, signToken } from "../src/app.ts";
import { decryptSecret, verifyToken } from "../src/auth.ts";
import { makeInvite, type ConnectFlow, type ConnectResult, type MailProviderName } from "../src/connect.ts";
import { ScanService } from "../src/service.ts";

const SECRET = "s".repeat(40), SID = "srv-onb", KEY = "ab".repeat(32), SETUP = "setup-token-123";
let conn: Connection, store: Store, app: FastifyInstance;
let nextResult: ConnectResult | Error;
// A stand-in for the provider round trip: the "cookie" simply carries the purpose back, like the real signed cookie does.
const flow: ConnectFlow = {
  providers: ["gmail", "outlook"], secureCookie: false,
  start: (p: MailProviderName, purpose: string) => ({ url: `https://idp.example/auth?p=${p}`, cookie: "cookie-" + Buffer.from(purpose).toString("base64url"), maxAge: 600 }),
  finish: async (_q, cookie) => {
    if (!cookie) throw new Error("no cookie");
    if (nextResult instanceof Error) throw nextResult;
    return { ...nextResult, purpose: Buffer.from(cookie.replace("cookie-", ""), "base64url").toString() };
  },
};
const mailbox: MailProvider = { fetchRaw: async () => Buffer.from(""), move: async () => {}, unmove: async () => {}, addLabel: async () => {}, ensureFolder: async (n) => n, listRecentInbox: async () => [], getLabelNames: async () => [], watch: async () => {} };
const tok = (u: User) => "Bearer " + signToken(SECRET, { uid: u.id, sid: SID, exp: Math.floor(Date.now() / 1000) + 3600 });
const cookieHeader = (purpose: string) => "ap_connect=cookie-" + Buffer.from(purpose).toString("base64url");
const callback = (purpose: string) => app.inject({ method: "GET", url: "/connect/callback?code=c&state=s", headers: { cookie: cookieHeader(purpose) } });
const form = (body: Record<string, string>) => ({ method: "POST" as const, url: "/setup/start", payload: new URLSearchParams(body).toString(), headers: { "content-type": "application/x-www-form-urlencoded" } });
const result = (email: string, provider: MailProviderName = "gmail"): ConnectResult => ({ provider, email, refreshToken: "refresh-for-" + email, purpose: "" });

beforeAll(async () => {
  conn = await connect();
  store = new Store(conn.db);
  app = buildApp({ store, admin: new AdminQueries(conn.db), secret: SECRET, serverId: SID, tokenKey: KEY, connect: flow, setupToken: SETUP, publicUrl: "https://phish.example", service: new ScanService({ store, mailFor: () => mailbox }) });
  await app.ready();
});
afterAll(async () => { await app.close(); await conn.close(); });

describe("first-run setup", () => {
  it("offers setup only while the server has no users, and refuses a wrong setup token", async () => {
    const page = await app.inject({ method: "GET", url: "/setup" });
    expect(page.statusCode).toBe(200);
    expect(page.body).toContain("Setup token");
    expect(page.headers["content-security-policy"]).toContain("default-src 'none'");
    expect((await app.inject(form({ token: "nope", provider: "gmail" }))).statusCode).toBe(400);
    expect((await app.inject(form({ token: "", provider: "gmail" }))).statusCode).toBe(400);
    expect((await app.inject(form({ token: SETUP, provider: "yahoo" }))).statusCode).toBe(400);
  });

  it("with the right token sends the browser to the provider and sets a sealed cookie", async () => {
    const r = await app.inject(form({ token: SETUP, provider: "gmail" }));
    expect(r.statusCode).toBe(302);
    expect(r.headers.location).toBe("https://idp.example/auth?p=gmail");
    expect(String(r.headers["set-cookie"])).toMatch(/ap_connect=.*HttpOnly.*SameSite=Lax/);
  });

  it("the callback creates the org, the first admin and the linked mailbox, then hands the dashboard a token in the fragment", async () => {
    nextResult = result("Founder@Acme.Example");
    const r = await callback("setup");
    expect(r.statusCode).toBe(302);
    const token = /^\/admin\/#token=(.+)$/.exec(String(r.headers.location))![1]!;
    const u = (await store.getUserByEmail("founder@acme.example"))!;
    expect(u).toMatchObject({ role: "admin", provider: "gmail" });
    expect(u.orgId).not.toBeNull();
    expect(verifyToken(SECRET, token, SID)?.uid).toBe(u.id);
    expect(JSON.parse(decryptSecret(KEY, u.encryptedTokens!)).refresh_token).toBe("refresh-for-Founder@Acme.Example");
  });

  it("is closed once a user exists, even with the right token", async () => {
    expect((await app.inject({ method: "GET", url: "/setup" })).statusCode).toBe(404);
    expect((await app.inject(form({ token: SETUP, provider: "gmail" }))).statusCode).toBe(404);
    nextResult = result("intruder@evil.example");
    expect((await callback("setup")).statusCode).toBe(400);
    expect(await store.getUserByEmail("intruder@evil.example")).toBeNull();
  });
});

describe("invites", () => {
  let admin: User, orgId: string;
  beforeAll(async () => { admin = (await store.getUserByEmail("founder@acme.example"))!; orgId = admin.orgId!; });
  const invite = async (email: string, role = "analyst") => {
    const r = await app.inject({ method: "POST", url: "/v1/admin/invites", payload: { email, role }, headers: { authorization: tok(admin) } });
    return { status: r.statusCode, body: r.json() };
  };

  it("only an admin can create one, and the link points at this server's public address", async () => {
    const r = await invite("Amy@Acme.Example");
    expect(r.status).toBe(201);
    expect(r.body.url).toMatch(/^https:\/\/phish\.example\/join\/.+/);
    expect(r.body).toMatchObject({ email: "amy@acme.example", role: "analyst" });
    const viewer = await store.createUser({ email: "v@acme.example", orgId, role: "viewer" });
    expect((await app.inject({ method: "POST", url: "/v1/admin/invites", payload: { email: "x@acme.example" }, headers: { authorization: tok(viewer) } })).statusCode).toBe(403);
    expect((await invite("not-an-email")).status).toBe(422);
  });

  it("the join page shows who is invited; a bad or expired link is a plain 404", async () => {
    const { token } = makeInvite(SECRET, { orgId, email: "amy@acme.example", role: "analyst" });
    const page = await app.inject({ method: "GET", url: `/join/${token}` });
    expect(page.statusCode).toBe(200);
    expect(page.body).toContain("amy@acme.example");
    expect((await app.inject({ method: "GET", url: "/join/garbage" })).statusCode).toBe(404);
    const old = makeInvite(SECRET, { orgId, email: "a@acme.example", role: "user" }, Date.now() - 8 * 86400_000);
    expect((await app.inject({ method: "GET", url: `/join/${old.token}` })).statusCode).toBe(404);
  });

  it("connecting the invited mailbox creates the user in the org with the invited role and shows a working extension token", async () => {
    const { token } = makeInvite(SECRET, { orgId, email: "amy@acme.example", role: "analyst" });
    nextResult = result("amy@acme.example");
    const r = await callback("invite:" + token);
    expect(r.statusCode).toBe(200);
    expect(r.headers["cache-control"]).toBe("no-store");
    const u = (await store.getUserByEmail("amy@acme.example"))!;
    expect(u).toMatchObject({ orgId, role: "analyst" });
    expect(u.encryptedTokens).not.toBeNull();
    const shown = /<textarea[^>]*>([^<]+)<\/textarea>/.exec(r.body)![1]!;
    expect(verifyToken(SECRET, shown, SID)?.uid).toBe(u.id);
  });

  it("refuses a different mailbox than the one invited, and a mailbox that belongs to another org", async () => {
    const { token } = makeInvite(SECRET, { orgId, email: "bob@acme.example", role: "user" });
    nextResult = result("mallory@evil.example");
    expect((await callback("invite:" + token)).statusCode).toBe(400);
    expect(await store.getUserByEmail("mallory@evil.example")).toBeNull();
    const other = await store.createOrg("Other");
    await store.createUser({ email: "carol@acme.example", orgId: other.id });
    const t2 = makeInvite(SECRET, { orgId, email: "carol@acme.example", role: "admin" });
    nextResult = result("carol@acme.example");
    expect((await callback("invite:" + t2.token)).statusCode).toBe(400);
    expect((await store.getUserByEmail("carol@acme.example"))!.orgId).toBe(other.id);
  });

  it("a rejected sign-in renders a generic page and clears the cookie", async () => {
    nextResult = new Error("State mismatch");
    const r = await callback("setup");
    expect(r.statusCode).toBe(400);
    expect(String(r.headers["set-cookie"])).toContain("Max-Age=0");
    expect(r.body).not.toContain("State mismatch");
  });

  it("reconnecting an existing member keeps their current role even if the new invite names a lower one", async () => {
    const { token } = makeInvite(SECRET, { orgId, email: "amy@acme.example", role: "viewer" });
    nextResult = result("amy@acme.example");
    await callback("invite:" + token);
    expect((await store.getUserByEmail("amy@acme.example"))!.role).toBe("analyst");
  });
});

describe("people management and erasure", () => {
  let admin: User, orgId: string, member: User;
  beforeAll(async () => {
    admin = (await store.getUserByEmail("founder@acme.example"))!; orgId = admin.orgId!;
    member = await store.createUser({ email: "temp@acme.example", orgId });
  });
  const call = (u: User, method: "GET" | "PATCH" | "DELETE" | "POST", url: string, payload?: object) => app.inject({ method, url, payload, headers: { authorization: tok(u) } });

  it("lists org members without tokens and changes a role", async () => {
    const l = await call(admin, "GET", "/v1/admin/org-users");
    expect(l.json().users.map((x: { email: string }) => x.email)).toContain("temp@acme.example");
    expect(l.body).not.toContain("encrypted");
    expect((await call(admin, "PATCH", `/v1/admin/users/${member.id}`, { role: "viewer" })).statusCode).toBe(200);
    expect((await store.getUser(member.id))!.role).toBe("viewer");
    expect((await call(admin, "PATCH", `/v1/admin/users/${member.id}`, { role: "root" })).statusCode).toBe(422);
    expect((await call(admin, "PATCH", `/v1/admin/users/${admin.id}`, { role: "user" })).statusCode).toBe(422); // not yourself
  });

  it("an admin cannot touch another org's users, and erasing a member removes their data", async () => {
    const other = await store.createOrg("Rival");
    const outsider = await store.createUser({ email: "o@rival.example", orgId: other.id });
    expect((await call(admin, "DELETE", `/v1/admin/users/${outsider.id}`)).statusCode).toBe(404);
    expect(await store.getUser(outsider.id)).not.toBeNull();
    expect((await call(admin, "DELETE", `/v1/admin/users/${member.id}`)).statusCode).toBe(200);
    expect(await store.getUser(member.id)).toBeNull();
  });

  it("mints an extension token for the signed-in user, and lets a member erase themselves", async () => {
    const t = await call(admin, "POST", "/v1/me/token", { days: 7 });
    expect(verifyToken(SECRET, t.json().token, SID)?.uid).toBe(admin.id);
    expect((await call(admin, "POST", "/v1/me/token", { days: 500 })).statusCode).toBe(422);
    const me = await store.createUser({ email: "leaver@acme.example", orgId });
    expect((await call(me, "DELETE", "/v1/me")).statusCode).toBe(200);
    expect(await store.getUser(me.id)).toBeNull();
  });

  it("the only admin cannot erase themselves", async () => {
    const r = await call(admin, "DELETE", "/v1/me");
    expect(r.statusCode).toBe(422);
    expect(await store.getUser(admin.id)).not.toBeNull();
  });
});
