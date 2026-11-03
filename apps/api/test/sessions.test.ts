import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { FastifyInstance } from "fastify";
import type { MailProvider } from "@ap/mail";
import { AdminQueries, connect, Store, type Connection, type User } from "@ap/db";
import { buildApp, signToken } from "../src/app.ts";
import { makeInvite, type ConnectFlow, type ConnectResult, type MailProviderName } from "../src/connect.ts";
import { ScanService } from "../src/service.ts";

const SECRET = "t".repeat(40), SID = "srv-sess", KEY = "ab".repeat(32);
let conn: Connection, store: Store, app: FastifyInstance, orgId: string, admin: User, member: User;
let nextResult: ConnectResult;
const flow: ConnectFlow = {
  providers: ["gmail", "outlook"], secureCookie: false,
  start: (p: MailProviderName, purpose: string) => ({ url: "https://idp.example/", cookie: "c-" + Buffer.from(purpose).toString("base64url"), maxAge: 600 }),
  finish: async (_q, cookie) => ({ ...nextResult, purpose: Buffer.from((cookie ?? "").replace("c-", ""), "base64url").toString() }),
};
const mailbox: MailProvider = { fetchRaw: async () => Buffer.from(""), move: async () => {}, unmove: async () => {}, addLabel: async () => {}, ensureFolder: async (n) => n, listRecentInbox: async () => [], getLabelNames: async () => [], watch: async () => {} };
const now = () => Math.floor(Date.now() / 1000);
const bearer = (u: User, extra: { sc?: "ext"; iat?: number } = {}) => ({ authorization: "Bearer " + signToken(SECRET, { uid: u.id, sid: SID, exp: now() + 3600, ...extra }) });
const call = (method: "GET" | "POST" | "DELETE" | "PATCH", url: string, headers: Record<string, string>, payload?: object) => app.inject({ method, url, headers, payload });
const callback = (purpose: string) => app.inject({ method: "GET", url: "/connect/callback?code=c&state=s", headers: { cookie: "ap_connect=c-" + Buffer.from(purpose).toString("base64url") } });

beforeAll(async () => {
  conn = await connect(); store = new Store(conn.db);
  app = buildApp({ store, admin: new AdminQueries(conn.db), secret: SECRET, serverId: SID, tokenKey: KEY, connect: flow, publicUrl: "https://phish.example", service: new ScanService({ store, mailFor: () => mailbox }) });
  await app.ready();
  orgId = (await store.createOrg("Sess")).id;
  admin = await store.createUser({ email: "admin@sess.example", orgId, role: "admin" });
  await store.createUser({ email: "second@sess.example", orgId, role: "admin" });
  member = await store.createUser({ email: "member@sess.example", orgId, role: "analyst" });
});
afterAll(async () => { await app.close(); await conn.close(); });

describe("extension tokens are less powerful than dashboard sessions", () => {
  it("an extension token works for scanning and settings but never as an admin, and cannot mint tokens or erase the account", async () => {
    const ext = bearer(admin, { sc: "ext" });
    expect((await call("GET", "/v1/settings", ext)).statusCode).toBe(200);
    expect((await call("GET", "/v1/me", ext)).json().role).toBe("user"); // capped, whatever the account's role
    expect((await call("GET", "/v1/admin/org-users", ext)).statusCode).toBe(403);
    expect((await call("POST", "/v1/admin/invites", ext, { email: "x@sess.example" })).statusCode).toBe(403);
    expect((await call("POST", "/v1/me/token", ext, {})).statusCode).toBe(403);
    expect((await call("DELETE", "/v1/me", ext)).statusCode).toBe(403);
    expect((await call("POST", "/v1/me/revoke-tokens", ext, {})).statusCode).toBe(403);
    expect(await store.getUser(admin.id)).not.toBeNull();
    expect((await call("GET", "/v1/admin/org-users", bearer(admin))).statusCode).toBe(200); // the full session still can
  });
  it("tokens minted by the API for the extension carry that limit", async () => {
    const minted = (await call("POST", "/v1/me/token", bearer(admin), { days: 7 })).json().token as string;
    const h = { authorization: "Bearer " + minted };
    expect((await call("GET", "/v1/admin/org-users", h)).statusCode).toBe(403);
    expect((await call("POST", "/v1/me/token", h, {})).statusCode).toBe(403); // a leaked token cannot renew itself
  });
  it("the token shown after joining by invite is an extension token", async () => {
    const { token } = makeInvite(SECRET, { orgId, email: "joiner@sess.example", role: "admin" });
    nextResult = { provider: "gmail", email: "joiner@sess.example", refreshToken: "r", purpose: "" };
    const page = await callback("invite:" + token);
    const shown = /<textarea[^>]*>([^<]+)<\/textarea>/.exec(page.body)![1]!;
    expect((await call("GET", "/v1/admin/org-users", { authorization: "Bearer " + shown })).statusCode).toBe(403); // joined as admin, but this credential is not an admin one
    expect((await call("GET", "/v1/settings", { authorization: "Bearer " + shown })).statusCode).toBe(200);
  });
});

describe("revoking sessions", () => {
  it("'sign out everywhere' kills older tokens but not ones issued afterwards", async () => {
    const u = await store.createUser({ email: "revoke@sess.example", orgId });
    const old = bearer(u, { iat: now() - 5 });
    expect((await call("GET", "/v1/me", old)).statusCode).toBe(200);
    expect((await call("POST", "/v1/me/revoke-tokens", old, {})).statusCode).toBe(200);
    expect((await call("GET", "/v1/me", old)).statusCode).toBe(401);
    expect((await call("GET", "/v1/me", bearer(u, { iat: now() + 3 }))).statusCode).toBe(200);
  });
  it("changing someone's role, or an admin revoking them, ends their old sessions", async () => {
    const old = bearer(member, { iat: now() - 5 });
    expect((await call("GET", "/v1/me", old)).statusCode).toBe(200);
    expect((await call("PATCH", `/v1/admin/users/${member.id}`, bearer(admin), { role: "viewer" })).statusCode).toBe(200);
    expect((await call("GET", "/v1/me", old)).statusCode).toBe(401);
    const other = await store.createUser({ email: "other@sess.example", orgId });
    const t = bearer(other, { iat: now() - 5 });
    expect((await call("POST", `/v1/admin/users/${other.id}/revoke-tokens`, bearer(admin), {})).statusCode).toBe(200);
    expect((await call("GET", "/v1/me", t)).statusCode).toBe(401);
    expect((await call("POST", `/v1/admin/users/${other.id}/revoke-tokens`, bearer(member, { iat: now() + 3 }), {})).statusCode).toBe(403);
  });
});

describe("invites are single use", () => {
  it("a used invite cannot bring the person back after they were erased", async () => {
    const { token } = makeInvite(SECRET, { orgId, email: "once@sess.example", role: "admin" });
    nextResult = { provider: "gmail", email: "once@sess.example", refreshToken: "r", purpose: "" };
    expect((await callback("invite:" + token)).statusCode).toBe(200);
    const u = (await store.getUserByEmail("once@sess.example"))!;
    expect((await call("DELETE", `/v1/admin/users/${u.id}`, bearer(admin))).statusCode).toBe(200);
    expect((await callback("invite:" + token)).statusCode).toBe(400);
    expect(await store.getUserByEmail("once@sess.example")).toBeNull();
  });
  it("a failed attempt (wrong mailbox) does not use the invite up", async () => {
    const { token } = makeInvite(SECRET, { orgId, email: "careful@sess.example", role: "user" });
    nextResult = { provider: "gmail", email: "someone-else@sess.example", refreshToken: "r", purpose: "" };
    expect((await callback("invite:" + token)).statusCode).toBe(400);
    nextResult = { provider: "gmail", email: "careful@sess.example", refreshToken: "r", purpose: "" };
    expect((await callback("invite:" + token)).statusCode).toBe(200);
  });
  it("redeeming an invite never switches an existing member to another mail provider", async () => {
    const gm = await store.createUser({ email: "gmailer@sess.example", orgId, provider: "gmail" });
    await store.setEncryptedTokens(gm.id, "original-blob");
    const { token } = makeInvite(SECRET, { orgId, email: "gmailer@sess.example", role: "user" });
    nextResult = { provider: "outlook", email: "gmailer@sess.example", refreshToken: "attacker", purpose: "" };
    expect((await callback("invite:" + token)).statusCode).toBe(400);
    const after = (await store.getUser(gm.id))!;
    expect(after.provider).toBe("gmail");
    expect(after.encryptedTokens).toBe("original-blob");
  });
});

describe("erasing a person also removes their address from the audit trail", () => {
  it("redacts the email in earlier audit entries, keeping the actions", async () => {
    const u = await store.createUser({ email: "forget-me@sess.example", orgId });
    await new AdminQueries(conn.db).audit(orgId, admin.id, "invite.create", "forget-me@sess.example as user");
    expect((await call("DELETE", `/v1/admin/users/${u.id}`, bearer(admin))).statusCode).toBe(200);
    const rows = (await call("GET", "/v1/admin/audit", bearer(admin))).json().rows as { action: string; target: string | null }[];
    expect(JSON.stringify(rows)).not.toContain("forget-me@sess.example");
    expect(rows.some((r) => r.action === "invite.create")).toBe(true);
  });
});
