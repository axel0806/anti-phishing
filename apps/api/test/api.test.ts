import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import type { FastifyInstance } from "fastify";
import type { MailProvider } from "@ap/mail";
import { connect, Store, type Connection, type User } from "@ap/db";
import { buildApp, signToken } from "../src/app.ts";
import { ScanService } from "../src/service.ts";
import { decryptSecret, encryptSecret, verifyToken } from "../src/auth.ts";

const eml = (p: string) => readFileSync(new URL("../../../corpus/" + p, import.meta.url));
const SECRET = "test-secret", SID = "server-1";

let conn: Connection, store: Store, app: FastifyInstance;
const mailLog: string[] = [];
const messages: Record<string, Buffer> = { phish: eml("phishing/paypal-spoof.eml"), lunch: eml("legit/lunch.eml") };
const fakeMail: MailProvider = {
  fetchRaw: async (id) => { if (!messages[id]) throw new Error("no such message"); return messages[id]!; },
  move: async (id, f) => { mailLog.push(`move ${id} ${f}`); },
  addLabel: async (id, l) => { mailLog.push(`label ${id} ${l}`); },
  ensureFolder: async (n) => n, listRecentInbox: async () => [], getLabelNames: async () => [], watch: async () => {},
};

const tokenFor = (u: User, sid = SID, exp = Math.floor(Date.now() / 1000) + 3600) => signToken(SECRET, { uid: u.id, sid, exp });
const call = (u: User | null, method: string, url: string, payload?: unknown, headers: Record<string, string> = {}) =>
  app.inject({ method: method as "GET", url, payload: payload as object, headers: { ...(u ? { authorization: "Bearer " + tokenFor(u) } : {}), ...headers } });

beforeAll(async () => {
  conn = await connect();
  store = new Store(conn.db);
  app = buildApp({ store, secret: SECRET, serverId: SID, service: new ScanService({ store, mailFor: () => fakeMail }) });
  await app.ready();
});
afterAll(async () => { await app.close(); await conn.close(); });

const newUser = (email: string, extra: Partial<{ orgId: string; role: "admin" | "user" }> = {}) => store.createUser({ email, ...extra });

describe("health and auth", () => {
  it("health is public and reports server identity", async () => {
    const r = await call(null, "GET", "/v1/health");
    expect(r.statusCode).toBe(200);
    expect(r.json()).toMatchObject({ serverId: SID, apiVersions: ["v1"] });
  });
  it("rejects missing, forged, expired and other-server tokens with the error envelope", async () => {
    const u = await newUser("auth@example.com");
    expect((await call(null, "GET", "/v1/settings")).json()).toEqual({ error: { code: "unauthorized", message: expect.any(String) } });
    const forged = signToken("wrong-secret", { uid: u.id, sid: SID, exp: 9999999999 });
    expect((await app.inject({ method: "GET", url: "/v1/settings", headers: { authorization: "Bearer " + forged } })).statusCode).toBe(401);
    const expired = tokenFor(u, SID, 1);
    expect((await app.inject({ method: "GET", url: "/v1/settings", headers: { authorization: "Bearer " + expired } })).statusCode).toBe(401);
    const other = tokenFor(u, "other-server");
    expect((await app.inject({ method: "GET", url: "/v1/settings", headers: { authorization: "Bearer " + other } })).statusCode).toBe(401);
    expect((await call(u, "GET", "/v1/settings")).statusCode).toBe(200);
  });
  it("token and secret helpers round-trip and detect tampering", () => {
    const t = signToken(SECRET, { uid: "u", sid: SID, exp: 9999999999 });
    expect(verifyToken(SECRET, t, SID)).toMatchObject({ uid: "u" });
    expect(verifyToken(SECRET, t.slice(0, -2) + "xx", SID)).toBeNull();
    const key = "00".repeat(32);
    const blob = encryptSecret(key, "refresh-token");
    expect(blob).not.toContain("refresh");
    expect(decryptSecret(key, blob)).toBe("refresh-token");
    expect(() => decryptSecret("11".repeat(32), blob)).toThrow();
  });
});

describe("settings layering and locks", () => {
  it("PATCH merges, GET shows effective settings; changes apply to the next scan", async () => {
    const u = await newUser("settings@example.com");
    const p = await call(u, "PATCH", "/v1/settings", { sensitivity: "strict", categoryMultipliers: { links: 2 } }, { "content-type": "application/merge-patch+json" });
    expect(p.statusCode).toBe(200);
    const g = (await call(u, "GET", "/v1/settings")).json();
    expect(g.settings.sensitivity).toBe("strict");
    expect(g.settings.categoryMultipliers.links).toBe(2);
    const del = await call(u, "PATCH", "/v1/settings", { sensitivity: null });
    expect(del.json().settings.sensitivity).toBe("balanced");
  });
  it("returns locked_field (409) for org-locked keys and validation (422) for bad input", async () => {
    const org = await store.createOrg("LockCo");
    const admin = await newUser("admin@lockco.example", { orgId: org.id, role: "admin" });
    const user = await newUser("user@lockco.example", { orgId: org.id });
    const put = await call(admin, "PUT", `/v1/orgs/${org.id}/policy`, { values: { sensitivity: "strict" }, locked: ["sensitivity"] });
    expect(put.statusCode).toBe(200);
    const r = await call(user, "PATCH", "/v1/settings", { sensitivity: "relaxed" });
    expect(r.statusCode).toBe(409);
    expect(r.json().error).toMatchObject({ code: "locked_field", fields: ["sensitivity"] });
    expect((await call(user, "GET", "/v1/settings")).json()).toMatchObject({ lockedFields: ["sensitivity"], settings: { sensitivity: "strict" } });
    const bad = await call(user, "PATCH", "/v1/settings", { thresholds: { suspicious: 90, phishing: 10 } });
    expect(bad.statusCode).toBe(422);
    expect(bad.json().error.code).toBe("validation");
  });
  it("org policy is admin-only and only for the admin's own org", async () => {
    const orgA = await store.createOrg("A"), orgB = await store.createOrg("B");
    const adminA = await newUser("adminA@example.com", { orgId: orgA.id, role: "admin" });
    const plain = await newUser("plain@example.com", { orgId: orgA.id });
    expect((await call(plain, "GET", `/v1/orgs/${orgA.id}/policy`)).statusCode).toBe(403);
    expect((await call(adminA, "GET", `/v1/orgs/${orgB.id}/policy`)).statusCode).toBe(403);
    expect((await call(adminA, "PUT", `/v1/orgs/${orgA.id}/policy`, { values: {}, locked: ["not_a_setting"] })).statusCode).toBe(422);
    expect((await call(adminA, "GET", `/v1/orgs/${orgA.id}/policy`)).statusCode).toBe(200);
  });
});

describe("lists", () => {
  it("adds and removes user entries, which affect scoring", async () => {
    const u = await newUser("lists@example.com");
    expect((await call(u, "POST", "/v1/lists/block", { matchType: "address", value: "alice@company.example" })).statusCode).toBe(201);
    const s = await call(u, "POST", "/v1/scan", { providerMessageId: "lunch" });
    expect(s.json()).toMatchObject({ verdict: "phishing", reason: expect.stringMatching(/blocklist/i) });
    expect((await call(u, "DELETE", "/v1/lists/block", { matchType: "address", value: "alice@company.example" })).statusCode).toBe(200);
    expect((await call(u, "DELETE", "/v1/lists/block", { matchType: "address", value: "alice@company.example" })).statusCode).toBe(404);
    expect((await call(u, "POST", "/v1/lists/nonsense", { matchType: "address", value: "x" })).statusCode).toBe(422);
  });
  it("only org admins may edit org lists", async () => {
    const org = await store.createOrg("ListCo");
    const user = await newUser("m@listco.example", { orgId: org.id });
    expect((await call(user, "POST", "/v1/lists/allow", { matchType: "domain", value: "x.com", scope: "org" })).statusCode).toBe(403);
  });
});

describe("scan, verdict, feedback", () => {
  it("dry_run scores and stores but never touches mail; the verdict endpoint explains it", async () => {
    const u = await newUser("dry@example.com");
    mailLog.length = 0;
    const r = await call(u, "POST", "/v1/scan", { providerMessageId: "phish" });
    expect(r.json()).toMatchObject({ verdict: "phishing", action: "none", cached: false });
    expect(r.json().flags.length).toBeGreaterThan(3);
    expect(mailLog).toEqual([]);
    const v = await call(u, "GET", "/v1/messages/phish/verdict");
    expect(v.json().verdict).toBe("phishing");
    expect((await call(u, "GET", "/v1/messages/unknown/verdict")).json().error.code).toBe("not_scanned");
  });
  it("act mode moves phishing once; repeated scans are cached (idempotent)", async () => {
    const u = await newUser("act@example.com");
    mailLog.length = 0;
    const a = await call(u, "POST", "/v1/scan", { providerMessageId: "phish", mode: "act" });
    expect(a.json()).toMatchObject({ action: "move_to_phishing" });
    const b = await call(u, "POST", "/v1/scan", { providerMessageId: "phish", mode: "act" });
    expect(b.json()).toMatchObject({ cached: true, action: "none" });
    expect(mailLog).toEqual(["move phish Phishing"]);
  });
  it("shadow mode in settings suppresses action", async () => {
    const u = await newUser("shadow@example.com");
    await call(u, "PATCH", "/v1/settings", { shadowMode: true });
    mailLog.length = 0;
    const a = await call(u, "POST", "/v1/scan", { providerMessageId: "phish", mode: "act" });
    expect(a.json()).toMatchObject({ verdict: "phishing", action: "none" });
    expect(mailLog).toEqual([]);
  });
  it("safe mail is left alone and sender history grows", async () => {
    const u = await newUser("safe@example.com");
    expect((await call(u, "POST", "/v1/scan", { providerMessageId: "lunch", mode: "act" })).json()).toMatchObject({ verdict: "safe", action: "none" });
    expect(await store.getSenderHistory(u.id, "alice@company.example")).toMatchObject({ messagesReceived: 1 });
  });
  it("feedback pins the verdict, can allowlist the sender, and rescan cannot override it", async () => {
    const u = await newUser("fb@example.com");
    await call(u, "POST", "/v1/scan", { providerMessageId: "phish" });
    const f = await call(u, "POST", "/v1/messages/phish/feedback", { label: "not_phishing", updateList: true });
    expect(f.json()).toMatchObject({ verdict: "safe", pinned: true });
    const re = await call(u, "POST", "/v1/scan", { providerMessageId: "phish", rescan: true });
    expect(re.json()).toMatchObject({ verdict: "safe", pinned: true, cached: true });
    expect((await store.listsFor(u)).allow).toEqual([{ matchType: "address", value: "help@paypa1-secure.net" }]);
    expect((await call(u, "POST", "/v1/messages/nope/feedback", { label: "phishing" })).json().error.code).toBe("not_scanned");
    expect((await call(u, "POST", "/v1/messages/phish/feedback", { label: "maybe" })).statusCode).toBe(422);
    expect((await call(u, "GET", "/v1/me/stats")).json()).toMatchObject({ scanned: 1, safe: 1, falsePositives: 1 });
  });
  it("validates input and reports mail failures cleanly", async () => {
    const u = await newUser("val@example.com");
    expect((await call(u, "POST", "/v1/scan", {})).statusCode).toBe(422);
    expect((await call(u, "GET", "/v1/messages/bad%20id/verdict")).statusCode).toBe(422);
    const noMail = buildApp({ store, secret: SECRET, serverId: SID, service: new ScanService({ store, mailFor: () => null }) });
    const r = await noMail.inject({ method: "POST", url: "/v1/scan", payload: { providerMessageId: "x" }, headers: { authorization: "Bearer " + tokenFor(u) } });
    expect(r.statusCode).toBe(503);
    expect(r.json().error.code).toBe("mail_unavailable");
    await noMail.close();
  });
  it("concurrent scans of the same message get scan_in_progress", async () => {
    const u = await newUser("race@example.com");
    const [a, b] = await Promise.all([
      call(u, "POST", "/v1/scan", { providerMessageId: "lunch" }),
      call(u, "POST", "/v1/scan", { providerMessageId: "lunch" }),
    ]);
    expect([a.statusCode, b.statusCode].sort()).toEqual([200, 409]);
  });
});
