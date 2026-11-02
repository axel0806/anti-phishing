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
  ensureFolder: async (n) => n, listRecentInbox: async () => [], getLabelNames: async () => [], watch: async () => {}, unmove: async (id, f) => { mailLog.push(`unmove ${id} ${f}`); },
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

describe("prototype pollution over HTTP", () => {
  it("a __proto__ merge-patch is rejected and cannot change how other requests are parsed", async () => {
    const u = await newUser("pollute@example.com");
    const r = await app.inject({
      method: "PATCH", url: "/v1/settings", payload: '{"__proto__":{"mode":"act","rescan":true}}',
      headers: { authorization: "Bearer " + tokenFor(u), "content-type": "application/merge-patch+json" },
    });
    expect(r.statusCode).toBeGreaterThanOrEqual(400);
    expect(r.statusCode).toBeLessThan(500);
    expect(({} as Record<string, unknown>).mode).toBeUndefined();
    mailLog.length = 0;
    const s = await call(u, "POST", "/v1/scan", { providerMessageId: "phish" });
    expect(s.json()).toMatchObject({ action: "none" });
    expect(mailLog).toEqual([]);
  });
});

describe("dry-run scans do not block later action", () => {
  it("an extension dry-run followed by an act scan still moves the mail, exactly once", async () => {
    const u = await newUser("dryfirst@example.com");
    mailLog.length = 0;
    await call(u, "POST", "/v1/scan", { providerMessageId: "phish", mode: "dry_run" });
    expect(mailLog).toEqual([]);
    const act = await call(u, "POST", "/v1/scan", { providerMessageId: "phish", mode: "act" });
    expect(act.json()).toMatchObject({ verdict: "phishing", action: "move_to_phishing", cached: true });
    const again = await call(u, "POST", "/v1/scan", { providerMessageId: "phish", mode: "act" });
    expect(again.json()).toMatchObject({ action: "none" });
    expect(mailLog).toEqual(["move phish Phishing"]);
  });
  it("shadow mode does not consume the chance to act; turning it off later does", async () => {
    const u = await newUser("shadowlater@example.com");
    await call(u, "PATCH", "/v1/settings", { shadowMode: true });
    mailLog.length = 0;
    await call(u, "POST", "/v1/scan", { providerMessageId: "phish", mode: "act" });
    expect(mailLog).toEqual([]);
    await call(u, "PATCH", "/v1/settings", { shadowMode: false });
    const r = await call(u, "POST", "/v1/scan", { providerMessageId: "phish", mode: "act" });
    expect(r.json()).toMatchObject({ action: "move_to_phishing" });
    expect(mailLog).toEqual(["move phish Phishing"]);
  });
});

describe("feedback acts on the mailbox", () => {
  it("not_phishing puts the message back; phishing moves it; mail failures do not fail the feedback", async () => {
    const u = await newUser("fbmail@example.com");
    await call(u, "POST", "/v1/scan", { providerMessageId: "phish", mode: "act" });
    mailLog.length = 0;
    const back = await call(u, "POST", "/v1/messages/phish/feedback", { label: "not_phishing" });
    expect(back.json()).toMatchObject({ verdict: "safe", mailAction: "restored" });
    expect(mailLog).toEqual(["unmove phish Phishing"]);
    const v2 = await newUser("fbmail2@example.com");
    await call(v2, "POST", "/v1/scan", { providerMessageId: "lunch" });
    mailLog.length = 0;
    const mv = await call(v2, "POST", "/v1/messages/lunch/feedback", { label: "phishing" });
    expect(mv.json()).toMatchObject({ verdict: "phishing", mailAction: "moved" });
    expect(mailLog).toEqual(["move lunch Phishing"]);
  });
  it("still records the feedback when the mailbox call fails", async () => {
    const failing = buildApp({ store, secret: SECRET, serverId: SID, service: new ScanService({ store, mailFor: () => ({ ...fakeMail, unmove: async () => { throw new Error("gmail down"); } }) }) });
    const u = await newUser("fbfail@example.com");
    await failing.inject({ method: "POST", url: "/v1/scan", payload: { providerMessageId: "phish" }, headers: { authorization: "Bearer " + tokenFor(u) } });
    const r = await failing.inject({ method: "POST", url: "/v1/messages/phish/feedback", payload: { label: "not_phishing" }, headers: { authorization: "Bearer " + tokenFor(u) } });
    expect(r.statusCode).toBe(200);
    expect(r.json()).toMatchObject({ verdict: "safe", pinned: true, mailAction: "failed" });
    await failing.close();
  });
});

describe("rescan", () => {
  it("re-scores recent scans after settings change, skips pinned ones, and reports counts", async () => {
    const u = await newUser("rescan@example.com");
    await call(u, "POST", "/v1/scan", { providerMessageId: "phish" });
    await call(u, "POST", "/v1/scan", { providerMessageId: "lunch" });
    await call(u, "POST", "/v1/messages/lunch/feedback", { label: "phishing" });
    await call(u, "POST", "/v1/lists/allow", { matchType: "domain", value: "paypa1-secure.net" }); // ignored while DMARC fails; verdict unchanged
    await call(u, "PATCH", "/v1/settings", { sensitivity: "relaxed", categoryMultipliers: { authentication: 0 } });
    const r = await call(u, "POST", "/v1/rescan", { days: 7 });
    expect(r.statusCode).toBe(200);
    expect(r.json()).toEqual({ rescanned: 1, skippedPinned: 1, failed: 0 });
    expect((await call(u, "GET", "/v1/messages/lunch/verdict")).json()).toMatchObject({ verdict: "phishing", pinned: true });
    expect((await call(u, "POST", "/v1/rescan", { days: 9999 })).statusCode).toBe(422);
  });
});

describe("who am I, and reading lists", () => {
  it("/v1/me reports the caller's identity and role", async () => {
    const org = await store.createOrg("MeCo");
    const u = await store.createUser({ email: "Me@MeCo.example", orgId: org.id, role: "analyst" });
    expect((await call(u, "GET", "/v1/me")).json()).toEqual({ id: u.id, email: "me@meco.example", role: "analyst", orgId: org.id, provider: "gmail" });
  });
  it("lists a user's own entries, and org entries only for an org admin", async () => {
    const org = await store.createOrg("ListRead");
    const admin = await store.createUser({ email: "ladmin@lr.example", orgId: org.id, role: "admin" });
    const member = await store.createUser({ email: "lmember@lr.example", orgId: org.id });
    await call(member, "POST", "/v1/lists/allow", { matchType: "domain", value: "Friends.com" });
    await call(admin, "POST", "/v1/lists/block", { matchType: "domain", value: "evil.example", scope: "org" });
    expect((await call(member, "GET", "/v1/lists")).json()).toEqual({ allow: [{ matchType: "domain", value: "friends.com" }], block: [] });
    expect((await call(admin, "GET", "/v1/lists?scope=org")).json()).toEqual({ allow: [], block: [{ matchType: "domain", value: "evil.example" }] });
    expect((await call(member, "GET", "/v1/lists?scope=org")).statusCode).toBe(403);
    expect((await call(member, "GET", "/v1/lists?scope=nonsense")).statusCode).toBe(422);
  });
});

describe("provider-specific message ids (Outlook add-in)", () => {
  it("resolves an Outlook REST id before looking up or scanning, so the add-in and the worker agree on one id", async () => {
    const resolved: string[] = [];
    const outlookMail: MailProvider = {
      ...fakeMail,
      resolveId: async (id, fmt) => { resolved.push(`${fmt}:${id}`); return fmt === "outlook_rest" ? "IMM-" + id : id; },
      fetchRaw: async () => messages.lunch!,
    };
    const a2 = buildApp({ store, secret: SECRET, serverId: SID, service: new ScanService({ store, mailFor: () => outlookMail }) });
    const u = await newUser("outlook-id@example.com");
    const h = { authorization: "Bearer " + tokenFor(u) };
    const miss = await a2.inject({ method: "GET", url: "/v1/messages/R1/verdict?idFormat=outlook_rest", headers: h });
    expect(miss.statusCode).toBe(404);
    const scan = await a2.inject({ method: "POST", url: "/v1/scan", payload: { providerMessageId: "R1", idFormat: "outlook_rest" }, headers: h });
    expect(scan.statusCode).toBe(200);
    expect(await store.getScan(u.id, "IMM-R1")).not.toBeNull(); // stored under the immutable id, not the REST id
    expect(await store.getScan(u.id, "R1")).toBeNull();
    const hit = await a2.inject({ method: "GET", url: "/v1/messages/R1/verdict?idFormat=outlook_rest", headers: h });
    expect(hit.statusCode).toBe(200);
    expect(resolved).toEqual(["outlook_rest:R1"]); // three requests, one Graph translation: the result is cached
    await a2.close();
  });
  it("rejects an unknown id format, and a format the user's mailbox does not support", async () => {
    const u = await newUser("badfmt@example.com");
    expect((await call(u, "GET", "/v1/messages/X/verdict?idFormat=weird")).statusCode).toBe(422);
    expect((await call(u, "POST", "/v1/scan", { providerMessageId: "X", idFormat: "weird" })).statusCode).toBe(422);
    const r = await call(u, "POST", "/v1/scan", { providerMessageId: "X", idFormat: "outlook_rest" }); // Gmail fake has no resolveId
    expect(r.statusCode).toBe(422);
    expect(r.json().error.message).toMatch(/not supported/i);
  });
});
