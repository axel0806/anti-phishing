import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { FastifyInstance } from "fastify";
import type { MailProvider } from "@ap/mail";
import type { Verdict } from "@ap/shared";
import { AdminQueries, connect, Store, type Connection, type User } from "@ap/db";
import { buildApp, signToken } from "../src/app.ts";
import { ScanService } from "../src/service.ts";
import { toCsv } from "../src/csv.ts";
import { Metrics } from "../src/metrics.ts";

const SECRET = "test-secret-admin", SID = "srv-admin";
let conn: Connection, store: Store, queries: AdminQueries, app: FastifyInstance, metrics: Metrics;
let org: { id: string }, admin: User, analyst: User, viewer: User, member: User, loner: User, outsider: User;
const mailLog: string[] = [];
const mailbox: MailProvider = {
  fetchRaw: async () => Buffer.from(""), move: async (id, f) => { mailLog.push(`move ${id} ${f}`); }, unmove: async (id, f) => { mailLog.push(`unmove ${id} ${f}`); },
  addLabel: async () => {}, ensureFolder: async (n) => n, listRecentInbox: async () => [], getLabelNames: async () => [], watch: async () => {},
};
const v = (verdict: Verdict["verdict"], score: number, flags: Verdict["flags"] = []): Verdict => ({ verdict, score, flags, aiUsed: false, settingsVersion: 1 });
const spf: Verdict["flags"][number] = { id: "spf_fail", category: "authentication", weight: 20, evidence: "SPF fail", source: "rule" };
const tok = (u: User) => "Bearer " + signToken(SECRET, { uid: u.id, sid: SID, exp: Math.floor(Date.now() / 1000) + 3600 });
const get = (u: User | null, url: string) => app.inject({ method: "GET", url, headers: u ? { authorization: tok(u) } : {} });
const post = (u: User, url: string, payload?: unknown) => app.inject({ method: "POST", url, payload: payload as object, headers: { authorization: tok(u) } });

beforeAll(async () => {
  conn = await connect(); store = new Store(conn.db); queries = new AdminQueries(conn.db); metrics = new Metrics();
  app = buildApp({ store, admin: queries, metrics, secret: SECRET, serverId: SID, service: new ScanService({ store, mailFor: () => mailbox }) });
  await app.ready();
  org = await store.createOrg("Acme");
  admin = await store.createUser({ email: "admin@acme.example", orgId: org.id, role: "admin" });
  analyst = await store.createUser({ email: "analyst@acme.example", orgId: org.id, role: "analyst" });
  viewer = await store.createUser({ email: "viewer@acme.example", orgId: org.id, role: "viewer" });
  member = await store.createUser({ email: "member@acme.example", orgId: org.id });
  loner = await store.createUser({ email: "loner@example.com" });
  const other = await store.createOrg("Rival");
  outsider = await store.createUser({ email: "boss@rival.example", orgId: other.id, role: "admin" });
  await store.saveScan(member.id, "m1", v("phishing", 80, [spf]), { latencyMs: 30, sender: "=cmd|calc@evil.example" });
  await store.saveScan(member.id, "m2", v("safe", 0), { latencyMs: 20, sender: "ok@ok.example" });
  await store.saveScan(outsider.id, "x1", v("phishing", 90, [spf]), { latencyMs: 30, sender: "z@rival-only.example" });
});
afterAll(async () => { await app.close(); await conn.close(); });

const PANELS = ["overview", "trend", "flags", "targets", "quality", "ai", "health"];

describe("role matrix", () => {
  it("requires a session and an organization", async () => {
    expect((await get(null, "/v1/admin/stats/overview")).statusCode).toBe(401);
    expect((await get(loner, "/v1/admin/stats/overview")).statusCode).toBe(403);
  });
  it("plain members see no dashboard data at all", async () => {
    for (const p of [...PANELS, "scans", "audit", "users"]) expect((await get(member, `/v1/admin/${p === "scans" || p === "audit" ? p : "stats/" + p}`)).statusCode, p).toBe(403);
  });
  it("viewers get the aggregate panels only", async () => {
    for (const p of PANELS) expect((await get(viewer, `/v1/admin/stats/${p}`)).statusCode, p).toBe(200);
    expect((await get(viewer, "/v1/admin/scans")).statusCode).toBe(403);
    expect((await get(viewer, "/v1/admin/stats/users")).statusCode).toBe(403);
    expect((await get(viewer, "/v1/admin/audit")).statusCode).toBe(403);
  });
  it("analysts also get the email log but not per-user data, audit or actions", async () => {
    expect((await get(analyst, "/v1/admin/scans")).statusCode).toBe(200);
    expect((await get(analyst, "/v1/admin/stats/users")).statusCode).toBe(403);
    expect((await get(analyst, "/v1/admin/audit")).statusCode).toBe(403);
    expect((await post(analyst, `/v1/admin/users/${member.id}/messages/m1/release`)).statusCode).toBe(403);
  });
  it("admins get everything", async () => {
    for (const u of ["/v1/admin/stats/users", "/v1/admin/audit", "/v1/admin/scans"]) expect((await get(admin, u)).statusCode, u).toBe(200);
  });
});

describe("data and isolation", () => {
  it("overview reflects only the caller's org (rollup happens on demand for today)", async () => {
    const r = (await get(viewer, "/v1/admin/stats/overview")).json();
    expect(r.current).toMatchObject({ scanned: 2, phishing: 1, safe: 1 });
  });
  it("the email log has no subject or body, and no row from another org", async () => {
    const r = (await get(analyst, "/v1/admin/scans")).json();
    expect(r.total).toBe(2);
    expect(JSON.stringify(r)).not.toMatch(/rival-only|boss@rival/);
    expect(r.rows[0]).not.toHaveProperty("subject");
    const f = (await get(analyst, "/v1/admin/scans?verdict=phishing&flag=spf_fail")).json();
    expect(f.rows.map((x: { messageId: string }) => x.messageId)).toEqual(["m1"]);
  });
  it("validates filters and date ranges", async () => {
    expect((await get(viewer, "/v1/admin/stats/overview?from=nope")).statusCode).toBe(422);
    expect((await get(viewer, "/v1/admin/stats/overview?from=2026-02-01&to=2026-01-01")).statusCode).toBe(422);
    expect((await get(viewer, "/v1/admin/stats/overview?from=2020-01-01&to=2026-01-01")).statusCode).toBe(422);
    expect((await get(analyst, "/v1/admin/scans?verdict=bogus")).statusCode).toBe(422);
    expect((await get(analyst, "/v1/admin/scans?limit=100000")).json().rows.length).toBeLessThanOrEqual(500);
  });
  it("another org's admin cannot reach this org's users or messages", async () => {
    expect((await post(outsider, `/v1/admin/users/${member.id}/messages/m1/release`)).statusCode).toBe(404);
  });
});

describe("csv export of the email log", () => {
  it("is not silently cut at the 500-row page size", async () => {
    const big = await store.createOrg("Big");
    const a = await store.createUser({ email: "analyst@big.example", orgId: big.id, role: "analyst" });
    const m = await store.createUser({ email: "m@big.example", orgId: big.id });
    for (let i = 0; i < 510; i++) await store.saveScan(m.id, `big${i}`, v("safe", 0), { latencyMs: 1, sender: `s${i}@ok.example` });
    const r = await get(a, "/v1/admin/scans?limit=100000&format=csv");
    expect(r.statusCode).toBe(200);
    expect(r.body.trim().split("\n").length).toBe(511); // header + 510
    expect(r.headers["x-export-truncated"]).toBeUndefined();
    expect((await get(a, "/v1/admin/scans?limit=100000")).json().rows.length).toBe(500); // JSON stays paged
  });
});

describe("csv export", () => {
  it("returns text/csv for any panel when asked", async () => {
    const r = await get(viewer, "/v1/admin/stats/flags?format=csv");
    expect(r.headers["content-type"]).toMatch(/text\/csv/);
    expect(r.body.split("\n")[0]).toBe("flagId,fired,inPhishing,falsePositives,falsePositiveRate");
    expect(r.body).toContain("spf_fail");
  });
  it("neutralises spreadsheet formulas, quotes commas and quotes, and handles empty data", () => {
    expect(toCsv([{ a: "=SUM(1,2)", b: 'say "hi", ok', c: "+1", d: "-2", e: "@x", f: 5, g: null }])).toBe(
      "a,b,c,d,e,f,g\n\"'=SUM(1,2)\",\"say \"\"hi\"\", ok\",'+1,'-2,'@x,5,",
    );
    expect(toCsv([], ["x", "y"])).toBe("x,y\n");
  });
  it("the email log export does not leak a formula from a hostile sender address", async () => {
    const r = await get(analyst, "/v1/admin/scans?format=csv");
    expect(r.body).toContain("'=cmd|calc@evil.example");
    expect(r.body).not.toMatch(/(^|,)=cmd/m);
  });
});

describe("audit trail", () => {
  it("records email log views, exports, per-user views and actions, visible to admins only", async () => {
    await get(analyst, "/v1/admin/scans?verdict=phishing");
    await get(viewer, "/v1/admin/stats/flags?format=csv");
    await get(admin, "/v1/admin/stats/users");
    const log = (await get(admin, "/v1/admin/audit")).json().rows as { actorEmail: string; action: string; target: string }[];
    const seen = log.map((r) => `${r.actorEmail}:${r.action}`);
    expect(seen).toEqual(expect.arrayContaining(["analyst@acme.example:email_log.view", "viewer@acme.example:export", "admin@acme.example:users.view"]));
    expect(log.find((r) => r.action === "email_log.view")!.target).toContain("verdict=phishing");
  });
  it("org policy changes and org list edits are audited", async () => {
    await app.inject({ method: "PUT", url: `/v1/orgs/${org.id}/policy`, payload: { values: { sensitivity: "strict" }, locked: [] }, headers: { authorization: tok(admin) } });
    await app.inject({ method: "POST", url: "/v1/lists/block", payload: { matchType: "domain", value: "evil.example", scope: "org" }, headers: { authorization: tok(admin) } });
    const actions = ((await get(admin, "/v1/admin/audit")).json().rows as { action: string }[]).map((r) => r.action);
    expect(actions).toEqual(expect.arrayContaining(["policy.update", "list.add"]));
  });
});

describe("release and re-quarantine", () => {
  it("an admin can release a message back to the user's inbox (pinned safe), and it is logged", async () => {
    mailLog.length = 0;
    const r = await post(admin, `/v1/admin/users/${member.id}/messages/m1/release`);
    expect(r.statusCode).toBe(200);
    expect(r.json()).toMatchObject({ verdict: "safe", pinned: true, mailAction: "restored" });
    expect(mailLog).toEqual(["unmove m1 Phishing"]);
    expect(((await get(admin, "/v1/admin/audit")).json().rows as { action: string; target: string }[]).some((x) => x.action === "message.release" && x.target.includes("m1"))).toBe(true);
  });
  it("and put it back", async () => {
    mailLog.length = 0;
    const r = await post(admin, `/v1/admin/users/${member.id}/messages/m1/requarantine`);
    expect(r.json()).toMatchObject({ verdict: "phishing", mailAction: "moved" });
    expect(mailLog).toEqual(["move m1 Phishing"]);
  });
  it("404s for unknown users, messages, and users outside the org", async () => {
    expect((await post(admin, `/v1/admin/users/${member.id}/messages/nope/release`)).statusCode).toBe(404);
    expect((await post(admin, `/v1/admin/users/${outsider.id}/messages/x1/release`)).statusCode).toBe(404);
    expect((await post(admin, "/v1/admin/users/not-a-uuid/messages/m1/release")).statusCode).toBe(404);
  });
});

describe("weight suggestions", () => {
  it("suggests lowering a flag the user keeps overturning, never applies it, and needs enough evidence", async () => {
    const u = await store.createUser({ email: "sug@example.com" });
    const urgency: Verdict["flags"][number] = { id: "urgency", category: "content", weight: 10, evidence: "x", source: "rule" };
    for (let i = 0; i < 6; i++) {
      await store.saveScan(u.id, "s" + i, v("suspicious", 30, [urgency]), { latencyMs: 1 });
      if (i < 4) await store.addFeedback(u.id, "s" + i, "not_phishing");
    }
    await store.saveScan(u.id, "single", v("suspicious", 30, [spf]), { latencyMs: 1 });
    await store.addFeedback(u.id, "single", "not_phishing");
    const r = (await get(u, "/v1/settings/suggestions")).json() as { suggestions: { flagId: string; currentWeight: number; suggestedWeight: number; falsePositiveRate: number }[] };
    expect(r.suggestions).toEqual([{ flagId: "urgency", fired: 6, falsePositives: 4, falsePositiveRate: expect.closeTo(4 / 6), currentWeight: 10, suggestedWeight: 3 }]);
    expect((await get(u, "/v1/settings")).json().settings.flags.urgency).toBeUndefined(); // nothing was changed behind their back
  });
});

describe("metrics", () => {
  it("renders Prometheus text and is refused to non-local callers without a token", async () => {
    metrics.inc("scans_total", { verdict: "phishing" });
    metrics.observe("scan_latency_ms", 40);
    const ok = await app.inject({ method: "GET", url: "/metrics", headers: { host: "127.0.0.1:8080" } });
    expect(ok.statusCode).toBe(200);
    expect(ok.body).toContain('scans_total{verdict="phishing"} 1');
    expect(ok.body).toMatch(/scan_latency_ms_bucket\{le="50"\} 1/);
    expect(ok.body).toContain("scan_latency_ms_count 1");
    expect((await app.inject({ method: "GET", url: "/metrics", headers: { host: "api.acme.example" }, remoteAddress: "198.51.100.7" })).statusCode).toBe(403);
  });
  it("cannot be unlocked by a spoofed Host header from a remote address, or through a local proxy", async () => {
    const remote = await app.inject({ method: "GET", url: "/metrics", headers: { host: "localhost" }, remoteAddress: "203.0.113.5" });
    expect(remote.statusCode).toBe(403);
    const proxied = await app.inject({ method: "GET", url: "/metrics", headers: { host: "localhost", "x-forwarded-for": "203.0.113.5" }, remoteAddress: "127.0.0.1" });
    expect(proxied.statusCode).toBe(403);
    expect((await app.inject({ method: "GET", url: "/metrics", remoteAddress: "127.0.0.1" })).statusCode).toBe(200);
  });
  it("histogram buckets are cumulative", () => {
    const m = new Metrics();
    [5, 40, 400, 9000].forEach((x) => m.observe("lat", x));
    const out = m.render();
    expect(out).toMatch(/lat_bucket\{le="10"\} 1/);
    expect(out).toMatch(/lat_bucket\{le="50"\} 2/);
    expect(out).toMatch(/lat_bucket\{le="\+Inf"\} 4/);
  });
});
