import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { sql } from "drizzle-orm";
import type { Verdict } from "@ap/shared";
import { AdminQueries, connect, Store, type Connection } from "../src/index.ts";

let conn: Connection, store: Store, admin: AdminQueries;
beforeAll(async () => { conn = await connect(); store = new Store(conn.db); admin = new AdminQueries(conn.db); });
afterAll(async () => { await conn.close(); });

type FlagSpec = [Verdict["flags"][number]["id"], number, string?];
const flagOf = ([id, weight, evidence]: FlagSpec): Verdict["flags"][number] => ({
  id, category: id === "spf_fail" ? "authentication" : id === "lookalike_domain" ? "sender" : "content", weight, evidence: evidence ?? id, source: "rule",
});
const v = (verdict: Verdict["verdict"], score: number, flags: FlagSpec[] = [], aiUsed = false): Verdict => ({ verdict, score, flags: flags.map(flagOf), aiUsed, settingsVersion: 1 });
const age = (userId: string, msg: string, daysAgo: number) =>
  conn.db.execute(sql`update scans set created_at = now() - (${daysAgo} || ' days')::interval where user_id = ${userId} and provider_message_id = ${msg}`);
const today = () => new Date().toISOString().slice(0, 10);
const day = (n: number) => new Date(Date.now() - n * 86_400_000).toISOString().slice(0, 10);
const range = (fromDays: number, toDays = -1) => ({ from: new Date(day(fromDays) + "T00:00:00Z"), to: new Date(day(toDays) + "T00:00:00Z") });

let orgId: string, alice: string, bob: string, otherOrgUser: string;
beforeAll(async () => {
  orgId = (await store.createOrg("Acme")).id;
  alice = (await store.createUser({ email: "alice@acme.example", orgId })).id;
  bob = (await store.createUser({ email: "bob@acme.example", orgId })).id;
  const other = await store.createOrg("Other");
  otherOrgUser = (await store.createUser({ email: "eve@other.example", orgId: other.id })).id;

  const meta = (sender: string) => ({ latencyMs: 40, sender });
  await store.saveScan(alice, "a1", v("phishing", 85, [["spf_fail", 20, "SPF fail"], ["lookalike_domain", 35, "paypa1.com resembles paypal.com"]]), meta("x@paypa1.com"));
  await store.saveScan(alice, "a2", v("phishing", 70, [["spf_fail", 20, "SPF fail"]], true), meta("y@evil.example"));
  await store.saveScan(alice, "a3", v("safe", 5), meta("friend@ok.example"));
  await store.saveScan(bob, "b1", v("suspicious", 40, [["spf_fail", 20, "SPF fail"]]), meta("z@evil.example"));
  await store.saveScan(bob, "b2", v("safe", 0), { latencyMs: 400, sender: "news@shop.example" });
  await store.saveScan(otherOrgUser, "o1", v("phishing", 90, [["spf_fail", 20, "SPF fail"]]), meta("q@elsewhere.example"));
  await age(alice, "a3", 3);
  await age(bob, "b2", 40);
  await store.addFeedback(alice, "a2", "not_phishing"); // a false positive
  await store.addFeedback(bob, "b2", "phishing");        // a miss: the user reports a mail we called safe
  await admin.rollupDay(today());
  await admin.rollupDay(day(3));
  await admin.rollupDay(day(40));
});

describe("rollup", () => {
  it("is idempotent: running a day twice does not double the numbers", async () => {
    await admin.rollupDay(today());
    const o = await admin.overview(orgId, range(0, -1));
    expect(o.current.scanned).toBe(3); // a1, a2, b1 today
  });
  it("never includes other orgs", async () => {
    const o = await admin.overview(orgId, range(60, -1));
    expect(o.current.scanned).toBe(5);
    expect(o.current.phishing).toBe(2);
  });
});

describe("overview and trend", () => {
  it("compares with the previous period of equal length", async () => {
    const o = await admin.overview(orgId, range(7, -1)); // last 7 days + today
    expect(o.current).toMatchObject({ scanned: 4, safe: 2, suspicious: 1, phishing: 1 }); // a2 was rescued by the user, so it counts as safe
    expect(o.current.phishingRate).toBeCloseTo(0.25);
    expect(o.previous.scanned).toBe(0);
  });
  it("returns one row per day with suspicious and phishing counts", async () => {
    const t = await admin.trend(orgId, range(7, -1));
    const todayRow = t.find((r) => r.date === today())!;
    expect(todayRow).toMatchObject({ suspicious: 1, phishing: 1 });
    expect(t.map((r) => r.date)).toEqual([...t.map((r) => r.date)].sort());
  });
});

describe("flags, brands, targets", () => {
  it("ranks flags with their share of phishing verdicts and false-positive rate", async () => {
    const f = await admin.topFlags(orgId, range(7, -1));
    const spf = f.find((x) => x.flagId === "spf_fail")!;
    expect(spf).toMatchObject({ fired: 3, inPhishing: 1, falsePositives: 1 });
    expect(spf.falsePositiveRate).toBeCloseTo(1 / 3);
    expect(f[0]!.flagId).toBe("spf_fail");
  });
  it("lists impersonated brands and attacking sender domains", async () => {
    const b = await admin.brandsAndDomains(orgId, range(7, -1));
    expect(b.impersonated[0]).toMatchObject({ evidence: "paypa1.com resembles paypal.com", count: 1 });
    expect(b.senderDomains.map((d) => d.domain)).toContain("evil.example");
    expect(b.senderDomains.map((d) => d.domain)).not.toContain("ok.example"); // only suspicious/phishing senders
  });
  it("shows the most targeted users", async () => {
    const t = await admin.targets(orgId, range(7, -1));
    expect(t[0]).toMatchObject({ email: "alice@acme.example", phishing: 1 });
  });
});

describe("quality, ai, health", () => {
  it("counts false positives and user-reported misses", async () => {
    const q = await admin.quality(orgId, range(60, -1));
    expect(q).toMatchObject({ falsePositives: 1, missesReported: 1 });
  });
  it("sums AI spend for the org's users and the share of emails escalated", async () => {
    await store.aiRecordUsage(alice, 0.5);
    await store.aiRecordUsage(bob, 0.25);
    await store.aiRecordUsage(otherOrgUser, 99);
    const a = await admin.aiUsage(orgId, range(7, -1));
    expect(a).toMatchObject({ calls: 2, escalated: 1 });
    expect(a.costUsd).toBeCloseTo(0.75);
    expect(a.escalatedShare).toBeCloseTo(0.25);
  });
  it("reports scan latency percentiles and the last scan time", async () => {
    const h = await admin.health(orgId);
    expect(h.scans24h).toBeGreaterThanOrEqual(3);
    expect(h.p50Ms).toBeGreaterThan(0);
    expect(h.p95Ms).toBeGreaterThanOrEqual(h.p50Ms);
    expect(h.lastScanAt).toBeInstanceOf(Date);
    expect(h.linkedMailboxes).toBe(0);
  });
});

describe("email log", () => {
  it("filters by verdict, flag and date, never includes other orgs, and exposes no subject or body", async () => {
    const all = await admin.scanLog(orgId, range(60, -1), {});
    expect(all.rows.map((r) => r.messageId).sort()).toEqual(["a1", "a2", "a3", "b1", "b2"]);
    const ph = await admin.scanLog(orgId, range(60, -1), { verdict: "phishing" });
    expect(ph.rows.map((r) => r.messageId).sort()).toEqual(["a1", "b2"]); // b2 became phishing after the user reported it
    const spf = await admin.scanLog(orgId, range(60, -1), { flag: "lookalike_domain" });
    expect(spf.rows.map((r) => r.messageId)).toEqual(["a1"]);
    expect(Object.keys(all.rows[0]!).sort()).toEqual(["createdAt", "flags", "messageId", "pinned", "score", "sender", "userEmail", "verdict"]);
    expect((await admin.scanLog(orgId, range(60, -1), {}, { limit: 2, offset: 0 })).rows).toHaveLength(2);
    expect((await admin.scanLog(orgId, range(60, -1), {}, { limit: 2, offset: 0 })).total).toBe(5);
  });
});

describe("audit log", () => {
  it("records and lists admin actions for the org only, newest first", async () => {
    await admin.audit(orgId, alice, "policy.update", "org");
    await admin.audit(orgId, alice, "email_log.view", "filters:verdict=phishing");
    await admin.audit("00000000-0000-0000-0000-000000000000", bob, "other", "x").catch(() => undefined);
    const rows = await admin.auditLog(orgId, { limit: 10, offset: 0 });
    expect(rows.map((r) => r.action)).toEqual(["email_log.view", "policy.update"]);
    expect(rows[0]).toMatchObject({ actorEmail: "alice@acme.example", target: "filters:verdict=phishing" });
  });
});

describe("weight suggestions", () => {
  it("proposes lower weights only for flags with enough evidence and a high false-positive rate", async () => {
    const u = (await store.createUser({ email: "sugg@example.com" })).id;
    for (let i = 0; i < 6; i++) {
      await store.saveScan(u, "u" + i, v("suspicious", 30, [["urgency", 10, "x"]]), { latencyMs: 1 });
      if (i < 4) await store.addFeedback(u, "u" + i, "not_phishing");
    }
    await store.saveScan(u, "few", v("suspicious", 30, [["spf_fail", 20, "x"]]), { latencyMs: 1 });
    await store.addFeedback(u, "few", "not_phishing");
    const s = await admin.flagFalsePositiveRates(u);
    expect(s.find((x) => x.flagId === "urgency")).toMatchObject({ fired: 6, falsePositives: 4 });
    expect(s.find((x) => x.flagId === "urgency")!.rate).toBeCloseTo(4 / 6);
    expect(s.find((x) => x.flagId === "spf_fail")).toMatchObject({ fired: 1, falsePositives: 1 });
  });
});
