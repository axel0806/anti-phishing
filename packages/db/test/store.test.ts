import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { Verdict } from "@ap/shared";
import { connect, migrate, MIGRATIONS, Store, type Connection } from "../src/index.ts";

const verdict = (v: Verdict["verdict"], score: number, flags: Verdict["flags"] = []): Verdict => ({ verdict: v, score, flags, aiUsed: false, settingsVersion: 1 });
const flag = (id: "spf_fail" | "urgency", weight: number) => ({ id, category: id === "spf_fail" ? ("authentication" as const) : ("content" as const), weight, evidence: id + " evidence", source: "rule" as const });

let conn: Connection, store: Store;
beforeAll(async () => { conn = await connect(); store = new Store(conn.db); });
afterAll(async () => { await conn.close(); });

describe("migrations", () => {
  it("are idempotent", async () => {
    expect(await migrate(conn.db)).toEqual([]);
  });
});

describe("users, orgs and policy", () => {
  it("creates users case-insensitively unique and round-trips overrides", async () => {
    const u = await store.createUser({ email: "Alice@Example.com" });
    expect((await store.getUserByEmail("alice@example.com"))!.id).toBe(u.id);
    await expect(store.createUser({ email: "alice@example.com" })).rejects.toThrow();
    await store.setUserOverrides(u.id, { sensitivity: "strict" });
    expect((await store.getUser(u.id))!.overrides).toEqual({ sensitivity: "strict" });
  });
  it("stores org policy and locks", async () => {
    const org = await store.createOrg("Acme");
    expect(await store.setOrgPolicy(org.id, { values: { sensitivity: "strict" }, locked: ["sensitivity"] })).toBe(true);
    expect(await store.getOrgPolicy(org.id)).toEqual({ values: { sensitivity: "strict" }, locked: ["sensitivity"] });
    expect(await store.getOrgPolicy(null)).toEqual({ values: {}, locked: [] });
    expect(await store.setOrgPolicy("00000000-0000-0000-0000-000000000000", { values: {}, locked: [] })).toBe(false);
  });
});

describe("lists", () => {
  it("merges user and org entries, dedupes, lowercases and removes", async () => {
    const org = await store.createOrg("L");
    const u = await store.createUser({ email: "lists@example.com", orgId: org.id });
    await store.addEntry({ kind: "user", id: u.id }, "allow", { matchType: "domain", value: "Good.com" });
    await store.addEntry({ kind: "user", id: u.id }, "allow", { matchType: "domain", value: "good.com" });
    await store.addEntry({ kind: "org", id: org.id }, "block", { matchType: "address", value: "bad@evil.io" });
    expect(await store.listsFor(u)).toEqual({ allow: [{ matchType: "domain", value: "good.com" }], block: [{ matchType: "address", value: "bad@evil.io" }] });
    expect(await store.removeEntry(u.id, "allow", { matchType: "domain", value: "GOOD.com" })).toBe(true);
    expect(await store.removeEntry(u.id, "allow", { matchType: "domain", value: "good.com" })).toBe(false);
  });
});

describe("scans, feedback, history, stats", () => {
  it("saves a scan with flags, replaces it on rescan, and reads it back", async () => {
    const u = await store.createUser({ email: "scan@example.com" });
    const s1 = await store.saveScan(u.id, "m1", verdict("suspicious", 35, [flag("spf_fail", 20), flag("urgency", 15)]), { latencyMs: 12.4, sender: "a@b.com" });
    expect(s1.verdict.flags.map((f) => f.id).sort()).toEqual(["spf_fail", "urgency"]);
    const s2 = await store.saveScan(u.id, "m1", verdict("safe", 0), { latencyMs: 5 });
    expect(s2.id).toBe(s1.id);
    expect(s2.verdict.verdict).toBe("safe");
    expect(s2.verdict.flags).toEqual([]);
    expect(await store.getScan(u.id, "nope")).toBeNull();
  });
  it("feedback pins the scan so a rescan cannot overwrite the user's judgement", async () => {
    const u = await store.createUser({ email: "fb@example.com" });
    await store.saveScan(u.id, "m1", verdict("phishing", 80, [flag("spf_fail", 20)]), { latencyMs: 1 });
    const pinned = await store.addFeedback(u.id, "m1", "not_phishing");
    expect(pinned).toMatchObject({ pinned: true, verdict: { verdict: "safe" } });
    const again = await store.saveScan(u.id, "m1", verdict("phishing", 90), { latencyMs: 1 });
    expect(again.verdict.verdict).toBe("safe");
    expect(await store.addFeedback(u.id, "never-scanned", "phishing")).toBeNull();
    expect(await store.statsFor(u.id, 7)).toMatchObject({ scanned: 1, safe: 1, falsePositives: 1 });
  });
  it("sender history counts messages", async () => {
    const u = await store.createUser({ email: "hist@example.com" });
    expect(await store.getSenderHistory(u.id, "x@y.com")).toBeUndefined();
    await store.recordSender(u.id, "X@y.com");
    await store.recordSender(u.id, "x@y.com");
    expect(await store.getSenderHistory(u.id, "x@y.com")).toEqual({ messagesReceived: 2, userReplied: false });
    expect(await store.countSenders(u.id)).toBe(1);
  });
  it("retention purge removes old scans with their flags", async () => {
    const u = await store.createUser({ email: "purge@example.com" });
    await store.saveScan(u.id, "old", verdict("safe", 0, []), { latencyMs: 1 });
    expect(await store.purgeScansOlderThan(90)).toBe(0);
    expect(await store.purgeScansOlderThan(-1)).toBeGreaterThanOrEqual(1);
    expect(await store.getScan(u.id, "old")).toBeNull();
  });
});

describe("connect with a data directory", () => {
  it("creates missing nested directories and persists data across reconnects", async () => {
    const { mkdtempSync, rmSync } = await import("node:fs");
    const { tmpdir } = await import("node:os");
    const { join } = await import("node:path");
    const root = mkdtempSync(join(tmpdir(), "ap-db-"));
    const dir = join(root, "a", "b", "data");
    try {
      const c1 = await connect(undefined, { dataDir: dir });
      await new Store(c1.db).createUser({ email: "persist@example.com" });
      await c1.close();
      const c2 = await connect(undefined, { dataDir: dir });
      expect(await new Store(c2.db).getUserByEmail("persist@example.com")).not.toBeNull();
      await c2.close();
    } finally { rmSync(root, { recursive: true, force: true }); }
  });
});

describe("concurrent migration", () => {
  it("two simultaneous migrate() calls on a fresh database both succeed and apply once", async () => {
    const { PGlite } = await import("@electric-sql/pglite");
    const { drizzle } = await import("drizzle-orm/pglite");
    const lite = new PGlite();
    const db = drizzle(lite) as unknown as Parameters<typeof migrate>[0];
    const [a, b] = await Promise.all([migrate(db), migrate(db)]);
    expect([...a, ...b]).toEqual(MIGRATIONS.map((m) => m.id));
    await lite.close();
  });
});

describe("acted-on tracking and write safety", () => {
  it("records the action taken on a scan and reads it back; dry-run scans start un-acted", async () => {
    const u = await store.createUser({ email: "acted@example.com" });
    const s = await store.saveScan(u.id, "m1", verdict("phishing", 80, [flag("spf_fail", 20)]), { latencyMs: 1 });
    expect(s.action).toBeNull();
    await store.setScanAction(u.id, "m1", "move_to_phishing");
    expect((await store.getScan(u.id, "m1"))!.action).toBe("move_to_phishing");
  });
  it("concurrent saves of the same new message produce one row and no error", async () => {
    const u = await store.createUser({ email: "race@example.com" });
    const [a, b] = await Promise.all([
      store.saveScan(u.id, "same", verdict("safe", 0), { latencyMs: 1 }),
      store.saveScan(u.id, "same", verdict("suspicious", 35, [flag("urgency", 35)]), { latencyMs: 1 }),
    ]);
    expect(a.id).toBe(b.id);
  });
  it("a rescan resets the acted-on marker so the new verdict can be acted on", async () => {
    const u = await store.createUser({ email: "reset@example.com" });
    await store.saveScan(u.id, "m", verdict("safe", 0), { latencyMs: 1 });
    await store.setScanAction(u.id, "m", "none");
    const again = await store.saveScan(u.id, "m", verdict("phishing", 90, [flag("spf_fail", 90)]), { latencyMs: 1 });
    expect(again.action).toBeNull();
  });
});
