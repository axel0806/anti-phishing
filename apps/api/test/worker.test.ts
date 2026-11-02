import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import type { MailProvider } from "@ap/mail";
import { connect, Store, type Connection } from "@ap/db";
import { ScanService } from "../src/service.ts";
import { runWorkerPass } from "../src/worker.ts";
import { gmailProviderFactory } from "../src/mailer.ts";
import { encryptSecret } from "../src/auth.ts";

const eml = (p: string) => readFileSync(new URL("../../../corpus/" + p, import.meta.url));
let conn: Connection, store: Store;
beforeAll(async () => { conn = await connect(); store = new Store(conn.db); });
afterAll(async () => { await conn.close(); });

function mail(log: string[], inbox: string[]): MailProvider {
  const msgs: Record<string, Buffer> = { p1: eml("phishing/paypal-spoof.eml"), l1: eml("legit/lunch.eml") };
  return {
    fetchRaw: async (id) => { if (id === "bad") throw new Error("boom"); return msgs[id]!; },
    move: async (id, f) => { log.push(`move ${id} ${f}`); }, addLabel: async (id, l) => { log.push(`label ${id} ${l}`); },
    ensureFolder: async (n) => n, listRecentInbox: async () => inbox, getLabelNames: async () => [], watch: async () => {}, unmove: async () => {},
  };
}

describe("worker pass", () => {
  it("scans every linked user's inbox in act mode, skips unlinked users, never re-acts, survives bad messages", async () => {
    const log: string[] = [];
    const linked = await store.createUser({ email: "w1@example.com" });
    await store.setEncryptedTokens(linked.id, "blob");
    await store.createUser({ email: "unlinked@example.com" });
    const m = mail(log, ["p1", "l1", "bad"]);
    const service = new ScanService({ store, mailFor: () => m });

    const first = await runWorkerPass(store, service, () => m, { limit: 25 });
    expect(first).toEqual({ users: 1, scanned: 2, failed: 1 });
    expect(log).toEqual(["move p1 Phishing"]);

    const second = await runWorkerPass(store, service, () => m, { limit: 25 });
    expect(second.scanned).toBe(0);
    expect(log).toEqual(["move p1 Phishing"]);
  });
  it("a user in shadow mode is scored but not touched", async () => {
    const log: string[] = [];
    const u = await store.createUser({ email: "w2@example.com" });
    await store.setEncryptedTokens(u.id, "blob");
    await store.setUserOverrides(u.id, { shadowMode: true });
    const m = mail(log, ["p1"]);
    await runWorkerPass(store, new ScanService({ store, mailFor: () => m }), () => m, { limit: 5 });
    expect(log).toEqual([]);
    expect((await store.getScan(u.id, "p1"))!.verdict.verdict).toBe("phishing");
  });
});

describe("gmailProviderFactory", () => {
  it("returns null without tokens or a key, and caches one provider per user", () => {
    const key = "ab".repeat(32);
    const f = gmailProviderFactory({ clientId: "c", clientSecret: "s", tokenKey: key });
    const base = { id: "u1", orgId: null, email: "e", provider: "gmail", role: "user" as const, overrides: {} };
    expect(f({ ...base, encryptedTokens: null })).toBeNull();
    const withTokens = { ...base, encryptedTokens: encryptSecret(key, JSON.stringify({ refresh_token: "r" })) };
    const a = f(withTokens);
    expect(a).not.toBeNull();
    expect(f(withTokens)).toBe(a);
    expect(f({ ...withTokens, encryptedTokens: "garbage" })).toBeNull();
  });
});

import { runMaintenance } from "../src/worker.ts";

describe("worker after an extension dry-run", () => {
  it("still acts on a message the extension already scanned in dry-run mode", async () => {
    const log: string[] = [];
    const u = await store.createUser({ email: "w3@example.com" });
    await store.setEncryptedTokens(u.id, "blob");
    const m = mail(log, ["p1"]);
    const service = new ScanService({ store, mailFor: () => m });
    await service.scan(u, "p1", { mode: "dry_run" });
    expect(log).toEqual([]);
    const r = await runWorkerPass(store, service, () => m, { limit: 5 });
    expect(r.scanned).toBe(1);
    expect(log).toEqual(["move p1 Phishing"]);
  });
});

describe("maintenance", () => {
  it("purges scans past the retention window", async () => {
    const u = await store.createUser({ email: "w4@example.com" });
    await store.saveScan(u.id, "old", { verdict: "safe", score: 0, flags: [], aiUsed: false, settingsVersion: 1 }, { latencyMs: 1 });
    expect(await runMaintenance(store, 90)).toEqual({ purged: 0 });
    expect((await runMaintenance(store, -1)).purged).toBeGreaterThanOrEqual(1);
  });
});
