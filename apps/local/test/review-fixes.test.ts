import { describe, it, expect } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { readFileSync } from "node:fs";
import type { AddressInfo } from "node:net";
import { DEFAULT_SETTINGS } from "@ap/shared";
import type { MailProvider } from "@ap/mail";
import { loadStore, saveStore, scanInbox, type VerdictStore } from "../src/runner.ts";
import { createVerdictServer } from "../src/server.ts";
import { VerdictCache } from "../../extension/src/cache.ts";

const eml = (p: string) => readFileSync(new URL("../../../corpus/" + p, import.meta.url));

const provider = (log: string[], labels: string[] = []): MailProvider => ({
  fetchRaw: async () => eml("phishing/paypal-spoof.eml"),
  move: async (id, f) => { log.push(`move ${id} ${f}`); },
  addLabel: async () => {}, unmove: async () => {}, ensureFolder: async (n) => n,
  listRecentInbox: async () => ["p1"], getLabelNames: async () => labels, watch: async () => {},
});

describe("review #6 persistence", () => {
  it("a rescued message is not re-moved after a restart", async () => {
    const dir = mkdtempSync(join(tmpdir(), "ap-"));
    const file = join(dir, "verdicts.json");
    try {
      const log: string[] = [];
      const s1: VerdictStore = new Map();
      await scanInbox(provider(log), DEFAULT_SETTINGS, s1);
      saveStore(file, s1);
      const s2 = loadStore(file); // simulated restart; the user has moved p1 back to the inbox
      await scanInbox(provider(log), DEFAULT_SETTINGS, s2);
      expect(log).toEqual(["move p1 Phishing"]);
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });
  it("loadStore tolerates a missing or corrupt file", () => {
    expect(loadStore("/nonexistent/x.json").size).toBe(0);
  });
  it("does not move a message that already carries the Phishing label", async () => {
    const log: string[] = [];
    await scanInbox(provider(log, ["INBOX", "Phishing"]), DEFAULT_SETTINGS, new Map());
    expect(log).toEqual([]);
  });
});

describe("review #7 verdict server hardening", () => {
  it("rejects foreign Host headers (DNS rebinding) and sends no CORS header", async () => {
    const store: VerdictStore = new Map();
    const srv = createVerdictServer(store);
    await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
    const port = (srv.address() as AddressInfo).port;
    const http = await import("node:http");
    const get = (host: string) => new Promise<{ status: number; cors: unknown }>((res) => {
      http.get({ host: "127.0.0.1", port, path: "/v1/health", headers: { Host: host } }, (r) => {
        r.resume(); res({ status: r.statusCode!, cors: r.headers["access-control-allow-origin"] });
      });
    });
    expect(await get("evil.example:" + port)).toMatchObject({ status: 403 });
    const ok = await get("127.0.0.1:" + port);
    expect(ok.status).toBe(200);
    expect(ok.cors).toBeUndefined();
    srv.close();
  });
});

describe("review #10 extension verdict cache", () => {
  it("fetches once per id, caches misses briefly, and refetches after the TTL", async () => {
    let now = 0, calls = 0;
    const c = new VerdictCache(async (id) => { calls++; return id === "hit" ? ({ action: "x" } as any) : null; }, 1000, () => now);
    await c.get("hit"); await c.get("hit");
    await c.get("miss"); await c.get("miss");
    expect(calls).toBe(2);
    now = 5000;
    await c.get("miss");
    expect(calls).toBe(3);
    await c.get("hit");
    expect(calls).toBe(3);
  });
});

describe("shadow records do not block act mode", () => {
  it("a message previewed in shadow mode is acted on once act mode starts, then never again", async () => {
    const log: string[] = [];
    const store: VerdictStore = new Map();
    await scanInbox(provider(log), { ...DEFAULT_SETTINGS, shadowMode: true }, store);
    expect(log).toEqual([]);
    await scanInbox(provider(log), DEFAULT_SETTINGS, store);
    await scanInbox(provider(log), DEFAULT_SETTINGS, store);
    expect(log).toEqual(["move p1 Phishing"]);
  });
});
