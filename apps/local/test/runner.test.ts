import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import type { AddressInfo } from "node:net";
import { DEFAULT_SETTINGS } from "@ap/shared";
import type { MailProvider } from "@ap/mail";
import { scanInbox, type VerdictStore } from "../src/runner.ts";
import { createVerdictServer } from "../src/server.ts";

const eml = (p: string) => readFileSync(new URL("../../../corpus/" + p, import.meta.url));

function fakeProvider() {
  const log: string[] = [];
  const msgs: Record<string, Buffer> = { p1: eml("phishing/paypal-spoof.eml"), l1: eml("legit/lunch.eml") };
  const p: MailProvider = {
    fetchRaw: async (id) => { if (id === "bad") throw new Error("boom"); return msgs[id]!; },
    move: async (id, f) => { log.push(`move ${id} ${f}`); },
    addLabel: async (id, l) => { log.push(`label ${id} ${l}`); },
    ensureFolder: async (n) => n,
    listRecentInbox: async () => ["p1", "l1", "bad"],
    getLabelNames: async () => [],
    watch: async () => {},
  };
  return { p, log };
}

describe("scanInbox", () => {
  it("shadow mode records verdicts but never touches mail", async () => {
    const { p, log } = fakeProvider();
    const store: VerdictStore = new Map();
    await scanInbox(p, { ...DEFAULT_SETTINGS, shadowMode: true }, store);
    expect(log).toEqual([]);
    expect(store.get("p1")!.verdict.verdict).toBe("phishing");
    expect(store.get("p1")!.shadow).toBe(true);
  });
  it("act mode moves phishing, leaves safe mail, and a failing message does not block the rest", async () => {
    const { p, log } = fakeProvider();
    const store: VerdictStore = new Map();
    const done = await scanInbox(p, DEFAULT_SETTINGS, store);
    expect(log).toEqual(["move p1 Phishing"]);
    expect(done).toEqual(["p1", "l1"]);
    expect(store.has("bad")).toBe(false);
  });
  it("is idempotent across passes", async () => {
    const { p, log } = fakeProvider();
    const store: VerdictStore = new Map();
    await scanInbox(p, DEFAULT_SETTINGS, store);
    await scanInbox(p, DEFAULT_SETTINGS, store);
    expect(log).toEqual(["move p1 Phishing"]);
  });
});

describe("verdict server", () => {
  it("serves stored verdicts without CORS, 404 otherwise", async () => {
    const store: VerdictStore = new Map();
    const { p } = fakeProvider();
    await scanInbox(p, { ...DEFAULT_SETTINGS, shadowMode: true }, store);
    const srv = createVerdictServer(store);
    await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
    const port = (srv.address() as AddressInfo).port;
    const ok = await fetch(`http://127.0.0.1:${port}/v1/messages/p1/verdict`);
    expect(ok.status).toBe(200);
    expect(ok.headers.get("access-control-allow-origin")).toBeNull();
    expect((await ok.json()).verdict.verdict).toBe("phishing");
    expect((await fetch(`http://127.0.0.1:${port}/v1/messages/zzz/verdict`)).status).toBe(404);
    srv.close();
  });
});
