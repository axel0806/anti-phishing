import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { FastifyInstance } from "fastify";
import type { MailProvider } from "@ap/mail";
import type { AiProvider } from "@ap/ai";
import { connect, Store, type Connection, type User } from "@ap/db";
import { buildApp, signToken } from "../src/app.ts";
import { ScanService } from "../src/service.ts";
import { loadConfig } from "../src/config.ts";

const SECRET = "test-secret", SID = "server-ai";
// Rule score 25 (reply-to mismatch + shortener): inside the uncertain band.
const uncertainEml = (n: number) => Buffer.from([
  "Authentication-Results: mx.google.com; spf=pass; dkim=pass; dmarc=pass",
  `From: "Sam" <sam${n}@shop.example>`, "Reply-To: other@elsewhere.org", "To: me@example.com", `Subject: Your order ${n}`,
  "MIME-Version: 1.0", "Content-Type: text/html; charset=utf-8", "",
  `<p>Track it here <a href="http://bit.ly/abc${n}">http://bit.ly/abc${n}</a>. Call 555-123-4567 or mail sam@shop.example</p>`,
].join("\r\n"));

let conn: Connection, store: Store;
const seen: unknown[] = [];
let calls = 0;
let mode: "ok" | "fail" = "ok";
const provider: AiProvider = {
  name: "fake-model",
  analyze: async (input) => {
    calls++; seen.push(input);
    if (mode === "fail") throw new Error("model down");
    return { verdict: { riskScore: 0.9, tactics: ["urgency"], impersonatedEntity: "Shop", explanation: "Fake delivery notice." }, usage: { inputTokens: 1_000_000, outputTokens: 0 } };
  },
};
const mailbox: MailProvider = {
  fetchRaw: async (id) => uncertainEml(Number(id.replace(/\D/g, "")) || 0),
  move: async () => {}, unmove: async () => {}, addLabel: async () => {}, ensureFolder: async (n) => n,
  listRecentInbox: async () => [], getLabelNames: async () => [], watch: async () => {},
};

function app(withAi = true): FastifyInstance {
  return buildApp({
    store, secret: SECRET, serverId: SID,
    service: new ScanService({ store, mailFor: () => mailbox, ai: withAi ? { provider, price: { inputPerMTokUsd: 1, outputPerMTokUsd: 5 } } : undefined }),
  });
}
let a: FastifyInstance;
beforeAll(async () => { conn = await connect(); store = new Store(conn.db); a = app(); await a.ready(); });
afterAll(async () => { await a.close(); await conn.close(); });

const tok = (u: User) => "Bearer " + signToken(SECRET, { uid: u.id, sid: SID, exp: Math.floor(Date.now() / 1000) + 3600 });
const call = (u: User, method: string, url: string, payload?: unknown) => a.inject({ method: method as "GET", url, payload: payload as object, headers: { authorization: tok(u) } });
const enable = (u: User, extra: object = {}) => call(u, "PATCH", "/v1/settings", { ai: { enabled: true, ...extra } });

describe("AI over the API", () => {
  it("is off by default: the model is never called and nothing leaves the server", async () => {
    const u = await store.createUser({ email: "ai-off@example.com" });
    calls = 0;
    const r = await call(u, "POST", "/v1/scan", { providerMessageId: "m1" });
    expect(r.json()).toMatchObject({ aiUsed: false, verdict: "safe" });
    expect(calls).toBe(0);
  });
  it("once enabled, an uncertain email is escalated; the verdict, explanation and usage are stored", async () => {
    const u = await store.createUser({ email: "ai-on@example.com" });
    await enable(u);
    calls = 0; seen.length = 0;
    const r = await call(u, "POST", "/v1/scan", { providerMessageId: "m2" });
    expect(r.json()).toMatchObject({ aiUsed: true, verdict: "phishing", aiExplanation: "Fake delivery notice." });
    expect(calls).toBe(1);
    const stored = await call(u, "GET", "/v1/messages/m2/verdict");
    expect(stored.json()).toMatchObject({ aiUsed: true, aiExplanation: "Fake delivery notice." });
    // privacy: the model saw redacted text only
    expect(JSON.stringify(seen[0])).not.toMatch(/555-123|sam@shop/);
    expect(await store.aiCallsThisMonth(u.id)).toBe(1);
    expect(await store.aiSpentThisMonth(u.id)).toBeCloseTo(1);
  });
  it("the same email content is answered from the cache, not the model", async () => {
    const u = await store.createUser({ email: "ai-cache@example.com" });
    await enable(u, { monthlyBudgetUsd: 100 });
    calls = 0;
    await call(u, "POST", "/v1/scan", { providerMessageId: "m3" });
    await call(u, "POST", "/v1/scan", { providerMessageId: "m3", rescan: true });
    expect(calls).toBe(1);
    expect(await store.aiCallsThisMonth(u.id)).toBe(1);
  });
  it("stops calling the model once the monthly budget is spent, but keeps scanning with rules", async () => {
    const u = await store.createUser({ email: "ai-budget@example.com" });
    await enable(u, { monthlyBudgetUsd: 1 }); // one call costs $1 with the fake price
    calls = 0;
    const first = await call(u, "POST", "/v1/scan", { providerMessageId: "m41" });
    const second = await call(u, "POST", "/v1/scan", { providerMessageId: "m42" });
    expect(first.json().aiUsed).toBe(true);
    expect(second.statusCode).toBe(200);
    expect(second.json()).toMatchObject({ aiUsed: false, verdict: "safe" });
    expect(calls).toBe(1);
  });
  it("a failing model never breaks scanning", async () => {
    const u = await store.createUser({ email: "ai-fail@example.com" });
    await enable(u, { monthlyBudgetUsd: 100 });
    mode = "fail";
    const r = await call(u, "POST", "/v1/scan", { providerMessageId: "m5" });
    mode = "ok";
    expect(r.statusCode).toBe(200);
    expect(r.json()).toMatchObject({ aiUsed: false, verdict: "safe" });
  });
  it("an org that locks AI off keeps it off for its users", async () => {
    const org = await store.createOrg("NoAI");
    await store.setOrgPolicy(org.id, { values: { ai: { enabled: false } }, locked: ["ai"] });
    const u = await store.createUser({ email: "ai-locked@example.com", orgId: org.id });
    expect((await enable(u)).statusCode).toBe(409);
    calls = 0;
    await call(u, "POST", "/v1/scan", { providerMessageId: "m6" });
    expect(calls).toBe(0);
  });
  it("is inert when the server has no AI provider configured, even if the user enables it", async () => {
    const plain = app(false);
    const u = await store.createUser({ email: "ai-noprov@example.com" });
    await enable(u);
    calls = 0;
    const r = await plain.inject({ method: "POST", url: "/v1/scan", payload: { providerMessageId: "m7" }, headers: { authorization: tok(u) } });
    expect(r.json()).toMatchObject({ aiUsed: false });
    expect(calls).toBe(0);
    await plain.close();
  });
  it("reports AI usage in the user's stats", async () => {
    const u = await store.createUser({ email: "ai-stats@example.com" });
    await enable(u);
    await call(u, "POST", "/v1/scan", { providerMessageId: "m8" });
    expect((await call(u, "GET", "/v1/me/stats")).json()).toMatchObject({ aiCalls: 1 });
  });
});

describe("AI config", () => {
  const good = { SERVER_SECRET: "s".repeat(32), TOKEN_KEY: "ab".repeat(32) };
  it("defaults to no AI", () => expect(loadConfig(good).ai).toBeNull());
  it("builds hosted and local provider settings, and requires prices for hosted budgeting", () => {
    expect(loadConfig({ ...good, AI_PROVIDER: "anthropic", ANTHROPIC_API_KEY: "k", AI_PRICE_IN_PER_MTOK: "1", AI_PRICE_OUT_PER_MTOK: "5" }).ai)
      .toMatchObject({ kind: "anthropic", apiKey: "k", model: "claude-haiku-5-5", price: { inputPerMTokUsd: 1, outputPerMTokUsd: 5 }, timeoutMs: 2500 });
    expect(loadConfig({ ...good, AI_PROVIDER: "openai", AI_BASE_URL: "http://localhost:11434/v1", AI_MODEL: "llama3.1" }).ai)
      .toMatchObject({ kind: "openai", baseUrl: "http://localhost:11434/v1", model: "llama3.1", price: { inputPerMTokUsd: 0, outputPerMTokUsd: 0 } });
    expect(() => loadConfig({ ...good, AI_PROVIDER: "anthropic", ANTHROPIC_API_KEY: "k" })).toThrow(/AI_PRICE/);
    expect(() => loadConfig({ ...good, AI_PROVIDER: "anthropic", AI_PRICE_IN_PER_MTOK: "1", AI_PRICE_OUT_PER_MTOK: "5" })).toThrow(/ANTHROPIC_API_KEY/);
    expect(() => loadConfig({ ...good, AI_PROVIDER: "openai", AI_MODEL: "m" })).toThrow(/AI_BASE_URL/);
    expect(() => loadConfig({ ...good, AI_PROVIDER: "magic" })).toThrow(/AI_PROVIDER/);
  });
});
