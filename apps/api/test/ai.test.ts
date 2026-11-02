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

describe("review I3: server cap, org pool, nested locks", () => {
  const capped = (maxUserBudgetUsd: number) => buildApp({
    store, secret: SECRET, serverId: SID,
    service: new ScanService({ store, mailFor: () => mailbox, ai: { provider, price: { inputPerMTokUsd: 1, outputPerMTokUsd: 5 }, maxUserBudgetUsd } }),
  });
  it("a user cannot raise their own budget above the server's cap", async () => {
    const c = capped(1);
    const u = await store.createUser({ email: "cap@example.com" });
    const h = { authorization: tok(u) };
    await c.inject({ method: "PATCH", url: "/v1/settings", payload: { ai: { enabled: true, monthlyBudgetUsd: 100000 } }, headers: h });
    calls = 0;
    const first = await c.inject({ method: "POST", url: "/v1/scan", payload: { providerMessageId: "m91" }, headers: h });
    const second = await c.inject({ method: "POST", url: "/v1/scan", payload: { providerMessageId: "m92" }, headers: h });
    expect(first.json().aiUsed).toBe(true);
    expect(second.json().aiUsed).toBe(false);
    expect(calls).toBe(1);
    await c.close();
  });
  it("an org's pooled monthly budget stops everyone in it, even users with budget left", async () => {
    const org = await store.createOrg("Pool Inc");
    await store.setOrgPolicy(org.id, { values: { ai: { orgMonthlyBudgetUsd: 1 } }, locked: [] });
    const a = await store.createUser({ email: "pool1@example.com", orgId: org.id });
    const b = await store.createUser({ email: "pool2@example.com", orgId: org.id });
    for (const u of [a, b]) await enable(u, { monthlyBudgetUsd: 50 });
    calls = 0;
    expect((await call(a, "POST", "/v1/scan", { providerMessageId: "m93" })).json().aiUsed).toBe(true);
    expect((await call(b, "POST", "/v1/scan", { providerMessageId: "m94" })).json().aiUsed).toBe(false);
    expect(calls).toBe(1);
  });
  it("a user cannot set the org pool themselves", async () => {
    const u = await store.createUser({ email: "nopool@example.com" });
    expect((await call(u, "PATCH", "/v1/settings", { ai: { orgMonthlyBudgetUsd: 1000000 } })).statusCode).toBe(422);
  });
  it("an org can lock just the budget field while users still switch AI on and off", async () => {
    const org = await store.createOrg("Nested Co");
    const admin = await store.createUser({ email: "admin@nested.example", orgId: org.id, role: "admin" });
    const put = await call(admin, "PUT", `/v1/orgs/${org.id}/policy`, { values: { ai: { monthlyBudgetUsd: 2 } }, locked: ["ai.monthlyBudgetUsd"] });
    expect(put.statusCode).toBe(200);
    const u = await store.createUser({ email: "u@nested.example", orgId: org.id });
    expect((await call(u, "PATCH", "/v1/settings", { ai: { enabled: true } })).statusCode).toBe(200);
    const blocked = await call(u, "PATCH", "/v1/settings", { ai: { monthlyBudgetUsd: 99 } });
    expect(blocked.statusCode).toBe(409);
    expect(blocked.json().error.fields).toEqual(["ai.monthlyBudgetUsd"]);
    expect((await call(u, "GET", "/v1/settings")).json().settings.ai).toMatchObject({ enabled: true, monthlyBudgetUsd: 2 });
    expect((await call(admin, "PUT", `/v1/orgs/${org.id}/policy`, { values: {}, locked: ["bogus.field"] })).statusCode).toBe(422);
  });
});

describe("review I6: the client can tell model output from rule evidence", () => {
  it("stored and returned flags keep their source", async () => {
    const u = await store.createUser({ email: "source@example.com" });
    await enable(u, { monthlyBudgetUsd: 100 });
    await call(u, "POST", "/v1/scan", { providerMessageId: "m95" });
    const flags = (await call(u, "GET", "/v1/messages/m95/verdict")).json().flags as { id: string; source: string }[];
    expect(Object.fromEntries(flags.map((f) => [f.id, f.source]))).toMatchObject({ reply_to_mismatch: "rule", urgency: "ai", ai_intent: "ai" });
  });
});

describe("review I4/I3 config", () => {
  const good = { SERVER_SECRET: "s".repeat(32), TOKEN_KEY: "ab".repeat(32) };
  it("validates prices and requires them for non-local endpoints", () => {
    expect(() => loadConfig({ ...good, AI_PROVIDER: "openai", AI_BASE_URL: "https://api.openai.com/v1", AI_MODEL: "m" })).toThrow(/AI_PRICE/);
    expect(() => loadConfig({ ...good, AI_PROVIDER: "openai", AI_BASE_URL: "http://localhost:11434/v1", AI_MODEL: "m", AI_PRICE_IN_PER_MTOK: "1,5" })).toThrow(/AI_PRICE/);
    expect(() => loadConfig({ ...good, AI_PROVIDER: "openai", AI_BASE_URL: "http://localhost:11434/v1", AI_MODEL: "m", AI_PRICE_OUT_PER_MTOK: "-1" })).toThrow(/AI_PRICE/);
    for (const url of ["http://localhost:11434/v1", "http://127.0.0.1:8000/v1", "http://192.168.1.20:1234/v1", "http://10.0.0.5/v1", "http://ollama:11434/v1", "http://gpu.local:8000/v1"]) {
      expect(() => loadConfig({ ...good, AI_PROVIDER: "openai", AI_BASE_URL: url, AI_MODEL: "m" }), url).not.toThrow();
    }
    expect(loadConfig({ ...good, AI_PROVIDER: "openai", AI_BASE_URL: "https://api.together.xyz/v1", AI_MODEL: "m", AI_PRICE_IN_PER_MTOK: "0.2", AI_PRICE_OUT_PER_MTOK: "0.6" }).ai)
      .toMatchObject({ price: { inputPerMTokUsd: 0.2, outputPerMTokUsd: 0.6 } });
  });
  it("has a server-wide cap on any user's AI budget, default $20", () => {
    const local = { ...good, AI_PROVIDER: "openai", AI_BASE_URL: "http://localhost:1/v1", AI_MODEL: "m" };
    expect(loadConfig(local).ai!.maxUserBudgetUsd).toBe(20);
    expect(loadConfig({ ...local, AI_MAX_USER_BUDGET_USD: "3.5" }).ai!.maxUserBudgetUsd).toBe(3.5);
    expect(() => loadConfig({ ...local, AI_MAX_USER_BUDGET_USD: "-1" })).toThrow(/AI_MAX_USER_BUDGET_USD/);
  });
});
