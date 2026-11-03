import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { FastifyInstance } from "fastify";
import type { MailProvider } from "@ap/mail";
import { connect, Store, type Connection, type User } from "@ap/db";
import { buildApp, signToken } from "../src/app.ts";
import { RateLimiter } from "../src/rateLimit.ts";
import { ScanService } from "../src/service.ts";

describe("RateLimiter", () => {
  it("allows up to the limit per key per window, then reports when to retry", () => {
    let now = 1_000_000;
    const l = new RateLimiter(60_000, 3, () => now);
    expect([1, 2, 3].map(() => l.take("a").ok)).toEqual([true, true, true]);
    const blocked = l.take("a");
    expect(blocked.ok).toBe(false);
    expect(blocked.retryAfterSec).toBeGreaterThan(0);
    expect(blocked.retryAfterSec).toBeLessThanOrEqual(60);
    expect(l.take("b").ok).toBe(true); // another key is unaffected
    now += 60_001;
    expect(l.take("a").ok).toBe(true); // a new window
  });
  it("forgets idle keys so memory stays bounded", () => {
    let now = 0;
    const l = new RateLimiter(1000, 1, () => now);
    for (let i = 0; i < 50; i++) l.take("k" + i);
    now = 5000;
    l.sweep();
    expect(l.size).toBe(0);
  });
});

const SECRET = "r".repeat(40), SID = "srv-rl";
let conn: Connection, store: Store, app: FastifyInstance, user: User;
const mailbox: MailProvider = { fetchRaw: async () => Buffer.from(""), move: async () => {}, unmove: async () => {}, addLabel: async () => {}, ensureFolder: async (n) => n, listRecentInbox: async () => [], getLabelNames: async () => [], watch: async () => {} };
const auth = () => "Bearer " + signToken(SECRET, { uid: user.id, sid: SID, exp: Math.floor(Date.now() / 1000) + 3600 });
beforeAll(async () => {
  conn = await connect();
  store = new Store(conn.db);
  user = await store.createUser({ email: "rl@example.com" });
  app = buildApp({
    store, secret: SECRET, serverId: SID, tokenKey: "ab".repeat(32), service: new ScanService({ store, mailFor: () => mailbox }),
    rateLimits: { publicPerMin: 5, userPerMin: 8, rescanPerMin: 2 },
  });
  await app.ready();
});
afterAll(async () => { await app.close(); await conn.close(); });

describe("HTTP rate limits", () => {
  it("throttle the public onboarding routes per address, with a Retry-After header", async () => {
    const codes: number[] = [];
    for (let i = 0; i < 8; i++) codes.push((await app.inject({ method: "GET", url: "/join/not-a-real-invite", remoteAddress: "198.51.100.9" })).statusCode);
    expect(codes.slice(0, 5)).toEqual([404, 404, 404, 404, 404]);
    expect(codes.slice(5)).toEqual([429, 429, 429]);
    const r = await app.inject({ method: "GET", url: "/join/x", remoteAddress: "198.51.100.9" });
    expect(Number(r.headers["retry-after"])).toBeGreaterThan(0);
    expect((await app.inject({ method: "GET", url: "/join/x", remoteAddress: "198.51.100.77" })).statusCode).toBe(404); // another address
  });
  it("ignore a spoofed X-Forwarded-For unless the server is told it sits behind a proxy", async () => {
    const codes: number[] = [];
    for (let i = 0; i < 8; i++) codes.push((await app.inject({ method: "GET", url: "/join/y", remoteAddress: "198.51.100.30", headers: { "x-forwarded-for": `203.0.113.${i}` } })).statusCode);
    expect(codes.slice(5)).toEqual([429, 429, 429]);
  });
  it("throttle an authenticated user, and /rescan much harder", async () => {
    const h = { authorization: auth() };
    const re: number[] = [];
    for (let i = 0; i < 4; i++) re.push((await app.inject({ method: "POST", url: "/v1/rescan", payload: {}, headers: h })).statusCode);
    expect(re.slice(0, 2)).toEqual([200, 200]);
    expect(re.slice(2)).toEqual([429, 429]);
    const rest: number[] = [];
    for (let i = 0; i < 9; i++) rest.push((await app.inject({ method: "GET", url: "/v1/me", headers: h })).statusCode);
    expect(rest.includes(429)).toBe(true);
  });
  it("leave the health check alone, so monitors and load balancers are never blocked", async () => {
    for (let i = 0; i < 30; i++) expect((await app.inject({ method: "GET", url: "/v1/health", remoteAddress: "198.51.100.50" })).statusCode).toBe(200);
  });
});
