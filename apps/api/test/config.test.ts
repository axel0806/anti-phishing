import { describe, expect, it } from "vitest";
import { loadConfig } from "../src/config.ts";

const good = { SERVER_SECRET: "s".repeat(32), TOKEN_KEY: "ab".repeat(32), GOOGLE_CLIENT_ID: "id", GOOGLE_CLIENT_SECRET: "sec" };

describe("loadConfig", () => {
  it("applies defaults and derives a stable server id from the secret", () => {
    const a = loadConfig(good), b = loadConfig(good), c = loadConfig({ ...good, SERVER_SECRET: "t".repeat(32) });
    expect(a).toMatchObject({ port: 8080, role: "all", pollSeconds: 60, databaseUrl: undefined });
    expect(a.serverId).toBe(b.serverId);
    expect(a.serverId).not.toBe(c.serverId);
    expect(a.serverId).not.toContain(good.SERVER_SECRET);
  });
  it("accepts an explicit SERVER_ID, DATABASE_URL, PORT and ROLE", () => {
    expect(loadConfig({ ...good, SERVER_ID: "my-server", DATABASE_URL: "postgres://x", PORT: "9000", ROLE: "worker" }))
      .toMatchObject({ serverId: "my-server", databaseUrl: "postgres://x", port: 9000, role: "worker" });
  });
  it("rejects weak or malformed secrets with every problem listed", () => {
    expect(() => loadConfig({})).toThrow(/SERVER_SECRET[\s\S]*TOKEN_KEY/);
    expect(() => loadConfig({ ...good, SERVER_SECRET: "short" })).toThrow(/SERVER_SECRET/);
    expect(() => loadConfig({ ...good, TOKEN_KEY: "xyz" })).toThrow(/TOKEN_KEY/);
    expect(() => loadConfig({ ...good, PORT: "nope" })).toThrow(/PORT/);
    expect(() => loadConfig({ ...good, ROLE: "boss" })).toThrow(/ROLE/);
  });
  it("works without Google credentials (API only), marking gmail unavailable", () => {
    const { GOOGLE_CLIENT_ID: _a, GOOGLE_CLIENT_SECRET: _b, ...noGoogle } = good;
    expect(loadConfig(noGoogle).google).toBeNull();
  });
});
