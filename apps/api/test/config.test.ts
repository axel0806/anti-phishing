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

describe("retention config", () => {
  it("defaults to 90 days and validates RETENTION_DAYS", () => {
    expect(loadConfig(good).retentionDays).toBe(90);
    expect(loadConfig({ ...good, RETENTION_DAYS: "30" }).retentionDays).toBe(30);
    expect(() => loadConfig({ ...good, RETENTION_DAYS: "0" })).toThrow(/RETENTION_DAYS/);
  });
});

describe("PUBLIC_URL and web onboarding config", () => {
  it("is checked even without single sign-on, since invite links and the Outlook manifest are built from it", () => {
    expect(() => loadConfig({ ...good, PUBLIC_URL: "http://phish.example" })).toThrow(/PUBLIC_URL must be an https URL/);
    expect(() => loadConfig({ ...good, PUBLIC_URL: "not a url" })).toThrow(/PUBLIC_URL/);
    expect(loadConfig({ ...good, PUBLIC_URL: "https://phish.example/" }).publicUrl).toBe("https://phish.example");
    expect(loadConfig({ ...good, PUBLIC_URL: "http://localhost:8080" }).publicUrl).toBe("http://localhost:8080");
  });
  it("reads an optional SETUP_TOKEN and refuses a weak one", () => {
    expect(loadConfig(good).setupToken).toBeUndefined();
    expect(loadConfig({ ...good, SETUP_TOKEN: "a-long-enough-setup-token" }).setupToken).toBe("a-long-enough-setup-token");
    expect(() => loadConfig({ ...good, SETUP_TOKEN: "short" })).toThrow(/SETUP_TOKEN/);
  });
});

describe("OIDC single sign-on config", () => {
  const sso = { OIDC_ISSUER: "https://login.example/", OIDC_CLIENT_ID: "cid", OIDC_CLIENT_SECRET: "sec", PUBLIC_URL: "https://phish.example/" };
  it("is off by default", () => expect(loadConfig(good).oidc).toBeNull());
  it("derives the redirect URI from PUBLIC_URL", () => {
    expect(loadConfig({ ...good, ...sso }).oidc).toMatchObject({ issuer: "https://login.example/", clientId: "cid", redirectUri: "https://phish.example/admin/callback", trustMissingEmailVerified: false });
    expect(loadConfig({ ...good, ...sso, OIDC_TRUST_MISSING_EMAIL_VERIFIED: "true" }).oidc!.trustMissingEmailVerified).toBe(true);
  });
  it("refuses a half-configured or insecure setup", () => {
    expect(() => loadConfig({ ...good, OIDC_ISSUER: "https://login.example" })).toThrow(/OIDC_CLIENT_ID/);
    expect(() => loadConfig({ ...good, ...sso, PUBLIC_URL: undefined })).toThrow(/PUBLIC_URL/);
    expect(() => loadConfig({ ...good, ...sso, PUBLIC_URL: "http://phish.example" })).toThrow(/https/);
    expect(() => loadConfig({ ...good, ...sso, OIDC_ISSUER: "http://login.example" })).toThrow(/https/);
  });
  it("allows plain http only for localhost development", () => {
    expect(() => loadConfig({ ...good, ...sso, PUBLIC_URL: "http://localhost:8080", OIDC_ISSUER: "http://localhost:9000" })).not.toThrow();
  });
});
