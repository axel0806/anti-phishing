import { describe, expect, it } from "vitest";
import { GmailProvider, GraphProvider, type FetchLike } from "@ap/mail";
import { mailProviderFactory } from "../src/mailer.ts";
import { decryptSecret, encryptSecret } from "../src/auth.ts";
import { loadConfig } from "../src/config.ts";

const KEY = "cd".repeat(32);
const blob = (refresh = "r1") => encryptSecret(KEY, JSON.stringify({ refresh_token: refresh }));
const user = (provider: string, tokens: string | null = blob()) => ({ id: "u-" + provider, orgId: null, email: "e@x.com", provider, role: "user" as const, overrides: {}, encryptedTokens: tokens });
const google = { clientId: "g", clientSecret: "gs" };
const microsoft = { clientId: "m", tenant: "common" };

describe("mailProviderFactory", () => {
  it("picks Gmail or Graph from the user's provider, and caches one client per user", () => {
    const f = mailProviderFactory({ google, microsoft, tokenKey: KEY });
    const stored = blob(); // the same stored token for the same user: encryption uses a random IV, so a fresh blob would be a different cache key
    const g = f(user("gmail", stored)), o = f(user("outlook", stored));
    expect(g).toBeInstanceOf(GmailProvider);
    expect(o).toBeInstanceOf(GraphProvider);
    expect(f(user("gmail", stored))).toBe(g);
    expect(f(user("gmail", blob("r-new")))).not.toBe(g); // a changed token (re-link) builds a fresh client
  });
  it("returns null for unlinked users, unconfigured providers, unknown providers and undecryptable tokens", () => {
    const onlyGoogle = mailProviderFactory({ google, tokenKey: KEY });
    expect(onlyGoogle(user("gmail", null))).toBeNull();
    expect(onlyGoogle(user("outlook"))).toBeNull();
    expect(onlyGoogle(user("carrier-pigeon"))).toBeNull();
    expect(onlyGoogle(user("gmail", "garbage"))).toBeNull();
    expect(mailProviderFactory({ microsoft, tokenKey: KEY })(user("gmail"))).toBeNull();
  });

  const tokenFetch = (respond: () => { status: number; json: unknown }) => {
    const calls: string[] = [];
    const f: FetchLike = async (url) => {
      calls.push(url);
      if (url.includes("login.microsoftonline.com") || url.includes("googleapis.com/token")) {
        const r = respond();
        return { ok: r.status < 300, status: r.status, json: async () => r.json, text: async () => JSON.stringify(r.json) };
      }
      return { ok: true, status: 200, json: async () => ({ value: [] }), text: async () => "{}" };
    };
    return { f, calls };
  };

  it("persists a rotated refresh token, encrypted, and only when it actually changed", async () => {
    const saved: { userId: string; blob: string }[] = [];
    const t = tokenFetch(() => ({ status: 200, json: { access_token: "a", expires_in: 1, refresh_token: "r2" } })); // expires at once: every call refreshes
    const f = mailProviderFactory({ microsoft, tokenKey: KEY, fetch: t.f, persist: async (userId, b) => { saved.push({ userId, blob: b }); } });
    const p = f(user("outlook"))!;
    await p.listRecentInbox(1);
    await p.listRecentInbox(1);
    expect(saved).toHaveLength(1); // r1 -> r2 once; the second refresh returned the same r2
    expect(saved[0]!.userId).toBe("u-outlook");
    expect(saved[0]!.blob).not.toContain("r2");
    expect(JSON.parse(decryptSecret(KEY, saved[0]!.blob)).refresh_token).toBe("r2");
  });

  it("reports a revoked link once so the worker can stop retrying it", async () => {
    const revoked: string[] = [];
    const t = tokenFetch(() => ({ status: 400, json: { error: "invalid_grant" } }));
    const f = mailProviderFactory({ google, tokenKey: KEY, fetch: t.f, onRevoked: (id) => revoked.push(id) });
    const p = f(user("gmail"))!;
    await expect(p.listRecentInbox(1)).rejects.toThrow(/invalid_grant/);
    expect(revoked).toEqual(["u-gmail"]);
  });
});

describe("Microsoft config", () => {
  const good = { SERVER_SECRET: "s".repeat(32), TOKEN_KEY: "ab".repeat(32) };
  it("is off by default and builds from MICROSOFT_* variables, secret optional, tenant defaulting to common", () => {
    expect(loadConfig(good).microsoft).toBeNull();
    expect(loadConfig({ ...good, MICROSOFT_CLIENT_ID: "m" }).microsoft).toEqual({ clientId: "m", clientSecret: undefined, tenant: "common" });
    expect(loadConfig({ ...good, MICROSOFT_CLIENT_ID: "m", MICROSOFT_CLIENT_SECRET: "s", MICROSOFT_TENANT: "contoso.onmicrosoft.com" }).microsoft)
      .toEqual({ clientId: "m", clientSecret: "s", tenant: "contoso.onmicrosoft.com" });
  });
  it("rejects a tenant that could redirect the sign-in somewhere else", () => {
    expect(() => loadConfig({ ...good, MICROSOFT_CLIENT_ID: "m", MICROSOFT_TENANT: "evil.example/../x" })).toThrow(/MICROSOFT_TENANT/);
    expect(() => loadConfig({ ...good, MICROSOFT_CLIENT_ID: "m", MICROSOFT_TENANT: "a b" })).toThrow(/MICROSOFT_TENANT/);
  });
});
