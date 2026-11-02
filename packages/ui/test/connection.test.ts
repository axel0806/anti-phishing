import { describe, expect, it } from "vitest";
import {
  DEFAULT_CONNECTION, applyConnection, handshake, normalizeServerUrl, normalizeVerdict, resolveConnection, type Connection,
} from "../src/connection.ts";

describe("normalizeServerUrl", () => {
  it("requires https except for localhost, strips trailing slashes and paths", () => {
    expect(normalizeServerUrl("https://phish.example.com/")).toEqual({ ok: true, url: "https://phish.example.com" });
    expect(normalizeServerUrl(" http://localhost:8080 ")).toEqual({ ok: true, url: "http://localhost:8080" });
    expect(normalizeServerUrl("http://127.0.0.1:8787/v1/")).toEqual({ ok: true, url: "http://127.0.0.1:8787" });
    expect(normalizeServerUrl("http://[::1]:8080")).toEqual({ ok: true, url: "http://[::1]:8080" });
    expect(normalizeServerUrl("http://phish.example.com")).toMatchObject({ ok: false });
    expect(normalizeServerUrl("http://192.168.1.5:8080")).toMatchObject({ ok: false });
    expect(normalizeServerUrl("ftp://x.com")).toMatchObject({ ok: false });
    expect(normalizeServerUrl("not a url")).toMatchObject({ ok: false });
    expect(normalizeServerUrl("https://user:pw@x.com")).toMatchObject({ ok: false });
  });
  it("does not treat lookalike hostnames as localhost", () => {
    expect(normalizeServerUrl("http://localhost.evil.com")).toMatchObject({ ok: false });
    expect(normalizeServerUrl("http://127.0.0.1.evil.com")).toMatchObject({ ok: false });
  });
});

describe("handshake", () => {
  const f = (body: unknown, ok = true) => (async () => ({ ok, json: async () => body })) as unknown as typeof fetch;
  it("accepts a server that speaks v1, with or without a server id", async () => {
    expect(await handshake("https://x.com", f({ version: "0.2.0", serverId: "abc", apiVersions: ["v1"] }))).toEqual({ ok: true, serverId: "abc", version: "0.2.0" });
    expect(await handshake("http://127.0.0.1:8787", f({ version: "0.1.0", apiVersions: ["v1"] }))).toEqual({ ok: true, serverId: null, version: "0.1.0" });
  });
  it("rejects wrong API versions, bad status, garbage and network errors", async () => {
    expect(await handshake("https://x.com", f({ version: "9", apiVersions: ["v2"] }))).toMatchObject({ ok: false });
    expect(await handshake("https://x.com", f({}, false))).toMatchObject({ ok: false });
    expect(await handshake("https://x.com", f("nope"))).toMatchObject({ ok: false });
    expect(await handshake("https://x.com", (async () => { throw new Error("down"); }) as unknown as typeof fetch)).toMatchObject({ ok: false });
  });
});

describe("applyConnection", () => {
  const cur: Connection = { serverUrl: "https://a.com", serverId: "A", token: "tok-a" };
  it("keeps the token when only the token changes on the same server", () => {
    expect(applyConnection(cur, { serverUrl: "https://a.com", serverId: "A", token: "tok-new" })).toEqual({ connection: { serverUrl: "https://a.com", serverId: "A", token: "tok-new" }, cleared: false });
  });
  it("clears the token and flags a cache reset when the URL or server id changes", () => {
    const r = applyConnection(cur, { serverUrl: "https://b.com", serverId: "B" });
    expect(r.connection).toEqual({ serverUrl: "https://b.com", serverId: "B", token: "" });
    expect(r.cleared).toBe(true);
    const sameUrlOtherServer = applyConnection(cur, { serverUrl: "https://a.com", serverId: "Z" });
    expect(sameUrlOtherServer).toMatchObject({ cleared: true, connection: { token: "" } });
  });
});

describe("resolveConnection (managed policy)", () => {
  const local: Connection = { serverUrl: "https://mine.example", serverId: "M", token: "t" };
  it("uses the stored connection when nothing is managed", () => {
    expect(resolveConnection(local, undefined)).toEqual({ connection: local, locked: false });
    expect(resolveConnection(null, undefined)).toEqual({ connection: DEFAULT_CONNECTION, locked: false });
  });
  it("a managed, locked server URL overrides and ignores the locally stored one", () => {
    const r = resolveConnection(local, { serverUrl: "https://corp.example/", lockServerUrl: true });
    expect(r.locked).toBe(true);
    expect(r.connection.serverUrl).toBe("https://corp.example");
    expect(r.connection.token).toBe(""); // the token belonged to a different server
  });
  it("keeps the token when the managed URL equals the stored one", () => {
    expect(resolveConnection(local, { serverUrl: "https://mine.example", lockServerUrl: true }).connection.token).toBe("t");
  });
  it("a managed URL without a lock is only a default", () => {
    expect(resolveConnection(local, { serverUrl: "https://corp.example" })).toEqual({ connection: local, locked: false });
    expect(resolveConnection(null, { serverUrl: "https://corp.example" }).connection.serverUrl).toBe("https://corp.example");
  });
});

describe("normalizeVerdict", () => {
  it("wraps the cloud API shape and passes the local runner shape through", () => {
    const api = { score: 70, verdict: "phishing", flags: [], aiUsed: false, settingsVersion: 1, action: "move_to_phishing", cached: false };
    expect(normalizeVerdict(api)).toMatchObject({ verdict: { score: 70, verdict: "phishing" }, action: "move_to_phishing", shadow: false });
    const local = { verdict: { score: 30, verdict: "suspicious", flags: [] }, action: "none", shadow: true };
    expect(normalizeVerdict(local)).toEqual(local);
    expect(normalizeVerdict(null)).toBeNull();
    expect(normalizeVerdict({ nonsense: true })).toBeNull();
  });
});

describe("applyConnection as the options page uses it (token field is pre-filled with the old token)", () => {
  const cur: Connection = { serverUrl: "https://a.com", serverId: "A", token: "OLD" };
  it("never carries the old token to a different server, even when the form still holds it", () => {
    const r = applyConnection(cur, { serverUrl: "https://evil.example", serverId: "B", token: "OLD" });
    expect(r.connection.token).toBe("");
    expect(r.cleared).toBe(true);
  });
  it("still accepts a genuinely new token for the new server", () => {
    expect(applyConnection(cur, { serverUrl: "https://b.com", serverId: "B", token: "NEW" }).connection.token).toBe("NEW");
  });
  it("keeps the token when the server is unchanged", () => {
    expect(applyConnection(cur, { serverUrl: "https://a.com", serverId: "A", token: "OLD" }).connection.token).toBe("OLD");
  });
});

describe("resolveConnection with an invalid managed lock", () => {
  it("stays locked and unusable with an error, instead of silently unlocking", () => {
    const r = resolveConnection({ serverUrl: "https://mine.example", serverId: "M", token: "t" }, { serverUrl: "http://evil.example", lockServerUrl: true });
    expect(r.locked).toBe(true);
    expect(r.connection.serverUrl).toBe("");
    expect(r.connection.token).toBe("");
    expect(r.error).toMatch(/managed/i);
  });
});

import { setupProblem } from "../src/connection.ts";
describe("setupProblem", () => {
  const ok = { connection: { serverUrl: "https://x.com", serverId: "X", token: "t" } };
  it("reports a missing permission, an invalid managed URL, or nothing", () => {
    expect(setupProblem(ok, true)).toBeNull();
    expect(setupProblem(ok, false)).toMatch(/allow access/i);
    expect(setupProblem({ connection: { serverUrl: "", serverId: null, token: "" }, error: "The managed server URL is invalid: x" }, false)).toMatch(/managed/i);
    expect(setupProblem({ connection: { serverUrl: "", serverId: null, token: "" } }, true)).toMatch(/no server/i);
  });
});
