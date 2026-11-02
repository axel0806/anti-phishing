import { describe, expect, it } from "vitest";
import { fetchVerdict } from "../src/client.ts";
import type { Connection } from "../src/connection.ts";

const conn = (token = ""): Connection => ({ serverUrl: "https://phish.example", serverId: "S", token });
type Call = { url: string; method: string; auth?: string; body?: string };

function fakeFetch(routes: Record<string, { status: number; body?: unknown }>) {
  const calls: Call[] = [];
  const f = (async (url: string, init?: { method?: string; headers?: Record<string, string>; body?: string }) => {
    const method = init?.method ?? "GET";
    calls.push({ url, method, auth: init?.headers?.Authorization, body: init?.body });
    const r = routes[method + " " + url];
    if (!r) throw new Error("unexpected " + method + " " + url);
    return { ok: r.status < 300, status: r.status, json: async () => r.body };
  }) as unknown as typeof fetch;
  return { f, calls };
}
const cloud = { score: 70, verdict: "phishing", flags: [], aiUsed: false, settingsVersion: 1 };

describe("fetchVerdict", () => {
  it("sends the bearer token, encodes the id and normalizes the cloud shape", async () => {
    const { f, calls } = fakeFetch({ "GET https://phish.example/v1/messages/a%2Fb/verdict": { status: 200, body: cloud } });
    expect(await fetchVerdict("a/b", conn("tok"), f)).toMatchObject({ verdict: { verdict: "phishing" } });
    expect(calls[0]!.auth).toBe("Bearer tok");
  });
  it("sends no Authorization header without a token (local runner)", async () => {
    const { f, calls } = fakeFetch({ "GET https://phish.example/v1/messages/x/verdict": { status: 200, body: cloud } });
    await fetchVerdict("x", conn(), f);
    expect(calls[0]!.auth).toBeUndefined();
  });
  it("asks the server for a dry-run scan when the message is not scanned yet and we have a token", async () => {
    const { f, calls } = fakeFetch({
      "GET https://phish.example/v1/messages/x/verdict": { status: 404, body: { error: { code: "not_scanned" } } },
      "POST https://phish.example/v1/scan": { status: 200, body: cloud },
    });
    expect(await fetchVerdict("x", conn("tok"), f)).toMatchObject({ verdict: { score: 70 } });
    expect(JSON.parse(calls[1]!.body!)).toEqual({ providerMessageId: "x", mode: "dry_run" });
  });
  it("does not try to scan without a token, and returns null on errors or when the server is down", async () => {
    const a = fakeFetch({ "GET https://phish.example/v1/messages/x/verdict": { status: 404 } });
    expect(await fetchVerdict("x", conn(), a.f)).toBeNull();
    expect(a.calls).toHaveLength(1);
    const b = fakeFetch({ "GET https://phish.example/v1/messages/x/verdict": { status: 401 } });
    expect(await fetchVerdict("x", conn("bad"), b.f)).toBeNull();
    expect(b.calls).toHaveLength(1);
    expect(await fetchVerdict("x", conn("t"), (async () => { throw new Error("down"); }) as unknown as typeof fetch)).toBeNull();
  });
});
