import { describe, expect, it } from "vitest";
import { createLookups } from "../src/lookups.ts";

type Call = { url: string; body?: string };
const mk = (handler: (url: string, init?: { method?: string; body?: string }) => { status?: number; json?: unknown } | Error, calls: Call[] = []) =>
  (async (url: string, init?: { method?: string; body?: string }) => {
    calls.push({ url, body: init?.body });
    const r = handler(url, init);
    if (r instanceof Error) throw r;
    return { ok: (r.status ?? 200) < 300, status: r.status ?? 200, json: async () => r.json } as Response;
  }) as unknown as typeof fetch;
const daysAgo = (n: number) => new Date(Date.now() - n * 86_400_000).toISOString();

describe("domainAgeDays (RDAP)", () => {
  it("computes age from the registration event and caches the answer", async () => {
    const calls: Call[] = [];
    const l = createLookups({ rdap: true, fetch: mk(() => ({ json: { events: [{ eventAction: "last changed", eventDate: daysAgo(1) }, { eventAction: "registration", eventDate: daysAgo(10) }] } }), calls) });
    expect(await l.domainAgeDays("fresh.example")).toBe(10);
    expect(await l.domainAgeDays("fresh.example")).toBe(10);
    expect(calls).toHaveLength(1);
    expect(calls[0]!.url).toBe("https://rdap.org/domain/fresh.example");
  });
  it("returns null (unknown, never a flag) on timeout, errors, 404 and malformed data; and is off by default", async () => {
    for (const h of [() => new Error("timeout"), () => ({ status: 404 }), () => ({ json: { nope: 1 } }), () => ({ json: { events: [{ eventAction: "registration", eventDate: "garbage" }] } })]) {
      expect(await createLookups({ rdap: true, fetch: mk(h) }).domainAgeDays("x.example")).toBeNull();
    }
    const calls: Call[] = [];
    expect(await createLookups({ fetch: mk(() => ({ json: {} }), calls) }).domainAgeDays("x.example")).toBeNull();
    expect(calls).toHaveLength(0);
  });
  it("refuses to look up anything that is not a plain domain name", async () => {
    const calls: Call[] = [];
    const l = createLookups({ rdap: true, fetch: mk(() => ({ json: {} }), calls) });
    expect(await l.domainAgeDays("evil.example/../../admin")).toBeNull();
    expect(await l.domainAgeDays("")).toBeNull();
    expect(calls).toHaveLength(0);
  });
});

describe("threatIntel (Safe Browsing)", () => {
  it("is off without a key and sends no data", async () => {
    const calls: Call[] = [];
    expect(await createLookups({ fetch: mk(() => ({ json: {} }), calls) }).threatIntel("http://bad.example/x")).toBe(false);
    expect(calls).toHaveLength(0);
  });
  it("reports a match, strips query strings and fragments before sending, and caches", async () => {
    const calls: Call[] = [];
    const l = createLookups({ safeBrowsingKey: "KEY", fetch: mk(() => ({ json: { matches: [{ threatType: "SOCIAL_ENGINEERING" }] } }), calls) });
    expect(await l.threatIntel("http://bad.example/login?token=SECRET#frag")).toBe(true);
    expect(await l.threatIntel("http://bad.example/login?token=SECRET#frag")).toBe(true);
    expect(calls).toHaveLength(1);
    expect(calls[0]!.url).toContain("key=KEY");
    expect(calls[0]!.body).toContain("http://bad.example/login");
    expect(calls[0]!.body).not.toMatch(/SECRET|frag/);
  });
  it("answers false for a clean URL, and fails open on quota or network errors", async () => {
    expect(await createLookups({ safeBrowsingKey: "k", fetch: mk(() => ({ json: {} })) }).threatIntel("http://ok.example/")).toBe(false);
    expect(await createLookups({ safeBrowsingKey: "k", fetch: mk(() => ({ status: 429 })) }).threatIntel("http://q.example/")).toBe(false);
    expect(await createLookups({ safeBrowsingKey: "k", fetch: mk(() => new Error("down")) }).threatIntel("http://n.example/")).toBe(false);
  });
});
