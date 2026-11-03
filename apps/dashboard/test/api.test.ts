import { describe, expect, it } from "vitest";
import { ApiError, checkServerUrl, chromeManagedPolicy, defaultRange, firefoxPolicy, makeApi, parseBulkImport, qs, takeToken, toggleLock, visibleTabs } from "../src/api.ts";

const mem = () => { const m = new Map<string, string>(); return { getItem: (k: string) => m.get(k) ?? null, setItem: (k: string, v: string) => void m.set(k, v), removeItem: (k: string) => void m.delete(k) }; };

describe("tabs by role", () => {
  it("shows only what the role may use", () => {
    expect(visibleTabs("viewer").map((t) => t.id)).toEqual(["overview", "account"]);
    expect(visibleTabs("analyst").map((t) => t.id)).toEqual(["overview", "log", "account"]);
    expect(visibleTabs("admin").map((t) => t.id)).toContain("people");
    expect(visibleTabs("analyst").map((t) => t.id)).not.toContain("people");
    expect(visibleTabs("admin").map((t) => t.id)).toContain("audit");
    expect(visibleTabs(undefined)).toEqual([]);
  });
});

describe("takeToken", () => {
  it("stores a fragment token and falls back to storage", () => {
    const s = mem();
    expect(takeToken("", s)).toBeNull();
    expect(takeToken("#token=abc.def_g-h", s)).toBe("abc.def_g-h");
    expect(takeToken("", s)).toBe("abc.def_g-h");
  });
  it("ignores a malformed fragment instead of storing it", () => {
    const s = mem();
    expect(takeToken("#token=<script>", s)).toBeNull();
    expect(s.getItem("ap_dashboard_token")).toBeNull();
  });
  it("survives unavailable storage", () => {
    const broken = { getItem: () => { throw new Error("x"); }, setItem: () => { throw new Error("x"); }, removeItem: () => { throw new Error("x"); } };
    expect(takeToken("#token=abc", broken)).toBe("abc");
    expect(takeToken("", broken)).toBeNull();
  });
});

describe("makeApi", () => {
  const reply = (status: number, body: unknown) => async () => new Response(JSON.stringify(body), { status });
  it("sends the bearer token and JSON body", async () => {
    let seen: { url: string; init?: RequestInit } | undefined;
    const api = makeApi("tok", async (url, init) => { seen = { url, init }; return new Response("{\"ok\":true}"); });
    await api.put("/v1/x", { a: 1 });
    expect(seen!.init!.method).toBe("PUT");
    expect((seen!.init!.headers as Record<string, string>).authorization).toBe("Bearer tok");
    expect(seen!.init!.body).toBe("{\"a\":1}");
  });
  it("turns an error envelope into ApiError", async () => {
    const api = makeApi("t", reply(403, { error: { code: "forbidden", message: "Nope" } }));
    await expect(api.get("/v1/me")).rejects.toMatchObject({ status: 403, code: "forbidden", message: "Nope" });
    await expect(api.get("/v1/me")).rejects.toBeInstanceOf(ApiError);
  });
  it("copes with a non-JSON error body", async () => {
    const api = makeApi("t", async () => new Response("<html>bad gateway</html>", { status: 502 }));
    await expect(api.get("/x")).rejects.toMatchObject({ status: 502, code: "error" });
  });
});

describe("qs and defaultRange", () => {
  it("drops empty values and encodes the rest", () => {
    expect(qs({ a: "x y", b: "", c: undefined, d: 0 })).toBe("?a=x+y&d=0");
    expect(qs({})).toBe("");
  });
  it("ends tomorrow so today is included", () => {
    expect(defaultRange(30, new Date("2026-03-10T12:00:00Z"))).toEqual({ from: "2026-02-09", to: "2026-03-11" });
  });
});

describe("parseBulkImport", () => {
  it("classifies, lowercases, dedupes and reports rejects", () => {
    const r = parseBulkImport("Boss@Corp.com\n corp.com, corp.com\n# comment\nnot valid\n-bad-.com;x@y");
    expect(r.entries).toEqual([{ matchType: "address", value: "boss@corp.com" }, { matchType: "domain", value: "corp.com" }]);
    expect(r.rejected).toEqual(["not valid", "-bad-.com", "x@y"]);
  });
});

describe("managed policy", () => {
  it("builds the Chrome document and the Firefox wrapper", () => {
    const o = { serverUrl: "https://p.example.com", lockServerUrl: true };
    expect(chromeManagedPolicy(o)).toEqual({ serverUrl: "https://p.example.com", lockServerUrl: true });
    expect(firefoxPolicy(o, "ap@example").policies["3rdparty"].Extensions["ap@example"]).toEqual(chromeManagedPolicy(o));
  });
  it("accepts https and loopback http only", () => {
    expect(checkServerUrl("https://a.example.com")).toBeNull();
    expect(checkServerUrl("http://localhost:8080")).toBeNull();
    expect(checkServerUrl("http://a.example.com")).not.toBeNull();
    expect(checkServerUrl("https://u:p@a.example.com")).not.toBeNull();
    expect(checkServerUrl("nonsense")).not.toBeNull();
  });
});

describe("toggleLock", () => {
  it("locking a whole setting removes its dotted locks", () => {
    expect(toggleLock(["ai.mode", "shadowMode"], "ai", true).sort()).toEqual(["ai", "shadowMode"]);
  });
  it("adds a dotted lock once and removes on off", () => {
    const a = toggleLock([], "ai.monthlyBudgetUsd", true);
    expect(toggleLock(a, "ai.monthlyBudgetUsd", true)).toEqual(["ai.monthlyBudgetUsd"]);
    expect(toggleLock(a, "ai.monthlyBudgetUsd", false)).toEqual([]);
  });
});
