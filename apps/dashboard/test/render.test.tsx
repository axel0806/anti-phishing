// @vitest-environment happy-dom
import { act } from "react";
import { createRoot } from "react-dom/client";
import { describe, expect, it } from "vitest";
import { makeApi, type Me } from "../src/api.ts";
import { AccountTab, AuditTab, DeployTab, EmailLog, ListsTab, Overview, PeopleTab, PolicyTab } from "../src/panels.tsx";

(globalThis as unknown as { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

const counts = { scanned: 10, safe: 7, suspicious: 2, phishing: 1, falsePositives: 0, aiCalls: 0, phishingRate: 0.1 };
const routes: Record<string, unknown> = {
  "/v1/admin/stats/overview": { current: counts, previous: { ...counts, scanned: 5 } },
  "/v1/admin/stats/trend": { rows: [{ date: "2026-01-01", suspicious: 2, phishing: 1 }] },
  "/v1/admin/stats/flags": { rows: [{ flagId: "dmarc_fail", fired: 3, inPhishing: 1, falsePositives: 0, falsePositiveRate: 0 }] },
  "/v1/admin/stats/targets": { impersonated: [{ evidence: "paypal", count: 2 }], senderDomains: [{ domain: "evil.test", count: 3 }] },
  "/v1/admin/stats/quality": { falsePositives: 1, missesReported: 0 },
  "/v1/admin/stats/ai": { calls: 0, costUsd: 0, escalated: 0, scanned: 10, escalatedShare: 0 },
  "/v1/admin/stats/health": { scans24h: 4, p50Ms: 12, p95Ms: 40, lastScanAt: null, linkedMailboxes: 2, worker: { mailboxes: 2, neverSynced: 0, erroring: 1, stale: 0, maxLagSeconds: 120 } },
  "/v1/admin/stats/users": { rows: [{ email: "a@corp.test", phishing: 1, suspicious: 0 }] },
  "/v1/admin/scans": { rows: [{ messageId: "m1", userId: "u1", userEmail: "a@corp.test", sender: "x@evil.test", score: 90, verdict: "phishing", pinned: false, createdAt: "2026-01-01T00:00:00Z", flags: ["dmarc_fail"] }], total: 1 },
  "/v1/lists": { allow: [], block: [{ matchType: "domain", value: "evil.test" }] },
  "/v1/admin/org-users": { users: [{ id: "u", email: "me@corp.test", role: "admin", provider: "gmail", linked: true }, { id: "w", email: "new@corp.test", role: "user", provider: "outlook", linked: false }] },
  "/v1/orgs/o/policy": { values: { shadowMode: true, sensitivity: "custom", thresholds: { suspicious: 35, phishing: 65 }, protectedDomains: ["acme.example"], ai: { monthlyBudgetUsd: 4 } }, locked: ["ai.mode"] },
  "/v1/admin/audit": { rows: [{ createdAt: "2026-01-01T00:00:00Z", actorEmail: null, action: "policy.update", target: null }] },
};
const seen: string[] = [];
const api = makeApi("t", async (url) => {
  seen.push(url);
  const body = routes[url.split("?")[0]!];
  return body === undefined ? new Response("{\"error\":{\"code\":\"not_found\",\"message\":\"x\"}}", { status: 404 }) : new Response(JSON.stringify(body));
});
const me = (role: Me["role"]): Me => ({ id: "u", email: "me@corp.test", role, orgId: "o", provider: "google" });

async function render(el: JSX.Element): Promise<HTMLElement> {
  const host = document.createElement("div");
  document.body.appendChild(host);
  await act(async () => { createRoot(host).render(el); });
  await act(async () => { await new Promise((r) => setTimeout(r, 20)); });
  return host;
}

describe("dashboard panels render from API data", () => {
  it("overview shows counts, the chart and brand names; per-user list only for admins", async () => {
    const admin = await render(<Overview api={api} me={me("admin")} />);
    expect(admin.textContent).toContain("Scanned");
    expect(admin.textContent).toContain("+100% vs previous period");
    expect(admin.textContent).toContain("paypal");
    expect(admin.textContent).toContain("1 erroring");
    expect(admin.querySelector("svg.chart rect")).not.toBeNull();
    expect(admin.textContent).toContain("Most targeted users");
    const viewer = await render(<Overview api={api} me={me("viewer")} />);
    expect(viewer.textContent).not.toContain("Most targeted users");
    expect(seen.filter((u) => u.startsWith("/v1/admin/stats/users")).length).toBe(1); // a viewer never even requests it
  });
  it("email log lists rows and offers actions only to admins", async () => {
    expect((await render(<EmailLog api={api} me={me("admin")} />)).textContent).toContain("Release");
    const analyst = await render(<EmailLog api={api} me={me("analyst")} />);
    expect(analyst.textContent).toContain("x@evil.test");
    expect(analyst.textContent).not.toContain("Release");
  });
  it("lists, audit and deploy tabs render", async () => {
    expect((await render(<ListsTab api={api} />)).textContent).toContain("evil.test");
    expect((await render(<AuditTab api={api} />)).textContent).toContain("policy.update");
    const d = await render(<DeployTab />);
    expect(d.textContent).toContain("lockServerUrl");
  });
  it("shows an API error instead of crashing", async () => {
    const broken = makeApi("t", async () => new Response("{\"error\":{\"code\":\"forbidden\",\"message\":\"Your role does not allow this\"}}", { status: 403 }));
    expect((await render(<AuditTab api={broken} />)).textContent).toContain("Your role does not allow this");
  });
});

describe("people and account tabs", () => {
  it("lists members with connection state, and cannot change or erase yourself", async () => {
    const host = await render(<PeopleTab api={api} me={me("admin")} />);
    expect(host.textContent).toContain("new@corp.test");
    expect(host.textContent).toContain("not connected");
    expect(host.textContent).toContain("gmail connected");
    expect(host.querySelectorAll("button.ghost").length).toBe(1); // Erase for the other person only
    expect(host.querySelector("select[aria-label=\"Role for me@corp.test\"]")).toBeNull();
    expect(host.querySelector("select[aria-label=\"Role for new@corp.test\"]")).not.toBeNull();
    expect(host.textContent).toContain("Create invite link");
  });
  it("account tab offers a token and erasure", async () => {
    const host = await render(<AccountTab api={api} me={me("viewer")} onErased={() => {}} />);
    expect(host.textContent).toContain("Create token");
    expect(host.textContent).toContain("Erase my account");
  });
});

describe("policy tab", () => {
  it("shows the current policy as a form and as JSON, with locks", async () => {
    const host = await render(<PolicyTab api={api} me={me("admin")} />);
    const selects = [...host.querySelectorAll("select")] as HTMLSelectElement[];
    expect(selects.some((s) => s.value === "true")).toBe(true); // shadow mode on
    expect((host.querySelector("textarea") as HTMLTextAreaElement).value).toBe("acme.example");
    expect([...host.querySelectorAll("input[type=number]")].map((i) => (i as HTMLInputElement).value)).toEqual(expect.arrayContaining(["35", "65", "4"]));
    expect(host.textContent).toContain("Advanced: settings as JSON");
    const locked = [...host.querySelectorAll("input[type=checkbox]")].filter((c) => (c as HTMLInputElement).checked);
    expect(locked.length).toBe(1);
  });
});
