import { describe, expect, it } from "vitest";
import { DEFAULT_SETTINGS, type ParsedEmail } from "@ap/shared";
import { aiFlagsFrom, analyze, buildAiInput, cacheKey, redact, type AiInput, type AiProvider } from "../src/index.ts";

const email = (o: Partial<ParsedEmail> = {}): ParsedEmail => ({
  providerMessageId: "m", receivedAt: new Date(), from: { name: "Sam", address: "sam@shop.example" }, subject: "Hi",
  text: "Hello", headers: {}, auth: { spf: "pass", dkim: "pass", dmarc: "pass" }, links: [], attachments: [], ...o,
});

describe("C1: URLs never reach the model with their paths, queries or tokens", () => {
  const secrets = /SECRETTOKEN|HTMLSECRET|ZZZTOKEN|SUBJTOKEN|EVTOKEN|FILETOKEN|bob%40|bob@corp/i;
  it("plain-text email where the link text is the whole URL", () => {
    const url = "https://acct.example/reset?token=SECRETTOKEN&email=bob%40corp.com";
    const i = buildAiInput(email({ text: `Reset your login: ${url}`, links: [{ text: url, href: url, domain: "acct.example" }] }), []);
    expect(JSON.stringify(i)).not.toMatch(secrets);
    expect(i.links[0]!.text).toBe("[link: acct.example]");
    expect(i.body).toContain("[link: acct.example]");
  });
  it("HTML-to-text bodies that append the href in brackets", () => {
    const i = buildAiInput(email({ text: "Click here [https://acct.example/magic?t=HTMLSECRET] to log in" }), []);
    expect(JSON.stringify(i)).not.toMatch(secrets);
    expect(i.body).toBe("Click here [[link: acct.example]] to log in");
  });
  it("scheme-less URLs with a path or query", () => {
    expect(redact("go to acct.example/reset?token=ZZZTOKEN now")).toBe("go to [link: acct.example] now");
  });
  it("subject, rule-flag evidence and attachment names too", () => {
    const i = buildAiInput(email({
      subject: "Open https://x.example/a?k=SUBJTOKEN",
      attachments: [{ name: "see https://f.example/get?k=FILETOKEN.pdf", mime: "application/pdf", size: 1, sha256: "x", encrypted: false }],
    }), [{ id: "link_text_mismatch", category: "links", weight: 30, evidence: "Link says paypal.com but goes to https://evil.example/p?k=EVTOKEN", source: "rule" }]);
    expect(JSON.stringify(i)).not.toMatch(secrets);
  });
  it("URL-encoded and bare email addresses are masked, but plain domains and prose survive", () => {
    expect(redact("write to bob%40corp.com or bob@corp.com")).toBe("write to [email] or [email]");
    expect(redact("Visit paypal.com for help.")).toBe("Visit paypal.com for help.");
  });
});

describe("M1: more identifiers are masked", () => {
  it("one-time codes, IBANs and groups separated by slashes", () => {
    expect(redact("Your OTP is 482913")).not.toContain("482913");
    expect(redact("IBAN GB29 NWBK 6016 1331 9268 19")).not.toMatch(/NWBK|6016/);
    expect(redact("call 0701/234567")).not.toContain("234567");
  });
  it("short numbers and times are kept", () => {
    expect(redact("order 4471 at 10:30 on floor 12")).toBe("order 4471 at 10:30 on floor 12");
  });
});

describe("M2: input size is bounded", () => {
  it("caps links, attachments, subject and rule flags", () => {
    const links = Array.from({ length: 500 }, (_, n) => ({ text: "x" + n, href: "http://a.com", domain: "a.com" }));
    const attachments = Array.from({ length: 200 }, (_, n) => ({ name: `f${n}.pdf`, mime: "application/pdf", size: 1, sha256: "x", encrypted: false }));
    const flags = Array.from({ length: 100 }, (_, n) => ({ id: "urgency" as const, category: "content" as const, weight: 1, evidence: "e" + n, source: "rule" as const }));
    const i = buildAiInput(email({ subject: "s".repeat(2000), links, attachments }), flags);
    expect(i.links.length).toBeLessThanOrEqual(20);
    expect(i.attachments.length).toBeLessThanOrEqual(20);
    expect(i.subject.length).toBeLessThanOrEqual(300);
    expect(i.ruleFlags.length).toBeLessThanOrEqual(30);
    expect(i.fromName.length).toBeLessThanOrEqual(100);
  });
});

describe("M4: the cache key includes a prompt version", () => {
  it("changes when the version changes", () => {
    const p: AiProvider = { name: "p", analyze: async () => { throw new Error("n/a"); } };
    const i = buildAiInput(email(), []);
    expect(cacheKey(p, i, "v1")).not.toBe(cacheKey(p, i, "v2"));
    expect(cacheKey(p, i)).toBe(cacheKey(p, i));
  });
});

describe("I2: calls that were sent still count against the budget", () => {
  const input: AiInput = buildAiInput(email({ text: "x".repeat(3000) }), []);
  const price = { inputPerMTokUsd: 10, outputPerMTokUsd: 50 };
  const recorder = () => { const spent: number[] = []; return { spent, budget: { allow: async () => true, record: async (c: number) => { spent.push(c); } } }; };

  it("a timeout records an estimated cost", async () => {
    const r = recorder();
    const hang: AiProvider = { name: "h", analyze: (_i, o) => new Promise((_res, rej) => o.signal.addEventListener("abort", () => rej(new Error("x")))) };
    expect(await analyze(hang, input, { timeoutMs: 20, budget: r.budget, price })).toMatchObject({ ok: false, reason: "timeout" });
    expect(r.spent).toHaveLength(1);
    expect(r.spent[0]).toBeGreaterThan(0);
  });
  it("invalid output records its real usage when reported, an estimate otherwise", async () => {
    const withUsage = recorder();
    const bad: AiProvider = { name: "b", analyze: async () => ({ verdict: { riskScore: 9 } as never, usage: { inputTokens: 1_000_000, outputTokens: 0 } }) };
    await analyze(bad, input, { timeoutMs: 100, budget: withUsage.budget, price });
    expect(withUsage.spent).toEqual([10]);
    const noUsage = recorder();
    const bad2: AiProvider = { name: "b2", analyze: async () => ({ verdict: { riskScore: 9 } as never }) };
    await analyze(bad2, input, { timeoutMs: 100, budget: noUsage.budget, price });
    expect(noUsage.spent[0]).toBeGreaterThan(0);
  });
  it("a valid answer with no usage field is charged the estimate rather than nothing", async () => {
    const r = recorder();
    const ok: AiProvider = { name: "o", analyze: async () => ({ verdict: { riskScore: 0.1, tactics: [], impersonatedEntity: null, explanation: "fine" } }) };
    await analyze(ok, input, { timeoutMs: 100, budget: r.budget, price });
    expect(r.spent[0]).toBeGreaterThan(0);
  });
  it("a provider error that never reached the model (thrown quickly) is not charged", async () => {
    const r = recorder();
    const down: AiProvider = { name: "d", analyze: async () => { throw new Error("ECONNREFUSED"); } };
    await analyze(down, input, { timeoutMs: 100, budget: r.budget, price });
    expect(r.spent).toEqual([]);
  });
});

describe("I5: AI flags respect the user's flag settings", () => {
  const v = { riskScore: 1, tactics: ["urgency", "credential_request"] as ("urgency" | "credential_request")[], impersonatedEntity: null, explanation: "x" };
  const s = (flags: typeof DEFAULT_SETTINGS.flags) => ({ ...DEFAULT_SETTINGS, flags });
  it("disabled flags are not raised by the model", () => {
    const f = aiFlagsFrom(v, s({ urgency: { enabled: false, weight: 10 }, ai_intent: { enabled: false, weight: 40 } }));
    expect(f.map((x) => x.id)).toEqual(["credential_request"]);
  });
  it("custom weights apply, and a custom ai_intent weight caps the model's contribution", () => {
    const f = aiFlagsFrom(v, s({ credential_request: { enabled: true, weight: 5 }, ai_intent: { enabled: true, weight: 15 } }));
    expect(f.find((x) => x.id === "credential_request")!.weight).toBe(5);
    expect(f.find((x) => x.id === "ai_intent")!.weight).toBe(15);
  });
  it("a low-risk explanation is not carried as the flag evidence", () => {
    const f = aiFlagsFrom({ riskScore: 0.3, tactics: [], impersonatedEntity: null, explanation: "This is a legitimate IT notice, safe to log in." }, DEFAULT_SETTINGS);
    expect(f[0]!.evidence).not.toMatch(/safe|legitimate/i);
  });
});
