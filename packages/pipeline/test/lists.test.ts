import { describe, it, expect } from "vitest";
import { DEFAULT_SETTINGS, type ParsedEmail } from "@ap/shared";
import { scanParsed } from "../src/index.ts";

const base = (o: Partial<ParsedEmail> = {}): ParsedEmail => ({
  providerMessageId: "m", receivedAt: new Date(), from: { name: "Bob", address: "bob@good.com" },
  subject: "s", text: "t", headers: {}, auth: { spf: "pass", dkim: "pass", dmarc: "pass" }, links: [], attachments: [], ...o,
});
const allow = { ...DEFAULT_SETTINGS, allowlist: [{ matchType: "address" as const, value: "BOB@good.com" }] };

describe("list check minors", () => {
  it("matches addresses case-insensitively", async () => {
    expect((await scanParsed(base(), allow)).verdict).toBe("safe");
  });
  it("ignores the allowlist when DMARC fails, so a spoofed From cannot skip the rules", async () => {
    const spoof = base({ auth: { spf: "fail", dkim: "none", dmarc: "fail" }, replyTo: "x@evil.io", links: [{ text: "paypal.com", href: "http://evil.io", domain: "evil.io" }] });
    const v = await scanParsed(spoof, allow);
    expect(v.flags.length).toBeGreaterThan(0);
    expect(v.verdict).not.toBe("safe");
  });
  it("blocklist verdicts carry a human-readable reason", async () => {
    const s = { ...DEFAULT_SETTINGS, blocklist: [{ matchType: "domain" as const, value: "good.com" }] };
    const v = await scanParsed(base(), s);
    expect(v.verdict).toBe("phishing");
    expect(v.reason).toMatch(/blocklist/i);
  });
});
