import { describe, it, expect } from "vitest";
import { DEFAULT_SETTINGS, type ParsedEmail } from "@ap/shared";
import { scanParsed } from "@ap/pipeline";
import { runDetectors, type DetectorContext } from "../src/index.ts";

const base = (o: Partial<ParsedEmail> = {}): ParsedEmail => ({
  providerMessageId: "m", receivedAt: new Date(), from: { name: "News", address: "news@twilio.com" },
  subject: "Hello", text: "Newsletter", headers: {},
  auth: { spf: "pass", dkim: "pass", dmarc: "pass" }, links: [], attachments: [], ...o,
});
const ctx: DetectorContext = { settings: DEFAULT_SETTINGS, lookups: { domainAgeDays: async () => null, threatIntel: async () => false } };
const link = (text: string, domain: string) => ({ text, href: "https://" + domain + "/x", domain });

describe("false-positive controls", () => {
  it("known email-service tracking domains do not count as a link mismatch", async () => {
    for (const d of ["tracking.inflection.io", "ctrk.klclick1.com", "track.pstmrk.it", "u123.ct.sendgrid.net"]) {
      const fl = await runDetectors(base({ links: [link("www.twilio.com", d)] }), ctx);
      expect(fl.map((f) => f.id), d).not.toContain("link_text_mismatch");
    }
  });
  it("an unknown mismatching domain still fires, at full weight when the sender is unauthenticated", async () => {
    const fl = await runDetectors(base({ auth: { spf: "pass", dkim: "none", dmarc: "none" }, links: [link("www.twilio.com", "evil.example")] }), ctx);
    expect(fl.find((f) => f.id === "link_text_mismatch")!.weight).toBe(30);
  });
  it("halves a lone link mismatch when DKIM and DMARC pass, so it stays Safe", async () => {
    const e = base({ links: [link("www.strato.se", "news.strato.com")] });
    const fl = await runDetectors(e, ctx);
    expect(fl.find((f) => f.id === "link_text_mismatch")!.weight).toBe(15);
    expect((await scanParsed(e, DEFAULT_SETTINGS)).verdict).toBe("safe");
  });
  it("an explicit user weight override is not halved", async () => {
    const s = { ...DEFAULT_SETTINGS, flags: { link_text_mismatch: { enabled: true, weight: 30 } } };
    const fl = await runDetectors(base({ links: [link("www.strato.se", "news.strato.com")] }), { ...ctx, settings: s });
    expect(fl.find((f) => f.id === "link_text_mismatch")!.weight).toBe(30);
  });
  it("a spoofed brand link in an authenticated email plus a lookalike sender still reaches Phishing", async () => {
    const e = base({ from: { name: "PayPal", address: "a@paypa1-secure.net" }, links: [link("paypal.com", "evil.example")] });
    expect((await scanParsed(e, DEFAULT_SETTINGS)).verdict).toBe("phishing");
  });
});
