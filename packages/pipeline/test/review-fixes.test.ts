import { describe, it, expect } from "vitest";
import { DEFAULT_SETTINGS, type ParsedEmail } from "@ap/shared";
import { runDetectors, type DetectorContext } from "@ap/detectors";
import { pickAuthResults } from "@ap/parser";
import { scanParsed } from "../src/index.ts";

const base = (o: Partial<ParsedEmail> = {}): ParsedEmail => ({
  providerMessageId: "m", receivedAt: new Date(), from: { name: "News", address: "news@example.com" },
  subject: "Hello", text: "Newsletter", headers: {},
  auth: { spf: "pass", dkim: "pass", dmarc: "pass" }, links: [], attachments: [], ...o,
});
const ctx: DetectorContext = { settings: DEFAULT_SETTINGS, lookups: { domainAgeDays: async () => null, threatIntel: async () => false } };
const ids = async (e: ParsedEmail) => (await runDetectors(e, ctx)).map((f) => f.id);
const link = (text: string, domain: string) => ({ text, href: "https://" + domain + "/x", domain });

describe("review #1 country-domain brand mail", () => {
  it("amazon.ca / google.ch senders are not lookalikes or impersonators and are not moved", async () => {
    for (const [name, addr] of [["Amazon", "ship@amazon.ca"], ["Google", "no-reply@google.ch"]] as const) {
      const e = base({ from: { name, address: addr } });
      const got = await ids(e);
      expect(got).not.toContain("lookalike_domain");
      expect(got).not.toContain("display_name_impersonation");
      expect((await scanParsed(e, DEFAULT_SETTINGS)).verdict).toBe("safe");
    }
  });
  it("an unowned country suffix still flags", async () => {
    expect(await ids(base({ from: { name: "x", address: "a@paypal.co" } }))).toContain("lookalike_domain");
  });
});

describe("review #2 substring host trick", () => {
  it("snapple.com.au is not a lookalike of apple.com, but paypal.com.evil.io still is", async () => {
    expect(await ids(base({ from: { name: "x", address: "n@snapple.com.au" } }))).not.toContain("lookalike_domain");
    expect(await ids(base({ from: { name: "x", address: "n@paypal.com.evil.io" } }))).toContain("lookalike_domain");
  });
});

describe("review #3/#4 tracking allowlist and halving", () => {
  it("hosting platforms are not exempt", async () => {
    const e = base({ links: [link("paypal.com/signin", "x.hs-sites.com")] });
    expect(await ids(e)).toContain("link_text_mismatch");
  });
  it("a tracking host is exempt only when the visible text is the sender's own domain", async () => {
    const own = base({ from: { name: "T", address: "a@twilio.com" }, links: [link("www.twilio.com", "track.pstmrk.it")] });
    expect(await ids(own)).not.toContain("link_text_mismatch");
    const other = base({ from: { name: "T", address: "a@twilio.com" }, links: [link("paypal.com", "track.pstmrk.it")] });
    expect(await ids(other)).toContain("link_text_mismatch");
  });
  it("no halving when the text names a protected brand, even if the attacker's domain is authenticated", async () => {
    const e = base({
      from: { name: "Alerts", address: "alerts@secure-account-center.net" },
      subject: "Urgent", text: "Your account suspended. Verify your password now.",
      links: [link("paypal.com", "evil.net")],
    });
    const v = await scanParsed(e, DEFAULT_SETTINGS);
    expect(v.flags.find((f) => f.id === "link_text_mismatch")!.weight).toBe(30);
    expect(v.verdict).toBe("phishing");
  });
});

describe("review #5 authserv-id", () => {
  it("ignores Authentication-Results from an untrusted authserv-id", () => {
    const forged = "evil.example; spf=pass; dkim=pass; dmarc=pass";
    expect(pickAuthResults([forged])).toEqual({ spf: "missing", dkim: "missing", dmarc: "missing" });
    expect(pickAuthResults([forged, "mx.google.com; spf=fail; dkim=none; dmarc=fail"])).toEqual({ spf: "fail", dkim: "none", dmarc: "fail" });
  });
  it("reports dkim pass if any signature passes", () => {
    expect(pickAuthResults(["mx.google.com; dkim=fail header.d=a.com; dkim=pass header.d=b.com; spf=pass; dmarc=pass"]).dkim).toBe("pass");
  });
});

describe("review #8 content gating and word boundaries", () => {
  it("DKIM missing alone does not unlock content flags", async () => {
    const e = base({ auth: { spf: "pass", dkim: "none", dmarc: "pass" }, text: "Your password expires. Change your password immediately." });
    const got = await ids(e);
    expect(got).toContain("dkim_fail");
    expect(got).not.toContain("urgency");
    expect(got).not.toContain("credential_request");
  });
  it("matches whole words only", async () => {
    const e = base({ auth: { spf: "fail", dkim: "pass", dmarc: "pass" }, text: "Insurgent forces and passwordless login" });
    const got = await ids(e);
    expect(got).not.toContain("urgency");
    expect(got).not.toContain("credential_request");
  });
});

describe("review #9 plain-text links", () => {
  it("analyses URLs in text-only emails", async () => {
    const { parseEmail } = await import("@ap/parser");
    const raw = Buffer.from("From: a@b.com\r\nSubject: hi\r\nContent-Type: text/plain\r\n\r\nClick http://bit.ly/abc123 now");
    const e = await parseEmail(raw, "t");
    expect(e.links.map((l) => l.domain)).toEqual(["bit.ly"]);
    expect(await ids(e)).toContain("shortener_or_ip");
  });
});

describe("tracking exemption for third-party (non-protected) link text", () => {
  it("a partner brand linked through click tracking is not flagged; a protected brand still is", async () => {
    const from = { name: "AceZone", address: "news@acezone.io" };
    expect(await ids(base({ from, links: [link("ProSettings.net", "ctrk.klclick1.com")] }))).not.toContain("link_text_mismatch");
    expect(await ids(base({ from, links: [link("paypal.com", "ctrk.klclick1.com")] }))).toContain("link_text_mismatch");
  });
});
