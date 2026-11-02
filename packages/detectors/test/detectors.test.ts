import { describe, it, expect } from "vitest";
import { DEFAULT_SETTINGS, type ParsedEmail } from "@ap/shared";
import { runDetectors, checkLists, type DetectorContext } from "../src/index.ts";

const base = (o: Partial<ParsedEmail> = {}): ParsedEmail => ({
  providerMessageId: "m", receivedAt: new Date(), from: { name: "Bob", address: "bob@example.com" },
  subject: "Hello", text: "Hi Bob, lunch tomorrow?", headers: {},
  auth: { spf: "pass", dkim: "pass", dmarc: "pass" }, links: [], attachments: [], ...o,
});
const ctx: DetectorContext = { settings: DEFAULT_SETTINGS, lookups: { domainAgeDays: async () => null, threatIntel: async () => false } };
const ids = async (e: ParsedEmail, c = ctx) => (await runDetectors(e, c)).map((f) => f.id).sort();

describe("detectors", () => {
  it("clean email fires nothing", async () => {
    expect(await ids(base())).toEqual([]);
  });
  it("authentication failures", async () => {
    expect(await ids(base({ auth: { spf: "fail", dkim: "missing", dmarc: "fail" } }))).toEqual(["dkim_fail", "dmarc_fail", "spf_fail"]);
    expect(await ids(base({ auth: { spf: "softfail", dkim: "pass", dmarc: "pass" } }))).toEqual(["spf_fail"]);
  });
  it("lookalike domain but not exact match or subdomain of the real one", async () => {
    expect(await ids(base({ from: { name: "x", address: "a@paypa1.com" } }))).toContain("lookalike_domain");
    expect(await ids(base({ from: { name: "x", address: "a@paypal.com" } }))).not.toContain("lookalike_domain");
    expect(await ids(base({ from: { name: "x", address: "a@mail.paypal.com" } }))).not.toContain("lookalike_domain");
    expect(await ids(base({ from: { name: "x", address: "a@paypal.com.evil.io" } }))).toContain("lookalike_domain");
  });
  it("display name impersonation", async () => {
    expect(await ids(base({ from: { name: "PayPal Support", address: "x@evil.net" } }))).toContain("display_name_impersonation");
    expect(await ids(base({ from: { name: "PayPal", address: "x@paypal.com" } }))).not.toContain("display_name_impersonation");
  });
  it("reply-to mismatch", async () => {
    expect(await ids(base({ replyTo: "a@other.org" }))).toContain("reply_to_mismatch");
    expect(await ids(base({ replyTo: "a@mail.example.com" }))).not.toContain("reply_to_mismatch");
  });
  it("link text mismatch, shortener/IP counted once, punycode", async () => {
    const l = (text: string, href: string, domain: string) => ({ text, href, domain });
    expect(await ids(base({ links: [l("https://paypal.com/signin", "http://evil.net/x", "evil.net")] }))).toContain("link_text_mismatch");
    expect(await ids(base({ links: [l("click here", "http://evil.net/x", "evil.net")] }))).not.toContain("link_text_mismatch");
    const many = [l("a", "http://bit.ly/1", "bit.ly"), l("b", "http://bit.ly/2", "bit.ly"), l("c", "http://1.2.3.4/x", "1.2.3.4")];
    expect((await runDetectors(base({ links: many }), ctx)).filter((f) => f.id === "shortener_or_ip")).toHaveLength(1);
    expect(await ids(base({ links: [l("x", "http://xn--pypal-4ve.com", "xn--pypal-4ve.com")] }))).toContain("punycode_domain");
  });
  it("threat intel via lookups", async () => {
    const c = { ...ctx, lookups: { ...ctx.lookups, threatIntel: async () => true } };
    expect(await ids(base({ links: [{ text: "t", href: "http://bad.io", domain: "bad.io" }] }), c)).toContain("url_threat_intel");
  });
  it("new domain from RDAP; unknown age does not fire", async () => {
    const c = { ...ctx, lookups: { ...ctx.lookups, domainAgeDays: async () => 3 } };
    expect(await ids(base(), c)).toContain("new_domain");
    expect(await ids(base())).not.toContain("new_domain");
  });
  it("attachments", async () => {
    const a = (name: string, mime = "application/octet-stream", encrypted = false) => ({ name, mime, size: 1, sha256: "0", encrypted });
    expect(await ids(base({ attachments: [a("setup.exe")] }))).toContain("risky_attachment");
    expect(await ids(base({ attachments: [a("report.pdf")] }))).toEqual([]);
    expect(await ids(base({ attachments: [a("invoice.pdf.exe")] }))).toContain("double_extension");
    expect(await ids(base({ attachments: [a("x.zip", "application/zip", true)] }))).toContain("encrypted_archive");
  });
  it("content flags only fire together with a sender-level signal for urgency", async () => {
    const urgent = base({ subject: "Account suspended", text: "Act within 24 hours or your account suspended." });
    expect(await ids(urgent)).not.toContain("urgency");
    expect(await ids({ ...urgent, replyTo: "x@other.org" })).toContain("urgency");
    expect(await ids({ ...urgent, replyTo: "x@other.org", text: "Please verify your password and send gift card" })).toContain("credential_request");
  });
  it("trusted contact subtracts; flag overrides disable and reweight", async () => {
    const h = { ...ctx, senderHistory: { messagesReceived: 5, userReplied: true } };
    expect(await ids(base(), h)).toEqual(["trusted_contact"]);
    const s = { ...DEFAULT_SETTINGS, flags: { spf_fail: { enabled: true, weight: 99 }, dkim_fail: { enabled: false, weight: 15 } } };
    const fl = await runDetectors(base({ auth: { spf: "fail", dkim: "fail", dmarc: "pass" } }), { ...ctx, settings: s });
    expect(fl.map((f) => [f.id, f.weight])).toEqual([["spf_fail", 99]]);
  });
});

describe("checkLists", () => {
  const s = { ...DEFAULT_SETTINGS, allowlist: [{ matchType: "domain" as const, value: "good.com" }], blocklist: [{ matchType: "address" as const, value: "evil@x.io" }] };
  it("allow, block, none", () => {
    expect(checkLists(base({ from: { name: "", address: "a@good.com" } }), s)).toBe("safe");
    expect(checkLists(base({ from: { name: "", address: "evil@x.io" } }), s)).toBe("phishing");
    expect(checkLists(base(), s)).toBeNull();
  });
});
