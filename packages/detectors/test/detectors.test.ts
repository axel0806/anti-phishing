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

describe("authentication when the provider gives no trusted results (Microsoft Graph)", () => {
  const allMissing = { spf: "missing", dkim: "missing", dmarc: "missing" } as const;
  it("raises no authentication flags when results are unavailable, not failed", async () => {
    expect(await ids(base({ auth: allMissing }), { ...ctx, authTrusted: false })).toEqual([]);
  });
  it("still flags a real failure and still flags missing results where they are trusted (Gmail)", async () => {
    expect(await ids(base({ auth: { spf: "fail", dkim: "fail", dmarc: "fail" } }), { ...ctx, authTrusted: false })).toEqual(["dkim_fail", "dmarc_fail", "spf_fail"]);
    expect(await ids(base({ auth: allMissing }))).toEqual(["dkim_fail"]);
  });
});

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

describe("first_time_sender", () => {
  it("fires only once the user has enough history to make 'new' meaningful", async () => {
    const withSize = (n: number | undefined, history?: { messagesReceived: number; userReplied: boolean }) =>
      ids(base(), { ...ctx, historySize: n, senderHistory: history });
    expect(await withSize(60)).toContain("first_time_sender");
    expect(await withSize(49)).not.toContain("first_time_sender");
    expect(await withSize(undefined)).not.toContain("first_time_sender");
    expect(await withSize(60, { messagesReceived: 3, userReplied: false })).not.toContain("first_time_sender");
  });
});

describe("attachment risk is judged by content, not just by extension", () => {
  const att = (o: object) => ({ name: "f", mime: "application/octet-stream", size: 1, sha256: "x", encrypted: false, ...o });
  it("a plain HTML attachment no longer flags; a risky one does and says why", async () => {
    expect(await ids(base({ attachments: [att({ name: "receipt.html", mime: "text/html" })] }))).toEqual([]);
    const flags = await runDetectors(base({ attachments: [att({ name: "login.html", mime: "text/html", risk: "contains a password field" })] }), ctx);
    expect(flags.map((f) => f.id)).toEqual(["risky_attachment"]);
    expect(flags[0]!.evidence).toContain("password field");
  });
  it("a macro hidden in an ordinary-looking Office file flags", async () => {
    expect(await ids(base({ attachments: [att({ name: "invoice.docx", risk: "contains macros" })] }))).toEqual(["risky_attachment"]);
  });
  it("executables and a disguised .html still flag", async () => {
    expect(await ids(base({ attachments: [att({ name: "setup.exe" })] }))).toEqual(["risky_attachment"]);
    expect((await ids(base({ attachments: [att({ name: "invoice.pdf.html" })] }))).sort()).toEqual(["double_extension"]);
  });
});

describe("content phrases in other languages", () => {
  // Content flags only fire together with a sender or link signal, so each case carries a Reply-To mismatch.
  const spoofed = { spf: "fail", dkim: "pass", dmarc: "pass" } as const;
  const withText = (text: string, subject = "Hi") => ids(base({ auth: spoofed, replyTo: "attacker@evil.example", subject, text }));
  it("German, French, Spanish, Italian, Dutch and Portuguese urgency and credential requests are recognised", async () => {
    expect(await withText("Ihr Konto wurde gesperrt. Bitte sofort handeln.")).toContain("urgency");
    expect(await withText("Bitte bestätigen Sie Ihr Passwort")).toContain("credential_request");
    expect(await withText("Votre compte a été suspendu, agissez immédiatement")).toContain("urgency");
    expect(await withText("Veuillez confirmer votre mot de passe")).toContain("credential_request");
    expect(await withText("Su cuenta ha sido suspendida, actúe de inmediato")).toContain("urgency");
    expect(await withText("Confirme su contraseña ahora")).toContain("credential_request");
    expect(await withText("Il tuo account è stato sospeso, agisci immediatamente")).toContain("urgency");
    expect(await withText("Uw account is geblokkeerd, handel onmiddellijk")).toContain("urgency");
    expect(await withText("Confirme a sua palavra-passe")).toContain("credential_request");
  });
  it("generic greetings in other languages are recognised", async () => {
    expect(await withText("Sehr geehrter Kunde, ")).toContain("generic_greeting");
    expect(await withText("Cher client, ")).toContain("generic_greeting");
    expect(await withText("Estimado cliente, ")).toContain("generic_greeting");
  });
  it("ordinary foreign-language mail does not fire, and words inside longer words do not match", async () => {
    expect(await ids(base({ text: "Hallo Anna, bis morgen zum Mittagessen! Viele Grüße", subject: "Mittagessen" }))).toEqual([]);
    expect(await withText("Wir sind dringendst beschäftigt gewesen")).not.toContain("urgency"); // part of a longer word
    expect(await withText("Unsere Rezeption ist sofortige Hilfe nicht")).not.toContain("urgency");
  });
});

describe("more protected brands, and a limit on link lookups", () => {
  it("impersonating a newly protected brand is caught, the real domain is not", async () => {
    expect(await ids(base({ from: { name: "Netflix", address: "billing@netfIix-support.com" } }))).toContain("display_name_impersonation");
    expect(await ids(base({ from: { name: "Netflix", address: "info@netflix.com" } }))).toEqual([]);
    expect(await ids(base({ from: { name: "Service", address: "x@c0inbase.com" } }))).toContain("lookalike_domain");
    expect(await ids(base({ from: { name: "Instagram", address: "security@mail.instagram.com" } }))).toEqual([]);
  });
  it("looks up at most 10 distinct link targets per email", async () => {
    const seen: string[] = [];
    const c = { ...ctx, lookups: { ...ctx.lookups, threatIntel: async (u: string) => { seen.push(u); return false; } } };
    const links = Array.from({ length: 40 }, (_, i) => ({ text: "t", href: `https://site${i % 25}.example/p`, domain: `site${i % 25}.example` }));
    await runDetectors(base({ links }), c);
    expect(seen.length).toBe(10);
    expect(new Set(seen).size).toBe(10);
  });
});

describe("display-name impersonation survives punctuation tricks", () => {
  const from = (name: string) => ({ name, address: "billing@random-shop.example" });
  it("catches the brand when joined to other words by punctuation", async () => {
    for (const name of ["PayPal-Support", "PayPal.Security", "Support | PayPal", "Amazon: Order Update", "[Apple] ID Team", "PayPal®"]) {
      expect(await ids(base({ from: from(name) })), name).toContain("display_name_impersonation");
    }
  });
  it("still ignores a brand that is merely part of a longer word", async () => {
    for (const name of ["Applebee's Rewards", "Googleplex Cafe", "Amazonia Travel"]) {
      expect(await ids(base({ from: from(name) })), name).not.toContain("display_name_impersonation");
    }
  });
});
