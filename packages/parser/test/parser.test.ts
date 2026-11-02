import { describe, it, expect } from "vitest";
import { parseEmail, parseAuthResults } from "../src/index.ts";

const raw = [
  "Authentication-Results: mx.google.com; spf=fail smtp.mailfrom=evil.io; dkim=none; dmarc=fail header.from=paypal.com",
  "Authentication-Results: forged.example; spf=pass; dkim=pass; dmarc=pass",
  'From: "PayPal Support" <help@paypa1-secure.net>',
  "Reply-To: other@elsewhere.org",
  "To: me@example.com",
  "Subject: Urgent: verify",
  "MIME-Version: 1.0",
  'Content-Type: multipart/mixed; boundary="b"',
  "",
  "--b",
  "Content-Type: text/html; charset=utf-8",
  "",
  '<p>Hi <a href="http://paypa1-secure.net/login">https://paypal.com/signin</a></p>',
  "--b",
  'Content-Type: application/octet-stream; name="invoice.pdf.exe"',
  'Content-Disposition: attachment; filename="invoice.pdf.exe"',
  "Content-Transfer-Encoding: base64",
  "",
  "TVqQAAMAAAA=",
  "--b--",
  "",
].join("\r\n");

describe("parseAuthResults", () => {
  it("reads spf/dkim/dmarc", () => {
    expect(parseAuthResults("x; spf=softfail; dkim=pass; dmarc=none")).toEqual({ spf: "softfail", dkim: "pass", dmarc: "none" });
    expect(parseAuthResults(undefined)).toEqual({ spf: "missing", dkim: "missing", dmarc: "missing" });
  });
});

describe("parseEmail", () => {
  it("extracts headers, links, attachments and uses only the topmost Authentication-Results", async () => {
    const e = await parseEmail(Buffer.from(raw), "m1");
    expect(e.from).toEqual({ name: "PayPal Support", address: "help@paypa1-secure.net" });
    expect(e.replyTo).toBe("other@elsewhere.org");
    expect(e.auth).toEqual({ spf: "fail", dkim: "none", dmarc: "fail" });
    expect(e.links).toEqual([{ text: "https://paypal.com/signin", href: "http://paypa1-secure.net/login", domain: "paypa1-secure.net" }]);
    expect(e.attachments[0]).toMatchObject({ name: "invoice.pdf.exe", encrypted: false });
    expect(e.attachments[0]!.sha256).toHaveLength(64);
  });
});
