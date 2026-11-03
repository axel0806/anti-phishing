import { simpleParser } from "mailparser";
import { parse } from "parse5";
import { createHash } from "node:crypto";
import { getDomain, getHostname } from "tldts";
import type { AuthResult, ParsedEmail } from "@ap/shared";

const AUTH_VALUES = new Set(["pass", "fail", "softfail", "none"]);

const TRUSTED_AUTHSERV_IDS = ["mx.google.com"];
const rank = (v: AuthResult): number => (v === "pass" ? 3 : v === "fail" || v === "softfail" ? 2 : v === "none" ? 1 : 0);

/** Reads spf/dkim/dmarc from one Authentication-Results value. With several results for a method (e.g. multiple DKIM signatures) any pass wins. */
export function parseAuthResults(header: string | undefined): ParsedEmail["auth"] {
  const out: ParsedEmail["auth"] = { spf: "missing", dkim: "missing", dmarc: "missing" };
  if (!header) return out;
  const parts = header.split(";").map((p) => p.trim().toLowerCase());
  for (const k of ["spf", "dkim", "dmarc"] as const) {
    for (const part of parts) {
      if (!part.startsWith(k + "=")) continue;
      const m = /^[a-z]+=([a-z]+)/.exec(part);
      if (!m) continue;
      const v = (AUTH_VALUES.has(m[1]!) ? m[1] : "none") as AuthResult;
      if (rank(v) > rank(out[k])) out[k] = v;
    }
  }
  return out;
}

/** Only trusts an Authentication-Results header written by our own receiving server (authserv-id); anything else could be forged by the sender. */
export function pickAuthResults(values: string[], trusted: string[] = TRUSTED_AUTHSERV_IDS): ParsedEmail["auth"] {
  const own = values.find((v) => trusted.includes((v.split(";")[0] ?? "").trim().toLowerCase().split(" ")[0] ?? ""));
  return parseAuthResults(own);
}

type Node5 = { nodeName: string; attrs?: { name: string; value: string }[]; childNodes?: Node5[]; value?: string };

export function extractLinks(html: string): ParsedEmail["links"] {
  const links: ParsedEmail["links"] = [];
  const textOf = (n: Node5): string => (n.nodeName === "#text" ? n.value ?? "" : (n.childNodes ?? []).map(textOf).join(""));
  const walk = (n: Node5) => {
    if (n.nodeName === "a") {
      const href = n.attrs?.find((a) => a.name === "href")?.value?.trim();
      if (href && /^https?:/i.test(href)) {
        links.push({ text: textOf(n).replace(/\s+/g, " ").trim(), href, domain: getHostname(href) ?? "" });
      }
    }
    n.childNodes?.forEach(walk);
  };
  walk(parse(html) as unknown as Node5);
  return links;
}

const URL_RE = /https?:\/\/[^\s<>"')\]]+/gi;

/** URLs in plain-text bodies; text and href are the same string. */
export function extractTextLinks(text: string): ParsedEmail["links"] {
  return (text.match(URL_RE) ?? []).map((u) => ({ text: u, href: u, domain: getHostname(u) ?? "" }));
}

const ENCRYPTED_ZIP_FLAG = 0x0001;
/** Detects ZIP entries with the encryption bit set in any local file header. */
export function zipIsEncrypted(buf: Buffer): boolean {
  let i = 0;
  while ((i = buf.indexOf(Buffer.from([0x50, 0x4b, 0x03, 0x04]), i)) !== -1) {
    if (i + 8 <= buf.length && (buf.readUInt16LE(i + 6) & ENCRYPTED_ZIP_FLAG)) return true;
    i += 4;
  }
  return false;
}

const MAX_ZIP_ENTRIES = 4000; // padding an archive with thousands of harmless entries before an .exe must not hide it
/** File names stored in a ZIP's local headers (names only; nothing is decompressed). Capped, and empty for anything that is not a ZIP. */
export function zipEntryNames(buf: Buffer): string[] {
  const names: string[] = [];
  let i = 0;
  while (names.length < MAX_ZIP_ENTRIES && (i = buf.indexOf(Buffer.from([0x50, 0x4b, 0x03, 0x04]), i)) !== -1) {
    if (i + 30 <= buf.length) {
      const len = buf.readUInt16LE(i + 26);
      if (len > 0 && len < 1024 && i + 30 + len <= buf.length) names.push(buf.subarray(i + 30, i + 30 + len).toString("utf8"));
    }
    i += 4;
  }
  return names;
}

const RISKY_ARCHIVE_ENTRY = /\.(exe|scr|js|jse|vbs|vbe|bat|cmd|com|msi|jar|iso|img|lnk|ps1|hta|docm|xlsm|pptm|html?)$/i;
const OFFICE_EXT = /\.(docx?|xlsx?|pptx?|docm|xlsm|pptm|dotx?|xltx?|potx?)$/i;
const MAX_INSPECT_BYTES = 128 * 1024; // credential forms and redirects sit near the top; a smaller window also bounds the work on hostile files

/**
 * Looks inside an attachment for what makes it dangerous, and returns a short reason or undefined.
 * HTML and SVG: password fields, forms posting to another site, obfuscated script, scripted redirects.
 * Office files: macros (a vbaProject.bin part), even when the name does not say "macro-enabled".
 * ZIP archives: an executable or script among the entries.
 * Never throws and never executes anything: this is pattern matching on bytes.
 */
export function attachmentRisk(name: string, mime: string, content: Buffer): string | undefined {
  try {
    const lower = name.toLowerCase();
    if (/\.(html?|xhtml|svg)$/.test(lower) || /html|svg/.test(mime)) {
      const t = content.subarray(0, MAX_INSPECT_BYTES).toString("latin1").toLowerCase();
      // Every repetition below is bounded ({0,N}), never * or +: the input is attacker-controlled, and an open-ended run such as [^>]* or \s*
      // goes quadratic on a file that repeats the opening token and never closes it (tens of seconds of a frozen server per attachment).
      if (/<input\b[^>]{0,300}type\s{0,10}=\s{0,10}["']?password/.test(t)) return "contains a password field";
      if (/<form\b[^>]{0,300}action\s{0,10}=\s{0,10}["']?https?:\/\//.test(t)) return "contains a form that posts to an outside site";
      if (/(eval|document\.write|function)\s{0,10}\(\s{0,10}(atob|unescape|string\.fromcharcode)|atob\s{0,10}\([^)]{0,200}\)[^;]{0,200}eval|eval\s{0,10}\(\s{0,10}atob/.test(t) || /document\.write\s{0,10}\(\s{0,10}unescape/.test(t)) return "contains obfuscated script";
      if (/http-equiv\s{0,10}=\s{0,10}["']?refresh[^>]{0,200}url\s{0,10}=/.test(t) || /(window\.|document\.|top\.|self\.)?location(\.href|\.replace\([^)]{0,200}\)|\.assign\([^)]{0,200}\))?\s{0,20}=?\s{0,20}[(']?\s{0,20}["']https?:\/\//.test(t)) return "redirects the browser to another site";
      return undefined;
    }
    const isZip = content.length > 4 && content.readUInt32LE(0) === 0x04034b50;
    if (!isZip) return undefined;
    const entries = zipEntryNames(content);
    if (OFFICE_EXT.test(lower)) return entries.some((e) => /vbaproject\.bin$/i.test(e)) ? "contains macros" : undefined;
    if (/zip/.test(mime) || lower.endsWith(".zip")) {
      const bad = entries.find((e) => RISKY_ARCHIVE_ENTRY.test(e));
      return bad ? `contains ${bad}` : undefined;
    }
  } catch { /* an unreadable attachment is simply not judged */ }
  return undefined;
}

export async function parseEmail(rawMime: Buffer, providerMessageId: string): Promise<ParsedEmail> {
  const m = await simpleParser(rawMime);
  const headers: Record<string, string[]> = {};
  for (const [k, v] of m.headerLines.map((h) => [h.key, h.line.slice(h.key.length + 1).trim()] as const)) {
    (headers[k] ??= []).push(v);
  }
  const auth = pickAuthResults(headers["authentication-results"] ?? []);

  const from = m.from?.value[0];
  const replyTo = m.replyTo?.value[0]?.address;
  const html = typeof m.html === "string" ? m.html : undefined;
  return {
    providerMessageId, receivedAt: m.date ?? new Date(),
    from: { name: from?.name ?? "", address: (from?.address ?? "").toLowerCase() },
    replyTo: replyTo?.toLowerCase(),
    returnPath: headers["return-path"]?.[0]?.replace(/[<>]/g, ""),
    subject: m.subject ?? "", text: m.text ?? "", html, headers, auth,
    links: html ? extractLinks(html) : extractTextLinks(m.text ?? ""),
    attachments: m.attachments.map((a) => ({
      name: a.filename ?? "", mime: a.contentType, size: a.size,
      sha256: createHash("sha256").update(a.content).digest("hex"),
      encrypted: /zip/.test(a.contentType) ? zipIsEncrypted(a.content) : false,
      risk: attachmentRisk(a.filename ?? "", a.contentType, a.content),
    })),
  };
}

export const registrableDomain = (hostOrAddress: string): string =>
  getDomain(hostOrAddress.includes("@") ? hostOrAddress.split("@").pop()! : hostOrAddress) ?? hostOrAddress.toLowerCase();
