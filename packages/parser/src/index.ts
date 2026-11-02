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
    })),
  };
}

export const registrableDomain = (hostOrAddress: string): string =>
  getDomain(hostOrAddress.includes("@") ? hostOrAddress.split("@").pop()! : hostOrAddress) ?? hostOrAddress.toLowerCase();
