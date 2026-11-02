import { simpleParser } from "mailparser";
import { parse } from "parse5";
import { createHash } from "node:crypto";
import { getDomain, getHostname } from "tldts";
import type { AuthResult, ParsedEmail } from "@ap/shared";

const AUTH_VALUES = new Set(["pass", "fail", "softfail", "none"]);

export function parseAuthResults(header: string | undefined): ParsedEmail["auth"] {
  const out: ParsedEmail["auth"] = { spf: "missing", dkim: "missing", dmarc: "missing" };
  if (!header) return out;
  for (const k of ["spf", "dkim", "dmarc"] as const) {
    const part = header.split(";").map((p) => p.trim().toLowerCase()).find((p) => p.startsWith(k + "="));
    const m = part ? /^[a-z]+=([a-z]+)/.exec(part) : null;
    if (m) {
      const v = m[1]!.toLowerCase();
      out[k] = (AUTH_VALUES.has(v) ? v : "none") as AuthResult;
    }
  }
  return out;
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
  // Topmost Authentication-Results is the one prepended by the receiving MTA; earlier hops can be forged.
  const auth = parseAuthResults(headers["authentication-results"]?.[0]);

  const from = m.from?.value[0];
  const replyTo = m.replyTo?.value[0]?.address;
  const html = typeof m.html === "string" ? m.html : undefined;
  return {
    providerMessageId, receivedAt: m.date ?? new Date(),
    from: { name: from?.name ?? "", address: (from?.address ?? "").toLowerCase() },
    replyTo: replyTo?.toLowerCase(),
    returnPath: headers["return-path"]?.[0]?.replace(/[<>]/g, ""),
    subject: m.subject ?? "", text: m.text ?? "", html, headers, auth,
    links: html ? extractLinks(html) : [],
    attachments: m.attachments.map((a) => ({
      name: a.filename ?? "", mime: a.contentType, size: a.size,
      sha256: createHash("sha256").update(a.content).digest("hex"),
      encrypted: /zip/.test(a.contentType) ? zipIsEncrypted(a.content) : false,
    })),
  };
}

export const registrableDomain = (hostOrAddress: string): string =>
  getDomain(hostOrAddress.includes("@") ? hostOrAddress.split("@").pop()! : hostOrAddress) ?? hostOrAddress.toLowerCase();
