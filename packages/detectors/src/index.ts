import { domainToUnicode } from "node:url";
import { registrableDomain } from "@ap/parser";
import {
  type Flag, type FlagId, type ListEntry, type ParsedEmail, type SenderHistory, type Settings, makeFlag,
} from "@ap/shared";

export interface DetectorContext {
  settings: Settings;
  senderHistory?: SenderHistory;
  /** How many distinct senders the user has history for. `first_time_sender` stays off until this reaches 50. */
  historySize?: number;
  lookups: { domainAgeDays(d: string): Promise<number | null>; threatIntel(url: string): Promise<boolean> };
}
export type Detector = (email: ParsedEmail, ctx: DetectorContext) => Flag[] | Promise<Flag[]>;

const compact = (xs: (Flag | null)[]): Flag[] => xs.filter((x): x is Flag => x !== null);
const fl = (ctx: DetectorContext, id: FlagId, evidence: string) => makeFlag(id, evidence, ctx.settings);

// ---------- string helpers ----------

/** Optimal-string-alignment (Damerau) distance. */
export function damerau(a: string, b: string): number {
  const d: number[][] = Array.from({ length: a.length + 1 }, (_, i) => [i, ...Array<number>(b.length).fill(0)]);
  for (let j = 0; j <= b.length; j++) d[0]![j] = j;
  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      let v = Math.min(d[i - 1]![j]! + 1, d[i]![j - 1]! + 1, d[i - 1]![j - 1]! + cost);
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) v = Math.min(v, d[i - 2]![j - 2]! + 1);
      d[i]![j] = v;
    }
  }
  return d[a.length]![b.length]!;
}

/** Collapse common look-alike characters so `paypa1` and `paypal` share a skeleton. */
export function skeleton(s: string): string {
  return s.normalize("NFKD").replace(/[̀-ͯ]/g, "").toLowerCase()
    .replace(/rn/g, "m").replace(/vv/g, "w").replace(/[01il|]/g, (c) => (c === "0" ? "o" : "l"));
}

const domainOf = (addr: string) => addr.split("@").pop()!.toLowerCase();

// ---------- detectors ----------

const authentication: Detector = (e, ctx) => {
  const bad = (r: string) => r === "fail" || r === "softfail";
  return compact([
    bad(e.auth.spf) ? fl(ctx, "spf_fail", `SPF ${e.auth.spf}`) : null,
    e.auth.dkim !== "pass" ? fl(ctx, "dkim_fail", `DKIM ${e.auth.dkim}`) : null,
    bad(e.auth.dmarc) ? fl(ctx, "dmarc_fail", `DMARC ${e.auth.dmarc}`) : null,
  ]);
};

/** Country suffixes under which big brands really own their name (amazon.ca, google.ch). Deliberately excludes e.g. `.co`. */
const COUNTRY_SUFFIXES = new Set([
  "ca", "de", "fr", "es", "it", "nl", "se", "no", "dk", "fi", "pl", "ie", "at", "be", "ch", "pt", "cz", "in", "jp", "co.jp",
  "co.uk", "uk", "com.au", "au", "nz", "co.nz", "com.br", "br", "mx", "com.mx", "sg", "com.sg", "kr", "co.kr", "cn", "com.tr",
]);
const labelOf = (reg: string) => reg.split(".")[0]!;
/** True for the same brand name under a known country suffix, e.g. amazon.ca vs amazon.com. */
export function isBrandCountryDomain(reg: string, protectedDomain: string): boolean {
  const label = labelOf(protectedDomain);
  return labelOf(reg) === label && reg !== protectedDomain && COUNTRY_SUFFIXES.has(reg.slice(label.length + 1));
}

const lookalike: Detector = (e, ctx) => {
  const host = domainOf(e.from.address);
  const reg = registrableDomain(host);
  const out: (Flag | null)[] = [];
  for (const raw of ctx.settings.protectedDomains) {
    const p = raw.toLowerCase();
    if (reg === p || isBrandCountryDomain(reg, p)) continue; // exact match, a real subdomain, or the brand's own country domain
    const label = p.split(".")[0]!;
    const max = label.length <= 4 ? 1 : 2;
    const segs = reg.split(".")[0]!.split("-");
    const close = damerau(reg, p) <= max || skeleton(reg) === skeleton(p) || (segs.length > 1 && segs.some((s) => skeleton(s) === skeleton(label)));
    const trick = ("." + host + ".").includes("." + p + ".") && reg !== p; // paypal.com.evil.io (whole labels only)
    if (close || trick) {
      out.push(fl(ctx, "lookalike_domain", `${host} resembles ${p}`));
      break;
    }
  }
  return compact(out);
};

const displayName: Detector = (e, ctx) => {
  const name = e.from.name.normalize("NFKC").toLowerCase();
  if (!name) return [];
  const reg = registrableDomain(e.from.address);
  for (const raw of ctx.settings.protectedDomains) {
    const p = raw.toLowerCase();
    const label = p.split(".")[0]!;
    const words = name.split(" ").map((w) => w.replace(/[^a-z0-9]/g, ""));
    if (words.includes(label) && reg !== p && !isBrandCountryDomain(reg, p)) {
      return compact([fl(ctx, "display_name_impersonation", `Name "${e.from.name}" claims ${label} but sent from ${reg}`)]);
    }
  }
  return [];
};

const replyTo: Detector = (e, ctx) => {
  if (!e.replyTo) return [];
  const a = registrableDomain(e.replyTo);
  const b = registrableDomain(e.from.address);
  return a !== b ? compact([fl(ctx, "reply_to_mismatch", `Reply-To ${a} differs from From ${b}`)]) : [];
};

const SHORTENERS = new Set(["bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at"]);
/** Email-service providers whose click-tracking redirects legitimately differ from the visible link text. */
export const TRACKING_DOMAINS = new Set([
  "inflection.io", "klclick1.com", "klclick.com", "pstmrk.it", "sendgrid.net", "list-manage.com",
  "mandrillapp.com", "hubspotlinks.com", "mkto-ab.com", "sparkpostmail.com",
  "amazonses.com", "rs6.net", "exct.net", "sailthru.com", "customeriomail.com", "mailgun.org", "convertkit-mail.com",
]); // pure click-tracking redirect hosts only; page-hosting platforms (hs-sites.com, ck.page, ...) are deliberately absent
const IPV4 = /^\d{1,3}(\.\d{1,3}){3}$/;
const LOOKS_LIKE_DOMAIN = /^(?:https?:\/\/)?((?:[a-z0-9-]+\.)+[a-z]{2,})(?:[/:?#]|$)/i;

const links: Detector = async (e, ctx) => {
  const out: (Flag | null)[] = [];
  for (const l of e.links) {
    const m = LOOKS_LIKE_DOMAIN.exec(l.text.trim());
    const textReg = m ? registrableDomain(m[1]!) : "";
    const hrefReg = registrableDomain(l.domain);
    const senderReg = registrableDomain(e.from.address);
    // A click-tracking redirect is trusted unless the visible text names a protected brand the sender is not.
    const protectedText = ctx.settings.protectedDomains.some((p) => p.toLowerCase() === textReg);
    const ownTracking = TRACKING_DOMAINS.has(hrefReg) && (textReg === senderReg || !protectedText);
    if (m && textReg !== hrefReg && !ownTracking) {
      const flag = fl(ctx, "link_text_mismatch", `Link says ${m[1]} but goes to ${l.domain}`);
      // Halve for an authenticated sender linking to its own site or its own brand (strato.se -> strato.com).
      // Never when the text names a protected brand: attackers pass DKIM/DMARC on their own domains.
      const authed = e.auth.dkim === "pass" && e.auth.dmarc === "pass";
      const ownBrand = textReg === senderReg || labelOf(textReg) === labelOf(hrefReg);
      if (flag && !ctx.settings.flags.link_text_mismatch && authed && ownBrand && !protectedText) flag.weight = Math.round(flag.weight / 2);
      out.push(flag);
      break;
    }
  }
  const short = e.links.find((l) => SHORTENERS.has(registrableDomain(l.domain)) || IPV4.test(l.domain));
  if (short) out.push(fl(ctx, "shortener_or_ip", `Shortener or IP link: ${short.domain}`));

  const domains = [...e.links.map((l) => l.domain), domainOf(e.from.address)];
  for (const d of domains) {
    if (!d.split(".").some((x) => x.startsWith("xn--"))) continue;
    const uni = domainToUnicode(d);
    const label = uni.split(".")[0]!;
    const scripts = new Set([...label].filter((c) => /\p{L}/u.test(c)).map((c) => (/\p{Script=Latin}/u.test(c) ? "latin" : "other")));
    const lookalikeP = ctx.settings.protectedDomains.some((p) => skeleton(uni) === skeleton(p));
    if (scripts.size > 1 || lookalikeP || (scripts.has("other") && /\p{Script=Cyrillic}|\p{Script=Greek}/u.test(label))) {
      out.push(fl(ctx, "punycode_domain", `Suspicious IDN domain ${d} (${uni})`));
      break;
    }
  }
  if (e.links.length) {
    const hits = await Promise.all(e.links.map(async (l) => ((await ctx.lookups.threatIntel(l.href)) ? l : null)));
    const hit = hits.find((h) => h);
    if (hit) out.push(fl(ctx, "url_threat_intel", `Known malicious URL: ${hit.domain}`));
  }
  return compact(out);
};

const newDomain: Detector = async (e, ctx) => {
  const age = await ctx.lookups.domainAgeDays(registrableDomain(e.from.address));
  return age !== null && age < 30 ? compact([fl(ctx, "new_domain", `Sender domain registered ${age} days ago`)]) : [];
};

const RISKY_EXT = new Set(["exe", "scr", "js", "jse", "vbs", "vbe", "bat", "cmd", "com", "msi", "jar", "iso", "img", "lnk", "ps1", "docm", "xlsm", "pptm", "html", "htm", "hta"]);
const DOC_EXT = new Set(["pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "jpg", "jpeg", "png", "zip"]);
const extOf = (n: string) => (n.includes(".") ? n.split(".").pop()!.toLowerCase() : "");

const attachments: Detector = (e, ctx) => {
  const out: (Flag | null)[] = [];
  const risky = e.attachments.find((a) => RISKY_EXT.has(extOf(a.name)));
  if (risky) out.push(fl(ctx, "risky_attachment", `Risky attachment: ${risky.name}`));
  const dbl = e.attachments.find((a) => {
    const parts = a.name.toLowerCase().split(".");
    const rtl = a.name.includes("‮");
    return rtl || (parts.length >= 3 && DOC_EXT.has(parts[parts.length - 2]!) && RISKY_EXT.has(parts[parts.length - 1]!));
  });
  if (dbl) out.push(fl(ctx, "double_extension", `Disguised file name: ${dbl.name}`));
  const enc = e.attachments.find((a) => a.encrypted);
  if (enc) out.push(fl(ctx, "encrypted_archive", `Password-protected archive: ${enc.name}`));
  return compact(out);
};

const URGENCY = ["account suspended", "suspended", "within 24 hours", "immediately", "urgent", "final notice", "verify your account", "will be closed"];
const CREDENTIALS = ["password", "verify your identity", "gift card", "wire transfer", "bank details", "bank account", "credit card", "social security", "login credentials", "update your payment"];
const GREETINGS = ["dear customer", "dear user", "dear sir", "dear valued", "dear account holder", "dear client"];
/** Whole-word phrase match: "urgent" must not match "insurgent". */
const hasPhrase = (text: string, list: string[]) =>
  list.find((p) => {
    for (let i = text.indexOf(p); i !== -1; i = text.indexOf(p, i + 1)) {
      const before = text[i - 1];
      const after = text[i + p.length];
      if (!(before && /[a-z0-9]/.test(before)) && !(after && /[a-z0-9]/.test(after))) return true;
    }
    return false;
  });

const content: Detector = (e, ctx) => {
  const t = (e.subject + " " + e.text).toLowerCase();
  const out: (Flag | null)[] = [];
  const u = hasPhrase(t, URGENCY);
  if (u) out.push(fl(ctx, "urgency", `Urgency language: "${u}"`));
  const c = hasPhrase(t, CREDENTIALS);
  if (c) out.push(fl(ctx, "credential_request", `Asks for sensitive info: "${c}"`));
  const g = hasPhrase(t, GREETINGS);
  if (g) out.push(fl(ctx, "generic_greeting", `Generic greeting: "${g}"`));
  return compact(out);
};

const MIN_HISTORY_FOR_FIRST_TIME = 50;
const firstTime: Detector = (_e, ctx) =>
  !ctx.senderHistory && (ctx.historySize ?? 0) >= MIN_HISTORY_FOR_FIRST_TIME ? compact([fl(ctx, "first_time_sender", "First email ever from this sender")]) : [];

const trust: Detector = (_e, ctx) => {
  const h = ctx.senderHistory;
  return h && h.userReplied && h.messagesReceived >= 2 ? compact([fl(ctx, "trusted_contact", "Prior two-way history")]) : [];
};

const CONTENT_IDS = new Set<FlagId>(["urgency", "credential_request", "generic_greeting"]);

/** Runs every enabled detector. Content flags fire only when another positive non-content flag also fired. */
export async function runDetectors(email: ParsedEmail, ctx: DetectorContext): Promise<Flag[]> {
  const results = await Promise.all(
    [authentication, lookalike, displayName, replyTo, links, newDomain, attachments, content, trust, firstTime].map(async (d) => d(email, ctx)),
  );
  const all = results.flat();
  // Per the plan, content flags need a sender or link signal; missing DKIM etc. alone is too common to unlock them.
  const otherSignal = all.some((f) => f.weight > 0 && (f.category === "sender" || f.category === "links"));
  return all.filter((f) => !CONTENT_IDS.has(f.id) || otherSignal);
}

// ---------- list check ----------

const matches = (e: ParsedEmail, l: ListEntry) =>
  l.matchType === "address"
    ? e.from.address.toLowerCase() === l.value.toLowerCase()
    : registrableDomain(e.from.address) === registrableDomain(l.value);

/** Allowlist first (Safe), then blocklist (Phishing); null when the rule engine should run. */
export function checkLists(e: ParsedEmail, s: Settings): "safe" | "phishing" | null {
  if (s.allowlist.some((l) => matches(e, l))) return "safe";
  if (s.blocklist.some((l) => matches(e, l))) return "phishing";
  return null;
}
