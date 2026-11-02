import { domainToUnicode } from "node:url";
import { registrableDomain } from "@ap/parser";
import {
  type Flag, type FlagId, type ListEntry, type ParsedEmail, type SenderHistory, type Settings, makeFlag,
} from "@ap/shared";

export interface DetectorContext {
  settings: Settings;
  senderHistory?: SenderHistory;
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

const lookalike: Detector = (e, ctx) => {
  const host = domainOf(e.from.address);
  const reg = registrableDomain(host);
  const out: (Flag | null)[] = [];
  for (const raw of ctx.settings.protectedDomains) {
    const p = raw.toLowerCase();
    if (reg === p) continue; // exact match (or a real subdomain of it)
    const label = p.split(".")[0]!;
    const max = label.length <= 4 ? 1 : 2;
    const segs = reg.split(".")[0]!.split("-");
    const close = damerau(reg, p) <= max || skeleton(reg) === skeleton(p) || (segs.length > 1 && segs.some((s) => skeleton(s) === skeleton(label)));
    const trick = (host === p + "." + reg || host.includes(p + ".")) && reg !== p; // paypal.com.evil.io
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
    if (words.includes(label) && reg !== p) {
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
  "inflection.io", "klclick1.com", "klclick.com", "pstmrk.it", "sendgrid.net", "mailchimp.com", "list-manage.com",
  "mandrillapp.com", "hubspotlinks.com", "hs-sites.com", "mkto-ab.com", "mktoweb.com", "sparkpostmail.com",
  "amazonses.com", "rs6.net", "constantcontact.com", "exct.net", "sailthru.com", "customeriomail.com", "mailgun.org",
  "braze.com", "iterable.com", "campaign-archive.com", "convertkit-mail.com", "ck.page",
]);
const IPV4 = /^\d{1,3}(\.\d{1,3}){3}$/;
const LOOKS_LIKE_DOMAIN = /^(?:https?:\/\/)?((?:[a-z0-9-]+\.)+[a-z]{2,})(?:[/:?#]|$)/i;

const links: Detector = async (e, ctx) => {
  const out: (Flag | null)[] = [];
  for (const l of e.links) {
    const m = LOOKS_LIKE_DOMAIN.exec(l.text.trim());
    if (m && registrableDomain(m[1]!) !== registrableDomain(l.domain) && !TRACKING_DOMAINS.has(registrableDomain(l.domain))) {
      const flag = fl(ctx, "link_text_mismatch", `Link says ${m[1]} but goes to ${l.domain}`);
      // Authenticated senders (DKIM + DMARC pass) get half weight, unless the user set an explicit weight.
      if (flag && !ctx.settings.flags.link_text_mismatch && e.auth.dkim === "pass" && e.auth.dmarc === "pass") flag.weight = Math.round(flag.weight / 2);
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
const hasPhrase = (text: string, list: string[]) => list.find((p) => text.includes(p));

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

const trust: Detector = (_e, ctx) => {
  const h = ctx.senderHistory;
  return h && h.userReplied && h.messagesReceived >= 2 ? compact([fl(ctx, "trusted_contact", "Prior two-way history")]) : [];
};

const CONTENT_IDS = new Set<FlagId>(["urgency", "credential_request", "generic_greeting"]);

/** Runs every enabled detector. Content flags fire only when another positive non-content flag also fired. */
export async function runDetectors(email: ParsedEmail, ctx: DetectorContext): Promise<Flag[]> {
  const results = await Promise.all(
    [authentication, lookalike, displayName, replyTo, links, newDomain, attachments, content, trust].map(async (d) => d(email, ctx)),
  );
  const all = results.flat();
  const otherSignal = all.some((f) => f.weight > 0 && !CONTENT_IDS.has(f.id));
  return all.filter((f) => !CONTENT_IDS.has(f.id) || otherSignal);
}

// ---------- list check ----------

const matches = (e: ParsedEmail, l: ListEntry) =>
  l.matchType === "address"
    ? e.from.address === l.value.toLowerCase()
    : registrableDomain(e.from.address) === registrableDomain(l.value);

/** Allowlist first (Safe), then blocklist (Phishing); null when the rule engine should run. */
export function checkLists(e: ParsedEmail, s: Settings): "safe" | "phishing" | null {
  if (s.allowlist.some((l) => matches(e, l))) return "safe";
  if (s.blocklist.some((l) => matches(e, l))) return "phishing";
  return null;
}
