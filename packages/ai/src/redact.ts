import type { Flag, ParsedEmail } from "@ap/shared";

export const MAX_BODY_CHARS = 4000;
const MAX_LINKS = 20;
const MAX_ATTACHMENTS = 20;
const MAX_RULE_FLAGS = 30;

// A URL, with or without a scheme. Anything after the host (path, query, fragment) can carry a credential, so only the host survives.
const URL_WITH_SCHEME = /https?:\/\/[^\s<>"')\]]+/gi;
const URL_SCHEMELESS = /\b(?:[a-z0-9-]+\.)+[a-z]{2,}\/[^\s<>"')\]]*/gi;
const EMAIL = /[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi;
// IBAN: country code, check digits, then groups of four (the last may be shorter).
const IBAN = /\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,4})?\b/g;
// A run of digits possibly separated by spaces, dots, slashes, underscores, dashes or parentheses (phones, cards, accounts, codes).
const NUMBER_RUN = /[+(]?\d[\d\s().\/_-]*\d/g;
const MIN_DIGITS = 6;

const hostOf = (url: string): string => {
  try {
    return new URL(/^https?:/i.test(url) ? url : "http://" + url).hostname;
  } catch {
    return "";
  }
};
const linkToken = (url: string) => {
  const host = hostOf(url);
  return host ? `[link: ${host}]` : "[link]";
};

/** Removes URLs (keeping the host), email addresses, IBANs, phone numbers, card numbers and one-time codes before anything leaves the server. */
export function redact(text: string): string {
  return text
    .replace(/%40/gi, "@") // URL-encoded addresses
    .replace(URL_WITH_SCHEME, linkToken)
    .replace(URL_SCHEMELESS, linkToken)
    .replace(EMAIL, "[email]")
    .replace(IBAN, "[number]")
    .replace(NUMBER_RUN, (run) => (run.replace(/\D/g, "").length >= MIN_DIGITS ? "[number]" : run));
}

export interface AiInput {
  fromName: string;
  fromAddress: string;
  replyTo?: string;
  subject: string;
  body: string;
  links: { text: string; domain: string }[];
  attachments: { name: string; mime: string }[];
  ruleFlags: { id: string; evidence: string }[];
}

/** Builds the minimal, redacted, size-bounded view of an email that the model may see: no raw MIME, no URL paths or queries, no hashes. */
export function buildAiInput(email: ParsedEmail, ruleFlags: Flag[]): AiInput {
  return {
    fromName: redact(email.from.name).slice(0, 100),
    fromAddress: email.from.address,
    replyTo: email.replyTo,
    subject: redact(email.subject).slice(0, 300),
    body: redact(email.text).slice(0, MAX_BODY_CHARS),
    links: email.links.slice(0, MAX_LINKS).map((l) => ({ text: redact(l.text).slice(0, 200), domain: l.domain })),
    attachments: email.attachments.slice(0, MAX_ATTACHMENTS).map((a) => ({ name: redact(a.name).slice(0, 200), mime: a.mime })),
    ruleFlags: ruleFlags.slice(0, MAX_RULE_FLAGS).map((f) => ({ id: f.id, evidence: redact(f.evidence).slice(0, 300) })),
  };
}
