import type { Flag, ParsedEmail } from "@ap/shared";

export const MAX_BODY_CHARS = 4000;

const EMAIL = /[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi;
// A run of digits possibly separated by spaces, dots, dashes or parentheses (phone numbers, card and account numbers).
const NUMBER_RUN = /[+(]?\d[\d\s().-]*\d/g;
const MIN_DIGITS = 7;

/** Removes email addresses, phone numbers and long digit strings before anything leaves the server. */
export function redact(text: string): string {
  return text
    .replace(EMAIL, "[email]")
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

/** Builds the minimal, redacted view of an email that the model may see: no raw MIME, no query strings, no hashes. */
export function buildAiInput(email: ParsedEmail, ruleFlags: Flag[]): AiInput {
  return {
    fromName: redact(email.from.name),
    fromAddress: email.from.address,
    replyTo: email.replyTo,
    subject: redact(email.subject),
    body: redact(email.text).slice(0, MAX_BODY_CHARS),
    links: email.links.map((l) => ({ text: redact(l.text).slice(0, 200), domain: l.domain })),
    attachments: email.attachments.map((a) => ({ name: redact(a.name), mime: a.mime })),
    ruleFlags: ruleFlags.map((f) => ({ id: f.id, evidence: redact(f.evidence) })),
  };
}
