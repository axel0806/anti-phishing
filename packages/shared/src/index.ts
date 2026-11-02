import { z } from "zod";

export type AuthResult = "pass" | "fail" | "softfail" | "none" | "missing";

export const FLAG_IDS = [
  "spf_fail", "dkim_fail", "dmarc_fail",
  "display_name_impersonation", "lookalike_domain", "reply_to_mismatch",
  "first_time_sender", "new_domain",
  "link_text_mismatch", "url_threat_intel", "shortener_or_ip", "punycode_domain",
  "risky_attachment", "encrypted_archive", "double_extension",
  "urgency", "credential_request", "generic_greeting",
  "ai_intent", "trusted_contact",
] as const;
export type FlagId = (typeof FLAG_IDS)[number];

export type FlagCategory = "authentication" | "sender" | "links" | "attachments" | "content" | "ai" | "trust";

export const FLAG_CATEGORY: Record<FlagId, FlagCategory> = {
  spf_fail: "authentication", dkim_fail: "authentication", dmarc_fail: "authentication",
  display_name_impersonation: "sender", lookalike_domain: "sender", reply_to_mismatch: "sender",
  first_time_sender: "sender", new_domain: "sender",
  link_text_mismatch: "links", url_threat_intel: "links", shortener_or_ip: "links", punycode_domain: "links",
  risky_attachment: "attachments", encrypted_archive: "attachments", double_extension: "attachments",
  urgency: "content", credential_request: "content", generic_greeting: "content",
  ai_intent: "ai", trusted_contact: "trust",
};

export const DEFAULT_WEIGHTS: Record<FlagId, number> = {
  spf_fail: 20, dkim_fail: 15, dmarc_fail: 25,
  display_name_impersonation: 30, lookalike_domain: 35, reply_to_mismatch: 15,
  first_time_sender: 10, new_domain: 20,
  link_text_mismatch: 30, url_threat_intel: 60, shortener_or_ip: 10, punycode_domain: 25,
  risky_attachment: 35, encrypted_archive: 25, double_extension: 40,
  urgency: 10, credential_request: 25, generic_greeting: 5,
  ai_intent: 40, trusted_contact: -20,
};

export interface Flag {
  id: FlagId; category: FlagCategory; weight: number; evidence: string; source: "rule" | "ai";
}

export interface ParsedEmail {
  providerMessageId: string; receivedAt: Date;
  from: { name: string; address: string }; replyTo?: string; returnPath?: string;
  subject: string; text: string; html?: string;
  headers: Record<string, string[]>;
  auth: { spf: AuthResult; dkim: AuthResult; dmarc: AuthResult };
  links: { text: string; href: string; domain: string }[];
  attachments: { name: string; mime: string; size: number; sha256: string; encrypted: boolean }[];
}

export interface SenderHistory { messagesReceived: number; userReplied: boolean }

export interface Settings {
  enabled: boolean;
  sensitivity: "relaxed" | "balanced" | "strict" | "custom";
  thresholds: { suspicious: number; phishing: number };
  flags: Partial<Record<FlagId, { enabled: boolean; weight: number }>>;
  categoryMultipliers: Partial<Record<FlagCategory, number>>;
  protectedDomains: string[];
  allowlist: ListEntry[];
  blocklist: ListEntry[];
  shadowMode: boolean;
}

export const ListEntrySchema = z.object({ matchType: z.enum(["address", "domain"]), value: z.string().min(1) });
export type ListEntry = z.infer<typeof ListEntrySchema>;

export const PRESET_THRESHOLDS = {
  relaxed: { suspicious: 40, phishing: 75 },
  balanced: { suspicious: 30, phishing: 60 },
  strict: { suspicious: 20, phishing: 45 },
} as const;

export const DEFAULT_SETTINGS: Settings = {
  enabled: true, sensitivity: "balanced", thresholds: { ...PRESET_THRESHOLDS.balanced },
  flags: {}, categoryMultipliers: {},
  protectedDomains: ["paypal.com", "microsoft.com", "google.com", "apple.com", "amazon.com"],
  allowlist: [], blocklist: [], shadowMode: false,
};

export interface Verdict {
  score: number; verdict: "safe" | "suspicious" | "phishing";
  flags: Flag[]; aiUsed: boolean; settingsVersion: number;
  /** Set when no flags explain the verdict (list hits). */
  reason?: string;
}

export function makeFlag(id: FlagId, evidence: string, settings?: Settings): Flag | null {
  const o = settings?.flags[id];
  if (o && !o.enabled) return null;
  return { id, category: FLAG_CATEGORY[id], weight: o?.weight ?? DEFAULT_WEIGHTS[id], evidence, source: "rule" };
}

export function thresholdsFor(s: Settings): { suspicious: number; phishing: number } {
  return s.sensitivity === "custom" ? s.thresholds : PRESET_THRESHOLDS[s.sensitivity];
}
