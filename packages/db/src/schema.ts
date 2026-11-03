import { boolean, date, doublePrecision, index, integer, jsonb, pgTable, primaryKey, text, timestamp, unique, uuid } from "drizzle-orm/pg-core";

export const orgs = pgTable("orgs", {
  id: uuid("id").primaryKey().defaultRandom(),
  name: text("name").notNull(),
  policy: jsonb("policy").notNull().default({}),
  lockedFields: text("locked_fields").array().notNull().default([]),
});

export const users = pgTable("users", {
  id: uuid("id").primaryKey().defaultRandom(),
  orgId: uuid("org_id").references(() => orgs.id),
  email: text("email").notNull().unique(),
  provider: text("provider").notNull().default("gmail"),
  role: text("role").notNull().default("user"), // user | viewer | analyst | admin
  encryptedTokens: text("encrypted_tokens"),
  settingsOverrides: jsonb("settings_overrides").notNull().default({}),
  /** Session tokens issued before this moment are refused ("sign out everywhere", role changes). */
  tokensValidAfter: timestamp("tokens_valid_after", { withTimezone: true }),
});

export const listEntries = pgTable("list_entries", {
  id: uuid("id").primaryKey().defaultRandom(),
  ownerKind: text("owner_kind").notNull(), // user | org
  ownerId: uuid("owner_id").notNull(),
  kind: text("kind").notNull(), // allow | block
  matchType: text("match_type").notNull(), // address | domain
  value: text("value").notNull(),
  createdBy: uuid("created_by"),
}, (t) => [
  unique("list_entries_unique").on(t.ownerId, t.kind, t.matchType, t.value),
  index("list_entries_owner_kind_value").on(t.ownerId, t.kind, t.value),
]);

export const senderHistory = pgTable("sender_history", {
  userId: uuid("user_id").notNull().references(() => users.id, { onDelete: "cascade" }),
  senderAddress: text("sender_address").notNull(),
  firstSeen: timestamp("first_seen", { withTimezone: true }).notNull().defaultNow(),
  messagesReceived: integer("messages_received").notNull().default(1),
  userReplied: boolean("user_replied").notNull().default(false),
}, (t) => [primaryKey({ columns: [t.userId, t.senderAddress] })]);

export const scans = pgTable("scans", {
  id: uuid("id").primaryKey().defaultRandom(),
  userId: uuid("user_id").notNull().references(() => users.id, { onDelete: "cascade" }),
  providerMessageId: text("provider_message_id").notNull(),
  score: integer("score").notNull(),
  verdict: text("verdict").notNull(),
  aiUsed: boolean("ai_used").notNull().default(false),
  latencyMs: integer("latency_ms").notNull(),
  settingsVersion: integer("settings_version").notNull(),
  reason: text("reason"),
  aiExplanation: text("ai_explanation"),
  sender: text("sender"),
  subjectHash: text("subject_hash"),
  pinned: boolean("pinned").notNull().default(false), // a manual verdict: never re-scored
  action: text("action"), // null until the worker/act scan has applied (or ruled out) a mailbox action
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
}, (t) => [
  unique("scans_user_message").on(t.userId, t.providerMessageId),
  index("scans_user_created").on(t.userId, t.createdAt),
  index("scans_verdict_created").on(t.verdict, t.createdAt),
]);

export const scanFlags = pgTable("scan_flags", {
  scanId: uuid("scan_id").notNull().references(() => scans.id, { onDelete: "cascade" }),
  flagId: text("flag_id").notNull(),
  weightApplied: integer("weight_applied").notNull(),
  evidence: text("evidence").notNull(),
  source: text("source").notNull().default("rule"), // rule | ai: model output must never pass for deterministic evidence
}, (t) => [primaryKey({ columns: [t.scanId, t.flagId] }), index("scan_flags_flag").on(t.flagId)]);

export const feedback = pgTable("feedback", {
  scanId: uuid("scan_id").notNull().references(() => scans.id, { onDelete: "cascade" }),
  userId: uuid("user_id").notNull().references(() => users.id, { onDelete: "cascade" }),
  label: text("label").notNull(), // not_phishing | phishing
  previousVerdict: text("previous_verdict"), // what we had decided before the user's judgement
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
}, (t) => [primaryKey({ columns: [t.scanId, t.userId] })]);

export const aiCache = pgTable("ai_cache", {
  key: text("key").primaryKey(),
  verdict: jsonb("verdict").notNull(),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
});

export const aiUsage = pgTable("ai_usage", {
  userId: uuid("user_id").notNull().references(() => users.id, { onDelete: "cascade" }),
  month: text("month").notNull(), // UTC, YYYY-MM
  calls: integer("calls").notNull().default(0),
  costUsd: doublePrecision("cost_usd").notNull().default(0),
}, (t) => [primaryKey({ columns: [t.userId, t.month] })]);

export const dailyStats = pgTable("daily_stats", {
  orgId: uuid("org_id").notNull().references(() => orgs.id, { onDelete: "cascade" }),
  date: date("date", { mode: "string" }).notNull(),
  userId: uuid("user_id").notNull().references(() => users.id, { onDelete: "cascade" }),
  scanned: integer("scanned").notNull().default(0),
  safe: integer("safe").notNull().default(0),
  suspicious: integer("suspicious").notNull().default(0),
  phishing: integer("phishing").notNull().default(0),
  falsePositives: integer("false_positives").notNull().default(0),
  aiCalls: integer("ai_calls").notNull().default(0),
}, (t) => [primaryKey({ columns: [t.orgId, t.date, t.userId] })]);

export const auditLog = pgTable("audit_log", {
  id: uuid("id").primaryKey().defaultRandom(),
  orgId: uuid("org_id").notNull().references(() => orgs.id, { onDelete: "cascade" }),
  actorId: uuid("actor_id").references(() => users.id, { onDelete: "set null" }),
  action: text("action").notNull(),
  target: text("target"),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
});
