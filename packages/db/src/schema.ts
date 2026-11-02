import { boolean, index, integer, jsonb, pgTable, primaryKey, text, timestamp, unique, uuid } from "drizzle-orm/pg-core";

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
  sender: text("sender"),
  subjectHash: text("subject_hash"),
  pinned: boolean("pinned").notNull().default(false), // a manual verdict: never re-scored
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
}, (t) => [primaryKey({ columns: [t.scanId, t.flagId] }), index("scan_flags_flag").on(t.flagId)]);

export const feedback = pgTable("feedback", {
  scanId: uuid("scan_id").notNull().references(() => scans.id, { onDelete: "cascade" }),
  userId: uuid("user_id").notNull().references(() => users.id, { onDelete: "cascade" }),
  label: text("label").notNull(), // not_phishing | phishing
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
}, (t) => [primaryKey({ columns: [t.scanId, t.userId] })]);
