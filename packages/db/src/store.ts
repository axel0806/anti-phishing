import { and, count, eq, gte, inArray, sql } from "drizzle-orm";
import { FLAG_CATEGORY, type Flag, type FlagId, type ListEntry, type SenderHistory, type Verdict } from "@ap/shared";
import type { OrgPolicy, SettingsOverrides } from "@ap/settings";
import type { Db } from "./migrate.ts";
import { feedback, listEntries, orgs, scanFlags, scans, senderHistory, users } from "./schema.ts";

export type Role = "user" | "viewer" | "analyst" | "admin";
export interface User { id: string; orgId: string | null; email: string; provider: string; role: Role; overrides: SettingsOverrides; encryptedTokens: string | null }
export interface StoredScan { id: string; verdict: Verdict; pinned: boolean; sender: string | null; createdAt: Date }
export interface Lists { allow: ListEntry[]; block: ListEntry[] }
export interface ScanMeta { latencyMs: number; sender?: string; subjectHash?: string }

const toUser = (r: typeof users.$inferSelect): User => ({
  id: r.id, orgId: r.orgId, email: r.email, provider: r.provider, role: r.role as Role,
  overrides: r.settingsOverrides as SettingsOverrides, encryptedTokens: r.encryptedTokens,
});

/** All persistence the API needs. Works on any drizzle Postgres driver (node-postgres in production, PGlite in tests). */
export class Store {
  constructor(private db: Db) {}

  // ---- orgs & users ----
  async createOrg(name: string): Promise<{ id: string }> {
    const [r] = await this.db.insert(orgs).values({ name }).returning({ id: orgs.id });
    return r!;
  }
  async getOrgPolicy(orgId: string | null): Promise<OrgPolicy> {
    if (!orgId) return { values: {}, locked: [] };
    const [r] = await this.db.select().from(orgs).where(eq(orgs.id, orgId));
    return r ? { values: r.policy as SettingsOverrides, locked: r.lockedFields } : { values: {}, locked: [] };
  }
  async setOrgPolicy(orgId: string, policy: OrgPolicy): Promise<boolean> {
    const r = await this.db.update(orgs).set({ policy: policy.values, lockedFields: policy.locked }).where(eq(orgs.id, orgId)).returning({ id: orgs.id });
    return r.length > 0;
  }
  async createUser(input: { email: string; orgId?: string | null; role?: Role; provider?: string }): Promise<User> {
    const [r] = await this.db.insert(users).values({
      email: input.email.toLowerCase(), orgId: input.orgId ?? null, role: input.role ?? "user", provider: input.provider ?? "gmail",
    }).returning();
    return toUser(r!);
  }
  async getUser(id: string): Promise<User | null> {
    const [r] = await this.db.select().from(users).where(eq(users.id, id));
    return r ? toUser(r) : null;
  }
  async getUserByEmail(email: string): Promise<User | null> {
    const [r] = await this.db.select().from(users).where(eq(users.email, email.toLowerCase()));
    return r ? toUser(r) : null;
  }
  async setUserOverrides(userId: string, overrides: SettingsOverrides): Promise<void> {
    await this.db.update(users).set({ settingsOverrides: overrides }).where(eq(users.id, userId));
  }

  async setEncryptedTokens(userId: string, blob: string | null): Promise<void> {
    await this.db.update(users).set({ encryptedTokens: blob }).where(eq(users.id, userId));
  }
  /** Users whose mailbox is linked: the worker scans these. */
  async listLinkedUsers(): Promise<User[]> {
    const rows = await this.db.select().from(users).where(sql`${users.encryptedTokens} is not null`);
    return rows.map(toUser);
  }

  // ---- allow / block lists ----
  async addEntry(owner: { kind: "user" | "org"; id: string }, kind: "allow" | "block", e: ListEntry, createdBy?: string): Promise<void> {
    await this.db.insert(listEntries).values({
      ownerKind: owner.kind, ownerId: owner.id, kind, matchType: e.matchType, value: e.value.toLowerCase(), createdBy: createdBy ?? null,
    }).onConflictDoNothing();
  }
  async removeEntry(ownerId: string, kind: "allow" | "block", e: ListEntry): Promise<boolean> {
    const r = await this.db.delete(listEntries).where(and(
      eq(listEntries.ownerId, ownerId), eq(listEntries.kind, kind), eq(listEntries.matchType, e.matchType), eq(listEntries.value, e.value.toLowerCase()),
    )).returning({ id: listEntries.id });
    return r.length > 0;
  }
  /** The user's own entries plus their org's. */
  async listsFor(user: Pick<User, "id" | "orgId">): Promise<Lists> {
    const owners = user.orgId ? [user.id, user.orgId] : [user.id];
    const rows = await this.db.select().from(listEntries).where(inArray(listEntries.ownerId, owners));
    const out: Lists = { allow: [], block: [] };
    for (const r of rows) (r.kind === "allow" ? out.allow : out.block).push({ matchType: r.matchType as ListEntry["matchType"], value: r.value });
    return out;
  }

  // ---- sender history ----
  async getSenderHistory(userId: string, address: string): Promise<SenderHistory | undefined> {
    const [r] = await this.db.select().from(senderHistory).where(and(eq(senderHistory.userId, userId), eq(senderHistory.senderAddress, address.toLowerCase())));
    return r ? { messagesReceived: r.messagesReceived, userReplied: r.userReplied } : undefined;
  }
  async recordSender(userId: string, address: string): Promise<void> {
    await this.db.insert(senderHistory).values({ userId, senderAddress: address.toLowerCase() })
      .onConflictDoUpdate({ target: [senderHistory.userId, senderHistory.senderAddress], set: { messagesReceived: sql`${senderHistory.messagesReceived} + 1` } });
  }
  async countSenders(userId: string): Promise<number> {
    const [r] = await this.db.select({ n: count() }).from(senderHistory).where(eq(senderHistory.userId, userId));
    return r?.n ?? 0;
  }

  // ---- scans ----
  async getScan(userId: string, providerMessageId: string): Promise<StoredScan | null> {
    const [s] = await this.db.select().from(scans).where(and(eq(scans.userId, userId), eq(scans.providerMessageId, providerMessageId)));
    if (!s) return null;
    const fl = await this.db.select().from(scanFlags).where(eq(scanFlags.scanId, s.id));
    const flags: Flag[] = fl.map((f) => ({
      id: f.flagId as FlagId, category: FLAG_CATEGORY[f.flagId as FlagId], weight: f.weightApplied, evidence: f.evidence,
      source: f.flagId === "ai_intent" ? "ai" : "rule",
    }));
    return {
      id: s.id, pinned: s.pinned, sender: s.sender, createdAt: s.createdAt,
      verdict: { score: s.score, verdict: s.verdict as Verdict["verdict"], flags, aiUsed: s.aiUsed, settingsVersion: s.settingsVersion, reason: s.reason ?? undefined },
    };
  }

  /** Insert or replace a scan. A pinned (manually judged) scan is returned untouched: manual verdicts are never re-scored. */
  async saveScan(userId: string, providerMessageId: string, v: Verdict, meta: ScanMeta): Promise<StoredScan> {
    await this.db.transaction(async (tx) => {
      const [ex] = await tx.select().from(scans).where(and(eq(scans.userId, userId), eq(scans.providerMessageId, providerMessageId)));
      if (ex?.pinned) return;
      const values = {
        userId, providerMessageId, score: v.score, verdict: v.verdict, aiUsed: v.aiUsed, latencyMs: Math.round(meta.latencyMs),
        settingsVersion: v.settingsVersion, reason: v.reason ?? null, sender: meta.sender ?? null, subjectHash: meta.subjectHash ?? null,
      };
      let id: string;
      if (ex) {
        id = ex.id;
        await tx.update(scans).set({ ...values, createdAt: new Date() }).where(eq(scans.id, id));
        await tx.delete(scanFlags).where(eq(scanFlags.scanId, id));
      } else {
        [{ id }] = (await tx.insert(scans).values(values).returning({ id: scans.id })) as [{ id: string }];
      }
      if (v.flags.length) {
        await tx.insert(scanFlags).values(v.flags.map((f) => ({ scanId: id, flagId: f.id, weightApplied: Math.round(f.weight), evidence: f.evidence })));
      }
    });
    return (await this.getScan(userId, providerMessageId))!;
  }

  /** Records the user's judgement and pins the scan so it is never re-scored. Null if the message was never scanned. */
  async addFeedback(userId: string, providerMessageId: string, label: "not_phishing" | "phishing"): Promise<StoredScan | null> {
    const s = await this.getScan(userId, providerMessageId);
    if (!s) return null;
    await this.db.transaction(async (tx) => {
      await tx.update(scans).set({ pinned: true, verdict: label === "phishing" ? "phishing" : "safe" }).where(eq(scans.id, s.id));
      await tx.insert(feedback).values({ scanId: s.id, userId, label })
        .onConflictDoUpdate({ target: [feedback.scanId, feedback.userId], set: { label, createdAt: new Date() } });
    });
    return this.getScan(userId, providerMessageId);
  }

  async statsFor(userId: string, days: number): Promise<{ scanned: number; safe: number; suspicious: number; phishing: number; falsePositives: number }> {
    const since = new Date(Date.now() - days * 86_400_000);
    const rows = await this.db.select({ verdict: scans.verdict, n: count() }).from(scans)
      .where(and(eq(scans.userId, userId), gte(scans.createdAt, since))).groupBy(scans.verdict);
    const by = Object.fromEntries(rows.map((r) => [r.verdict, r.n]));
    const [fp] = await this.db.select({ n: count() }).from(feedback)
      .where(and(eq(feedback.userId, userId), eq(feedback.label, "not_phishing"), gte(feedback.createdAt, since)));
    const safe = by.safe ?? 0, suspicious = by.suspicious ?? 0, phishing = by.phishing ?? 0;
    return { scanned: safe + suspicious + phishing, safe, suspicious, phishing, falsePositives: fp?.n ?? 0 };
  }

  /** Retention: delete scans (and, by cascade, their flags and feedback) older than `days`. Returns rows removed. */
  async purgeScansOlderThan(days: number): Promise<number> {
    const cutoff = new Date(Date.now() - days * 86_400_000);
    const r = await this.db.delete(scans).where(sql`${scans.createdAt} < ${cutoff}`).returning({ id: scans.id });
    return r.length;
  }
}

