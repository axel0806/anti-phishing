import { and, count, eq, gte, inArray, sql } from "drizzle-orm";
import { FLAG_CATEGORY, type Flag, type FlagId, type ListEntry, type SenderHistory, type Verdict } from "@ap/shared";
import type { OrgPolicy, SettingsOverrides } from "@ap/settings";
import type { Db } from "./migrate.ts";
import { aiCache, aiUsage, feedback, listEntries, orgs, scanFlags, scans, senderHistory, users } from "./schema.ts";

export type Role = "user" | "viewer" | "analyst" | "admin";
export interface User { id: string; orgId: string | null; email: string; provider: string; role: Role; overrides: SettingsOverrides; encryptedTokens: string | null }
export interface StoredScan { id: string; verdict: Verdict; pinned: boolean; /** null until a mailbox action was applied or ruled out */ action: string | null; sender: string | null; createdAt: Date }
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

  async setUserRole(userId: string, role: Role): Promise<void> {
    await this.db.update(users).set({ role }).where(eq(users.id, userId));
  }
  async setEncryptedTokens(userId: string, blob: string | null): Promise<void> {
    await this.db.update(users).set({ encryptedTokens: blob }).where(eq(users.id, userId));
  }
  async countUsers(): Promise<number> {
    const [r] = await this.db.select({ n: count() }).from(users);
    return Number(r?.n ?? 0);
  }
  /** An org's members for the admin Users tab. Never includes tokens, only whether a mailbox is linked. */
  async listOrgUsers(orgId: string): Promise<{ id: string; email: string; role: Role; provider: string; linked: boolean }[]> {
    const rows = await this.db.select().from(users).where(eq(users.orgId, orgId));
    return rows.map((r) => ({ id: r.id, email: r.email, role: r.role as Role, provider: r.provider, linked: r.encryptedTokens !== null })).sort((x, y) => x.email.localeCompare(y.email));
  }
  async setUserMembership(userId: string, m: { orgId: string | null; role: Role; provider: string }): Promise<void> {
    await this.db.update(users).set({ orgId: m.orgId, role: m.role, provider: m.provider }).where(eq(users.id, userId));
  }
  /** Erases a user and everything keyed to them (scans, flags, feedback, history, AI usage and their own list entries cascade or are removed here). */
  async deleteUser(userId: string): Promise<boolean> {
    return this.db.transaction(async (tx) => {
      await tx.delete(listEntries).where(and(eq(listEntries.ownerKind, "user"), eq(listEntries.ownerId, userId)));
      const r = await tx.delete(users).where(eq(users.id, userId)).returning({ id: users.id });
      return r.length > 0;
    });
  }
  // ---- worker coordination: one worker per mailbox at a time, and visible lag ----
  private async rows(q: ReturnType<typeof sql>): Promise<Record<string, unknown>[]> {
    return ((await this.db.execute(q)) as unknown as { rows: Record<string, unknown>[] }).rows;
  }
  /** Takes the mailbox for `seconds` if nobody else holds it. A crashed worker's lease simply expires. */
  async leaseMailbox(userId: string, seconds: number): Promise<boolean> {
    const r = await this.rows(sql`
      insert into mailbox_state (user_id, leased_until) values (${userId}, now() + (${seconds} * interval '1 second'))
      on conflict (user_id) do update set leased_until = excluded.leased_until
        where mailbox_state.leased_until is null or mailbox_state.leased_until <= now()
      returning user_id`);
    return r.length > 0;
  }
  async releaseMailbox(userId: string, r: { ok: boolean; error?: string }): Promise<void> {
    await this.db.execute(sql`
      update mailbox_state set leased_until = null, last_attempt_at = now(),
        last_success_at = case when ${r.ok} then now() else last_success_at end,
        last_error = case when ${r.ok} then null else ${(r.error ?? "error").slice(0, 300)} end
      where user_id = ${userId}`);
  }
  /** Counts only, never provider error text: this feeds the dashboard. */
  async mailboxHealth(orgId: string): Promise<{ mailboxes: number; neverSynced: number; erroring: number; stale: number; maxLagSeconds: number }> {
    const [r] = await this.rows(sql`
      select count(*) as n,
        count(*) filter (where m.last_success_at is null) as never_synced,
        count(*) filter (where m.last_error is not null) as erroring,
        count(*) filter (where m.last_success_at < now() - interval '10 minutes') as stale,
        coalesce(max(extract(epoch from (now() - m.last_success_at))), 0) as lag
      from users u left join mailbox_state m on m.user_id = u.id
      where u.org_id = ${orgId} and u.encrypted_tokens is not null`);
    const n = (v: unknown) => Number(v ?? 0);
    return { mailboxes: n(r?.n), neverSynced: n(r?.never_synced), erroring: n(r?.erroring), stale: n(r?.stale), maxLagSeconds: Math.round(n(r?.lag)) };
  }
  /** Which of these message ids were already handled (acted on, or judged by the user)? One query instead of one per message. */
  async handledIds(userId: string, ids: string[]): Promise<Set<string>> {
    if (!ids.length) return new Set();
    const rows = await this.db.select({ id: scans.providerMessageId, pinned: scans.pinned, action: scans.action }).from(scans)
      .where(and(eq(scans.userId, userId), inArray(scans.providerMessageId, ids)));
    return new Set(rows.filter((r) => r.pinned || r.action !== null).map((r) => r.id));
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
  /** Entries owned by exactly one user or org (no merging), for management screens. */
  async listOwn(ownerId: string): Promise<Lists> {
    const rows = await this.db.select().from(listEntries).where(eq(listEntries.ownerId, ownerId));
    const out: Lists = { allow: [], block: [] };
    for (const r of rows) (r.kind === "allow" ? out.allow : out.block).push({ matchType: r.matchType as ListEntry["matchType"], value: r.value });
    return out;
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
      source: f.source === "ai" ? "ai" : "rule",
    }));
    return {
      id: s.id, pinned: s.pinned, action: s.action, sender: s.sender, createdAt: s.createdAt,
      verdict: { score: s.score, verdict: s.verdict as Verdict["verdict"], flags, aiUsed: s.aiUsed, settingsVersion: s.settingsVersion, reason: s.reason ?? undefined, aiExplanation: s.aiExplanation ?? undefined },
    };
  }

  /**
   * Insert or replace a scan, safe under concurrency: the row is locked while it is read and rewritten, and a racing insert
   * falls through to the update path. A pinned (manually judged) scan is returned untouched: manual verdicts are never re-scored.
   * A rewrite clears `action`, so the new verdict can be acted on.
   */
  async saveScan(userId: string, providerMessageId: string, v: Verdict, meta: ScanMeta): Promise<StoredScan> {
    const values = {
      userId, providerMessageId, score: v.score, verdict: v.verdict, aiUsed: v.aiUsed, latencyMs: Math.round(meta.latencyMs),
      settingsVersion: v.settingsVersion, reason: v.reason ?? null, aiExplanation: v.aiExplanation ?? null, sender: meta.sender ?? null, subjectHash: meta.subjectHash ?? null, action: null,
    };
    await this.db.transaction(async (tx) => {
      const lock = () => tx.select().from(scans).where(and(eq(scans.userId, userId), eq(scans.providerMessageId, providerMessageId))).for("update");
      let [ex] = await lock();
      let id: string;
      if (!ex) {
        const ins = await tx.insert(scans).values(values).onConflictDoNothing().returning({ id: scans.id });
        if (ins[0]) id = ins[0].id;
        else { [ex] = await lock(); if (!ex) throw new Error("scan vanished during save"); id = ex.id; }
        if (ins[0]) { await this.writeFlags(tx, id, v); return; }
      } else id = ex.id;
      if (ex!.pinned) return;
      await tx.update(scans).set({ ...values, createdAt: new Date() }).where(eq(scans.id, id));
      await tx.delete(scanFlags).where(eq(scanFlags.scanId, id));
      await this.writeFlags(tx, id, v);
    });
    return (await this.getScan(userId, providerMessageId))!;
  }

  private async writeFlags(tx: Pick<Db, "insert">, scanId: string, v: Verdict): Promise<void> {
    if (v.flags.length) await tx.insert(scanFlags).values(v.flags.map((f) => ({ scanId, flagId: f.id, weightApplied: Math.round(f.weight), evidence: f.evidence, source: f.source })));
  }

  /** Message ids scanned in the last `days` days, newest first. */
  async recentScanIds(userId: string, days: number, opts: { excludePinned?: boolean } = {}): Promise<string[]> {
    if (days <= 0) return [];
    const since = new Date(Date.now() - days * 86_400_000);
    const conds = [eq(scans.userId, userId), gte(scans.createdAt, since)];
    if (opts.excludePinned) conds.push(eq(scans.pinned, false));
    const rows = await this.db.select({ id: scans.providerMessageId }).from(scans).where(and(...conds)).orderBy(sql`${scans.createdAt} desc`).limit(1000);
    return rows.map((r) => r.id);
  }

  /** Records the mailbox action that was applied (or ruled out) for a scan, so it is never applied twice. */
  async setScanAction(userId: string, providerMessageId: string, action: string): Promise<void> {
    await this.db.update(scans).set({ action }).where(and(eq(scans.userId, userId), eq(scans.providerMessageId, providerMessageId)));
  }

  /** Records the user's judgement and pins the scan so it is never re-scored. The row is locked so a concurrent rescan cannot overwrite it. Null if never scanned. */
  async addFeedback(userId: string, providerMessageId: string, label: "not_phishing" | "phishing"): Promise<StoredScan | null> {
    const found = await this.db.transaction(async (tx) => {
      const [s] = await tx.select().from(scans).where(and(eq(scans.userId, userId), eq(scans.providerMessageId, providerMessageId))).for("update");
      if (!s) return false;
      await tx.update(scans).set({ pinned: true, verdict: label === "phishing" ? "phishing" : "safe", action: "manual" }).where(eq(scans.id, s.id));
      // Keep the FIRST decision we made as `previous_verdict`: a user changing their mind must not erase what we originally said.
      await tx.insert(feedback).values({ scanId: s.id, userId, label, previousVerdict: s.verdict })
        .onConflictDoUpdate({ target: [feedback.scanId, feedback.userId], set: { label, createdAt: new Date() } });
      return true;
    });
    return found ? this.getScan(userId, providerMessageId) : null;
  }

  // ---- AI layer: response cache and monthly usage ----
  async aiCacheGet(key: string): Promise<unknown | null> {
    const [r] = await this.db.select().from(aiCache).where(eq(aiCache.key, key));
    return r ? r.verdict : null;
  }
  async aiCacheSet(key: string, verdict: unknown): Promise<void> {
    await this.db.insert(aiCache).values({ key, verdict }).onConflictDoUpdate({ target: aiCache.key, set: { verdict, createdAt: new Date() } });
  }
  async purgeAiCacheOlderThan(days: number): Promise<number> {
    const cutoff = new Date(Date.now() - days * 86_400_000);
    return (await this.db.delete(aiCache).where(sql`${aiCache.createdAt} < ${cutoff}`).returning({ k: aiCache.key })).length;
  }
  async aiRecordUsage(userId: string, costUsd: number, now = new Date()): Promise<void> {
    const month = now.toISOString().slice(0, 7);
    await this.db.insert(aiUsage).values({ userId, month, calls: 1, costUsd })
      .onConflictDoUpdate({ target: [aiUsage.userId, aiUsage.month], set: { calls: sql`${aiUsage.calls} + 1`, costUsd: sql`${aiUsage.costUsd} + ${costUsd}` } });
  }
  async aiSpentThisMonth(userId: string, now = new Date()): Promise<number> {
    const [r] = await this.db.select().from(aiUsage).where(and(eq(aiUsage.userId, userId), eq(aiUsage.month, now.toISOString().slice(0, 7))));
    return r?.costUsd ?? 0;
  }
  /** Combined spend of everyone in an org this month. */
  async aiSpentThisMonthForOrg(orgId: string, now = new Date()): Promise<number> {
    const [r] = await this.db.select({ total: sql<number>`coalesce(sum(${aiUsage.costUsd}), 0)` }).from(aiUsage)
      .innerJoin(users, eq(users.id, aiUsage.userId))
      .where(and(eq(users.orgId, orgId), eq(aiUsage.month, now.toISOString().slice(0, 7))));
    return Number(r?.total ?? 0);
  }
  async aiCallsThisMonth(userId: string, now = new Date()): Promise<number> {
    const [r] = await this.db.select().from(aiUsage).where(and(eq(aiUsage.userId, userId), eq(aiUsage.month, now.toISOString().slice(0, 7))));
    return r?.calls ?? 0;
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

