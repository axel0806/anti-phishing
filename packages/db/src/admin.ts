import { sql, type SQL } from "drizzle-orm";
import type { Db } from "./migrate.ts";

export interface Range { from: Date; to: Date } // [from, to)
export interface Counts { scanned: number; safe: number; suspicious: number; phishing: number; falsePositives: number; aiCalls: number; phishingRate: number }
export interface Page { limit: number; offset: number }
export interface LogFilters { verdict?: "safe" | "suspicious" | "phishing"; flag?: string; sender?: string }
export interface LogRow {
  messageId: string; userId: string; userEmail: string; sender: string | null; score: number; verdict: string; pinned: boolean; createdAt: Date; flags: string[];
}

const num = (v: unknown): number => Number(v ?? 0);
const iso = (d: Date) => d.toISOString();
const dateOnly = (d: Date) => d.toISOString().slice(0, 10);
type Row = Record<string, unknown>;

/**
 * Read-only, org-scoped analytics for the admin dashboard. Every query is bound to one org, and none reads message bodies
 * (they are never stored) or subjects (only a hash is). Numbers come back as JS numbers whatever the driver returns for bigint.
 */
export class AdminQueries {
  constructor(private db: Db) {}

  private async rows(q: SQL): Promise<Row[]> {
    return ((await this.db.execute(q)) as unknown as { rows: Row[] }).rows;
  }

  // ---- rollup (daily_stats) ----
  /** Rebuilds one UTC day of per-org, per-user counts from `scans`. Idempotent; run for yesterday and today, before retention purges old scans. */
  async rollupDay(day: string): Promise<void> {
    await this.db.transaction(async (tx) => {
      // Concurrent rebuilds of one day (several dashboard requests at once) queue here instead of colliding on the primary key.
      await tx.execute(sql`select pg_advisory_xact_lock(hashtext(${"rollup:" + day}))`);
      // Scans are purged after the retention period. A day must never be replaced by a smaller picture of itself,
      // or the history the rollup exists to keep would be wiped by the next catch-up run.
      const read = async (q: SQL) => num((((await tx.execute(q)) as unknown as { rows: Row[] }).rows[0] ?? {}).n);
      const settled = await read(sql`select coalesce(sum(scanned), 0) as n from daily_stats where date = ${day}::date`);
      const live = await read(sql`select count(*) as n from scans s join users u on u.id = s.user_id where u.org_id is not null and (s.created_at at time zone 'UTC')::date = ${day}::date`);
      if (live < settled) return;
      await tx.execute(sql`delete from daily_stats where date = ${day}::date`);
      await tx.execute(sql`
        insert into daily_stats (org_id, date, user_id, scanned, safe, suspicious, phishing, false_positives, ai_calls)
        select u.org_id, ${day}::date, s.user_id, count(*),
          count(*) filter (where s.verdict = 'safe'), count(*) filter (where s.verdict = 'suspicious'), count(*) filter (where s.verdict = 'phishing'),
          count(*) filter (where exists (select 1 from feedback f where f.scan_id = s.id and f.label = 'not_phishing')),
          count(*) filter (where s.ai_used)
        from scans s join users u on u.id = s.user_id
        where u.org_id is not null and (s.created_at at time zone 'UTC')::date = ${day}::date
        group by u.org_id, s.user_id`);
    });
  }

  private async sums(orgId: string, r: Range): Promise<Counts> {
    const [row] = await this.rows(sql`
      select coalesce(sum(scanned), 0) as scanned, coalesce(sum(safe), 0) as safe, coalesce(sum(suspicious), 0) as suspicious,
             coalesce(sum(phishing), 0) as phishing, coalesce(sum(false_positives), 0) as fps, coalesce(sum(ai_calls), 0) as ai
      from daily_stats where org_id = ${orgId} and date >= ${dateOnly(r.from)}::date and date < ${dateOnly(r.to)}::date`);
    const scanned = num(row?.scanned), phishing = num(row?.phishing);
    return { scanned, safe: num(row?.safe), suspicious: num(row?.suspicious), phishing, falsePositives: num(row?.fps), aiCalls: num(row?.ai), phishingRate: scanned ? phishing / scanned : 0 };
  }

  async overview(orgId: string, r: Range): Promise<{ current: Counts; previous: Counts }> {
    const span = r.to.getTime() - r.from.getTime();
    return { current: await this.sums(orgId, r), previous: await this.sums(orgId, { from: new Date(r.from.getTime() - span), to: r.from }) };
  }

  async trend(orgId: string, r: Range): Promise<{ date: string; suspicious: number; phishing: number }[]> {
    const rows = await this.rows(sql`
      select to_char(date, 'YYYY-MM-DD') as date, sum(suspicious) as suspicious, sum(phishing) as phishing
      from daily_stats where org_id = ${orgId} and date >= ${dateOnly(r.from)}::date and date < ${dateOnly(r.to)}::date
      group by date order by date`);
    return rows.map((x) => ({ date: String(x.date), suspicious: num(x.suspicious), phishing: num(x.phishing) }));
  }

  // ---- live queries over scans ----
  async topFlags(orgId: string, r: Range): Promise<{ flagId: string; fired: number; inPhishing: number; falsePositives: number; falsePositiveRate: number }[]> {
    const rows = await this.rows(sql`
      select sf.flag_id, count(*) as fired, count(*) filter (where s.verdict = 'phishing') as in_phishing,
        count(*) filter (where exists (select 1 from feedback f where f.scan_id = s.id and f.label = 'not_phishing')) as fps
      from scan_flags sf join scans s on s.id = sf.scan_id join users u on u.id = s.user_id
      where u.org_id = ${orgId} and s.created_at >= ${iso(r.from)}::timestamptz and s.created_at < ${iso(r.to)}::timestamptz
      group by sf.flag_id order by fired desc, sf.flag_id limit 20`);
    return rows.map((x) => ({ flagId: String(x.flag_id), fired: num(x.fired), inPhishing: num(x.in_phishing), falsePositives: num(x.fps), falsePositiveRate: num(x.fired) ? num(x.fps) / num(x.fired) : 0 }));
  }

  async brandsAndDomains(orgId: string, r: Range): Promise<{ impersonated: { evidence: string; count: number }[]; senderDomains: { domain: string; count: number }[] }> {
    const win = sql`u.org_id = ${orgId} and s.created_at >= ${iso(r.from)}::timestamptz and s.created_at < ${iso(r.to)}::timestamptz`;
    const imp = await this.rows(sql`
      select sf.evidence, count(*) as n from scan_flags sf join scans s on s.id = sf.scan_id join users u on u.id = s.user_id
      where sf.flag_id in ('lookalike_domain', 'display_name_impersonation') and ${win}
      group by sf.evidence order by n desc, sf.evidence limit 10`);
    const dom = await this.rows(sql`
      select lower(split_part(s.sender, '@', 2)) as domain, count(*) as n from scans s join users u on u.id = s.user_id
      where s.verdict in ('suspicious', 'phishing') and s.sender is not null and ${win}
      group by domain order by n desc, domain limit 10`);
    return { impersonated: imp.map((x) => ({ evidence: String(x.evidence), count: num(x.n) })), senderDomains: dom.map((x) => ({ domain: String(x.domain), count: num(x.n) })) };
  }

  async targets(orgId: string, r: Range): Promise<{ email: string; phishing: number; suspicious: number }[]> {
    const rows = await this.rows(sql`
      select u.email, count(*) filter (where s.verdict = 'phishing') as phishing, count(*) filter (where s.verdict = 'suspicious') as suspicious
      from scans s join users u on u.id = s.user_id
      where u.org_id = ${orgId} and s.created_at >= ${iso(r.from)}::timestamptz and s.created_at < ${iso(r.to)}::timestamptz
      group by u.email having count(*) filter (where s.verdict = 'phishing') > 0
      order by phishing desc, u.email limit 10`);
    return rows.map((x) => ({ email: String(x.email), phishing: num(x.phishing), suspicious: num(x.suspicious) }));
  }

  /** False positives = "not phishing" on something we flagged; misses = "report phishing" on something we called safe. */
  async quality(orgId: string, r: Range): Promise<{ falsePositives: number; missesReported: number }> {
    const [row] = await this.rows(sql`
      select count(*) filter (where f.label = 'not_phishing' and f.previous_verdict in ('suspicious', 'phishing')) as fps,
             count(*) filter (where f.label = 'phishing' and f.previous_verdict = 'safe') as misses
      from feedback f join users u on u.id = f.user_id
      where u.org_id = ${orgId} and f.created_at >= ${iso(r.from)}::timestamptz and f.created_at < ${iso(r.to)}::timestamptz`);
    return { falsePositives: num(row?.fps), missesReported: num(row?.misses) };
  }

  async aiUsage(orgId: string, r: Range): Promise<{ calls: number; costUsd: number; escalated: number; scanned: number; escalatedShare: number }> {
    const m0 = r.from.toISOString().slice(0, 7), m1 = new Date(r.to.getTime() - 1).toISOString().slice(0, 7);
    const [use] = await this.rows(sql`
      select coalesce(sum(a.calls), 0) as calls, coalesce(sum(a.cost_usd), 0) as cost
      from ai_usage a join users u on u.id = a.user_id where u.org_id = ${orgId} and a.month >= ${m0} and a.month <= ${m1}`);
    const [sc] = await this.rows(sql`
      select count(*) as scanned, count(*) filter (where s.ai_used) as escalated
      from scans s join users u on u.id = s.user_id
      where u.org_id = ${orgId} and s.created_at >= ${iso(r.from)}::timestamptz and s.created_at < ${iso(r.to)}::timestamptz`);
    const scanned = num(sc?.scanned), escalated = num(sc?.escalated);
    return { calls: num(use?.calls), costUsd: num(use?.cost), escalated, scanned, escalatedShare: scanned ? escalated / scanned : 0 };
  }

  async health(orgId: string): Promise<{ scans24h: number; p50Ms: number; p95Ms: number; lastScanAt: Date | null; linkedMailboxes: number }> {
    const [l] = await this.rows(sql`
      select count(*) as n, coalesce(percentile_cont(0.5) within group (order by s.latency_ms), 0) as p50,
             coalesce(percentile_cont(0.95) within group (order by s.latency_ms), 0) as p95
      from scans s join users u on u.id = s.user_id where u.org_id = ${orgId} and s.created_at >= now() - interval '24 hours'`);
    const [last] = await this.rows(sql`select max(s.created_at) as t from scans s join users u on u.id = s.user_id where u.org_id = ${orgId}`);
    const [mb] = await this.rows(sql`select count(*) as n from users where org_id = ${orgId} and encrypted_tokens is not null`);
    return { scans24h: num(l?.n), p50Ms: num(l?.p50), p95Ms: num(l?.p95), lastScanAt: last?.t ? new Date(String(last.t)) : null, linkedMailboxes: num(mb?.n) };
  }

  /** The email log. Deliberately has no subject or body: bodies are never stored and the subject only as a hash. */
  async scanLog(orgId: string, r: Range, f: LogFilters, page: Page = { limit: 50, offset: 0 }): Promise<{ rows: LogRow[]; total: number }> {
    const conds: SQL[] = [sql`u.org_id = ${orgId}`, sql`s.created_at >= ${iso(r.from)}::timestamptz`, sql`s.created_at < ${iso(r.to)}::timestamptz`];
    if (f.verdict) conds.push(sql`s.verdict = ${f.verdict}`);
    if (f.flag) conds.push(sql`exists (select 1 from scan_flags x where x.scan_id = s.id and x.flag_id = ${f.flag})`);
    if (f.sender) conds.push(sql`position(lower(${f.sender}) in lower(coalesce(s.sender, ''))) > 0`);
    const where = sql.join(conds, sql` and `);
    const [t] = await this.rows(sql`select count(*) as n from scans s join users u on u.id = s.user_id where ${where}`);
    const rows = await this.rows(sql`
      select s.provider_message_id, u.id as user_id, u.email, s.sender, s.score, s.verdict, s.pinned, s.created_at,
        coalesce((select string_agg(x.flag_id, ',' order by x.flag_id) from scan_flags x where x.scan_id = s.id), '') as flags
      from scans s join users u on u.id = s.user_id where ${where}
      order by s.created_at desc, s.provider_message_id limit ${Math.min(page.limit, 500)} offset ${Math.max(page.offset, 0)}`);
    return {
      total: num(t?.n),
      rows: rows.map((x) => ({
        messageId: String(x.provider_message_id), userId: String(x.user_id), userEmail: String(x.email), sender: (x.sender as string | null) ?? null, score: num(x.score),
        verdict: String(x.verdict), pinned: Boolean(x.pinned), createdAt: new Date(String(x.created_at)), flags: String(x.flags) ? String(x.flags).split(",") : [],
      })),
    };
  }

  // ---- audit ----
  async audit(orgId: string, actorId: string, action: string, target: string | null): Promise<void> {
    await this.db.execute(sql`insert into audit_log (org_id, actor_id, action, target) values (${orgId}, ${actorId}, ${action}, ${target})`);
  }

  async auditLog(orgId: string, page: Page): Promise<{ id: string; actorEmail: string | null; action: string; target: string | null; createdAt: Date }[]> {
    const rows = await this.rows(sql`
      select a.id, u.email, a.action, a.target, a.created_at from audit_log a left join users u on u.id = a.actor_id
      where a.org_id = ${orgId} order by a.created_at desc, a.id limit ${Math.min(page.limit, 500)} offset ${Math.max(page.offset, 0)}`);
    return rows.map((x) => ({ id: String(x.id), actorEmail: (x.email as string | null) ?? null, action: String(x.action), target: (x.target as string | null) ?? null, createdAt: new Date(String(x.created_at)) }));
  }

  // ---- weight suggestions ----
  /** Per flag: how often it fired on this user's mail, and how often they then said "not phishing". Never applied automatically. */
  async flagFalsePositiveRates(userId: string): Promise<{ flagId: string; fired: number; falsePositives: number; rate: number }[]> {
    const rows = await this.rows(sql`
      select sf.flag_id, count(*) as fired,
        count(*) filter (where exists (select 1 from feedback f where f.scan_id = s.id and f.label = 'not_phishing')) as fps
      from scan_flags sf join scans s on s.id = sf.scan_id where s.user_id = ${userId}
      group by sf.flag_id order by fired desc, sf.flag_id`);
    return rows.map((x) => ({ flagId: String(x.flag_id), fired: num(x.fired), falsePositives: num(x.fps), rate: num(x.fired) ? num(x.fps) / num(x.fired) : 0 }));
  }
}
