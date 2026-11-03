import type { MailProvider } from "@ap/mail";
import type { AdminQueries, Store, User } from "@ap/db";
import type { Metrics } from "./metrics.ts";
import { MailUnavailable, ScanInProgress, type ScanService } from "./service.ts";

export interface PassResult { users: number; scanned: number; failed: number }

export interface PassOptions {
  /** How many of the newest inbox messages to look at per mailbox per pass. Default 200. */
  limit?: number;
  /** Most new messages to scan per mailbox per pass, newest first; the rest wait for the next pass. Default 100. */
  maxScansPerMailbox?: number;
  /** Mailboxes worked on at the same time. Default 4. */
  concurrency?: number;
  log?: (m: string) => void;
  metrics?: Metrics;
}

const LEASE_SECONDS = 300;

/**
 * One polling pass over every linked mailbox. Scans are idempotent per (user, message), so a crash or an overlapping
 * pass can never double-move mail. A failing message or user never blocks the rest. Several workers (or passes) can run
 * at once: each mailbox is leased, so only one handles it at a time, and the lease of a crashed worker expires on its own.
 */
export async function runWorkerPass(
  store: Store, service: ScanService, mailFor: (u: User) => MailProvider | null, opts: PassOptions = {},
): Promise<PassResult> {
  const out: PassResult = { users: 0, scanned: 0, failed: 0 };
  const limit = opts.limit ?? 200, perBox = opts.maxScansPerMailbox ?? 100;
  const queue = [...(await store.listLinkedUsers())];

  const work = async (user: User): Promise<void> => {
    const mail = mailFor(user);
    if (!mail) return;
    if (!(await store.leaseMailbox(user.id, LEASE_SECONDS))) return; // another worker has it
    out.users++;
    let ok = true, error: string | undefined;
    try {
      let ids: string[];
      try { ids = await mail.listRecentInbox(limit); } catch (e) {
        out.failed++; ok = false; error = (e as Error).message;
        opts.metrics?.inc("provider_errors_total"); opts.log?.(`list failed for user ${user.id}: ${error}`);
        return;
      }
      const handled = await store.handledIds(user.id, ids); // acted on, or judged by the user; a dry-run scan still awaits its action
      let budget = perBox;
      for (const id of ids) {
        if (handled.has(id)) continue;
        if (budget-- <= 0) break; // newest first: the remainder is picked up on the next pass
        try {
          const r = await service.scan(user, id, { mode: "act" });
          if (!r.cached || r.action !== "none") out.scanned++;
        } catch (e) {
          if (e instanceof ScanInProgress || e instanceof MailUnavailable) continue;
          out.failed++;
          opts.metrics?.inc("provider_errors_total");
          opts.log?.(`scan failed for user ${user.id}/${id}: ${(e as Error).message}`);
        }
      }
    } finally {
      await store.releaseMailbox(user.id, { ok, error }).catch(() => {});
    }
  };

  const lanes = Math.max(1, Math.min(opts.concurrency ?? 4, queue.length));
  await Promise.all(Array.from({ length: lanes }, async () => { for (let u = queue.shift(); u; u = queue.shift()) await work(u); }));
  return out;
}

/** Nightly housekeeping: enforce data retention. */
export async function runMaintenance(store: Store, retentionDays: number, admin?: AdminQueries): Promise<{ purged: number }> {
  // Settle the last few days into daily_stats BEFORE anything expires, so dashboard history outlives the scans it came from.
  // Covering several days also repairs gaps after downtime.
  if (admin) for (let n = 3; n >= 0; n--) await admin.rollupDay(new Date(Date.now() - n * 86_400_000).toISOString().slice(0, 10));
  await store.purgeAiCacheOlderThan(Math.min(30, retentionDays)); // cached answers derive from mail, so they never outlive it
  return { purged: await store.purgeScansOlderThan(retentionDays) };
}
