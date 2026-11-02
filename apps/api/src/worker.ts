import type { MailProvider } from "@ap/mail";
import type { Store, User } from "@ap/db";
import { MailUnavailable, ScanInProgress, type ScanService } from "./service.ts";

export interface PassResult { users: number; scanned: number; failed: number }

/**
 * One polling pass over every linked mailbox. Scans are idempotent per (user, message), so a crash or an
 * overlapping pass can never double-move mail. A failing message or user never blocks the rest.
 */
export async function runWorkerPass(
  store: Store, service: ScanService, mailFor: (u: User) => MailProvider | null, opts: { limit?: number; log?: (m: string) => void } = {},
): Promise<PassResult> {
  const out: PassResult = { users: 0, scanned: 0, failed: 0 };
  for (const user of await store.listLinkedUsers()) {
    const mail = mailFor(user);
    if (!mail) continue;
    out.users++;
    let ids: string[];
    try { ids = await mail.listRecentInbox(opts.limit ?? 25); } catch (e) { out.failed++; opts.log?.(`list failed for user ${user.id}: ${(e as Error).message}`); continue; }
    for (const id of ids) {
      const seen = await store.getScan(user.id, id);
      if (seen && (seen.pinned || seen.action !== null)) continue; // handled, or judged by the user; a dry-run scan still awaits its action
      try {
        const r = await service.scan(user, id, { mode: "act" });
        if (!r.cached || r.action !== "none") out.scanned++;
      } catch (e) {
        if (e instanceof ScanInProgress || e instanceof MailUnavailable) continue;
        out.failed++;
        opts.log?.(`scan failed for user ${user.id}/${id}: ${(e as Error).message}`);
      }
    }
  }
  return out;
}

/** Nightly housekeeping: enforce data retention. */
export async function runMaintenance(store: Store, retentionDays: number): Promise<{ purged: number }> {
  return { purged: await store.purgeScansOlderThan(retentionDays) };
}
