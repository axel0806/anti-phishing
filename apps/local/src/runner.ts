import type { MailProvider } from "@ap/mail";
import { actionFor, scanRaw } from "@ap/pipeline";
import type { Settings, Verdict } from "@ap/shared";

export const PHISHING_FOLDER = "Phishing";
export const SUSPICIOUS_LABEL = "Suspicious";

export interface StoredVerdict { verdict: Verdict; action: ReturnType<typeof actionFor>; shadow: boolean }
export type VerdictStore = Map<string, StoredVerdict>;

/** One polling pass. Idempotent: messages already in the store are skipped, so retries never double-act. */
export async function scanInbox(provider: MailProvider, settings: Settings, store: VerdictStore, limit = 25): Promise<string[]> {
  const scanned: string[] = [];
  for (const id of await provider.listRecentInbox(limit)) {
    if (store.has(id)) continue;
    try {
      const verdict = await scanRaw(await provider.fetchRaw(id), id, settings);
      const action = actionFor(verdict, settings);
      if (action === "move_to_phishing") await provider.move(id, PHISHING_FOLDER);
      else if (action === "label_suspicious") await provider.addLabel(id, SUSPICIOUS_LABEL);
      store.set(id, { verdict, action, shadow: settings.shadowMode });
      scanned.push(id);
    } catch (err) {
      // A failed message is retried on the next pass; it never blocks the others.
      console.error(`scan failed for ${id}:`, (err as Error).message);
    }
  }
  return scanned;
}
