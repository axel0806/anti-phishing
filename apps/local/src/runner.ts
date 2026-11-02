import { existsSync, readFileSync, writeFileSync } from "node:fs";
import type { MailProvider } from "@ap/mail";
import { actionFor, scanRaw } from "@ap/pipeline";
import type { Settings, Verdict } from "@ap/shared";

export const PHISHING_FOLDER = "Phishing";
export const SUSPICIOUS_LABEL = "Suspicious";

export interface StoredVerdict { verdict: Verdict; action: ReturnType<typeof actionFor>; shadow: boolean }
export type VerdictStore = Map<string, StoredVerdict>;

/** Verdicts persist across restarts so a message the user rescued from Phishing is never re-scored or re-moved. */
export function loadStore(path: string): VerdictStore {
  try {
    return existsSync(path) ? new Map(Object.entries(JSON.parse(readFileSync(path, "utf8")) as Record<string, StoredVerdict>)) : new Map();
  } catch {
    return new Map();
  }
}

export function saveStore(path: string, store: VerdictStore): void {
  writeFileSync(path, JSON.stringify(Object.fromEntries(store)));
}

/** One polling pass. Idempotent: messages already in the store are skipped, so retries never double-act. */
export async function scanInbox(provider: MailProvider, settings: Settings, store: VerdictStore, limit = 25): Promise<string[]> {
  const scanned: string[] = [];
  for (const id of await provider.listRecentInbox(limit)) {
    const prior = store.get(id);
    // Skip anything already handled. A shadow-mode record is only a preview, so switching to act mode re-evaluates it.
    if (prior && !(prior.shadow && !settings.shadowMode)) continue;
    try {
      const verdict = await scanRaw(await provider.fetchRaw(id), id, settings);
      const action = actionFor(verdict, settings);
      if (action === "move_to_phishing") {
        // Check the current folder first: never move what is already there.
        if (!(await provider.getLabelNames(id)).includes(PHISHING_FOLDER)) await provider.move(id, PHISHING_FOLDER);
      }
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
