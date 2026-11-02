import { parseEmail } from "@ap/parser";
import { checkLists, runDetectors, type DetectorContext } from "@ap/detectors";
import { score } from "@ap/scoring";
import type { ParsedEmail, Settings, Verdict } from "@ap/shared";

export type ScanContext = Omit<DetectorContext, "settings">;

export const offlineLookups: DetectorContext["lookups"] = {
  domainAgeDays: async () => null,
  threatIntel: async () => false,
};

/** List check -> rule engine -> score. (AI stage arrives in Phase 3.) */
export async function scanParsed(email: ParsedEmail, settings: Settings, ctx: ScanContext = { lookups: offlineLookups }): Promise<Verdict> {
  let listed = checkLists(email, settings);
  // A From address is trivially spoofed: the allowlist only applies when DMARC passed for it.
  if (listed === "safe" && email.auth.dmarc !== "pass") listed = null;
  if (listed) {
    const reason = listed === "safe" ? "Sender is on your allowlist" : "Sender is on your blocklist";
    return { score: listed === "safe" ? 0 : 100, verdict: listed, flags: [], aiUsed: false, settingsVersion: 0, reason };
  }
  const flags = await runDetectors(email, { ...ctx, settings });
  return score(flags, settings);
}

export async function scanRaw(raw: Buffer, id: string, settings: Settings, ctx?: ScanContext): Promise<Verdict> {
  return scanParsed(await parseEmail(raw, id), settings, ctx);
}

/** In shadow mode a verdict is logged but no action (move/label) is taken. */
export function actionFor(v: Verdict, settings: Settings): "move_to_phishing" | "label_suspicious" | "none" {
  if (settings.shadowMode || !settings.enabled) return "none";
  return v.verdict === "phishing" ? "move_to_phishing" : v.verdict === "suspicious" ? "label_suspicious" : "none";
}
