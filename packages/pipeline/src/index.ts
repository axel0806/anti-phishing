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
  const listed = checkLists(email, settings);
  if (listed) return { score: listed === "safe" ? 0 : 100, verdict: listed, flags: [], aiUsed: false, settingsVersion: 0 };
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
