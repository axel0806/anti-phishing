import { parseEmail } from "@ap/parser";
import { checkLists, runDetectors, type DetectorContext } from "@ap/detectors";
import { score } from "@ap/scoring";
import { aiFlagsFrom, analyze, buildAiInput, shouldUseAi, type AiBudget, type AiCache, type AiProvider, type Price } from "@ap/ai";
import type { ParsedEmail, Settings, Verdict } from "@ap/shared";

/** Optional AI stage: judgment on intent and social engineering that rules cannot make. */
export interface AiStage {
  provider: AiProvider;
  /** Hard limit; on timeout the verdict falls back to rules-only. Default 2500 ms. */
  timeoutMs?: number;
  cache?: AiCache;
  budget?: AiBudget;
  price?: Price;
  /** Called when the model could not be used, so the caller can log it. */
  onEvent?: (e: { reason: "timeout" | "error" | "invalid" | "budget"; message?: string }) => void;
}

export type ScanContext = Omit<DetectorContext, "settings"> & { ai?: AiStage };

export const offlineLookups: DetectorContext["lookups"] = {
  domainAgeDays: async () => null,
  threatIntel: async () => false,
};

export const DEFAULT_AI_TIMEOUT_MS = 2500;

/**
 * List check -> rule engine -> (uncertain band only) AI -> score.
 * The AI can only add points (never subtract), is capped at 40, and any failure yields the exact rules-only verdict.
 */
export async function scanParsed(email: ParsedEmail, settings: Settings, ctx: ScanContext = { lookups: offlineLookups }): Promise<Verdict> {
  let listed = checkLists(email, settings);
  // A From address is trivially spoofed: the allowlist only applies when DMARC passed for it.
  if (listed === "safe" && email.auth.dmarc !== "pass") listed = null;
  if (listed) {
    const reason = listed === "safe" ? "Sender is on your allowlist" : "Sender is on your blocklist";
    return { score: listed === "safe" ? 0 : 100, verdict: listed, flags: [], aiUsed: false, settingsVersion: 0, reason };
  }
  const flags = await runDetectors(email, { ...ctx, settings });
  const rulesOnly = score(flags, settings);

  const ai = ctx.ai;
  if (!ai || !shouldUseAi(rulesOnly.score, settings)) return rulesOnly;

  const result = await analyze(ai.provider, buildAiInput(email, flags), {
    timeoutMs: ai.timeoutMs ?? DEFAULT_AI_TIMEOUT_MS, cache: ai.cache, budget: ai.budget, price: ai.price,
  });
  if (!result.ok) {
    ai.onEvent?.({ reason: result.reason, message: result.message });
    return rulesOnly;
  }
  const withAi = score([...flags, ...aiFlagsFrom(result.verdict)], settings, { aiUsed: true });
  withAi.aiExplanation = result.verdict.explanation;
  return withAi;
}

export async function scanRaw(raw: Buffer, id: string, settings: Settings, ctx?: ScanContext): Promise<Verdict> {
  return scanParsed(await parseEmail(raw, id), settings, ctx);
}

/** In shadow mode a verdict is logged but no action (move/label) is taken. */
export function actionFor(v: Verdict, settings: Settings): "move_to_phishing" | "label_suspicious" | "none" {
  if (settings.shadowMode || !settings.enabled) return "none";
  return v.verdict === "phishing" ? "move_to_phishing" : v.verdict === "suspicious" ? "label_suspicious" : "none";
}
