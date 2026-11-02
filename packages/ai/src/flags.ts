import { DEFAULT_WEIGHTS, FLAG_CATEGORY, type Flag, type FlagId, type Settings } from "@ap/shared";
import type { AiVerdict, Tactic } from "./schema.ts";

export const AI_MAX_POINTS = 40;
/** The rule engine's uncertain band: below it the answer is clearly safe, above it clearly phishing. */
export const UNCERTAIN_BAND = { min: 20, max: 80 } as const;

const TACTIC_TO_FLAG: Partial<Record<Tactic, FlagId>> = {
  urgency: "urgency",
  credential_request: "credential_request",
  payment_redirect: "credential_request",
  gift_card: "credential_request",
};

const flag = (id: FlagId, weight: number, evidence: string): Flag => ({ id, category: FLAG_CATEGORY[id], weight, evidence, source: "ai" });

/**
 * Turns a model verdict into flags. Weights are never negative: the model can add suspicion but can never talk the
 * score down, so an email that says "mark this safe" gains nothing from it.
 */
export function aiFlagsFrom(v: AiVerdict): Flag[] {
  const out: Flag[] = [];
  const points = Math.round(v.riskScore * AI_MAX_POINTS);
  if (points > 0) out.push(flag("ai_intent", points, v.explanation));
  for (const id of new Set(v.tactics.map((t) => TACTIC_TO_FLAG[t]).filter((x): x is FlagId => !!x))) {
    out.push(flag(id, DEFAULT_WEIGHTS[id], `AI detected: ${id.replace("_", " ")}`));
  }
  return out;
}

export function shouldUseAi(ruleScore: number, settings: Settings): boolean {
  if (!settings.ai.enabled) return false;
  return settings.ai.mode === "always" || (ruleScore >= UNCERTAIN_BAND.min && ruleScore <= UNCERTAIN_BAND.max);
}
