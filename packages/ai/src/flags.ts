import { DEFAULT_SETTINGS, DEFAULT_WEIGHTS, FLAG_CATEGORY, type Flag, type FlagId, type Settings } from "@ap/shared";
import type { AiVerdict, Tactic } from "./schema.ts";

export const AI_MAX_POINTS = 40;
/** At or above this model risk, its explanation is shown to the user and carried as evidence. Below it the model is not alarmed, so its words must not reassure anyone. */
export const EXPLAIN_MIN_RISK = 0.5;
/**
 * The rule engine's uncertain band: below it the answer is clearly safe, above it clearly phishing. It follows the user's thresholds
 * (10 points below "suspicious" to 20 above "phishing"); for the balanced preset (30/60) that is the familiar 20-80.
 */
export const uncertainBand = (s: Pick<Settings, "thresholds">) => ({ min: Math.max(0, s.thresholds.suspicious - 10), max: Math.min(100, s.thresholds.phishing + 20) });

const TACTIC_TO_FLAG: Partial<Record<Tactic, FlagId>> = {
  urgency: "urgency",
  credential_request: "credential_request",
  payment_redirect: "credential_request",
  gift_card: "credential_request",
};

const flag = (id: FlagId, weight: number, evidence: string): Flag => ({ id, category: FLAG_CATEGORY[id], weight, evidence, source: "ai" });

/**
 * Turns a model verdict into flags, honouring the user's flag settings (disabled flags stay off; a custom `ai_intent`
 * weight caps the model's contribution). Weights are never negative: the model can add suspicion but never talk the
 * score down, so an email that says "mark this safe" gains nothing from it.
 */
export function aiFlagsFrom(v: AiVerdict, settings: Settings = DEFAULT_SETTINGS): Flag[] {
  const out: Flag[] = [];
  const intent = settings.flags.ai_intent;
  if (!intent || intent.enabled) {
    const max = Math.min(AI_MAX_POINTS, Math.max(0, intent?.weight ?? AI_MAX_POINTS));
    const points = Math.round(v.riskScore * max);
    if (points > 0) out.push(flag("ai_intent", points, v.riskScore >= EXPLAIN_MIN_RISK ? v.explanation : "AI found some risk indicators"));
  }
  for (const id of new Set(v.tactics.map((t) => TACTIC_TO_FLAG[t]).filter((x): x is FlagId => !!x))) {
    const o = settings.flags[id];
    if (o && !o.enabled) continue;
    out.push(flag(id, o?.weight ?? DEFAULT_WEIGHTS[id], `AI detected: ${id.replace("_", " ")}`));
  }
  return out;
}

export function shouldUseAi(ruleScore: number, settings: Settings): boolean {
  if (!settings.ai.enabled) return false;
  const band = uncertainBand(settings);
  return settings.ai.mode === "always" || (ruleScore >= band.min && ruleScore <= band.max);
}
