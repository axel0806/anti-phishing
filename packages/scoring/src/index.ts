import { type Flag, type Settings, type Verdict, thresholdsFor } from "@ap/shared";

export const AI_POINT_CAP = 40;

export function score(flags: Flag[], settings: Settings, opts: { aiUsed?: boolean; settingsVersion?: number } = {}): Verdict {
  // Each flag ID counts once per email: keep the highest-weight instance.
  const byId = new Map<string, Flag>();
  for (const f of flags) {
    const prev = byId.get(f.id);
    // A deterministic rule flag always beats an AI copy of the same id, so its evidence survives and it stays outside the AI cap.
    const better = !prev || (f.source === "rule" && prev.source === "ai") || (f.source === prev.source && f.weight > prev.weight);
    if (better) byId.set(f.id, f);
  }
  const unique = [...byId.values()];

  const mult = (f: Flag) => settings.categoryMultipliers[f.category] ?? 1;
  let ruleTotal = 0;
  let aiTotal = 0;
  for (const f of unique) {
    const pts = f.weight * mult(f);
    if (f.source === "ai") aiTotal += pts; else ruleTotal += pts;
  }
  aiTotal = Math.min(aiTotal, AI_POINT_CAP);
  const total = Math.round(Math.min(100, Math.max(0, ruleTotal + aiTotal)));

  const t = thresholdsFor(settings);
  let verdict: Verdict["verdict"] = total >= t.phishing ? "phishing" : total >= t.suspicious ? "suspicious" : "safe";
  // The LLM alone can never push an email into Phishing: it needs a deterministic positive flag.
  const hasRulePositive = unique.some((f) => f.source === "rule" && f.weight > 0);
  if (verdict === "phishing" && !hasRulePositive) verdict = "suspicious";

  return { score: total, verdict, flags: unique, aiUsed: opts.aiUsed ?? aiTotal > 0, settingsVersion: opts.settingsVersion ?? 0 };
}
