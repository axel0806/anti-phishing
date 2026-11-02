export interface VerdictDto {
  verdict: { score: number; verdict: "safe" | "suspicious" | "phishing"; flags: { id: string; weight: number; evidence: string }[]; reason?: string; aiExplanation?: string };
  action: string;
  shadow: boolean;
}

export interface BannerModel {
  level: "suspicious" | "phishing";
  title: string;
  note?: string;
  /** Plain-language assessment from the AI layer, when it was used. */
  explanation?: string;
  reasons: string[];
}

/** Pure: decides what to show. Returns null for safe mail. Reasons are the top flags, highest weight first. */
export function bannerModel(dto: VerdictDto): BannerModel | null {
  const v = dto.verdict;
  if (v.verdict === "safe") return null;
  const reasons = [...v.flags]
    .filter((f) => f.weight > 0 && f.id !== "ai_intent") // its text is shown as the explanation instead
    .sort((a, b) => b.weight - a.weight)
    .slice(0, 3)
    .map((f) => f.evidence);
  if (reasons.length === 0 && v.reason) reasons.push(v.reason);
  return {
    level: v.verdict,
    title: `${v.verdict === "phishing" ? "Likely phishing" : "Suspicious email"} (risk score ${v.score}/100)`,
    note: dto.shadow ? "Shadow mode: this email was not moved." : undefined,
    reasons,
    explanation: v.aiExplanation,
  };
}
