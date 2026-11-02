import { describe, it, expect } from "vitest";
import { bannerModel, type VerdictDto } from "../src/banner.ts";

const dto = (verdict: "safe" | "suspicious" | "phishing", shadow = false): VerdictDto => ({
  action: "none", shadow,
  verdict: { score: 70, verdict, flags: [
    { id: "a", weight: 10, evidence: "small" }, { id: "b", weight: 35, evidence: "big" },
    { id: "c", weight: -20, evidence: "trust" }, { id: "d", weight: 25, evidence: "mid" }, { id: "e", weight: 5, evidence: "tiny" },
  ] },
});

describe("bannerModel", () => {
  it("shows nothing for safe mail", () => expect(bannerModel(dto("safe"))).toBeNull());
  it("lists the top three positive flags, heaviest first", () => {
    const m = bannerModel(dto("phishing"))!;
    expect(m.level).toBe("phishing");
    expect(m.reasons).toEqual(["big", "mid", "small"]);
    expect(m.title).toContain("70/100");
  });
  it("notes shadow mode", () => expect(bannerModel(dto("suspicious", true))!.note).toMatch(/not moved/));
});

describe("bannerModel list reasons", () => {
  it("falls back to the verdict reason when there are no flags", () => {
    const m = bannerModel({ action: "none", shadow: false, verdict: { score: 100, verdict: "phishing", flags: [], reason: "Sender is on your blocklist" } })!;
    expect(m.reasons).toEqual(["Sender is on your blocklist"]);
  });
});

describe("bannerModel AI explanation", () => {
  const base = { action: "none", shadow: false, verdict: { score: 70, verdict: "phishing" as const, flags: [{ id: "ai_intent", weight: 36, evidence: "Fake delivery notice." }], aiExplanation: "Fake delivery notice." } };
  it("carries the AI explanation separately and does not repeat it as a reason", () => {
    const m = bannerModel(base)!;
    expect(m.explanation).toBe("Fake delivery notice.");
    expect(m.reasons).toEqual([]);
  });
  it("keeps other reasons and has no explanation when the AI was not used", () => {
    const withRule = { ...base, verdict: { ...base.verdict, flags: [...base.verdict.flags, { id: "spf_fail", weight: 20, evidence: "SPF fail" }] } };
    expect(bannerModel(withRule)!.reasons).toEqual(["SPF fail"]);
    const noAi = bannerModel({ ...base, verdict: { ...base.verdict, aiExplanation: undefined, flags: [{ id: "spf_fail", weight: 20, evidence: "SPF fail" }] } })!;
    expect(noAi.explanation).toBeUndefined();
  });
});
