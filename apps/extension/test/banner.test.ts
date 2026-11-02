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
