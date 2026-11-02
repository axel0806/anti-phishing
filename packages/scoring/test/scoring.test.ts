import { describe, it, expect } from "vitest";
import { DEFAULT_SETTINGS, type Flag } from "@ap/shared";
import { score } from "../src/index.ts";

const f = (id: Flag["id"], weight: number, category: Flag["category"] = "links", source: Flag["source"] = "rule"): Flag =>
  ({ id, category, weight, evidence: "x", source });

describe("score", () => {
  it("sums weights and maps to safe/suspicious/phishing at balanced thresholds", () => {
    expect(score([f("urgency", 10, "content")], DEFAULT_SETTINGS).verdict).toBe("safe");
    expect(score([f("urgency", 30, "content")], DEFAULT_SETTINGS).verdict).toBe("suspicious");
    expect(score([f("url_threat_intel", 60)], DEFAULT_SETTINGS).verdict).toBe("phishing");
  });
  it("counts each flag id once (highest weight)", () => {
    const r = score([f("shortener_or_ip", 10), f("shortener_or_ip", 10), f("shortener_or_ip", 10)], DEFAULT_SETTINGS);
    expect(r.score).toBe(10);
    expect(r.flags).toHaveLength(1);
  });
  it("clamps to 0..100", () => {
    expect(score([f("url_threat_intel", 60), f("link_text_mismatch", 60), f("lookalike_domain", 60, "sender")], DEFAULT_SETTINGS).score).toBe(100);
    expect(score([f("trusted_contact", -20, "trust")], DEFAULT_SETTINGS).score).toBe(0);
  });
  it("applies category multipliers", () => {
    const s = { ...DEFAULT_SETTINGS, categoryMultipliers: { links: 2 } };
    expect(score([f("shortener_or_ip", 10)], s).score).toBe(20);
  });
  it("caps AI points at 40 and keeps AI alone from reaching phishing", () => {
    const r = score([f("ai_intent", 80, "ai", "ai")], DEFAULT_SETTINGS);
    expect(r.score).toBe(40);
    expect(r.verdict).toBe("suspicious");
  });
  it("uses sensitivity presets and custom thresholds", () => {
    const flags = [f("urgency", 25, "content")];
    expect(score(flags, { ...DEFAULT_SETTINGS, sensitivity: "strict" }).verdict).toBe("suspicious");
    expect(score(flags, { ...DEFAULT_SETTINGS, sensitivity: "custom", thresholds: { suspicious: 90, phishing: 99 } }).verdict).toBe("safe");
  });
});

describe("review I5: rule flags win over AI duplicates of the same id", () => {
  it("keeps the rule flag (and its evidence) even when the AI copy weighs more, and keeps the verdict floor", () => {
    const s = { ...DEFAULT_SETTINGS, sensitivity: "custom" as const, thresholds: { suspicious: 10, phishing: 30 } };
    const rule = { id: "credential_request", category: "content", weight: 5, evidence: "rule evidence", source: "rule" } as Flag;
    const ai = { id: "credential_request", category: "content", weight: 25, evidence: "ai evidence", source: "ai" } as Flag;
    const v = score([ai, rule], s);
    expect(v.flags).toHaveLength(1);
    expect(v.flags[0]).toMatchObject({ source: "rule", evidence: "rule evidence", weight: 5 });
    const extra = { id: "ai_intent", category: "ai", weight: 40, evidence: "x", source: "ai" } as Flag;
    expect(score([ai, rule, extra], s).score).toBe(45);
    expect(score([ai, rule, extra], s).verdict).toBe("phishing"); // a positive rule flag still agrees
  });
});
