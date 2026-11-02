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
