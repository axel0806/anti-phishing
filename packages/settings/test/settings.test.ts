import { describe, it, expect } from "vitest";
import { DEFAULT_SETTINGS } from "@ap/shared";
import { applyPatch, resolveSettings, type OrgPolicy } from "../src/index.ts";

const org = (values: OrgPolicy["values"] = {}, locked: OrgPolicy["locked"] = []): OrgPolicy => ({ values, locked });

describe("resolveSettings (defaults -> org -> user)", () => {
  it("later layers win, objects merge deeply", () => {
    const r = resolveSettings(DEFAULT_SETTINGS, org({ sensitivity: "strict", flags: { spf_fail: { enabled: true, weight: 30 } } }), {
      flags: { dkim_fail: { enabled: false, weight: 15 } }, categoryMultipliers: { links: 2 },
    });
    expect(r.settings.sensitivity).toBe("strict");
    expect(r.settings.flags.spf_fail?.weight).toBe(30);
    expect(r.settings.flags.dkim_fail?.enabled).toBe(false);
    expect(r.settings.categoryMultipliers.links).toBe(2);
  });
  it("org-locked fields ignore user overrides", () => {
    const r = resolveSettings(DEFAULT_SETTINGS, org({ sensitivity: "strict" }, ["sensitivity"]), { sensitivity: "relaxed" });
    expect(r.settings.sensitivity).toBe("strict");
    expect(r.lockedFields).toEqual(["sensitivity"]);
  });
  it("does not mutate its inputs", () => {
    const snapshot = JSON.stringify(DEFAULT_SETTINGS);
    resolveSettings(DEFAULT_SETTINGS, org(), { flags: { spf_fail: { enabled: true, weight: 1 } } });
    expect(JSON.stringify(DEFAULT_SETTINGS)).toBe(snapshot);
  });
});

describe("applyPatch (JSON Merge Patch on user overrides)", () => {
  it("sets, deep-merges and deletes with null", () => {
    let o = applyPatch({}, { sensitivity: "strict", categoryMultipliers: { links: 2 } }, []);
    expect(o).toEqual({ ok: true, overrides: { sensitivity: "strict", categoryMultipliers: { links: 2 } } });
    o = applyPatch((o as any).overrides, { categoryMultipliers: { content: 1.5 }, sensitivity: null }, []);
    expect(o).toEqual({ ok: true, overrides: { categoryMultipliers: { links: 2, content: 1.5 } } });
  });
  it("rejects locked fields with the offending names", () => {
    expect(applyPatch({}, { sensitivity: "relaxed", enabled: false }, ["sensitivity"])).toEqual({ ok: false, error: "locked_field", fields: ["sensitivity"] });
  });
  it("rejects invalid values and unknown keys", () => {
    expect(applyPatch({}, { thresholds: { suspicious: 80, phishing: 20 } }, [])).toMatchObject({ ok: false, error: "validation" });
    expect(applyPatch({}, { sensitivity: "paranoid" }, [])).toMatchObject({ ok: false, error: "validation" });
    expect(applyPatch({}, { bogus: 1 }, [])).toMatchObject({ ok: false, error: "validation" });
    expect(applyPatch({}, { flags: { not_a_flag: { enabled: true, weight: 1 } } }, [])).toMatchObject({ ok: false, error: "validation" });
  });
  it("does not let lists be set through settings (they live in list endpoints)", () => {
    expect(applyPatch({}, { allowlist: [{ matchType: "domain", value: "a.com" }] }, [])).toMatchObject({ ok: false, error: "validation" });
  });
});
