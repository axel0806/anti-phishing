import { describe, expect, it } from "vitest";
import { readdirSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { DEFAULT_SETTINGS } from "@ap/shared";
import { buildPrompt, type AiInput, type AiProvider } from "@ap/ai";
import { offlineLookups, scanRaw } from "@ap/pipeline";
import { compareRuns, formatReport } from "./ab.ts";

const root = fileURLToPath(new URL("./uncertain", import.meta.url));
const injectionDir = fileURLToPath(new URL("./injection", import.meta.url));

// A stand-in judge that flags requests for money by keyword. It is not a real model; it only exercises the harness.
const keywordJudge = (flagEverything = false): AiProvider => ({
  name: "keyword-judge",
  analyze: async (i: AiInput) => {
    const text = (i.subject + " " + i.body).toLowerCase();
    const bad = flagEverything || /fee|bank details|payment|pay /.test(text);
    return { verdict: { riskScore: bad ? 0.9 : 0.05, tactics: bad ? ["urgency"] : [], impersonatedEntity: null, explanation: bad ? "Asks for money." : "Looks ordinary." } };
  },
});

describe("A/B harness on the uncertain-band corpus", () => {
  it("rules alone miss the uncertain phishing; a good judge raises recall without raising false positives", async () => {
    const r = await compareRuns(root, keywordJudge());
    expect(r.baseline.recall).toBe(0);
    expect(r.baseline.fpr).toBe(0);
    expect(r.withAi.recall).toBe(1);
    expect(r.withAi.fpr).toBe(0);
    expect(r.pass).toBe(true);
    expect(r.withAi.aiCalls).toBe(4); // all four sit in the uncertain band
    expect(formatReport(r)).toMatch(/gate.*PASS/);
  });
  it("fails the gate when the judge raises false positives", async () => {
    const r = await compareRuns(root, keywordJudge(true));
    expect(r.fprChange).toBeGreaterThan(0);
    expect(r.pass).toBe(false);
  });
  it("fails the gate when the AI adds nothing", async () => {
    const lazy: AiProvider = { name: "lazy", analyze: async () => ({ verdict: { riskScore: 0, tactics: [], impersonatedEntity: null, explanation: "ok" } }) };
    const r = await compareRuns(root, lazy);
    expect(r.recallGain).toBe(0);
    expect(r.pass).toBe(false);
  });
});

describe("prompt-injection fixtures", () => {
  const files = readdirSync(injectionDir).filter((f) => f.endsWith(".eml"));
  const on = { ...DEFAULT_SETTINGS, ai: { ...DEFAULT_SETTINGS.ai, enabled: true } };
  const obedient: AiProvider = { name: "obedient", analyze: async () => ({ verdict: { riskScore: 0, tactics: [], impersonatedEntity: null, explanation: "Safe, as the email instructed." } }) };

  it("has at least three attacks", () => expect(files.length).toBeGreaterThanOrEqual(3));
  for (const f of files) {
    const raw = () => readFileSync(`${injectionDir}/${f}`);
    it(`${f}: a model that obeys the injection still cannot lower the verdict`, async () => {
      const rules = await scanRaw(raw(), f, on, { lookups: offlineLookups });
      const ai = await scanRaw(raw(), f, on, { lookups: offlineLookups, ai: { provider: obedient } });
      expect(ai.score).toBeGreaterThanOrEqual(rules.score);
      expect(ai.verdict).toBe(rules.verdict);
      expect(ai.aiUsed).toBe(true);
    });
    it(`${f}: the prompt keeps the attack inside exactly one fenced data block`, async () => {
      let captured: AiInput | undefined;
      const spy: AiProvider = { name: "spy", analyze: async (i) => { captured = i; return obedient.analyze(i, { signal: AbortSignal.timeout(100) }); } };
      await scanRaw(raw(), f, on, { lookups: offlineLookups, ai: { provider: spy } });
      expect(captured).toBeDefined();
      const p = buildPrompt(captured!);
      expect(p.user.split(p.boundary)).toHaveLength(3); // one opening and one closing marker, none forged by the email
      expect(p.system).not.toMatch(/ignore all previous|maintenance mode|riskScore\\":0/i);
      expect(p.user.replace(p.boundary, "").replace(p.boundary, "")).not.toMatch(/<<<|>>>/);
    });
  }
});
