import { existsSync, readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { DEFAULT_SETTINGS, type Settings } from "@ap/shared";
import { MemoryCache, type AiProvider } from "@ap/ai";
import { offlineLookups, scanRaw } from "@ap/pipeline";

export interface RunStats { phishing: number; legit: number; tp: number; fp: number; recall: number; fpr: number; aiCalls: number; aiUsed: number }
export interface AbReport {
  baseline: RunStats; withAi: RunStats; recallGain: number; fprChange: number; pass: boolean;
  details: { file: string; label: string; baseline: string; withAi: string }[];
}

const dir = dirname(fileURLToPath(import.meta.url));

/** Counts "Suspicious or Phishing" as flagged: this is about what reaches the user's attention. */
async function run(root: string, settings: Settings, provider: AiProvider | null, tally: (f: string, label: string, v: string) => void): Promise<RunStats> {
  const s: RunStats = { phishing: 0, legit: 0, tp: 0, fp: 0, recall: 0, fpr: 0, aiCalls: 0, aiUsed: 0 };
  const cache = new MemoryCache();
  const counting: AiProvider | null = provider && { name: provider.name, analyze: async (i, o) => { s.aiCalls++; return provider.analyze(i, o); } };
  for (const label of ["phishing", "legit"] as const) {
    const d = join(root, label);
    if (!existsSync(d)) continue;
    for (const f of readdirSync(d).filter((x) => x.endsWith(".eml"))) {
      const v = await scanRaw(readFileSync(join(d, f)), f, settings, { lookups: offlineLookups, ai: counting ? { provider: counting, cache } : undefined });
      if (v.aiUsed) s.aiUsed++;
      tally(f, label, v.verdict);
      if (label === "phishing") { s.phishing++; if (v.verdict !== "safe") s.tp++; } else { s.legit++; if (v.verdict !== "safe") s.fp++; }
    }
  }
  s.recall = s.phishing ? s.tp / s.phishing : 1;
  s.fpr = s.legit ? s.fp / s.legit : 0;
  return s;
}

/**
 * Phase 3 gate: the AI must raise recall on the uncertain band without raising the false-positive rate.
 * Runs the same labelled emails through the rules-only pipeline and the rules + AI pipeline.
 */
export async function compareRuns(root: string, provider: AiProvider, base: Settings = DEFAULT_SETTINGS): Promise<AbReport> {
  const rows = new Map<string, { file: string; label: string; baseline: string; withAi: string }>();
  const record = (key: "baseline" | "withAi") => (f: string, label: string, v: string) => {
    const r = rows.get(label + f) ?? { file: f, label, baseline: "", withAi: "" };
    r[key] = v;
    rows.set(label + f, r);
  };
  const baseline = await run(root, { ...base, ai: { ...base.ai, enabled: false } }, null, record("baseline"));
  const withAi = await run(root, { ...base, ai: { ...base.ai, enabled: true, mode: "uncertain_only" } }, provider, record("withAi"));
  const recallGain = withAi.recall - baseline.recall;
  const fprChange = withAi.fpr - baseline.fpr;
  return { baseline, withAi, recallGain, fprChange, pass: recallGain > 0 && fprChange <= 0, details: [...rows.values()] };
}

export function formatReport(r: AbReport): string {
  const pct = (x: number) => (x * 100).toFixed(1) + "%";
  const sign = (x: number) => (x >= 0 ? "+" : "") + (x * 100).toFixed(1) + " pts";
  return [
    "A/B: rules-only vs rules + AI (uncertain band)",
    `  recall  ${pct(r.baseline.recall)} -> ${pct(r.withAi.recall)}  (${sign(r.recallGain)})`,
    `  FPR     ${pct(r.baseline.fpr)} -> ${pct(r.withAi.fpr)}  (${sign(r.fprChange)})`,
    `  model calls: ${r.withAi.aiCalls}, emails escalated: ${r.withAi.aiUsed} of ${r.withAi.phishing + r.withAi.legit}`,
    `  gate (recall up, FPR not up): ${r.pass ? "PASS" : "FAIL"}`,
    ...r.details.map((d) => `    ${d.label.padEnd(9)} ${d.file.padEnd(28)} ${d.baseline.padEnd(11)} -> ${d.withAi}`),
  ].join("\n");
}

// CLI: npm run corpus:ab [path]   (needs AI_PROVIDER=anthropic + ANTHROPIC_API_KEY, or AI_PROVIDER=openai + AI_BASE_URL + AI_MODEL)
if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const { AnthropicProvider, OpenAiCompatibleProvider } = await import("@ap/ai");
  const e = process.env;
  let provider: AiProvider;
  if (e.AI_PROVIDER === "anthropic" && e.ANTHROPIC_API_KEY) provider = new AnthropicProvider({ apiKey: e.ANTHROPIC_API_KEY, model: e.AI_MODEL ?? "claude-haiku-5-5" });
  else if (e.AI_PROVIDER === "openai" && e.AI_BASE_URL && e.AI_MODEL) provider = new OpenAiCompatibleProvider({ baseUrl: e.AI_BASE_URL, model: e.AI_MODEL, apiKey: e.AI_API_KEY });
  else {
    console.error("Set AI_PROVIDER=anthropic (+ANTHROPIC_API_KEY) or AI_PROVIDER=openai (+AI_BASE_URL, AI_MODEL).");
    process.exit(1);
  }
  console.log(formatReport(await compareRuns(process.argv[2] ?? join(dir, "uncertain"), provider)));
}
