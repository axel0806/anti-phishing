import { readdirSync, readFileSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { DEFAULT_SETTINGS, type Settings } from "@ap/shared";
import { scanRaw } from "@ap/pipeline";

export interface CorpusReport {
  total: number; tp: number; fp: number; fn: number; tn: number;
  precision: number; recall: number; fpr: number; misses: string[]; falsePositives: string[];
}

const dir = dirname(fileURLToPath(import.meta.url));

/** "Positive" means the email was classified as phishing or suspicious (anything the user is warned about) when `strict`=false; phishing only when true. */
export async function runCorpus(root = dir, settings: Settings = DEFAULT_SETTINGS, threshold: "suspicious" | "phishing" = "phishing"): Promise<CorpusReport> {
  const r: CorpusReport = { total: 0, tp: 0, fp: 0, fn: 0, tn: 0, precision: 0, recall: 0, fpr: 0, misses: [], falsePositives: [] };
  for (const label of ["phishing", "legit"] as const) {
    const d = join(root, label);
    if (!existsSync(d)) continue;
    for (const f of readdirSync(d).filter((x) => x.endsWith(".eml"))) {
      const v = await scanRaw(readFileSync(join(d, f)), f, settings);
      const flagged = threshold === "phishing" ? v.verdict === "phishing" : v.verdict !== "safe";
      r.total++;
      if (label === "phishing") { if (flagged) r.tp++; else { r.fn++; r.misses.push(f); } }
      else if (flagged) { r.fp++; r.falsePositives.push(f); } else r.tn++;
    }
  }
  r.precision = r.tp + r.fp ? r.tp / (r.tp + r.fp) : 1;
  r.recall = r.tp + r.fn ? r.tp / (r.tp + r.fn) : 1;
  r.fpr = r.fp + r.tn ? r.fp / (r.fp + r.tn) : 0;
  return r;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const rep = await runCorpus();
  console.log(JSON.stringify(rep, null, 2));
}
