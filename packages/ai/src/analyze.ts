import { createHash } from "node:crypto";
import { AiVerdictSchema, type AiVerdict } from "./schema.ts";
import type { AiInput } from "./redact.ts";

export interface Usage { inputTokens: number; outputTokens: number }
export interface AiResult { verdict: AiVerdict; usage?: Usage }
export interface AiProvider {
  /** Identifies provider + model; part of the cache key so switching models never serves stale answers. */
  name: string;
  analyze(input: AiInput, opts: { signal: AbortSignal }): Promise<AiResult>;
}

export interface AiCache { get(key: string): Promise<AiVerdict | null>; set(key: string, v: AiVerdict): Promise<void> }
export interface AiBudget { allow(): Promise<boolean>; record(costUsd: number): Promise<void> }
export interface Price { inputPerMTokUsd: number; outputPerMTokUsd: number }

export class MemoryCache implements AiCache {
  private m = new Map<string, AiVerdict>();
  constructor(private max = 1000) {}
  async get(key: string) { return this.m.get(key) ?? null; }
  async set(key: string, v: AiVerdict) {
    if (this.m.size >= this.max) this.m.delete(this.m.keys().next().value!);
    this.m.set(key, v);
  }
}

export function estimateCostUsd(u: Usage | undefined, p: Price): number {
  return u ? (u.inputTokens * p.inputPerMTokUsd + u.outputTokens * p.outputPerMTokUsd) / 1_000_000 : 0;
}

export type AnalyzeResult =
  | { ok: true; verdict: AiVerdict; cached: boolean; usage?: Usage; costUsd: number }
  | { ok: false; reason: "timeout" | "error" | "invalid" | "budget"; message?: string };

export const cacheKey = (provider: AiProvider, input: AiInput) =>
  createHash("sha256").update(provider.name + "\n" + JSON.stringify(input)).digest("hex");

/**
 * One guarded model call. Never throws: any failure becomes `ok: false` so the caller falls back to rules-only scoring.
 * Order: cache (free) -> budget -> model call with a hard timeout -> schema validation -> record cost and cache.
 */
export async function analyze(
  provider: AiProvider, input: AiInput,
  opts: { timeoutMs: number; cache?: AiCache; budget?: AiBudget; price?: Price },
): Promise<AnalyzeResult> {
  const key = cacheKey(provider, input);
  try {
    const hit = await opts.cache?.get(key);
    if (hit) return { ok: true, verdict: hit, cached: true, costUsd: 0 };
    if (opts.budget && !(await opts.budget.allow())) return { ok: false, reason: "budget" };

    const signal = AbortSignal.timeout(opts.timeoutMs);
    const aborted = new Promise<never>((_, reject) => signal.addEventListener("abort", () => reject(new Error("timeout")), { once: true }));
    let raw;
    try {
      raw = await Promise.race([provider.analyze(input, { signal }), aborted]);
    } catch (e) {
      if (signal.aborted) return { ok: false, reason: "timeout" };
      return { ok: false, reason: "error", message: (e as Error).message };
    }
    const parsed = AiVerdictSchema.safeParse(raw.verdict);
    if (!parsed.success) return { ok: false, reason: "invalid", message: parsed.error.issues[0]?.message };

    const costUsd = opts.price ? estimateCostUsd(raw.usage, opts.price) : 0;
    await opts.budget?.record(costUsd);
    await opts.cache?.set(key, parsed.data);
    return { ok: true, verdict: parsed.data, cached: false, usage: raw.usage, costUsd };
  } catch (e) {
    return { ok: false, reason: "error", message: (e as Error).message };
  }
}
