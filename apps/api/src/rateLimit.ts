/** Fixed-window counter per key, in memory. Enough to stop a script hammering one endpoint; a multi-process deployment limits per process. */
export class RateLimiter {
  private hits = new Map<string, { n: number; reset: number }>();

  constructor(private windowMs: number, private max: number, private now: () => number = Date.now) {}

  take(key: string): { ok: boolean; retryAfterSec: number } {
    const t = this.now();
    let h = this.hits.get(key);
    if (!h || h.reset <= t) { h = { n: 0, reset: t + this.windowMs }; this.hits.set(key, h); }
    h.n++;
    return { ok: h.n <= this.max, retryAfterSec: Math.max(1, Math.ceil((h.reset - t) / 1000)) };
  }

  /** Drops windows that have ended. Call now and then; the app does so on a timer. */
  sweep(): void {
    const t = this.now();
    for (const [k, h] of this.hits) if (h.reset <= t) this.hits.delete(k);
  }

  get size(): number { return this.hits.size; }
}
