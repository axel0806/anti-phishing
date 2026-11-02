import type { VerdictDto } from "./banner.ts";

/** Per-message verdict cache: hits are kept for the session, misses (null) only for `missTtlMs` so a later scan is picked up. */
export class VerdictCache {
  private entries = new Map<string, { value: VerdictDto | null; at: number }>();
  private pending = new Map<string, Promise<VerdictDto | null>>();

  constructor(
    private fetcher: (id: string) => Promise<VerdictDto | null>,
    private missTtlMs = 30_000,
    private now: () => number = Date.now,
  ) {}

  async get(id: string): Promise<VerdictDto | null> {
    const e = this.entries.get(id);
    if (e && (e.value !== null || this.now() - e.at < this.missTtlMs)) return e.value;
    const inflight = this.pending.get(id);
    if (inflight) return inflight;
    const p = this.fetcher(id).then((value) => {
      this.entries.set(id, { value, at: this.now() });
      this.pending.delete(id);
      return value;
    }, (err) => { this.pending.delete(id); throw err; });
    this.pending.set(id, p);
    return p;
  }
}
