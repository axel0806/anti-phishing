const BUCKETS = [10, 50, 100, 250, 500, 1000, 2500, 5000];

const esc = (v: string) => v.replace(/\\/g, "\\\\").replace(/"/g, '\\"').replace(/\n/g, "\\n");
const labelStr = (l: Record<string, string>) => {
  const k = Object.keys(l).sort();
  return k.length ? "{" + k.map((x) => `${x}="${esc(l[x]!)}"`).join(",") + "}" : "";
};

/** Minimal Prometheus-format registry: counters and cumulative histograms. Per process; no external dependency. */
export class Metrics {
  private counters = new Map<string, { name: string; labels: Record<string, string>; n: number }>();
  private hist = new Map<string, { counts: number[]; sum: number; n: number }>();

  inc(name: string, labels: Record<string, string> = {}, by = 1): void {
    const key = name + labelStr(labels);
    const c = this.counters.get(key) ?? { name, labels, n: 0 };
    c.n += by;
    this.counters.set(key, c);
  }

  observe(name: string, value: number): void {
    const h = this.hist.get(name) ?? { counts: new Array(BUCKETS.length).fill(0) as number[], sum: 0, n: 0 };
    BUCKETS.forEach((b, i) => { if (value <= b) h.counts[i]!++; });
    h.sum += value;
    h.n++;
    this.hist.set(name, h);
  }

  render(): string {
    const out: string[] = [];
    for (const [key, c] of [...this.counters].sort(([a], [b]) => a.localeCompare(b))) out.push(`${key} ${c.n}`);
    for (const [name, h] of [...this.hist].sort(([a], [b]) => a.localeCompare(b))) {
      BUCKETS.forEach((b, i) => out.push(`${name}_bucket{le="${b}"} ${h.counts[i]}`));
      out.push(`${name}_bucket{le="+Inf"} ${h.n}`, `${name}_sum ${h.sum}`, `${name}_count ${h.n}`);
    }
    return out.join("\n") + "\n";
  }
}
