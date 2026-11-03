import { useCallback, useEffect, useState, type ReactNode } from "react";
import { ApiError, download, type Api } from "./api.ts";

/** Runs a loader whenever `deps` change; exposes loading/error state and a reload. */
export function useLoad<T>(load: () => Promise<T>, deps: unknown[]): { data: T | null; error: string | null; loading: boolean; reload: () => void } {
  const [state, setState] = useState<{ data: T | null; error: string | null; loading: boolean }>({ data: null, error: null, loading: true });
  const [tick, setTick] = useState(0);
  useEffect(() => {
    let live = true;
    setState((s) => ({ ...s, loading: true, error: null }));
    load().then(
      (data) => live && setState({ data, error: null, loading: false }),
      (e) => live && setState({ data: null, error: message(e), loading: false }),
    );
    return () => { live = false; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, tick]);
  return { ...state, reload: useCallback(() => setTick((t) => t + 1), []) };
}

export const message = (e: unknown): string => (e instanceof ApiError ? e.message : e instanceof Error ? e.message : "Something went wrong");

export function Panel({ title, children, actions }: { title: string; children: ReactNode; actions?: ReactNode }) {
  return (
    <section className="panel">
      <header><h2>{title}</h2><div className="actions">{actions}</div></header>
      {children}
    </section>
  );
}

export function Status({ loading, error }: { loading: boolean; error: string | null }) {
  if (error) return <p className="error" role="alert">{error}</p>;
  return loading ? <p className="muted">Loading…</p> : null;
}

export function CsvButton({ api, path, name }: { api: Api; path: string; name: string }) {
  const [err, setErr] = useState<string | null>(null);
  return (
    <>
      <button type="button" className="ghost" onClick={() => api.csv(path + (path.includes("?") ? "&" : "?") + "format=csv").then((t) => download(name + ".csv", t), (e) => setErr(message(e)))}>CSV</button>
      {err && <span className="error">{err}</span>}
    </>
  );
}

export function Stat({ label, value, sub }: { label: string; value: string | number; sub?: string }) {
  return <div className="stat"><div className="v">{value}</div><div className="l">{label}</div>{sub && <div className="s">{sub}</div>}</div>;
}

/** Percent change of `cur` against `prev`, or null when there is nothing to compare. */
export function delta(cur: number, prev: number): string | null {
  if (!prev) return null;
  const d = ((cur - prev) / prev) * 100;
  return `${d >= 0 ? "+" : ""}${d.toFixed(0)}% vs previous period`;
}

/** Stacked daily bars (suspicious + phishing) in plain SVG; no chart library. */
export function TrendChart({ rows }: { rows: { date: string; suspicious: number; phishing: number }[] }) {
  if (!rows.length) return <p className="muted">No detections in this period.</p>;
  const W = 640, H = 160, pad = 24;
  const max = Math.max(1, ...rows.map((r) => r.suspicious + r.phishing));
  const bw = (W - pad * 2) / rows.length;
  return (
    <svg viewBox={`0 0 ${W} ${H + 18}`} role="img" aria-label="Daily detections" className="chart">
      <line x1={pad} x2={W - pad} y1={H} y2={H} className="axis" />
      <text x={2} y={12} className="tick">{max}</text>
      {rows.map((r, i) => {
        const ph = (r.phishing / max) * (H - 16), su = (r.suspicious / max) * (H - 16);
        const x = pad + i * bw + bw * 0.1, w = Math.max(1, bw * 0.8);
        return (
          <g key={r.date}>
            <title>{`${r.date}: ${r.phishing} phishing, ${r.suspicious} suspicious`}</title>
            <rect x={x} y={H - ph} width={w} height={ph} className="bar-phish" />
            <rect x={x} y={H - ph - su} width={w} height={su} className="bar-susp" />
          </g>
        );
      })}
      <text x={pad} y={H + 14} className="tick">{rows[0]!.date}</text>
      <text x={W - pad} y={H + 14} textAnchor="end" className="tick">{rows[rows.length - 1]!.date}</text>
    </svg>
  );
}

/** Horizontal bars for a ranked list. */
export function BarList({ items }: { items: { label: string; value: number; note?: string }[] }) {
  if (!items.length) return <p className="muted">Nothing to show.</p>;
  const max = Math.max(1, ...items.map((i) => i.value));
  return (
    <ul className="barlist">
      {items.map((i) => (
        <li key={i.label}>
          <span className="name" title={i.label}>{i.label}</span>
          <span className="track"><span className="fill" style={{ width: `${(i.value / max) * 100}%` }} /></span>
          <span className="num">{i.value}{i.note ? <small> {i.note}</small> : null}</span>
        </li>
      ))}
    </ul>
  );
}
