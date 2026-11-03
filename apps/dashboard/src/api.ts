// Thin, UI-free client and helpers for the admin dashboard. Everything here is unit-testable without a DOM.

export type Role = "viewer" | "analyst" | "admin";
export interface Me { id: string; email: string; role: Role; orgId: string | null; provider: string }
export interface Range { from: string; to: string }

const RANK: Record<Role, number> = { viewer: 1, analyst: 2, admin: 3 };
export const atLeast = (role: Role | undefined, min: Role): boolean => !!role && RANK[role] >= RANK[min];

export interface TabDef { id: string; label: string; min: Role }
export const TABS: TabDef[] = [
  { id: "overview", label: "Overview", min: "viewer" },
  { id: "log", label: "Email log", min: "analyst" },
  { id: "people", label: "People", min: "admin" },
  { id: "lists", label: "Lists", min: "admin" },
  { id: "policy", label: "Policy", min: "admin" },
  { id: "deploy", label: "Deployment", min: "admin" },
  { id: "audit", label: "Audit", min: "admin" },
  { id: "account", label: "Account", min: "viewer" },
];
export const visibleTabs = (role: Role | undefined): TabDef[] => TABS.filter((t) => atLeast(role, t.min));

// ---- session token: sessionStorage, picked up from the #token= fragment after SSO ----
const KEY = "ap_dashboard_token";
export interface TokenStore { getItem(k: string): string | null; setItem(k: string, v: string): void; removeItem(k: string): void }

/** Moves a `#token=` fragment into storage and returns the token to use (or null). The caller clears the fragment from the URL. */
export function takeToken(hash: string, store: TokenStore): string | null {
  const m = /^#token=([A-Za-z0-9._~-]+)$/.exec(hash);
  try {
    if (m) { store.setItem(KEY, m[1]!); return m[1]!; }
    return store.getItem(KEY);
  } catch { return m ? m[1]! : null; }
}
export const forgetToken = (store: TokenStore): void => { try { store.removeItem(KEY); } catch { /* storage unavailable */ } };
export const saveToken = (store: TokenStore, t: string): void => { try { store.setItem(KEY, t.trim()); } catch { /* storage unavailable */ } };

export class ApiError extends Error {
  constructor(public status: number, public code: string, message: string, public fields?: string[]) { super(message); }
}

export type Fetch = (input: string, init?: RequestInit) => Promise<Response>;

export function makeApi(token: string, fetchFn: Fetch = (i, init) => fetch(i, init), base = "") {
  const call = async <T>(method: string, path: string, body?: unknown): Promise<T> => {
    const res = await fetchFn(base + path, {
      method,
      headers: { authorization: `Bearer ${token}`, ...(body !== undefined ? { "content-type": "application/json" } : {}) },
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
    const text = await res.text();
    let data: unknown = null;
    try { data = text ? JSON.parse(text) : null; } catch { /* not JSON */ }
    if (!res.ok) {
      const e = (data as { error?: { code?: string; message?: string; fields?: string[] } } | null)?.error;
      throw new ApiError(res.status, e?.code ?? "error", e?.message ?? `Request failed (${res.status})`, e?.fields);
    }
    return data as T;
  };
  return {
    get: <T>(path: string) => call<T>("GET", path),
    put: <T>(path: string, body: unknown) => call<T>("PUT", path, body),
    post: <T>(path: string, body: unknown) => call<T>("POST", path, body),
    patch: <T>(path: string, body: unknown) => call<T>("PATCH", path, body),
    del: <T>(path: string, body?: unknown) => call<T>("DELETE", path, body),
    /** Downloads a CSV through the authenticated API (a plain link could not send the bearer token). */
    csv: async (path: string): Promise<{ text: string; note?: string }> => {
      const res = await fetchFn(base + path, { headers: { authorization: `Bearer ${token}` } });
      if (!res.ok) throw new ApiError(res.status, "error", `Export failed (${res.status})`);
      const cut = res.headers.get("x-export-truncated");
      return { text: await res.text(), note: cut ? `Only ${cut} rows were exported. Narrow the date range or add filters.` : undefined };
    },
  };
}
export type Api = ReturnType<typeof makeApi>;

export const qs = (params: object): string => {
  const p = new URLSearchParams();
  for (const [k, v] of Object.entries(params) as [string, string | number | undefined | null][]) if (v !== undefined && v !== null && v !== "") p.set(k, String(v));
  const s = p.toString();
  return s ? `?${s}` : "";
};

/** Default range: the last `days` days, ending tomorrow (the API's `to` is exclusive). */
export function defaultRange(days = 30, now = new Date()): Range {
  const day = (d: Date) => d.toISOString().slice(0, 10);
  const to = new Date(now.getTime() + 86_400_000);
  return { from: day(new Date(now.getTime() - (days - 1) * 86_400_000)), to: day(to) };
}

// ---- list bulk import ----
export interface ListEntry { matchType: "address" | "domain"; value: string }
export interface ParsedImport { entries: ListEntry[]; rejected: string[] }

/** One entry per line or comma-separated. `a@b.c` is an address, `b.c` a domain. Duplicates and comments are dropped. */
export function parseBulkImport(text: string): ParsedImport {
  const seen = new Set<string>();
  const entries: ListEntry[] = [];
  const rejected: string[] = [];
  for (const raw of text.split(/[\n,;]+/)) {
    const v = raw.trim().toLowerCase();
    if (!v || v.startsWith("#")) continue;
    let e: ListEntry | null = null;
    if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v)) e = { matchType: "address", value: v };
    else if (/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/.test(v)) e = { matchType: "domain", value: v };
    if (!e) { rejected.push(raw.trim()); continue; }
    const k = `${e.matchType}:${e.value}`;
    if (!seen.has(k)) { seen.add(k); entries.push(e); }
  }
  return { entries, rejected };
}

// ---- managed policy generator ----
export interface ManagedOptions { serverUrl: string; lockServerUrl: boolean }

/** Chrome/Edge `chrome.storage.managed` document (deployed as a managed-storage JSON file or via group policy). */
export const chromeManagedPolicy = (o: ManagedOptions) => ({ serverUrl: o.serverUrl, lockServerUrl: o.lockServerUrl });

/** Firefox `policies.json` fragment: managed storage for an extension lives under `3rdparty.Extensions`. */
export function firefoxPolicy(o: ManagedOptions, extensionId: string) {
  return { policies: { "3rdparty": { Extensions: { [extensionId]: chromeManagedPolicy(o) } } } };
}

/** Validates a server URL for the managed policy: https, or plain http only for loopback. */
export function checkServerUrl(raw: string): string | null {
  let u: URL;
  try { u = new URL(raw); } catch { return "Enter a full URL such as https://phish.example.com"; }
  const loopback = ["localhost", "127.0.0.1", "[::1]"].includes(u.hostname);
  if (u.protocol !== "https:" && !(u.protocol === "http:" && loopback)) return "Use https (plain http is only allowed for localhost)";
  if (u.username || u.password) return "The URL must not contain credentials";
  return null;
}

// ---- policy editing ----
export const LOCKABLE = ["enabled", "sensitivity", "thresholds", "flags", "categoryMultipliers", "protectedDomains", "shadowMode", "ai", "ai.enabled", "ai.mode", "ai.monthlyBudgetUsd"] as const;

/** Toggles a lock; locking a whole setting drops its now-redundant dotted locks. */
export function toggleLock(locked: string[], key: string, on: boolean): string[] {
  const rest = locked.filter((k) => k !== key);
  if (!on) return rest;
  return [...(key.includes(".") ? rest : rest.filter((k) => !k.startsWith(key + "."))), key];
}

export const pct = (x: number): string => `${(x * 100).toFixed(1)}%`;
export const usd = (x: number): string => `$${x.toFixed(2)}`;

/** CSV text → a browser download. */
export function download(name: string, text: string, type = "text/csv"): void {
  const url = URL.createObjectURL(new Blob([text], { type }));
  const a = document.createElement("a");
  a.href = url; a.download = name; a.click();
  URL.revokeObjectURL(url);
}

const UNSAFE = new Set(["__proto__", "constructor", "prototype"]);
/** Returns a copy of `obj` with the value at `path` set, or removed when `value` is undefined (empty parents are pruned). */
export function setField(obj: Record<string, unknown>, path: string[], value: unknown): Record<string, unknown> {
  if (path.some((k) => UNSAFE.has(k))) throw new Error("Unsafe key");
  const [head, ...rest] = path;
  const out: Record<string, unknown> = { ...obj };
  if (!rest.length) {
    if (value === undefined) delete out[head!]; else out[head!] = value;
    return out;
  }
  const child = setField((out[head!] as Record<string, unknown> | undefined) ?? {}, rest, value);
  if (Object.keys(child).length) out[head!] = child; else delete out[head!];
  return out;
}
