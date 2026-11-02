import type { DetectorContext } from "@ap/detectors";

type Lookups = DetectorContext["lookups"];
const DOMAIN = /^(?:[a-z0-9-]+\.)+[a-z]{2,}$/i;
const DAY_MS = 86_400_000;

class TtlCache<V> {
  private m = new Map<string, { v: V; at: number }>();
  constructor(private ttlMs: number, private max = 5000) {}
  get(k: string): V | undefined {
    const e = this.m.get(k);
    if (!e) return undefined;
    if (Date.now() - e.at > this.ttlMs) { this.m.delete(k); return undefined; }
    return e.v;
  }
  set(k: string, v: V) {
    if (this.m.size >= this.max) this.m.delete(this.m.keys().next().value!);
    this.m.set(k, { v, at: Date.now() });
  }
}

export interface LookupOptions {
  /** Look up sender domain registration dates via RDAP. Off by default: the domain name leaves your server. */
  rdap?: boolean;
  /** Google Safe Browsing API key. Without it, no URL is ever sent anywhere. */
  safeBrowsingKey?: string;
  fetch?: typeof fetch;
  timeoutMs?: number;
  log?: (m: string) => void;
}

/**
 * The detectors' network lookups. Both fail open: a timeout, quota error or malformed answer means "unknown",
 * which never raises a flag. Answers are cached (RDAP 24 h, threat intel 1 h) as the plan specifies.
 */
export function createLookups(o: LookupOptions = {}): Lookups {
  const f = o.fetch ?? fetch;
  const timeoutMs = o.timeoutMs ?? 2000;
  const age = new TtlCache<number | null>(DAY_MS);
  const threat = new TtlCache<boolean>(DAY_MS / 24);

  return {
    async domainAgeDays(domain) {
      if (!o.rdap || !DOMAIN.test(domain)) return null;
      const key = domain.toLowerCase();
      const hit = age.get(key);
      if (hit !== undefined) return hit;
      let days: number | null = null;
      try {
        const res = await f(`https://rdap.org/domain/${key}`, { signal: AbortSignal.timeout(timeoutMs) });
        if (res.ok) {
          const j = (await res.json()) as { events?: { eventAction?: string; eventDate?: string }[] };
          const reg = j.events?.find((e) => e.eventAction === "registration")?.eventDate;
          const t = reg ? Date.parse(reg) : NaN;
          if (Number.isFinite(t)) days = Math.max(0, Math.floor((Date.now() - t) / DAY_MS));
        }
      } catch (e) {
        o.log?.(`RDAP lookup failed for ${key}: ${(e as Error).message}`);
      }
      age.set(key, days);
      return days;
    },

    async threatIntel(url) {
      if (!o.safeBrowsingKey) return false;
      let clean: string;
      try {
        const u = new URL(url);
        clean = `${u.protocol}//${u.host}${u.pathname}`; // query strings and fragments can carry tokens: never send them
      } catch {
        return false;
      }
      const hit = threat.get(clean);
      if (hit !== undefined) return hit;
      let bad = false;
      try {
        const res = await f(`https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${encodeURIComponent(o.safeBrowsingKey)}`, {
          method: "POST",
          signal: AbortSignal.timeout(timeoutMs),
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            client: { clientId: "anti-phishing", clientVersion: "1" },
            threatInfo: {
              threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"], platformTypes: ["ANY_PLATFORM"],
              threatEntryTypes: ["URL"], threatEntries: [{ url: clean }],
            },
          }),
        });
        if (res.ok) {
          const j = (await res.json()) as { matches?: unknown[] };
          bad = Array.isArray(j.matches) && j.matches.length > 0;
        } else o.log?.(`Safe Browsing answered ${res.status}; failing open`);
      } catch (e) {
        o.log?.(`Safe Browsing lookup failed: ${(e as Error).message}`);
      }
      threat.set(clean, bad);
      return bad;
    },
  };
}
