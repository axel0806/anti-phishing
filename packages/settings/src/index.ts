import { z } from "zod";
import { FLAG_IDS, type FlagCategory, type Settings } from "@ap/shared";

const CATEGORIES = ["authentication", "sender", "links", "attachments", "content", "ai", "trust"] as const satisfies readonly FlagCategory[];

/** What a user or org may override. Allow/block lists are managed through their own endpoints, not here. */
export const SettingsOverridesSchema = z.strictObject({
  enabled: z.boolean(),
  sensitivity: z.enum(["relaxed", "balanced", "strict", "custom"]),
  thresholds: z.strictObject({ suspicious: z.number().min(0).max(100), phishing: z.number().min(0).max(100) })
    .refine((t) => t.suspicious < t.phishing, { message: "suspicious must be lower than phishing" }),
  flags: z.partialRecord(z.enum(FLAG_IDS), z.strictObject({ enabled: z.boolean(), weight: z.number().min(-100).max(100) })),
  categoryMultipliers: z.partialRecord(z.enum(CATEGORIES), z.number().min(0).max(10)),
  protectedDomains: z.array(z.string().min(1)).max(500),
  shadowMode: z.boolean(),
}).partial();

export type SettingsOverrides = z.infer<typeof SettingsOverridesSchema>;
export interface OrgPolicy { values: SettingsOverrides; locked: string[] }

const isObj = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);

const DANGEROUS_KEYS = new Set(["__proto__", "constructor", "prototype"]);

/** True if any object key, at any depth, could reach Object.prototype when assigned. JSON.parse keeps `__proto__` as an ordinary own key. */
export function hasDangerousKey(v: unknown): boolean {
  if (Array.isArray(v)) return v.some(hasDangerousKey);
  if (!isObj(v)) return false;
  return Object.keys(v).some((k) => DANGEROUS_KEYS.has(k) || hasDangerousKey(v[k]));
}

function deepMerge(base: Record<string, unknown>, over: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = { ...base };
  for (const [k, v] of Object.entries(over)) {
    if (DANGEROUS_KEYS.has(k)) continue; // never write prototype-reaching keys, even from stored data
    out[k] = isObj(v) && Object.hasOwn(out, k) && isObj(out[k]) ? deepMerge(out[k] as Record<string, unknown>, v) : isObj(v) ? deepMerge({}, v) : v;
  }
  return out;
}

export interface Resolved { settings: Settings; lockedFields: string[] }

/** Built-in defaults, then org policy, then user overrides. Org-locked fields ignore the user layer. */
export function resolveSettings(defaults: Settings, org: OrgPolicy, user: SettingsOverrides): Resolved {
  const userEffective = Object.fromEntries(Object.entries(user).filter(([k]) => !org.locked.includes(k)));
  let merged = deepMerge(defaults as unknown as Record<string, unknown>, org.values as Record<string, unknown>);
  merged = deepMerge(merged, userEffective);
  return { settings: merged as unknown as Settings, lockedFields: [...org.locked] };
}

export type PatchResult =
  | { ok: true; overrides: SettingsOverrides }
  | { ok: false; error: "locked_field"; fields: string[] }
  | { ok: false; error: "validation"; message: string; fields: string[] };

/** JSON Merge Patch (RFC 7386) onto stored user overrides: null deletes a key, objects merge, everything else replaces. */
export function applyPatch(current: SettingsOverrides, patch: unknown, locked: string[]): PatchResult {
  if (!isObj(patch)) return { ok: false, error: "validation", message: "Patch must be a JSON object", fields: [] };
  if (hasDangerousKey(patch)) return { ok: false, error: "validation", message: "Patch contains a forbidden key", fields: [] };
  const touchedLocked = Object.keys(patch).filter((k) => locked.includes(k));
  if (touchedLocked.length) return { ok: false, error: "locked_field", fields: touchedLocked };

  const merged: Record<string, unknown> = structuredClone(current) as Record<string, unknown>;
  const apply = (target: Record<string, unknown>, p: Record<string, unknown>) => {
    for (const [k, v] of Object.entries(p)) {
      if (v === null) delete target[k];
      else if (isObj(v)) {
        const child = Object.hasOwn(target, k) && isObj(target[k]) ? (target[k] as Record<string, unknown>) : {};
        target[k] = child;
        apply(child, v);
      } else target[k] = v;
    }
  };
  apply(merged, patch);

  const parsed = SettingsOverridesSchema.safeParse(merged);
  if (!parsed.success) {
    return {
      ok: false, error: "validation",
      message: parsed.error.issues.map((i) => `${i.path.join(".") || "(root)"}: ${i.message}`).join("; "),
      fields: [...new Set(parsed.error.issues.map((i) => String(i.path[0] ?? "")).filter(Boolean))],
    };
  }
  return { ok: true, overrides: parsed.data };
}
