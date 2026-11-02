import { createHash } from "node:crypto";

export interface AiConfig {
  kind: "anthropic" | "openai";
  apiKey?: string;
  model: string;
  baseUrl?: string;
  timeoutMs: number;
  /** Hard ceiling on any one user's monthly AI budget, whatever they set for themselves. */
  maxUserBudgetUsd: number;
  /** USD per million tokens, for budget accounting. Local models cost nothing. */
  price: { inputPerMTokUsd: number; outputPerMTokUsd: number };
}

export interface OidcSettings {
  issuer: string;
  clientId: string;
  clientSecret: string;
  redirectUri: string;
  trustMissingEmailVerified: boolean;
}

export interface Config {
  port: number;
  role: "api" | "worker" | "all";
  databaseUrl: string | undefined;
  secret: string;
  tokenKey: string;
  serverId: string;
  pollSeconds: number;
  google: { clientId: string; clientSecret: string } | null;
  /** Outlook / Microsoft 365. A client secret is optional (public-client registrations have none). */
  microsoft: { clientId: string; clientSecret: string | undefined; tenant: string } | null;
  dataDir: string;
  /** Lets a Prometheus server on another host read /metrics. Loopback callers never need it. */
  metricsToken: string | undefined;
  retentionDays: number;
  /** Single sign-on for the admin dashboard; null = sign in with a session token only. */
  oidc: OidcSettings | null;
  /** Network lookups used by the detectors. Both are opt-in because they send data (a domain name / a URL path) to a third party. */
  lookups: { rdap: boolean; safeBrowsingKey: string | undefined };
  /** null = the server offers no AI layer at all, whatever users enable. */
  ai: AiConfig | null;
}

type Env = Record<string, string | undefined>;

/** Loopback, private-range, .local and single-label hosts: model servers on your own network, which cost nothing per call. */
export function isLocalEndpoint(url: string): boolean {
  let h: string;
  try { h = new URL(url).hostname.toLowerCase(); } catch { return false; }
  if (h === "localhost" || h === "[::1]" || h.endsWith(".local") || !h.includes(".")) return true;
  const m = /^(\d+)\.(\d+)\.\d+\.\d+$/.exec(h);
  if (!m) return false;
  const a = Number(m[1]), b = Number(m[2]);
  return a === 127 || a === 10 || (a === 192 && b === 168) || (a === 172 && b >= 16 && b <= 31);
}

/** Reads and validates environment configuration; throws one error listing every problem. */
export function loadConfig(env: Env): Config {
  const problems: string[] = [];
  const secret = env.SERVER_SECRET ?? "";
  if (secret.length < 32) problems.push("SERVER_SECRET must be at least 32 characters");
  const tokenKey = env.TOKEN_KEY ?? "";
  if (!/^[0-9a-fA-F]{64}$/.test(tokenKey)) problems.push("TOKEN_KEY must be 64 hex characters (32 bytes)");
  const port = env.PORT === undefined ? 8080 : Number(env.PORT);
  if (!Number.isInteger(port) || port < 1 || port > 65535) problems.push("PORT must be 1-65535");
  const role = (env.ROLE ?? "all") as Config["role"];
  if (!["api", "worker", "all"].includes(role)) problems.push("ROLE must be api, worker or all");
  const pollSeconds = env.POLL_SECONDS === undefined ? 60 : Number(env.POLL_SECONDS);
  if (!Number.isFinite(pollSeconds) || pollSeconds < 5) problems.push("POLL_SECONDS must be at least 5");
  const retentionDays = env.RETENTION_DAYS === undefined ? 90 : Number(env.RETENTION_DAYS);
  if (!Number.isInteger(retentionDays) || retentionDays < 1) problems.push("RETENTION_DAYS must be a whole number of at least 1");
  let ai: AiConfig | null = null;
  const kind = env.AI_PROVIDER ?? "none";
  if (kind !== "none") {
    const timeoutMs = env.AI_TIMEOUT_MS === undefined ? 2500 : Number(env.AI_TIMEOUT_MS);
    if (!Number.isFinite(timeoutMs) || timeoutMs < 100) problems.push("AI_TIMEOUT_MS must be at least 100");
    const maxUserBudgetUsd = env.AI_MAX_USER_BUDGET_USD === undefined ? 20 : Number(env.AI_MAX_USER_BUDGET_USD);
    if (!Number.isFinite(maxUserBudgetUsd) || maxUserBudgetUsd < 0) problems.push("AI_MAX_USER_BUDGET_USD must be a number of at least 0");
    if (kind === "anthropic") {
      if (!env.ANTHROPIC_API_KEY) problems.push("ANTHROPIC_API_KEY is required when AI_PROVIDER=anthropic");
      const pin = Number(env.AI_PRICE_IN_PER_MTOK), pout = Number(env.AI_PRICE_OUT_PER_MTOK);
      if (env.AI_PRICE_IN_PER_MTOK === undefined || env.AI_PRICE_OUT_PER_MTOK === undefined || !(pin >= 0) || !(pout >= 0)) {
        problems.push("AI_PRICE_IN_PER_MTOK and AI_PRICE_OUT_PER_MTOK (USD per million tokens) are required so budgets work");
      }
      ai = { kind, apiKey: env.ANTHROPIC_API_KEY, model: env.AI_MODEL ?? "claude-haiku-5-5", timeoutMs, maxUserBudgetUsd, price: { inputPerMTokUsd: pin, outputPerMTokUsd: pout } };
    } else if (kind === "openai") {
      if (!env.AI_BASE_URL) problems.push("AI_BASE_URL is required when AI_PROVIDER=openai (e.g. http://localhost:11434/v1)");
      if (!env.AI_MODEL) problems.push("AI_MODEL is required when AI_PROVIDER=openai");
      // Hosted OpenAI-compatible endpoints bill per token, so budgets need real prices; servers on your own network cost nothing.
      const local = isLocalEndpoint(env.AI_BASE_URL ?? "");
      const priced = env.AI_PRICE_IN_PER_MTOK !== undefined || env.AI_PRICE_OUT_PER_MTOK !== undefined;
      const pin = Number(env.AI_PRICE_IN_PER_MTOK ?? 0), pout = Number(env.AI_PRICE_OUT_PER_MTOK ?? 0);
      if (!(pin >= 0) || !(pout >= 0)) problems.push("AI_PRICE_IN_PER_MTOK / AI_PRICE_OUT_PER_MTOK must be numbers of at least 0 (use a dot, not a comma)");
      else if (!local && !priced) problems.push("AI_PRICE_IN_PER_MTOK and AI_PRICE_OUT_PER_MTOK are required for a non-local AI_BASE_URL so budgets work");
      ai = { kind, apiKey: env.AI_API_KEY || undefined, model: env.AI_MODEL ?? "", baseUrl: env.AI_BASE_URL, timeoutMs, maxUserBudgetUsd, price: { inputPerMTokUsd: pin, outputPerMTokUsd: pout } };
    } else problems.push("AI_PROVIDER must be none, anthropic or openai");
  }
  let oidc: OidcSettings | null = null;
  const oidcKeys = ["OIDC_ISSUER", "OIDC_CLIENT_ID", "OIDC_CLIENT_SECRET"] as const;
  if (oidcKeys.some((k) => env[k])) {
    for (const k of oidcKeys) if (!env[k]) problems.push(`${k} is required when single sign-on is configured`);
    if (!env.PUBLIC_URL) problems.push("PUBLIC_URL (the address users reach this server at) is required for single sign-on");
    const secureOrLocal = (u: string) => { try { const x = new URL(u); return x.protocol === "https:" || (x.protocol === "http:" && ["localhost", "127.0.0.1", "[::1]"].includes(x.hostname)); } catch { return false; } };
    if (env.OIDC_ISSUER && !secureOrLocal(env.OIDC_ISSUER)) problems.push("OIDC_ISSUER must be an https URL");
    if (env.PUBLIC_URL && !secureOrLocal(env.PUBLIC_URL)) problems.push("PUBLIC_URL must be an https URL (http is allowed for localhost only)");
    if (oidcKeys.every((k) => env[k]) && env.PUBLIC_URL) {
      oidc = {
        issuer: env.OIDC_ISSUER!, clientId: env.OIDC_CLIENT_ID!, clientSecret: env.OIDC_CLIENT_SECRET!,
        redirectUri: env.PUBLIC_URL.replace(/\/+$/, "") + "/admin/callback",
        trustMissingEmailVerified: env.OIDC_TRUST_MISSING_EMAIL_VERIFIED === "true",
      };
    }
  }
  // The tenant is spliced into a login URL, so only a tenant GUID, a domain name or a well-known alias is accepted.
  const tenant = env.MICROSOFT_TENANT ?? "common";
  if (env.MICROSOFT_CLIENT_ID && !/^(?:common|organizations|consumers|[0-9a-fA-F-]{36}|[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)$/.test(tenant)) {
    problems.push("MICROSOFT_TENANT must be a tenant ID, a domain name, or common/organizations/consumers");
  }
  if (problems.length) throw new Error("Invalid configuration:\n- " + problems.join("\n- "));

  const clientId = env.GOOGLE_CLIENT_ID ?? env.CLIENT_ID;
  const clientSecret = env.GOOGLE_CLIENT_SECRET ?? env.CLIENT_SECRET;
  return {
    port, role, pollSeconds, secret, tokenKey, retentionDays, ai, oidc,
    lookups: { rdap: env.RDAP_LOOKUPS === "true", safeBrowsingKey: env.SAFE_BROWSING_API_KEY || undefined },
    databaseUrl: env.DATABASE_URL || undefined,
    // Derived, not secret: lets clients tell servers apart and scopes session tokens to this one.
    serverId: env.SERVER_ID || createHash("sha256").update("server-id:" + secret).digest("hex").slice(0, 16),
    google: clientId && clientSecret ? { clientId, clientSecret } : null,
    microsoft: env.MICROSOFT_CLIENT_ID ? { clientId: env.MICROSOFT_CLIENT_ID, clientSecret: env.MICROSOFT_CLIENT_SECRET || undefined, tenant } : null,
    dataDir: env.DATA_DIR ?? ".data",
    metricsToken: env.METRICS_TOKEN || undefined,
  };
}
