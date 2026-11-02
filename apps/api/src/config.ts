import { createHash } from "node:crypto";

export interface AiConfig {
  kind: "anthropic" | "openai";
  apiKey?: string;
  model: string;
  baseUrl?: string;
  timeoutMs: number;
  /** USD per million tokens, for budget accounting. Local models cost nothing. */
  price: { inputPerMTokUsd: number; outputPerMTokUsd: number };
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
  dataDir: string;
  retentionDays: number;
  /** null = the server offers no AI layer at all, whatever users enable. */
  ai: AiConfig | null;
}

type Env = Record<string, string | undefined>;

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
    if (kind === "anthropic") {
      if (!env.ANTHROPIC_API_KEY) problems.push("ANTHROPIC_API_KEY is required when AI_PROVIDER=anthropic");
      const pin = Number(env.AI_PRICE_IN_PER_MTOK), pout = Number(env.AI_PRICE_OUT_PER_MTOK);
      if (env.AI_PRICE_IN_PER_MTOK === undefined || env.AI_PRICE_OUT_PER_MTOK === undefined || !(pin >= 0) || !(pout >= 0)) {
        problems.push("AI_PRICE_IN_PER_MTOK and AI_PRICE_OUT_PER_MTOK (USD per million tokens) are required so budgets work");
      }
      ai = { kind, apiKey: env.ANTHROPIC_API_KEY, model: env.AI_MODEL ?? "claude-haiku-5-5", timeoutMs, price: { inputPerMTokUsd: pin, outputPerMTokUsd: pout } };
    } else if (kind === "openai") {
      if (!env.AI_BASE_URL) problems.push("AI_BASE_URL is required when AI_PROVIDER=openai (e.g. http://localhost:11434/v1)");
      if (!env.AI_MODEL) problems.push("AI_MODEL is required when AI_PROVIDER=openai");
      ai = {
        kind, apiKey: env.AI_API_KEY || undefined, model: env.AI_MODEL ?? "", baseUrl: env.AI_BASE_URL, timeoutMs,
        price: { inputPerMTokUsd: Number(env.AI_PRICE_IN_PER_MTOK ?? 0), outputPerMTokUsd: Number(env.AI_PRICE_OUT_PER_MTOK ?? 0) },
      };
    } else problems.push("AI_PROVIDER must be none, anthropic or openai");
  }
  if (problems.length) throw new Error("Invalid configuration:\n- " + problems.join("\n- "));

  const clientId = env.GOOGLE_CLIENT_ID ?? env.CLIENT_ID;
  const clientSecret = env.GOOGLE_CLIENT_SECRET ?? env.CLIENT_SECRET;
  return {
    port, role, pollSeconds, secret, tokenKey, retentionDays, ai,
    databaseUrl: env.DATABASE_URL || undefined,
    // Derived, not secret: lets clients tell servers apart and scopes session tokens to this one.
    serverId: env.SERVER_ID || createHash("sha256").update("server-id:" + secret).digest("hex").slice(0, 16),
    google: clientId && clientSecret ? { clientId, clientSecret } : null,
    dataDir: env.DATA_DIR ?? ".data",
  };
}
