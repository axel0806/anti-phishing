import { createHash } from "node:crypto";

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
  if (problems.length) throw new Error("Invalid configuration:\n- " + problems.join("\n- "));

  const clientId = env.GOOGLE_CLIENT_ID ?? env.CLIENT_ID;
  const clientSecret = env.GOOGLE_CLIENT_SECRET ?? env.CLIENT_SECRET;
  return {
    port, role, pollSeconds, secret, tokenKey, retentionDays,
    databaseUrl: env.DATABASE_URL || undefined,
    // Derived, not secret: lets clients tell servers apart and scopes session tokens to this one.
    serverId: env.SERVER_ID || createHash("sha256").update("server-id:" + secret).digest("hex").slice(0, 16),
    google: clientId && clientSecret ? { clientId, clientSecret } : null,
    dataDir: env.DATA_DIR ?? ".data",
  };
}
