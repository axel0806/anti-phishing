import {
  GmailProvider, GraphProvider, MICROSOFT_SCOPE, microsoftEndpoints, tokenSource,
  type FetchLike, type MailProvider, type OAuthConfig, type Tokens,
} from "@ap/mail";
import type { User } from "@ap/db";
import { decryptSecret, encryptSecret } from "./auth.ts";

export interface MailerConfig {
  google?: { clientId: string; clientSecret: string } | null;
  microsoft?: { clientId: string; clientSecret?: string; tenant?: string } | null;
  tokenKey: string;
  /** Called with the new ENCRYPTED token blob when the provider rotates a refresh token (Microsoft does on every refresh). */
  persist?: (userId: string, encryptedTokens: string) => void | Promise<void>;
  /** Called when the provider says the user's grant is gone (revoked, expired). The caller should unlink the mailbox. */
  onRevoked?: (userId: string) => void;
  fetch?: FetchLike;
}

/** Builds mail clients from each user's encrypted refresh token: Gmail or Outlook according to `user.provider`. One cached client per user. */
export function mailProviderFactory(cfg: MailerConfig) {
  const cache = new Map<string, { blob: string; provider: MailProvider }>();
  return (user: Pick<User, "id" | "provider" | "encryptedTokens">): MailProvider | null => {
    if (!user.encryptedTokens) return null;
    const hit = cache.get(user.id);
    if (hit && hit.blob === user.encryptedTokens) return hit.provider;

    let oauth: OAuthConfig;
    if (user.provider === "gmail" && cfg.google) oauth = { clientId: cfg.google.clientId, clientSecret: cfg.google.clientSecret };
    else if (user.provider === "outlook" && cfg.microsoft) {
      oauth = { clientId: cfg.microsoft.clientId, clientSecret: cfg.microsoft.clientSecret, ...microsoftEndpoints(cfg.microsoft.tenant), scope: MICROSOFT_SCOPE, redirectHost: "localhost" };
    } else return null;

    let tokens: Tokens;
    try { tokens = JSON.parse(decryptSecret(cfg.tokenKey, user.encryptedTokens)) as Tokens; } catch { return null; }
    let current = tokens.refresh_token;
    const save = (t: Tokens) => {
      if (t.refresh_token === current) return; // access tokens are short-lived and not stored; only a changed refresh token is worth a write
      current = t.refresh_token;
      void cfg.persist?.(user.id, encryptSecret(cfg.tokenKey, JSON.stringify({ refresh_token: t.refresh_token })));
    };
    const source = tokenSource(oauth, tokens, save, cfg.fetch, () => cfg.onRevoked?.(user.id));
    const provider = user.provider === "outlook" ? new GraphProvider(source, cfg.fetch) : new GmailProvider(source, cfg.fetch);
    cache.set(user.id, { blob: user.encryptedTokens, provider });
    return provider;
  };
}

/** Gmail-only convenience kept for existing callers. */
export const gmailProviderFactory = (cfg: { clientId: string; clientSecret: string; tokenKey: string }) =>
  mailProviderFactory({ google: { clientId: cfg.clientId, clientSecret: cfg.clientSecret }, tokenKey: cfg.tokenKey });
