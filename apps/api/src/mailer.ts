import { GmailProvider, tokenSource, type MailProvider, type OAuthConfig, type Tokens } from "@ap/mail";
import type { User } from "@ap/db";
import { decryptSecret } from "./auth.ts";

/** Builds Gmail clients from each user's encrypted refresh token; one cached client per user so access tokens are reused. */
export function gmailProviderFactory(cfg: OAuthConfig & { tokenKey: string }) {
  const cache = new Map<string, { blob: string; provider: MailProvider }>();
  return (user: Pick<User, "id" | "encryptedTokens">): MailProvider | null => {
    if (!user.encryptedTokens) return null;
    const hit = cache.get(user.id);
    if (hit && hit.blob === user.encryptedTokens) return hit.provider;
    try {
      const tokens = JSON.parse(decryptSecret(cfg.tokenKey, user.encryptedTokens)) as Tokens;
      const provider = new GmailProvider(tokenSource(cfg, tokens, () => { /* access tokens are short-lived; the refresh token is unchanged */ }));
      cache.set(user.id, { blob: user.encryptedTokens, provider });
      return provider;
    } catch {
      return null;
    }
  };
}
