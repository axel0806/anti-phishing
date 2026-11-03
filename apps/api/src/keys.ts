import type { Store } from "@ap/db";
import { decryptSecret, encryptSecret } from "./auth.ts";

/** Decrypts with the current key, or with a previous one during a rotation. Throws if none fits. */
export function decryptSecretAny(keys: string[], blob: string): string {
  let last: unknown;
  for (const k of keys) {
    try { return decryptSecret(k, blob); } catch (e) { last = e; }
  }
  throw last instanceof Error ? last : new Error("No key could decrypt this value");
}

/**
 * Re-encrypts every stored mailbox token under the current key. Run after setting TOKEN_KEY to the new key and TOKEN_KEY_PREVIOUS to the old one;
 * afterwards TOKEN_KEY_PREVIOUS can be removed. Tokens nobody can decrypt are reported, never deleted.
 */
export async function rotateTokenKeys(store: Store, current: string, previous: string[]): Promise<{ rotated: number; alreadyCurrent: number; unreadable: string[] }> {
  const out = { rotated: 0, alreadyCurrent: 0, unreadable: [] as string[] };
  for (const u of await store.listLinkedUsers()) {
    const blob = u.encryptedTokens!;
    try { decryptSecret(current, blob); out.alreadyCurrent++; continue; } catch { /* needs rotating */ }
    try {
      const plain = decryptSecretAny(previous, blob);
      await store.setEncryptedTokens(u.id, encryptSecret(current, plain));
      out.rotated++;
    } catch { out.unreadable.push(u.email); }
  }
  return out;
}
