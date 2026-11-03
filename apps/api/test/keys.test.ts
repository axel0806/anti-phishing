import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { connect, Store, type Connection } from "@ap/db";
import { decryptSecret, encryptSecret } from "../src/auth.ts";
import { decryptSecretAny, rotateTokenKeys } from "../src/keys.ts";
import { mailProviderFactory } from "../src/mailer.ts";

const OLD = "11".repeat(32), NEW = "22".repeat(32), OTHER = "33".repeat(32);
let conn: Connection, store: Store;
beforeAll(async () => { conn = await connect(); store = new Store(conn.db); });
afterAll(async () => { await conn.close(); });

describe("token key rotation", () => {
  it("decrypts with the current key or a previous one, and fails when none fits", () => {
    const blob = encryptSecret(OLD, "secret");
    expect(decryptSecretAny([NEW, OLD], blob)).toBe("secret");
    expect(() => decryptSecretAny([NEW, OTHER], blob)).toThrow();
  });

  it("the mail client keeps working for a token still under the previous key", () => {
    const blob = encryptSecret(OLD, JSON.stringify({ refresh_token: "r" }));
    const make = (previous: string[]) => mailProviderFactory({ google: { clientId: "a", clientSecret: "b" }, tokenKey: NEW, previousTokenKeys: previous });
    const user = { id: "u", provider: "gmail", encryptedTokens: blob };
    expect(make([OLD])(user)).not.toBeNull();
    expect(make([])(user)).toBeNull(); // without the old key it cannot be read
  });

  it("re-encrypts every token under the new key, reports unreadable ones, and leaves them untouched", async () => {
    const a = await store.createUser({ email: "rot-a@example.com" });
    const b = await store.createUser({ email: "rot-b@example.com" });
    const c = await store.createUser({ email: "rot-c@example.com" });
    const d = await store.createUser({ email: "rot-d@example.com" });
    await store.setEncryptedTokens(a.id, encryptSecret(OLD, "A"));
    await store.setEncryptedTokens(b.id, encryptSecret(NEW, "B"));
    await store.setEncryptedTokens(c.id, encryptSecret(OTHER, "C"));
    const unreadableBlob = encryptSecret(OTHER, "D");
    await store.setEncryptedTokens(d.id, unreadableBlob);
    const r = await rotateTokenKeys(store, NEW, [OLD]);
    expect(r.rotated).toBe(1);
    expect(r.alreadyCurrent).toBe(1);
    expect(r.unreadable.sort()).toEqual(["rot-c@example.com", "rot-d@example.com"]);
    expect(decryptSecret(NEW, (await store.getUser(a.id))!.encryptedTokens!)).toBe("A");
    expect((await store.getUser(d.id))!.encryptedTokens).toBe(unreadableBlob);
    const again = await rotateTokenKeys(store, NEW, [OLD]);
    expect(again.rotated).toBe(0);
  });
});
