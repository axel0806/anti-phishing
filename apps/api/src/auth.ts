import { createCipheriv, createDecipheriv, createHmac, randomBytes, timingSafeEqual } from "node:crypto";

const b64 = (b: Buffer | string) => Buffer.from(b).toString("base64url");

export interface TokenClaims { uid: string; sid: string; exp: number }

/** Session token: v1.<claims>.<hmac>. Scoped to one server ID, so a token from another server never validates here. */
export function signToken(secret: string, claims: TokenClaims): string {
  const body = b64(JSON.stringify(claims));
  return `v1.${body}.${b64(createHmac("sha256", secret).update("v1." + body).digest())}`;
}

export function verifyToken(secret: string, token: string, serverId: string, now = Date.now()): TokenClaims | null {
  const [v, body, sig] = token.split(".");
  if (v !== "v1" || !body || !sig) return null;
  const expected = createHmac("sha256", secret).update("v1." + body).digest();
  const given = Buffer.from(sig, "base64url");
  if (given.length !== expected.length || !timingSafeEqual(given, expected)) return null;
  try {
    const c = JSON.parse(Buffer.from(body, "base64url").toString("utf8")) as TokenClaims;
    return c.sid === serverId && typeof c.uid === "string" && c.exp * 1000 > now ? c : null;
  } catch {
    return null;
  }
}

/** AES-256-GCM for OAuth refresh tokens at rest. Key is 32 bytes, hex-encoded (TOKEN_KEY). */
export function encryptSecret(keyHex: string, plaintext: string): string {
  const iv = randomBytes(12);
  const c = createCipheriv("aes-256-gcm", Buffer.from(keyHex, "hex"), iv);
  const enc = Buffer.concat([c.update(plaintext, "utf8"), c.final()]);
  return [b64(iv), b64(c.getAuthTag()), b64(enc)].join(".");
}

export function decryptSecret(keyHex: string, blob: string): string {
  const [iv, tag, enc] = blob.split(".").map((p) => Buffer.from(p ?? "", "base64url"));
  const d = createDecipheriv("aes-256-gcm", Buffer.from(keyHex, "hex"), iv!);
  d.setAuthTag(tag!);
  return Buffer.concat([d.update(enc!), d.final()]).toString("utf8");
}

/** Signed (not encrypted) blob for short-lived browser state, e.g. the OIDC login cookie. Domain-separated from session tokens. */
export function signBlob(secret: string, data: string): string {
  const body = b64(data);
  return `${body}.${b64(createHmac("sha256", secret).update("blob." + body).digest())}`;
}

export function verifyBlob(secret: string, blob: string): string | null {
  const [body, sig] = blob.split(".");
  if (!body || !sig) return null;
  const expected = createHmac("sha256", secret).update("blob." + body).digest();
  const given = Buffer.from(sig, "base64url");
  if (given.length !== expected.length || !timingSafeEqual(given, expected)) return null;
  return Buffer.from(body, "base64url").toString("utf8");
}
