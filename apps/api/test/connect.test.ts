import { describe, expect, it } from "vitest";
import { signBlob } from "../src/auth.ts";
import { Connect, ConnectError, makeInvite, readInvite } from "../src/connect.ts";

const SECRET = "x".repeat(40);
const TENANT = "11111111-2222-3333-4444-555555555555";
const GMAIL_SCOPE = "openid email https://www.googleapis.com/auth/gmail.modify";
const idToken = (claims: object) => `h.${Buffer.from(JSON.stringify(claims)).toString("base64url")}.s`;
const mk = (tokenBody: object, calls: { url: string; body: string }[] = []) => new Connect({
  secret: SECRET, publicUrl: "https://phish.example",
  google: { clientId: "gid", clientSecret: "gsec" }, microsoft: { clientId: "mid", clientSecret: "msec", tenant: TENANT },
  fetch: (async (url: string, init: { body: string }) => { calls.push({ url, body: init.body }); return { ok: true, status: 200, json: async () => tokenBody } as Response; }) as unknown as typeof fetch,
});
const state = (url: string) => new URL(url).searchParams.get("state")!;

describe("web mailbox connection", () => {
  it("builds a PKCE authorization URL that redirects to this server and asks only for the mail scope plus identity", () => {
    const u = new URL(mk({}).start("gmail", "setup").url);
    expect(u.origin + u.pathname).toBe("https://accounts.google.com/o/oauth2/v2/auth");
    expect(u.searchParams.get("redirect_uri")).toBe("https://phish.example/connect/callback");
    expect(u.searchParams.get("code_challenge_method")).toBe("S256");
    expect(u.searchParams.get("scope")).toBe("openid email https://www.googleapis.com/auth/gmail.modify");
    expect(u.searchParams.get("access_type")).toBe("offline");
    const o = new URL(mk({}).start("outlook", "x").url);
    expect(o.pathname).toBe(`/${TENANT}/oauth2/v2.0/authorize`);
    expect(o.searchParams.get("scope")).toBe("openid email offline_access Mail.ReadWrite");
  });

  it("exchanges the code with the stored verifier and returns the verified mailbox and the purpose", async () => {
    const calls: { url: string; body: string }[] = [];
    const c = mk({ refresh_token: "rt", scope: GMAIL_SCOPE, id_token: idToken({ email: "Boss@Corp.Example", email_verified: true }) }, calls);
    const s = c.start("gmail", "invite:abc");
    const r = await c.finish({ code: "code1", state: state(s.url) }, s.cookie);
    expect(r).toEqual({ provider: "gmail", email: "boss@corp.example", refreshToken: "rt", purpose: "invite:abc" });
    const sent = new URLSearchParams(calls[0]!.body);
    expect(sent.get("code_verifier")).toBeTruthy();
    expect(sent.get("client_secret")).toBe("gsec");
    expect(calls[0]!.url).toBe("https://oauth2.googleapis.com/token");
  });

  it("uses preferred_username for Microsoft work accounts without an email claim", async () => {
    const c = mk({ refresh_token: "rt", id_token: idToken({ preferred_username: "amy@contoso.com", tid: TENANT }) });
    const s = c.start("outlook", "p");
    expect((await c.finish({ code: "c", state: state(s.url) }, s.cookie)).email).toBe("amy@contoso.com");
  });

  it("refuses a wrong state, a missing or forged cookie, an SSO cookie, an unverified Google email, and a missing refresh token", async () => {
    const good = { refresh_token: "rt", scope: GMAIL_SCOPE, id_token: idToken({ email: "a@b.example", email_verified: true }) };
    const c = mk(good);
    const s = c.start("gmail", "p");
    await expect(c.finish({ code: "c", state: "wrong" }, s.cookie)).rejects.toBeInstanceOf(ConnectError);
    await expect(c.finish({ code: "c", state: state(s.url) }, undefined)).rejects.toBeInstanceOf(ConnectError);
    await expect(c.finish({ code: "c", state: state(s.url) }, s.cookie + "x")).rejects.toBeInstanceOf(ConnectError);
    const sso = signBlob(SECRET, JSON.stringify({ s: state(s.url), n: "n", v: "v", e: Math.floor(Date.now() / 1000) + 99 }));
    await expect(c.finish({ code: "c", state: state(s.url) }, sso)).rejects.toThrow(/Not a connect cookie/);
    const unverified = mk({ refresh_token: "rt", scope: GMAIL_SCOPE, id_token: idToken({ email: "a@b.example", email_verified: false }) });
    const s2 = unverified.start("gmail", "p");
    await expect(unverified.finish({ code: "c", state: state(s2.url) }, s2.cookie)).rejects.toThrow(/not verified/);
    const noRefresh = mk({ id_token: good.id_token });
    const s3 = noRefresh.start("gmail", "p");
    await expect(noRefresh.finish({ code: "c", state: state(s3.url) }, s3.cookie)).rejects.toThrow(/refresh token/);
  });

  it("refuses a Google grant that left out the mail permission, and a Microsoft identity from any other tenant", async () => {
    const idt = idToken({ email: "a@b.example", email_verified: true });
    const partial = mk({ refresh_token: "rt", id_token: idt, scope: "openid email" });
    const s = partial.start("gmail", "p");
    await expect(partial.finish({ code: "c", state: state(s.url) }, s.cookie)).rejects.toThrow(/permission/);
    for (const tid of ["99999999-2222-3333-4444-555555555555", undefined]) {
      const ms = mk({ refresh_token: "rt", id_token: idToken({ email: "victim@corp.example", tid }) });
      const x = ms.start("outlook", "p");
      await expect(ms.finish({ code: "c", state: state(x.url) }, x.cookie)).rejects.toThrow(/tenant/);
    }
  });

  it("offers Outlook for web sign-in only when it is locked to one tenant (an id), never common/organizations/consumers or a domain", () => {
    const mkp = (tenant: string) => new Connect({ secret: SECRET, publicUrl: "https://p.example", microsoft: { clientId: "m", tenant } }).providers;
    expect(mkp(TENANT)).toEqual(["outlook"]);
    for (const t of ["common", "organizations", "consumers", "contoso.com"]) expect(mkp(t)).toEqual([]);
  });

  it("only offers providers that are configured", () => {
    expect(new Connect({ secret: SECRET, publicUrl: "http://localhost:8080", google: { clientId: "a", clientSecret: "b" } }).providers).toEqual(["gmail"]);
    expect(() => new Connect({ secret: SECRET, publicUrl: "http://localhost:8080", google: { clientId: "a", clientSecret: "b" } }).start("outlook", "p")).toThrow(/not configured/);
  });
});

describe("invites", () => {
  it("round-trip, bind the address in lower case, and expire", () => {
    const { token } = makeInvite(SECRET, { orgId: "o1", email: "New@Corp.Example", role: "analyst" });
    expect(readInvite(SECRET, token)).toMatchObject({ orgId: "o1", email: "new@corp.example", role: "analyst" });
    expect(readInvite(SECRET, token, Date.now() + 8 * 86400_000)).toBeNull();
  });
  it("reject tampering, another secret, and other signed blobs (an SSO cookie or a connect cookie)", () => {
    const { token } = makeInvite(SECRET, { orgId: "o1", email: "a@b.example", role: "admin" });
    expect(readInvite(SECRET, token.slice(0, -2) + "xx")).toBeNull();
    expect(readInvite("y".repeat(40), token)).toBeNull();
    expect(readInvite(SECRET, signBlob(SECRET, JSON.stringify({ k: "connect", o: "o1", e: "a@b.example", r: "admin", x: 9999999999 })))).toBeNull();
  });
});
