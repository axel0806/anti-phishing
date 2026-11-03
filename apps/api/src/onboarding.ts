import { timingSafeEqual } from "node:crypto";
import type { FastifyInstance, FastifyReply } from "fastify";
import type { AdminQueries, Store } from "@ap/db";
import { encryptSecret, signToken } from "./auth.ts";
import { ConnectError, readInvite, type ConnectFlow, type MailProviderName } from "./connect.ts";

export interface OnboardingDeps {
  store: Store;
  admin?: AdminQueries;
  connect?: ConnectFlow;
  secret: string;
  serverId: string;
  tokenKey: string;
  /** Proves whoever opens /setup on a fresh server controls it: printed to the server log at startup, or set as SETUP_TOKEN. */
  setupToken?: string;
}

const esc = (s: string) => s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]!);
const LABEL: Record<MailProviderName, string> = { gmail: "Gmail / Google Workspace", outlook: "Outlook / Microsoft 365" };
const PAGE_CSP = "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'";
const STYLE = "body{font:16px/1.5 system-ui,sans-serif;max-width:34rem;margin:8vh auto;padding:0 1rem;color:#1b1f24}h1{font-size:1.4rem}a.b,button{display:block;width:100%;box-sizing:border-box;margin:.5rem 0;padding:.7rem 1rem;border-radius:8px;border:1px solid #1f5fbf;background:#1f5fbf;color:#fff;text-decoration:none;font:inherit;cursor:pointer;text-align:center}input,textarea{width:100%;box-sizing:border-box;padding:.5rem;font:inherit}code,textarea{font-family:ui-monospace,monospace}.muted{color:#5b6570;font-size:.9rem}";

function html(reply: FastifyReply, status: number, title: string, body: string) {
  return reply.code(status).header("content-type", "text/html; charset=utf-8").header("content-security-policy", PAGE_CSP)
    .header("cache-control", "no-store").header("x-content-type-options", "nosniff").header("referrer-policy", "no-referrer")
    .send(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(title)}</title><style>${STYLE}</style></head><body><h1>${esc(title)}</h1>${body}</body></html>`);
}

const tokensBlob = (key: string, refresh: string) => encryptSecret(key, JSON.stringify({ refresh_token: refresh }));
const safeEqual = (a: string, b: string) => { const x = Buffer.from(a), y = Buffer.from(b); return x.length === y.length && timingSafeEqual(x, y); };

/**
 * Web onboarding, so nobody needs a command line:
 *  /setup            first run only, gated by a one-time setup token: connect the first admin's mailbox, creating the organization
 *  /join/:invite     an admin-created invite: connect your own mailbox and receive your extension token
 *  /connect/callback where the mail provider sends the browser back
 * Everything is stateless: in-flight state is one signed cookie.
 */
export function registerOnboarding(app: FastifyInstance, deps: OnboardingDeps): void {
  const { store, admin, connect, secret, serverId, tokenKey } = deps;
  app.addContentTypeParser("application/x-www-form-urlencoded", { parseAs: "string" }, (_req, body, done) => {
    done(null, Object.fromEntries(new URLSearchParams(body as string)));
  });

  const COOKIE = "ap_connect";
  const attrs = (maxAge: number) => `; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAge}${connect?.secureCookie ? "; Secure" : ""}`;
  const clearCookie = `${COOKIE}=${attrs(0)}`;
  const buttons = (hrefFor: (p: MailProviderName) => string) =>
    (connect?.providers ?? []).map((p) => `<a class="b" href="${esc(hrefFor(p))}">Connect ${esc(LABEL[p])}</a>`).join("");
  const unavailable = (reply: FastifyReply) => html(reply, 503, "Mailbox connection is not set up",
    "<p>The server needs <code>PUBLIC_URL</code> and a Google or Microsoft app registration before mailboxes can be connected. See docs/ONBOARDING.md.</p>");
  const failed = (reply: FastifyReply, msg = "That did not work. Go back to the link you were given and try again.") =>
    html(reply.header("set-cookie", clearCookie), 400, "Could not connect", `<p>${esc(msg)}</p>`);

  // ---- first-run setup ----
  app.get("/setup", async (_req, reply) => {
    if (await store.countUsers() > 0) return html(reply, 404, "Already set up", "<p>This server already has users. Ask an administrator for an invite link.</p>");
    if (!connect?.providers.length) return unavailable(reply);
    const submit = connect.providers.map((p) => `<button type="submit" name="provider" value="${esc(p)}">Connect ${esc(LABEL[p])} as the first administrator</button>`).join("");
    return html(reply, 200, "Set up your server",
      `<p>Create the first administrator by connecting their mailbox. The setup token is printed in the server log when it starts (or is the <code>SETUP_TOKEN</code> you configured).</p>
       <form method="post" action="/setup/start"><label>Setup token <input name="token" type="password" autocomplete="off" required></label>${submit}</form>`);
  });
  app.post<{ Body: { token?: string; provider?: string } }>("/setup/start", async (req, reply) => {
    const b = req.body ?? {};
    if (!connect?.providers.length) return unavailable(reply);
    if (await store.countUsers() > 0) return html(reply, 404, "Already set up", "<p>This server already has users.</p>");
    if (!deps.setupToken || !b.token || !safeEqual(b.token, deps.setupToken)) return failed(reply, "The setup token is wrong.");
    const p = connect.providers.find((x) => x === b.provider);
    if (!p) return failed(reply, "Unknown provider.");
    const s = connect.start(p, "setup");
    return reply.header("set-cookie", `${COOKIE}=${s.cookie}${attrs(s.maxAge)}`).redirect(s.url);
  });

  // ---- invites ----
  app.get<{ Params: { invite: string } }>("/join/:invite", async (req, reply) => {
    const inv = readInvite(secret, req.params.invite);
    if (!inv) return html(reply, 404, "Invite not valid", "<p>This invite link is invalid or has expired. Ask your administrator for a new one.</p>");
    if (!connect?.providers.length) return unavailable(reply);
    return html(reply, 200, "Connect your mailbox",
      `<p>You were invited as <b>${esc(inv.email)}</b> (${esc(inv.role === "user" ? "protected mailbox" : inv.role)}). Connect that mailbox so incoming mail can be checked for phishing. Mail is never deleted; suspicious messages are only moved to a folder you can open.</p>
       ${buttons((p) => `/join/${encodeURIComponent(req.params.invite)}/start/${p}`)}`);
  });
  app.get<{ Params: { invite: string; provider: string } }>("/join/:invite/start/:provider", async (req, reply) => {
    const inv = readInvite(secret, req.params.invite);
    const p = connect?.providers.find((x) => x === req.params.provider);
    if (!inv || !connect || !p) return failed(reply, "This invite link is invalid or has expired.");
    const s = connect.start(p, "invite:" + req.params.invite);
    return reply.header("set-cookie", `${COOKIE}=${s.cookie}${attrs(s.maxAge)}`).header("cache-control", "no-store").redirect(s.url);
  });

  // ---- the provider sends the browser back here ----
  app.get<{ Querystring: { code?: string; state?: string } }>("/connect/callback", async (req, reply) => {
    if (!connect) return unavailable(reply);
    const cookie = /(?:^|; )ap_connect=([^;]+)/.exec(req.headers.cookie ?? "")?.[1];
    let r;
    try { r = await connect.finish(req.query, cookie); } catch (e) {
      return failed(reply, e instanceof ConnectError ? "The sign-in could not be completed. Please start again from your link." : undefined);
    }
    const done = (r2: { id: string }, days: number, sc?: "ext") => signToken(secret, { uid: r2.id, sid: serverId, exp: Math.floor(Date.now() / 1000) + days * 86400, ...(sc ? { sc } : {}) });

    if (r.purpose === "setup") {
      // One transaction decides who is first, so two people finishing at once cannot both become administrator.
      const first = await store.createFirstAdmin({ email: r.email, provider: r.provider === "outlook" ? "outlook" : "gmail", orgName: r.email.split("@")[1] ?? "organization" });
      if (!first) return failed(reply, "This server was already set up.");
      const user = first.user;
      await store.setEncryptedTokens(user.id, tokensBlob(tokenKey, r.refreshToken));
      await admin?.audit(first.orgId, user.id, "setup.complete", r.email);
      // In the fragment, like SSO: never sent to a server, logged, or leaked in Referer. The dashboard moves it into sessionStorage.
      return reply.header("set-cookie", clearCookie).header("cache-control", "no-store").redirect(`/admin/#token=${done(user, 1)}`);
    }

    if (r.purpose.startsWith("invite:")) {
      const inv = readInvite(secret, r.purpose.slice(7));
      if (!inv) return failed(reply, "This invite link is invalid or has expired.");
      if (inv.email !== r.email) return failed(reply, `This invite is for ${inv.email}, but you signed in as ${r.email}. Sign in with the invited mailbox.`);
      const provider = r.provider === "outlook" ? "outlook" : "gmail";
      let user = await store.getUserByEmail(r.email);
      if (user && user.orgId && user.orgId !== inv.orgId) return failed(reply, "This mailbox already belongs to another organization.");
      // Reconnecting must not swap how an existing member's mailbox is reached, or overwrite their tokens through another provider.
      if (user && user.encryptedTokens && user.provider !== provider) return failed(reply, `This mailbox is already connected through ${user.provider === "outlook" ? "Outlook" : "Gmail"}. Use that option.`);
      // Single use: spent only now that every check has passed, so a wrong-mailbox attempt does not burn the link, and an erased person cannot return with it.
      if (!(await store.consumeInvite(inv.id))) return failed(reply, "This invite was already used. Ask your administrator for a new one.");
      if (!user) user = await store.createUser({ email: r.email, orgId: inv.orgId, role: inv.role, provider });
      else await store.setUserMembership(user.id, { orgId: inv.orgId, role: user.orgId === inv.orgId ? user.role : inv.role, provider: user.encryptedTokens ? user.provider : provider });
      await store.setEncryptedTokens(user.id, tokensBlob(tokenKey, r.refreshToken));
      await admin?.audit(inv.orgId, user.id, "user.connected", r.email);
      return html(reply.header("set-cookie", clearCookie), 200, "Mailbox connected",
        `<p><b>${esc(r.email)}</b> is now protected. Paste this token into the browser extension's settings (or the Outlook add-in) together with this server's address. It is valid for 30 days and works like a password.</p>
         <textarea readonly rows="6">${esc(done(user, 30, "ext"))}</textarea>
         <p class="muted">You can close this tab afterwards. To disconnect, remove the app from your Google or Microsoft account's connected apps.</p>`);
    }
    return failed(reply);
  });
}
