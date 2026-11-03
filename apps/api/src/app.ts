import Fastify, { type FastifyInstance, type FastifyReply, type FastifyRequest } from "fastify";
import { timingSafeEqual } from "node:crypto";
import { z } from "zod";
import { applyPatch, hasDangerousKey, OrgValuesSchema, SettingsOverridesSchema } from "@ap/settings";
import { ListEntrySchema } from "@ap/shared";
import type { AdminQueries, Store, User } from "@ap/db";
import { signToken, verifyToken } from "./auth.ts";
import { registerAdminRoutes } from "./adminRoutes.ts";
import { Oidc, OidcError } from "./oidc.ts";
import { fail } from "./errors.ts";
import { registerSites, type Sites } from "./sites.ts";
import { registerOnboarding } from "./onboarding.ts";
import { RateLimiter } from "./rateLimit.ts";
import type { ConnectFlow } from "./connect.ts";
import { renderManifest } from "../../outlook-addin/src/manifest.ts";
import type { Metrics } from "./metrics.ts";
import { MailUnavailable, ScanInProgress, UnsupportedIdFormat, type ScanService } from "./service.ts";

export const API_VERSION = "0.2.0";

export interface AppDeps {
  store: Store;
  service: ScanService;
  serverId: string;
  secret: string;
  /** Enables the /v1/admin dashboard API, the audit log and weight suggestions. */
  admin?: AdminQueries;
  metrics?: Metrics;
  /** Single sign-on for the admin dashboard. */
  oidc?: Oidc;
  /** Built front-ends to host: the admin dashboard at /admin/ and the Outlook add-in at /addin/. */
  sites?: Sites;
  /** The address users reach this server at (https). Used to generate the Outlook add-in manifest. */
  publicUrl?: string;
  /** Bearer token for /metrics from non-loopback hosts. Without it, only loopback callers may read metrics. */
  metricsToken?: string;
  /** Browser-based mailbox connection (web onboarding). Needs PUBLIC_URL and a Google or Microsoft app. */
  connect?: ConnectFlow;
  /** Key for OAuth refresh tokens at rest (TOKEN_KEY); required for web onboarding to store a connected mailbox. */
  tokenKey?: string;
  /** One-time token that unlocks /setup on a server with no users. */
  setupToken?: string;
  /** Trust X-Forwarded-For for the client address. Only set this behind a reverse proxy you control; otherwise callers could dodge rate limits by spoofing it. */
  trustProxy?: boolean;
  /** Requests per minute. Defaults: 60 per address on public pages, 600 per user on the API, 12 rescans per user. */
  rateLimits?: { publicPerMin?: number; userPerMin?: number; rescanPerMin?: number };
}

declare module "fastify" {
  interface FastifyRequest { user?: User }
}


const IdFormat = z.enum(["outlook_rest"]);
const ScanBody = z.object({ providerMessageId: z.string().min(1).max(500), idFormat: IdFormat.optional(), mode: z.enum(["dry_run", "act"]).optional(), rescan: z.boolean().optional() });
const FeedbackBody = z.object({ label: z.enum(["not_phishing", "phishing"]), updateList: z.boolean().optional() });
const PolicyBody = z.object({ values: OrgValuesSchema, locked: z.array(z.string().max(100)).max(100) });
const KindParam = z.enum(["allow", "block"]);
const ListBody = ListEntrySchema.extend({ scope: z.enum(["user", "org"]).optional() });
const SETTINGS_KEYS = new Set(Object.keys(SettingsOverridesSchema.shape));
const SAFE_ID = /^[A-Za-z0-9_-]{1,200}$/;
// Outlook REST ids are base64-like and may contain = + / (clients URL-encode them).
const REST_ID = /^[A-Za-z0-9_=+/-]{1,500}$/;

export function buildApp(deps: AppDeps): FastifyInstance {
  const { store, service, serverId, secret, admin } = deps;
  const app = Fastify({ logger: false, bodyLimit: 64 * 1024, routerOptions: { maxParamLength: 1000 }, trustProxy: deps.trustProxy ?? false }); // signed invite links in the URL path are longer than the default 100
  // ---- rate limits: stop one address or user hammering the server. The health check is exempt so monitors never get blocked. ----
  const rl = deps.rateLimits ?? {};
  const publicLimit = new RateLimiter(60_000, rl.publicPerMin ?? 60);
  const userLimit = new RateLimiter(60_000, rl.userPerMin ?? 600);
  const rescanLimit = new RateLimiter(60_000, rl.rescanPerMin ?? 12);
  const sweeper = setInterval(() => { publicLimit.sweep(); userLimit.sweep(); rescanLimit.sweep(); }, 60_000);
  sweeper.unref();
  app.addHook("onClose", async () => clearInterval(sweeper));
  const tooMany = (reply: FastifyReply, retryAfterSec: number) =>
    reply.header("retry-after", String(retryAfterSec)).code(429).send({ error: { code: "rate_limited", message: "Too many requests. Try again shortly." } });
  const PUBLIC_PATHS = /^\/(setup|join|connect|admin\/login|admin\/callback)(\/|\?|$)/;
  app.addHook("onRequest", async (req, reply) => {
    // Match the route Fastify resolved, not the raw URL: "/%73etup" reaches the /setup handler but would not match a pattern on the raw text.
    if (!PUBLIC_PATHS.test(req.routeOptions?.url ?? "")) return;
    const r = publicLimit.take(req.ip);
    if (!r.ok) return tooMany(reply, r.retryAfterSec);
  });

  // RFC 7386 merge patches arrive as application/merge-patch+json; treat them as JSON.
  app.addContentTypeParser("application/merge-patch+json", { parseAs: "string" }, (_req, body, done) => {
    try {
      const parsed: unknown = JSON.parse(body as string);
      if (hasDangerousKey(parsed)) return done(Object.assign(new Error("Forbidden key in body"), { statusCode: 400 }));
      done(null, parsed);
    } catch (e) { done(e as Error); }
  });
  app.setErrorHandler((err: unknown, _req, reply) => {
    const status = (err as { statusCode?: number }).statusCode;
    if (status && status < 500) return fail(reply, "validation", (err as Error).message);
    return reply.code(500).send({ error: { code: "internal", message: "Internal error" } });
  });

  // ---- admin SSO (OIDC). Only existing users with a dashboard role may sign in; accounts are never created here. ----
  if (deps.oidc) {
    const oidc = deps.oidc;
    const COOKIE = "ap_oidc";
    const cookieAttrs = (maxAge: number) => `; Path=/admin; HttpOnly; SameSite=Lax; Max-Age=${maxAge}${oidc.secureCookie ? "; Secure" : ""}`;
    const text = (reply: FastifyReply, code: number, msg: string) => reply.code(code).header("content-type", "text/plain; charset=utf-8").send(msg);

    app.get("/admin/login", async (_req, reply) => {
      try {
        const s = await oidc.start();
        return reply.header("set-cookie", `${COOKIE}=${s.cookie}${cookieAttrs(s.maxAge)}`).header("cache-control", "no-store").redirect(s.url);
      } catch {
        return text(reply, 502, "Single sign-on is temporarily unavailable.");
      }
    });

    app.get<{ Querystring: { code?: string; state?: string } }>("/admin/callback", async (req, reply) => {
      const cookie = /(?:^|; )ap_oidc=([^;]+)/.exec(req.headers.cookie ?? "")?.[1];
      const clear = `${COOKIE}=${cookieAttrs(0)}`;
      try {
        const { email } = await oidc.finish({ code: req.query.code, state: req.query.state }, cookie);
        const user = await store.getUserByEmail(email);
        if (!user || (user.role !== "admin" && user.role !== "analyst" && user.role !== "viewer")) {
          return reply.header("set-cookie", clear).code(403).header("content-type", "text/plain; charset=utf-8").send("Your account is not set up for the dashboard. Ask an administrator.");
        }
        const token = signToken(secret, { uid: user.id, sid: serverId, exp: Math.floor(Date.now() / 1000) + 8 * 3600 });
        // In the fragment so it is never sent to a server, logged, or leaked through Referer; the page moves it to sessionStorage.
        return reply.header("set-cookie", clear).header("cache-control", "no-store").redirect(`/admin/#token=${token}`);
      } catch (e) {
        const msg = e instanceof OidcError ? "Sign-in failed. Please try again." : "Sign-in failed.";
        return reply.header("set-cookie", clear).code(400).header("content-type", "text/plain; charset=utf-8").send(msg);
      }
    });
  }

  if (deps.tokenKey) registerOnboarding(app, { store, admin, connect: deps.connect, secret, serverId, tokenKey: deps.tokenKey, setupToken: deps.setupToken });

  if (deps.sites) registerSites(app, deps.sites);
  if (deps.sites?.addin) {
    app.get("/addin/manifest.xml", async (_req, reply) => {
      let xml: string;
      try { xml = renderManifest(deps.publicUrl ?? ""); } catch { return fail(reply, "not_found", "Set PUBLIC_URL (https) to enable the add-in manifest"); }
      return reply.header("content-type", "application/xml; charset=utf-8").header("content-disposition", 'attachment; filename="manifest.xml"').send(xml);
    });
  }

  app.get("/v1/health", async () => ({ version: API_VERSION, serverId, apiVersions: ["v1"] }));

  app.get("/metrics", async (req, reply) => {
    if (!deps.metrics) return fail(reply, "not_found", "Metrics are not enabled");
    // The Host header is chosen by the caller, so it proves nothing. Trust the socket, and refuse anything that came through a proxy
    // (a same-host reverse proxy makes every client look like loopback).
    const peer = req.socket.remoteAddress ?? "";
    const viaProxy = Boolean(req.headers["x-forwarded-for"] || req.headers["forwarded"] || req.headers["x-real-ip"]);
    const loopback = !viaProxy && (peer === "127.0.0.1" || peer === "::1" || peer === "::ffff:127.0.0.1");
    const bearer = /^Bearer (.+)$/.exec(req.headers.authorization ?? "")?.[1];
    const tokenOk = Boolean(deps.metricsToken && bearer && bearer.length === deps.metricsToken.length && timingSafeEqual(Buffer.from(bearer), Buffer.from(deps.metricsToken)));
    if (!loopback && !tokenOk) return fail(reply, "forbidden", "Metrics are only available locally or with the metrics token");
    return reply.header("content-type", "text/plain; version=0.0.4").send(deps.metrics.render());
  });

  // ---- everything below needs a valid session token for this server ----
  app.register(async (priv) => {
    priv.addHook("preHandler", async (req: FastifyRequest, reply: FastifyReply) => {
      const m = /^Bearer (.+)$/.exec(req.headers.authorization ?? "");
      const claims = m ? verifyToken(secret, m[1]!, serverId) : null;
      const user = claims ? await store.getUser(claims.uid) : null;
      if (!user) return fail(reply, "unauthorized", "Missing or invalid session token");
      req.user = user;
      const r = userLimit.take(user.id);
      if (!r.ok) return tooMany(reply, r.retryAfterSec);
      if (req.url.startsWith("/v1/rescan")) { const x = rescanLimit.take(user.id); if (!x.ok) return tooMany(reply, x.retryAfterSec); }
    });

    if (admin) registerAdminRoutes(priv, { store, admin, service, secret, publicUrl: deps.publicUrl });

    priv.get("/v1/me", async (req) => {
      const u = req.user!;
      return { id: u.id, email: u.email, role: u.role, orgId: u.orgId, provider: u.provider };
    });

    // An extension or add-in token, minted from an already signed-in session (e.g. the dashboard) for up to 90 days.
    priv.post("/v1/me/token", async (req, reply) => {
      const body = z.object({ days: z.number().int().min(1).max(90).default(30) }).safeParse(req.body ?? {});
      if (!body.success) return fail(reply, "validation", "days must be a whole number from 1 to 90");
      const exp = Math.floor(Date.now() / 1000) + body.data.days * 86400;
      return { token: signToken(secret, { uid: req.user!.id, sid: serverId, exp }), expiresAt: new Date(exp * 1000).toISOString() };
    });
    // Self-service erasure: removes the account and everything stored about it. The last admin of an org must hand over first.
    priv.delete("/v1/me", async (req, reply) => {
      const u = req.user!;
      if (u.orgId && u.role === "admin") {
        const admins = (await store.listOrgUsers(u.orgId)).filter((x) => x.role === "admin");
        if (admins.length <= 1) return fail(reply, "validation", "You are the organization's only admin. Make someone else an admin first.");
      }
      if (u.orgId) await admin?.audit(u.orgId, u.id, "user.self_erase", u.email); // before the delete: the row references the actor
      await store.deleteUser(u.id);
      return { ok: true };
    });

    priv.get<{ Querystring: { scope?: string } }>("/v1/lists", async (req, reply) => {
      const scope = z.enum(["user", "org"]).default("user").safeParse(req.query.scope);
      if (!scope.success) return fail(reply, "validation", "scope must be user or org");
      const u = req.user!;
      if (scope.data === "org") {
        if (u.role !== "admin" || !u.orgId) return fail(reply, "forbidden", "Only an org admin can read org lists");
        return store.listOwn(u.orgId);
      }
      return store.listOwn(u.id);
    });

    priv.get("/v1/settings", async (req) => {
      const e = await service.effectiveSettings(req.user!);
      return { settings: e.settings, lockedFields: e.lockedFields, version: e.version };
    });

    priv.patch("/v1/settings", async (req, reply) => {
      const user = req.user!;
      const policy = await store.getOrgPolicy(user.orgId);
      const r = applyPatch(user.overrides, req.body, policy.locked);
      if (!r.ok) return fail(reply, r.error, r.error === "locked_field" ? "Field is locked by your organization" : r.message, r.fields);
      await store.setUserOverrides(user.id, r.overrides);
      const e = await service.effectiveSettings({ ...user, overrides: r.overrides });
      return { settings: e.settings, lockedFields: e.lockedFields, version: e.version };
    });

    const adminOf = async (req: FastifyRequest, reply: FastifyReply, orgId: string) => {
      const u = req.user!;
      if (u.role !== "admin" || u.orgId !== orgId) { fail(reply, "forbidden", "Admin of this organization only"); return false; }
      return true;
    };
    priv.get<{ Params: { id: string } }>("/v1/orgs/:id/policy", async (req, reply) => {
      if (!(await adminOf(req, reply, req.params.id))) return;
      return store.getOrgPolicy(req.params.id);
    });
    priv.put<{ Params: { id: string } }>("/v1/orgs/:id/policy", async (req, reply) => {
      if (!(await adminOf(req, reply, req.params.id))) return;
      const body = PolicyBody.safeParse(req.body);
      if (!body.success) return fail(reply, "validation", body.error.issues.map((i) => `${i.path.join(".")}: ${i.message}`).join("; "));
      // A lock names a setting ("ai") or one field of it ("ai.monthlyBudgetUsd"); the setting must exist.
      const unknown = body.data.locked.filter((k) => !SETTINGS_KEYS.has(k.split(".")[0]!));
      if (unknown.length) return fail(reply, "validation", "Unknown settings keys in locked", unknown);
      await store.setOrgPolicy(req.params.id, body.data);
      await admin?.audit(req.params.id, req.user!.id, "policy.update", null);
      return body.data;
    });

    priv.post<{ Params: { kind: string } }>("/v1/lists/:kind", async (req, reply) => {
      const kind = KindParam.safeParse(req.params.kind);
      const body = ListBody.safeParse(req.body);
      if (!kind.success || !body.success) return fail(reply, "validation", "kind must be allow or block; body needs matchType and value");
      const u = req.user!;
      const org = body.data.scope === "org";
      if (org && (u.role !== "admin" || !u.orgId)) return fail(reply, "forbidden", "Only an org admin can edit org lists");
      await store.addEntry(org ? { kind: "org", id: u.orgId! } : { kind: "user", id: u.id }, kind.data, body.data, u.id);
      if (org) await admin?.audit(u.orgId!, u.id, "list.add", `${kind.data}:${body.data.matchType}:${body.data.value}`);
      return reply.code(201).send({ ok: true });
    });
    priv.delete<{ Params: { kind: string } }>("/v1/lists/:kind", async (req, reply) => {
      const kind = KindParam.safeParse(req.params.kind);
      const body = ListBody.safeParse(req.body);
      if (!kind.success || !body.success) return fail(reply, "validation", "kind must be allow or block; body needs matchType and value");
      const u = req.user!;
      const org = body.data.scope === "org";
      if (org && (u.role !== "admin" || !u.orgId)) return fail(reply, "forbidden", "Only an org admin can edit org lists");
      const removed = await store.removeEntry(org ? u.orgId! : u.id, kind.data, body.data);
      if (org && removed) await admin?.audit(u.orgId!, u.id, "list.remove", `${kind.data}:${body.data.matchType}:${body.data.value}`);
      return removed ? { ok: true } : fail(reply, "not_found", "No such list entry");
    });

    /** Resolves a client-specific id format (Outlook add-in) to the id scans are stored under, or replies with the right error. */
    const resolveId = async (req: FastifyRequest, reply: FastifyReply, id: string, rawFormat: unknown): Promise<string | null> => {
      const fmt = IdFormat.optional().safeParse(rawFormat);
      if (!fmt.success) { fail(reply, "validation", "idFormat must be outlook_rest"); return null; }
      if (!fmt.data && !SAFE_ID.test(id)) { fail(reply, "validation", "Bad message id"); return null; }
      if (fmt.data && !REST_ID.test(id)) { fail(reply, "validation", "Bad message id"); return null; }
      try {
        return await service.resolveMessageId(req.user!, id, fmt.data);
      } catch (e) {
        if (e instanceof UnsupportedIdFormat) fail(reply, "validation", e.message);
        else if (e instanceof MailUnavailable) fail(reply, "mail_unavailable", e.message);
        else fail(reply, "validation", "That message id could not be resolved");
        return null;
      }
    };

    priv.post("/v1/scan", async (req, reply) => {
      const body = ScanBody.safeParse(req.body);
      if (!body.success) return fail(reply, "validation", body.error.issues.map((i) => `${i.path.join(".")}: ${i.message}`).join("; "));
      const id = await resolveId(req, reply, body.data.providerMessageId, body.data.idFormat);
      if (id === null) return;
      try {
        const r = await service.scan(req.user!, id, { mode: body.data.mode, rescan: body.data.rescan });
        return { ...r.scan.verdict, pinned: r.scan.pinned, action: r.action, cached: r.cached };
      } catch (e) {
        if (e instanceof ScanInProgress) return fail(reply, "scan_in_progress", "This message is already being scanned");
        if (e instanceof MailUnavailable) return fail(reply, "mail_unavailable", e.message);
        throw e;
      }
    });

    priv.post("/v1/rescan", async (req, reply) => {
      const body = z.object({ days: z.number().int().min(1).max(30).default(7) }).safeParse(req.body ?? {});
      if (!body.success) return fail(reply, "validation", "days must be a whole number from 1 to 30");
      return service.rescanRecent(req.user!, body.data.days);
    });

    priv.get<{ Params: { id: string }; Querystring: { idFormat?: string } }>("/v1/messages/:id/verdict", async (req, reply) => {
      const id = await resolveId(req, reply, req.params.id, req.query.idFormat);
      if (id === null) return;
      const s = await store.getScan(req.user!.id, id);
      return s ? { ...s.verdict, pinned: s.pinned } : fail(reply, "not_scanned", "Message not scanned yet");
    });

    priv.post<{ Params: { id: string }; Querystring: { idFormat?: string } }>("/v1/messages/:id/feedback", async (req, reply) => {
      const body = FeedbackBody.safeParse(req.body);
      if (!body.success) return fail(reply, "validation", "label must be not_phishing or phishing");
      const id = await resolveId(req, reply, req.params.id, req.query.idFormat);
      if (id === null) return;
      const u = req.user!;
      const fb = await service.applyFeedback(u, id, body.data.label);
      if (!fb) return fail(reply, "not_scanned", "Message not scanned yet");
      const s = fb.scan;
      if (body.data.updateList && s.sender) {
        await store.addEntry({ kind: "user", id: u.id }, body.data.label === "phishing" ? "block" : "allow", { matchType: "address", value: s.sender }, u.id);
      }
      return { ...s.verdict, pinned: s.pinned, mailAction: fb.mailAction };
    });

    priv.get<{ Querystring: { days?: string } }>("/v1/me/stats", async (req) => {
      const days = Math.min(365, Math.max(1, Number(req.query.days) || 7));
      const id = req.user!.id;
      return { days, ...(await store.statsFor(id, days)), aiCalls: await store.aiCallsThisMonth(id), aiSpentUsd: await store.aiSpentThisMonth(id) };
    });
  });

  return app;
}

export { signToken };
