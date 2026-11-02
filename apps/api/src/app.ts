import Fastify, { type FastifyInstance, type FastifyReply, type FastifyRequest } from "fastify";
import { z } from "zod";
import { applyPatch, hasDangerousKey, OrgValuesSchema, SettingsOverridesSchema } from "@ap/settings";
import { ListEntrySchema } from "@ap/shared";
import type { AdminQueries, Store, User } from "@ap/db";
import { signToken, verifyToken } from "./auth.ts";
import { registerAdminRoutes } from "./adminRoutes.ts";
import { Oidc, OidcError } from "./oidc.ts";
import { fail } from "./errors.ts";
import { registerSites, type Sites } from "./sites.ts";
import type { Metrics } from "./metrics.ts";
import { MailUnavailable, ScanInProgress, type ScanService } from "./service.ts";

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
  /** Bearer token for /metrics from non-loopback hosts. Without it, only loopback callers may read metrics. */
  metricsToken?: string;
}

declare module "fastify" {
  interface FastifyRequest { user?: User }
}


const ScanBody = z.object({ providerMessageId: z.string().min(1).max(200), mode: z.enum(["dry_run", "act"]).optional(), rescan: z.boolean().optional() });
const FeedbackBody = z.object({ label: z.enum(["not_phishing", "phishing"]), updateList: z.boolean().optional() });
const PolicyBody = z.object({ values: OrgValuesSchema, locked: z.array(z.string().max(100)).max(100) });
const KindParam = z.enum(["allow", "block"]);
const ListBody = ListEntrySchema.extend({ scope: z.enum(["user", "org"]).optional() });
const SETTINGS_KEYS = new Set(Object.keys(SettingsOverridesSchema.shape));
const SAFE_ID = /^[A-Za-z0-9_-]{1,200}$/;

export function buildApp(deps: AppDeps): FastifyInstance {
  const { store, service, serverId, secret, admin } = deps;
  const app = Fastify({ logger: false, bodyLimit: 64 * 1024 });
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

  if (deps.sites) registerSites(app, deps.sites);

  app.get("/v1/health", async () => ({ version: API_VERSION, serverId, apiVersions: ["v1"] }));

  app.get("/metrics", async (req, reply) => {
    if (!deps.metrics) return fail(reply, "not_found", "Metrics are not enabled");
    const host = (req.headers.host ?? "").replace(/:\d+$/, "").toLowerCase();
    const loopback = host === "127.0.0.1" || host === "localhost" || host === "[::1]";
    const bearer = /^Bearer (.+)$/.exec(req.headers.authorization ?? "")?.[1];
    if (!loopback && !(deps.metricsToken && bearer === deps.metricsToken)) return fail(reply, "forbidden", "Metrics are only available locally or with the metrics token");
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
    });

    if (admin) registerAdminRoutes(priv, { store, admin, service });

    priv.get("/v1/me", async (req) => {
      const u = req.user!;
      return { id: u.id, email: u.email, role: u.role, orgId: u.orgId, provider: u.provider };
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

    priv.post("/v1/scan", async (req, reply) => {
      const body = ScanBody.safeParse(req.body);
      if (!body.success) return fail(reply, "validation", body.error.issues.map((i) => `${i.path.join(".")}: ${i.message}`).join("; "));
      try {
        const r = await service.scan(req.user!, body.data.providerMessageId, { mode: body.data.mode, rescan: body.data.rescan });
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

    priv.get<{ Params: { id: string } }>("/v1/messages/:id/verdict", async (req, reply) => {
      if (!SAFE_ID.test(req.params.id)) return fail(reply, "validation", "Bad message id");
      const s = await store.getScan(req.user!.id, req.params.id);
      return s ? { ...s.verdict, pinned: s.pinned } : fail(reply, "not_scanned", "Message not scanned yet");
    });

    priv.post<{ Params: { id: string } }>("/v1/messages/:id/feedback", async (req, reply) => {
      if (!SAFE_ID.test(req.params.id)) return fail(reply, "validation", "Bad message id");
      const body = FeedbackBody.safeParse(req.body);
      if (!body.success) return fail(reply, "validation", "label must be not_phishing or phishing");
      const u = req.user!;
      const fb = await service.applyFeedback(u, req.params.id, body.data.label);
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
