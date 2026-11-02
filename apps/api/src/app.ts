import Fastify, { type FastifyInstance, type FastifyReply, type FastifyRequest } from "fastify";
import { z } from "zod";
import { applyPatch, hasDangerousKey, SettingsOverridesSchema } from "@ap/settings";
import { ListEntrySchema } from "@ap/shared";
import type { Store, User } from "@ap/db";
import { signToken, verifyToken } from "./auth.ts";
import { MailUnavailable, ScanInProgress, type ScanService } from "./service.ts";

export const API_VERSION = "0.2.0";

export interface AppDeps {
  store: Store;
  service: ScanService;
  serverId: string;
  secret: string;
}

declare module "fastify" {
  interface FastifyRequest { user?: User }
}

type Code = "locked_field" | "validation" | "unauthorized" | "forbidden" | "rate_limited" | "scan_in_progress" | "not_found" | "not_scanned" | "mail_unavailable";
const STATUS: Record<Code, number> = {
  locked_field: 409, validation: 422, unauthorized: 401, forbidden: 403, rate_limited: 429, scan_in_progress: 409,
  not_found: 404, not_scanned: 404, mail_unavailable: 503,
};
function fail(reply: FastifyReply, code: Code, message: string, fields?: string[]) {
  return reply.code(STATUS[code]).send({ error: { code, message, ...(fields?.length ? { fields } : {}) } });
}

const ScanBody = z.object({ providerMessageId: z.string().min(1).max(200), mode: z.enum(["dry_run", "act"]).optional(), rescan: z.boolean().optional() });
const FeedbackBody = z.object({ label: z.enum(["not_phishing", "phishing"]), updateList: z.boolean().optional() });
const PolicyBody = z.object({ values: SettingsOverridesSchema, locked: z.array(z.string()) });
const KindParam = z.enum(["allow", "block"]);
const ListBody = ListEntrySchema.extend({ scope: z.enum(["user", "org"]).optional() });
const SETTINGS_KEYS = new Set(Object.keys(SettingsOverridesSchema.shape));
const SAFE_ID = /^[A-Za-z0-9_-]{1,200}$/;

export function buildApp(deps: AppDeps): FastifyInstance {
  const { store, service, serverId, secret } = deps;
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

  app.get("/v1/health", async () => ({ version: API_VERSION, serverId, apiVersions: ["v1"] }));

  // ---- everything below needs a valid session token for this server ----
  app.register(async (priv) => {
    priv.addHook("preHandler", async (req: FastifyRequest, reply: FastifyReply) => {
      const m = /^Bearer (.+)$/.exec(req.headers.authorization ?? "");
      const claims = m ? verifyToken(secret, m[1]!, serverId) : null;
      const user = claims ? await store.getUser(claims.uid) : null;
      if (!user) return fail(reply, "unauthorized", "Missing or invalid session token");
      req.user = user;
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
      const unknown = body.data.locked.filter((k) => !SETTINGS_KEYS.has(k));
      if (unknown.length) return fail(reply, "validation", "Unknown settings keys in locked", unknown);
      await store.setOrgPolicy(req.params.id, body.data);
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
      return { days, ...(await store.statsFor(req.user!.id, days)) };
    });
  });

  return app;
}

export { signToken };
