import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { z } from "zod";
import { DEFAULT_WEIGHTS, type FlagId } from "@ap/shared";
import type { AdminQueries, Range, Store, User } from "@ap/db";
import { toCsv } from "./csv.ts";
import { fail } from "./errors.ts";
import type { ScanService } from "./service.ts";

type Role = "viewer" | "analyst" | "admin";
const RANK: Record<string, number> = { viewer: 1, analyst: 2, admin: 3 };
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const SAFE_ID = /^[A-Za-z0-9_-]{1,200}$/;
const DAY = /^\d{4}-\d{2}-\d{2}$/;
const MS_DAY = 86_400_000;
const MAX_SPAN_DAYS = 366;

const Verdict = z.enum(["safe", "suspicious", "phishing"]);
const LogQuery = z.object({
  verdict: Verdict.optional(), flag: z.string().max(60).optional(), sender: z.string().max(200).optional(),
  limit: z.coerce.number().int().min(1).max(100000).default(50), offset: z.coerce.number().int().min(0).default(0),
});

interface Deps { store: Store; admin: AdminQueries; service: ScanService }

function parseRange(q: { from?: string; to?: string }): Range | string {
  const day = (s: string) => (DAY.test(s) && !Number.isNaN(Date.parse(s + "T00:00:00Z")) ? new Date(s + "T00:00:00Z") : null);
  const tomorrow = new Date(new Date().toISOString().slice(0, 10) + "T00:00:00Z").getTime() + MS_DAY;
  const to = q.to ? day(q.to) : new Date(tomorrow);
  const from = q.from ? day(q.from) : to ? new Date(to.getTime() - 30 * MS_DAY) : null;
  if (!from || !to) return "from and to must be dates like 2026-01-31";
  if (from >= to) return "from must be before to";
  if ((to.getTime() - from.getTime()) / MS_DAY > MAX_SPAN_DAYS) return `the range may span at most ${MAX_SPAN_DAYS} days`;
  return { from, to };
}

/**
 * The admin dashboard API. Every route is scoped to the caller's own org and gated by role:
 * viewer = aggregate panels, analyst = + email log, admin = + per-user data, audit log and actions.
 * Email-log views, exports, per-user views and actions are written to the audit log.
 */
export function registerAdminRoutes(priv: FastifyInstance, deps: Deps): void {
  const { store, admin, service } = deps;

  const need = (min: Role) => async (req: FastifyRequest, reply: FastifyReply) => {
    const u = req.user!;
    if (!u.orgId || (RANK[u.role] ?? 0) < RANK[min]!) return fail(reply, "forbidden", "Your role does not allow this");
  };
  const csvOrJson = async (req: FastifyRequest, reply: FastifyReply, panel: string, json: unknown, rows: Record<string, unknown>[], columns?: string[]) => {
    if ((req.query as { format?: string }).format !== "csv") return json;
    const u = req.user!;
    await admin.audit(u.orgId!, u.id, "export", `panel:${panel}`);
    return reply.header("content-type", "text/csv; charset=utf-8").header("content-disposition", `attachment; filename="${panel}.csv"`).send(toCsv(rows, columns));
  };
  const withRange = (panel: string, min: Role, fn: (u: User, r: Range, req: FastifyRequest, reply: FastifyReply) => Promise<{ json: unknown; rows: Record<string, unknown>[]; columns?: string[] } | void>) => {
    priv.get<{ Querystring: { from?: string; to?: string; format?: string } }>(`/v1/admin/stats/${panel}`, { preHandler: need(min) }, async (req, reply) => {
      const range = parseRange(req.query);
      if (typeof range === "string") return fail(reply, "validation", range);
      const out = await fn(req.user!, range, req, reply);
      if (!out) return; // the handler already replied
      return csvOrJson(req, reply, panel, out.json, out.rows, out.columns);
    });
  };

  // Keep today's and yesterday's rollup fresh on demand; older days are settled by the nightly job.
  const refresh = async () => {
    const d = (n: number) => new Date(Date.now() - n * MS_DAY).toISOString().slice(0, 10);
    await admin.rollupDay(d(1));
    await admin.rollupDay(d(0));
  };

  withRange("overview", "viewer", async (u, r) => {
    await refresh();
    const o = await admin.overview(u.orgId!, r);
    return { json: o, rows: [{ period: "current", ...o.current }, { period: "previous", ...o.previous }] };
  });
  withRange("trend", "viewer", async (u, r) => {
    await refresh();
    const rows = await admin.trend(u.orgId!, r);
    return { json: { rows }, rows };
  });
  withRange("flags", "viewer", async (u, r) => {
    const rows = await admin.topFlags(u.orgId!, r);
    return { json: { rows }, rows };
  });
  withRange("targets", "viewer", async (u, r) => {
    const b = await admin.brandsAndDomains(u.orgId!, r);
    return { json: b, rows: [...b.impersonated.map((x) => ({ kind: "impersonated", name: x.evidence, count: x.count })), ...b.senderDomains.map((x) => ({ kind: "sender_domain", name: x.domain, count: x.count }))] };
  });
  withRange("quality", "viewer", async (u, r) => {
    const q = await admin.quality(u.orgId!, r);
    return { json: q, rows: [q] };
  });
  withRange("ai", "viewer", async (u, r) => {
    const a = await admin.aiUsage(u.orgId!, r);
    return { json: a, rows: [a] };
  });
  withRange("health", "viewer", async (u) => {
    const h = await admin.health(u.orgId!);
    return { json: h, rows: [h] };
  });
  withRange("users", "admin", async (u, r) => {
    await admin.audit(u.orgId!, u.id, "users.view", null);
    const rows = await admin.targets(u.orgId!, r);
    return { json: { rows }, rows };
  });

  priv.get<{ Querystring: Record<string, string> }>("/v1/admin/scans", { preHandler: need("analyst") }, async (req, reply) => {
    const range = parseRange(req.query);
    if (typeof range === "string") return fail(reply, "validation", range);
    const q = LogQuery.safeParse(req.query);
    if (!q.success) return fail(reply, "validation", q.error.issues.map((i) => `${i.path.join(".")}: ${i.message}`).join("; "));
    const u = req.user!;
    const { limit, offset, ...filters } = q.data;
    const out = await admin.scanLog(u.orgId!, range, filters, { limit, offset });
    const described = Object.entries(filters).filter(([, v]) => v).map(([k, v]) => `${k}=${v}`).join(" ");
    await admin.audit(u.orgId!, u.id, "email_log.view", described || "all");
    const rows = out.rows.map((x) => ({ ...x, createdAt: x.createdAt.toISOString() }));
    return csvOrJson(req, reply, "scans", { rows, total: out.total }, rows, ["messageId", "userEmail", "sender", "score", "verdict", "pinned", "createdAt", "flags"]);
  });

  priv.get<{ Querystring: { limit?: string; offset?: string } }>("/v1/admin/audit", { preHandler: need("admin") }, async (req) => {
    const limit = Math.min(500, Math.max(1, Number(req.query.limit) || 100));
    const offset = Math.max(0, Number(req.query.offset) || 0);
    const rows = (await admin.auditLog(req.user!.orgId!, { limit, offset })).map((r) => ({ ...r, createdAt: r.createdAt.toISOString() }));
    return { rows };
  });

  const act = (verb: "release" | "requarantine", label: "not_phishing" | "phishing") =>
    priv.post<{ Params: { userId: string; id: string } }>(`/v1/admin/users/:userId/messages/:id/${verb}`, { preHandler: need("admin") }, async (req, reply) => {
      const actor = req.user!;
      const { userId, id } = req.params;
      const target = UUID.test(userId) && SAFE_ID.test(id) ? await store.getUser(userId) : null;
      if (!target || target.orgId !== actor.orgId) return fail(reply, "not_found", "No such user in your organization"); // same answer for "exists elsewhere": no probing
      const fb = await service.applyFeedback(target, id, label);
      if (!fb) return fail(reply, "not_found", "That message was never scanned");
      await admin.audit(actor.orgId!, actor.id, `message.${verb}`, `user=${target.email} message=${id}`);
      return { ...fb.scan.verdict, pinned: fb.scan.pinned, mailAction: fb.mailAction };
    });
  act("release", "not_phishing");
  act("requarantine", "phishing");

  // ---- weight suggestions: shown, never applied ----
  priv.get("/v1/settings/suggestions", async (req) => {
    const user = req.user!;
    const [rates, eff] = await Promise.all([admin.flagFalsePositiveRates(user.id), service.effectiveSettings(user)]);
    const suggestions = rates
      .filter((r) => r.fired >= 5 && r.rate >= 0.3)
      .map((r) => {
        const current = eff.settings.flags[r.flagId as FlagId]?.weight ?? DEFAULT_WEIGHTS[r.flagId as FlagId] ?? 0;
        return { flagId: r.flagId, fired: r.fired, falsePositives: r.falsePositives, falsePositiveRate: r.rate, currentWeight: current, suggestedWeight: Math.max(0, Math.round(current * (1 - r.rate))) };
      })
      .filter((s) => s.currentWeight > 0 && s.suggestedWeight < s.currentWeight);
    return { suggestions };
  });
}
