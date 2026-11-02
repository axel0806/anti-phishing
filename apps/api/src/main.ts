import { AdminQueries, connect, Store } from "@ap/db";
import { buildApp } from "./app.ts";
import { existsSync } from "node:fs";
import { resolve } from "node:path";
import { loadConfig } from "./config.ts";
import { Oidc } from "./oidc.ts";
import { loadDotEnv } from "./env.ts";
import { aiProviderFromConfig } from "./aiProvider.ts";
import { createLookups } from "./lookups.ts";
import { mailProviderFactory } from "./mailer.ts";
import { Metrics } from "./metrics.ts";
import { ScanService } from "./service.ts";
import { runMaintenance, runWorkerPass } from "./worker.ts";

loadDotEnv();
const cfg = loadConfig(process.env);
const conn = await connect(cfg.databaseUrl, { dataDir: cfg.dataDir });
const store = new Store(conn.db);
const admin = new AdminQueries(conn.db);
const metrics = new Metrics();
const mailFor = cfg.google || cfg.microsoft
  ? mailProviderFactory({
      google: cfg.google, microsoft: cfg.microsoft, tokenKey: cfg.tokenKey,
      persist: (userId, blob) => store.setEncryptedTokens(userId, blob).catch((e) => console.error("could not save refreshed token:", (e as Error).message)),
      // A revoked link would otherwise fail on every pass forever: unlink it so the user can reconnect.
      onRevoked: (userId) => { console.error(`mailbox access was revoked for user ${userId}; unlinking`); void store.setEncryptedTokens(userId, null); },
    })
  : () => null;
const service = new ScanService({
  store, mailFor, metrics,
  lookups: createLookups({ ...cfg.lookups, log: (m) => console.error(m) }),
  ai: cfg.ai ? { provider: aiProviderFromConfig(cfg.ai), timeoutMs: cfg.ai.timeoutMs, price: cfg.ai.price, maxUserBudgetUsd: cfg.ai.maxUserBudgetUsd, log: (m) => console.error(m) } : undefined,
});
if (cfg.ai) console.log(`AI layer available: ${cfg.ai.kind}/${cfg.ai.model} (off for each user until they enable it)`);

/** The dashboard and add-in are built into dist folders (npm run build:ui); serve whichever exist. */
function builtSites() {
  const dir = (p: string) => (existsSync(resolve(p)) ? resolve(p) : undefined);
  const sites = { admin: dir("apps/dashboard/dist"), addin: dir("apps/outlook-addin/dist") };
  if (!sites.admin) console.log("Dashboard not built (run: npm run build:ui); /admin/ will be unavailable.");
  return sites;
}

if (cfg.role !== "worker") {
  const app = buildApp({ store, service, admin, metrics, sites: builtSites(), oidc: cfg.oidc ? new Oidc({ ...cfg.oidc, secret: cfg.secret }) : undefined, metricsToken: cfg.metricsToken, serverId: cfg.serverId, secret: cfg.secret });
  await app.listen({ port: cfg.port, host: "0.0.0.0" });
  console.log(`API listening on :${cfg.port} (server id ${cfg.serverId})`);
}
if (cfg.role !== "api") {
  let running = false;
  const tick = async () => {
    if (running) return; // never overlap passes
    running = true;
    try {
      const r = await runWorkerPass(store, service, mailFor, { log: (m) => console.error(m), metrics });
      if (r.scanned || r.failed) console.log(`worker: users=${r.users} scanned=${r.scanned} failed=${r.failed}`);
    } catch (e) {
      console.error("worker pass failed:", (e as Error).message);
    } finally {
      running = false;
    }
  };
  void tick();
  setInterval(tick, cfg.pollSeconds * 1000);
  console.log(`Worker polling every ${cfg.pollSeconds}s`);
  const maintain = () => runMaintenance(store, cfg.retentionDays, admin).then((r) => r.purged && console.log(`retention: purged ${r.purged} scans older than ${cfg.retentionDays} days`), (e) => console.error("maintenance failed:", (e as Error).message));
  void maintain();
  setInterval(maintain, 24 * 3600 * 1000);
}

const shutdown = async () => {
  await conn.close();
  process.exit(0);
};
process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);
