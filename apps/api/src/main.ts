import { AdminQueries, connect, Store } from "@ap/db";
import { buildApp } from "./app.ts";
import { loadConfig } from "./config.ts";
import { loadDotEnv } from "./env.ts";
import { aiProviderFromConfig } from "./aiProvider.ts";
import { createLookups } from "./lookups.ts";
import { gmailProviderFactory } from "./mailer.ts";
import { Metrics } from "./metrics.ts";
import { ScanService } from "./service.ts";
import { runMaintenance, runWorkerPass } from "./worker.ts";

loadDotEnv();
const cfg = loadConfig(process.env);
const conn = await connect(cfg.databaseUrl, { dataDir: cfg.dataDir });
const store = new Store(conn.db);
const admin = new AdminQueries(conn.db);
const metrics = new Metrics();
const mailFor = cfg.google ? gmailProviderFactory({ ...cfg.google, tokenKey: cfg.tokenKey }) : () => null;
const service = new ScanService({
  store, mailFor, metrics,
  lookups: createLookups({ ...cfg.lookups, log: (m) => console.error(m) }),
  ai: cfg.ai ? { provider: aiProviderFromConfig(cfg.ai), timeoutMs: cfg.ai.timeoutMs, price: cfg.ai.price, maxUserBudgetUsd: cfg.ai.maxUserBudgetUsd, log: (m) => console.error(m) } : undefined,
});
if (cfg.ai) console.log(`AI layer available: ${cfg.ai.kind}/${cfg.ai.model} (off for each user until they enable it)`);

if (cfg.role !== "worker") {
  const app = buildApp({ store, service, admin, metrics, metricsToken: cfg.metricsToken, serverId: cfg.serverId, secret: cfg.secret });
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
