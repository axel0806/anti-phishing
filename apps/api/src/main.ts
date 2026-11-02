import { connect, Store } from "@ap/db";
import { buildApp } from "./app.ts";
import { loadConfig } from "./config.ts";
import { loadDotEnv } from "./env.ts";
import { gmailProviderFactory } from "./mailer.ts";
import { ScanService } from "./service.ts";
import { runWorkerPass } from "./worker.ts";

loadDotEnv();
const cfg = loadConfig(process.env);
const conn = await connect(cfg.databaseUrl, { dataDir: cfg.dataDir });
const store = new Store(conn.db);
const mailFor = cfg.google ? gmailProviderFactory({ ...cfg.google, tokenKey: cfg.tokenKey }) : () => null;
const service = new ScanService({ store, mailFor });

if (cfg.role !== "worker") {
  const app = buildApp({ store, service, serverId: cfg.serverId, secret: cfg.secret });
  await app.listen({ port: cfg.port, host: "0.0.0.0" });
  console.log(`API listening on :${cfg.port} (server id ${cfg.serverId})`);
}
if (cfg.role !== "api") {
  let running = false;
  const tick = async () => {
    if (running) return; // never overlap passes
    running = true;
    try {
      const r = await runWorkerPass(store, service, mailFor, { log: (m) => console.error(m) });
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
}

const shutdown = async () => {
  await conn.close();
  process.exit(0);
};
process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);
