import { createServer, type Server } from "node:http";
import type { VerdictStore } from "./runner.ts";

const ALLOWED_ORIGIN = "https://mail.google.com";

/** Read-only verdict API on localhost; same shape as the Phase 2 `/v1/messages/:id/verdict`. */
export function createVerdictServer(store: VerdictStore): Server {
  return createServer((req, res) => {
    const headers: Record<string, string> = {
      "Content-Type": "application/json",
      "Access-Control-Allow-Origin": ALLOWED_ORIGIN,
      Vary: "Origin",
    };
    const url = new URL(req.url ?? "/", "http://127.0.0.1");
    if (req.method === "OPTIONS") { res.writeHead(204, { ...headers, "Access-Control-Allow-Methods": "GET" }).end(); return; }
    if (url.pathname === "/v1/health") { res.writeHead(200, headers).end(JSON.stringify({ version: "0.1.0", apiVersions: ["v1"] })); return; }
    const m = /^\/v1\/messages\/([A-Za-z0-9_-]+)\/verdict$/.exec(url.pathname);
    if (req.method !== "GET" || !m) { res.writeHead(404, headers).end(JSON.stringify({ error: { code: "not_found", message: "Not found" } })); return; }
    const v = store.get(m[1]!);
    if (!v) { res.writeHead(404, headers).end(JSON.stringify({ error: { code: "not_scanned", message: "Message not scanned yet" } })); return; }
    res.writeHead(200, headers).end(JSON.stringify(v));
  });
}
