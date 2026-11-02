import { createServer, type Server } from "node:http";
import type { VerdictStore } from "./runner.ts";

/** Read-only verdict API on localhost, no CORS (the extension fetches from its background script); same shape as the Phase 2 `/v1/messages/:id/verdict`. */
export function createVerdictServer(store: VerdictStore): Server {
  return createServer((req, res) => {
    // Only loopback Host headers are served: a DNS-rebinding page reaches this port with its own hostname.
    const host = (req.headers.host ?? "").replace(/:\d+$/, "").toLowerCase();
    const headers: Record<string, string> = { "Content-Type": "application/json" };
    if (host !== "127.0.0.1" && host !== "localhost") {
      res.writeHead(403, headers).end(JSON.stringify({ error: { code: "forbidden", message: "Bad host" } }));
      return;
    }
    const url = new URL(req.url ?? "/", "http://127.0.0.1");
    if (url.pathname === "/v1/health") { res.writeHead(200, headers).end(JSON.stringify({ version: "0.1.0", apiVersions: ["v1"] })); return; }
    const m = /^\/v1\/messages\/([A-Za-z0-9_-]+)\/verdict$/.exec(url.pathname);
    if (req.method !== "GET" || !m) { res.writeHead(404, headers).end(JSON.stringify({ error: { code: "not_found", message: "Not found" } })); return; }
    const v = store.get(m[1]!);
    if (!v) { res.writeHead(404, headers).end(JSON.stringify({ error: { code: "not_scanned", message: "Message not scanned yet" } })); return; }
    res.writeHead(200, headers).end(JSON.stringify(v));
  });
}
