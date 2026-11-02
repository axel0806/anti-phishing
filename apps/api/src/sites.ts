import fastifyStatic from "@fastify/static";
import type { FastifyInstance } from "fastify";

export interface Sites {
  /** Folder holding the built admin dashboard (served at /admin/). */
  admin?: string;
  /** Folder holding the built Outlook add-in task pane (served at /addin/). */
  addin?: string;
}

// The dashboard loads nothing from anywhere but itself and can never be framed (clickjacking).
const DASHBOARD_CSP = [
  "default-src 'self'", "script-src 'self'", "style-src 'self' 'unsafe-inline'", "img-src 'self' data:", "connect-src 'self'",
  "frame-ancestors 'none'", "base-uri 'none'", "form-action 'self'", "object-src 'none'",
].join("; ");

// Office hosts must be allowed to frame the task pane, and Office.js must come from Microsoft's CDN. Nothing else is opened up.
const ADDIN_CSP = [
  "default-src 'self'", "script-src 'self' https://appsforoffice.microsoft.com", "style-src 'self' 'unsafe-inline'", "img-src 'self' data:", "connect-src 'self'",
  "frame-ancestors https://*.office.com https://*.office365.com https://*.outlook.com https://outlook.live.com https://*.microsoft.com",
  "base-uri 'none'", "object-src 'none'",
].join("; ");

/** Serves the built dashboard and add-in. Missing files are plain 404s: there is no SPA fallback that could mask a typo or probe. */
export function registerSites(app: FastifyInstance, sites: Sites): void {
  const entries: [string, string, string][] = [];
  if (sites.admin) entries.push(["/admin/", sites.admin, DASHBOARD_CSP]);
  if (sites.addin) entries.push(["/addin/", sites.addin, ADDIN_CSP]);
  entries.forEach(([prefix, root, csp], i) => {
    app.register(fastifyStatic, {
      root, prefix, decorateReply: i === 0, index: ["index.html", "taskpane.html"], dotfiles: "deny",
      setHeaders: (res) => {
        res.header("Content-Security-Policy", csp);
        res.header("X-Content-Type-Options", "nosniff");
        res.header("Referrer-Policy", "no-referrer");
        res.header("Cache-Control", "no-cache");
      },
    });
  });
  if (sites.admin) app.get("/admin", async (_req, reply) => reply.redirect("/admin/"));
}
