import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { FastifyInstance } from "fastify";
import { connect, Store, type Connection } from "@ap/db";
import { buildApp } from "../src/app.ts";
import { ScanService } from "../src/service.ts";

let root: string, conn: Connection, app: FastifyInstance;
beforeAll(async () => {
  root = mkdtempSync(join(tmpdir(), "ap-static-"));
  mkdirSync(join(root, "admin")); mkdirSync(join(root, "addin"));
  writeFileSync(join(root, "admin", "index.html"), "<!doctype html><title>Dashboard</title>");
  writeFileSync(join(root, "admin", "app.js"), "console.log('dash')");
  writeFileSync(join(root, "addin", "taskpane.html"), "<!doctype html><title>Pane</title>");
  writeFileSync(join(root, "secret.txt"), "TOP SECRET");
  conn = await connect();
  const store = new Store(conn.db);
  app = buildApp({ store, secret: "s".repeat(32), serverId: "x", service: new ScanService({ store, mailFor: () => null }), sites: { admin: join(root, "admin"), addin: join(root, "addin") } });
  await app.ready();
});
afterAll(async () => { await app.close(); await conn.close(); rmSync(root, { recursive: true, force: true }); });

describe("dashboard hosting", () => {
  it("serves index.html with a strict content security policy and hardening headers", async () => {
    const r = await app.inject({ method: "GET", url: "/admin/" });
    expect(r.statusCode).toBe(200);
    expect(r.body).toContain("Dashboard");
    const csp = String(r.headers["content-security-policy"]);
    expect(csp).toContain("default-src 'self'");
    expect(csp).toContain("script-src 'self'");
    expect(csp).not.toMatch(/script-src[^;]*unsafe/);
    expect(csp).toContain("frame-ancestors 'none'");
    expect(r.headers["x-content-type-options"]).toBe("nosniff");
    expect(r.headers["referrer-policy"]).toBe("no-referrer");
  });
  it("redirects /admin to /admin/ and serves assets with the right type", async () => {
    expect((await app.inject({ method: "GET", url: "/admin" })).statusCode).toBe(302);
    const js = await app.inject({ method: "GET", url: "/admin/app.js" });
    expect(js.headers["content-type"]).toMatch(/javascript/);
  });
  it("cannot be tricked into reading files outside its folder", async () => {
    for (const u of ["/admin/..%2fsecret.txt", "/admin/../secret.txt", "/admin/%2e%2e/secret.txt", "/admin/..%5csecret.txt"]) {
      const r = await app.inject({ method: "GET", url: u });
      expect(r.body, u).not.toContain("TOP SECRET");
    }
  });
  it("404s for missing files rather than serving the app shell for them", async () => {
    expect((await app.inject({ method: "GET", url: "/admin/nope.js" })).statusCode).toBe(404);
  });
  it("does not shadow SSO or API routes", async () => {
    expect((await app.inject({ method: "GET", url: "/admin/login" })).statusCode).toBe(404); // no SSO configured: a 404, not a file
    expect((await app.inject({ method: "GET", url: "/v1/health" })).statusCode).toBe(200);
  });
});

describe("Outlook add-in hosting", () => {
  it("serves the task pane to Office hosts, allowing the Office.js CDN and Microsoft frames only", async () => {
    const r = await app.inject({ method: "GET", url: "/addin/taskpane.html" });
    expect(r.statusCode).toBe(200);
    const csp = String(r.headers["content-security-policy"]);
    expect(csp).toContain("https://appsforoffice.microsoft.com");
    expect(csp).toMatch(/frame-ancestors[^;]*outlook/);
    expect(csp).not.toMatch(/frame-ancestors[^;]*\*[^.]/); // never a bare wildcard
    expect(csp).toContain("script-src 'self' https://appsforoffice.microsoft.com");
  });
});

describe("not configured", () => {
  it("serves nothing when no site folders are given", async () => {
    const store = new Store(conn.db);
    const bare = buildApp({ store, secret: "s".repeat(32), serverId: "x", service: new ScanService({ store, mailFor: () => null }) });
    expect((await bare.inject({ method: "GET", url: "/admin/" })).statusCode).toBe(404);
    expect((await bare.inject({ method: "GET", url: "/addin/taskpane.html" })).statusCode).toBe(404);
    await bare.close();
  });
});

describe("Outlook add-in manifest", () => {
  const withUrl = (publicUrl?: string) => {
    const store = new Store(conn.db);
    return buildApp({ store, secret: "s".repeat(32), serverId: "x", service: new ScanService({ store, mailFor: () => null }), sites: { admin: join(root, "admin"), addin: join(root, "addin") }, publicUrl });
  };
  it("is generated from the server's public URL, so it can never point at the wrong address", async () => {
    const a = withUrl("https://phish.acme.example/");
    const r = await a.inject({ method: "GET", url: "/addin/manifest.xml" });
    expect(r.statusCode).toBe(200);
    expect(r.headers["content-type"]).toMatch(/xml/);
    expect(r.headers["content-disposition"]).toMatch(/manifest\.xml/);
    expect(r.body).toContain("https://phish.acme.example/addin/taskpane.html");
    await a.close();
  });
  it("is unavailable (404) without a PUBLIC_URL, or with an insecure one", async () => {
    const none = withUrl(undefined), bad = withUrl("http://phish.acme.example");
    expect((await none.inject({ method: "GET", url: "/addin/manifest.xml" })).statusCode).toBe(404);
    expect((await bad.inject({ method: "GET", url: "/addin/manifest.xml" })).statusCode).toBe(404);
    await none.close(); await bad.close();
  });
});
