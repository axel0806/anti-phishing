import { describe, expect, it } from "vitest";
import { GraphProvider } from "../src/graph.ts";
import { buildAuthUrl, tokenSource, MICROSOFT_SCOPE, microsoftEndpoints, type OAuthConfig } from "../src/oauth.ts";
import type { FetchLike } from "../src/gmail.ts";

type Call = { method: string; url: string; headers: Record<string, string>; body?: any };
type Handler = (c: Call) => { status?: number; json?: unknown; text?: string } | undefined;

function fake(handler: Handler) {
  const calls: Call[] = [];
  const f: FetchLike = async (url, init) => {
    const call: Call = { method: init?.method ?? "GET", url, headers: init?.headers ?? {}, body: init?.body ? JSON.parse(init.body) : undefined };
    calls.push(call);
    const r = handler(call) ?? { json: {} };
    const status = r.status ?? 200;
    return { ok: status < 300, status, json: async () => r.json ?? {}, text: async () => r.text ?? JSON.stringify(r.json ?? {}) };
  };
  return { f, calls };
}
const G = "https://graph.microsoft.com/v1.0";
const provider = (h: Handler) => { const x = fake(h); return { p: new GraphProvider(async () => "tok", x.f), calls: x.calls }; };

describe("GraphProvider safety", () => {
  it("never sends the bearer token to a page link outside Microsoft Graph", async () => {
    const { p, calls } = provider((c) => (c.url.includes("evil") ? { json: {} } : { json: { value: [{ id: "a" }], "@odata.nextLink": "https://evil.example/steal" } }));
    await expect(p.listRecentInbox(50)).rejects.toThrow(/outside Microsoft Graph/);
    expect(calls.some((c) => c.url.includes("evil"))).toBe(false);
  });

  it("reads the MIME source as bytes, so 8-bit content is not corrupted", async () => {
    const bytes = Buffer.from([0x53, 0x3a, 0x20, 0xe9, 0xff, 0x0d, 0x0a]);
    const f: FetchLike = async () => ({ ok: true, status: 200, json: async () => ({}), text: async () => bytes.toString("utf8"), arrayBuffer: async () => bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.length) as ArrayBuffer });
    expect((await new GraphProvider(async () => "t", f).fetchRaw("x")).equals(bytes)).toBe(true);
  });
});

describe("GraphProvider", () => {
  it("asks for immutable ids on every request, so a moved message keeps its id", async () => {
    const { p, calls } = provider(() => ({ json: { value: [] } }));
    await p.listRecentInbox(5);
    expect(calls.every((c) => c.headers.Prefer === 'IdType="ImmutableId"' && c.headers.Authorization === "Bearer tok")).toBe(true);
  });

  it("fetchRaw returns the MIME source", async () => {
    const { p, calls } = provider(() => ({ text: "Subject: hi\r\n\r\nbody" }));
    expect((await p.fetchRaw("AAA=")).toString()).toContain("Subject: hi");
    expect(calls[0]!.url).toBe(`${G}/me/messages/AAA%3D/$value`);
  });

  it("lists the newest inbox ids and follows pages up to the requested count", async () => {
    const { p, calls } = provider((c) => c.url.includes("page2")
      ? { json: { value: [{ id: "c" }, { id: "d" }] } }
      : { json: { value: [{ id: "a" }, { id: "b" }], "@odata.nextLink": `${G}/me/mailFolders/inbox/messages?page2` } });
    expect(await p.listRecentInbox(3)).toEqual(["a", "b", "c"]);
    expect(calls[0]!.url).toContain("/me/mailFolders/inbox/messages");
    expect(calls[0]!.url).toContain("$orderby=receivedDateTime%20desc");
    expect(await p.listRecentInbox(10)).toEqual(["a", "b", "c", "d"]);
  });

  it("creates the Phishing folder once, then moves into it and never deletes", async () => {
    const folders: { id: string; displayName: string }[] = [];
    const { p, calls } = provider((c) => {
      if (c.method === "GET" && c.url.includes("/me/mailFolders?")) return { json: { value: folders.filter((f) => c.url.includes(encodeURIComponent(`'${f.displayName}'`))) } };
      if (c.method === "POST" && c.url.endsWith("/me/mailFolders")) { const f = { id: "F1", displayName: c.body.displayName }; folders.push(f); return { json: f }; }
      return { json: { id: "moved" } };
    });
    await p.move("m1", "Phishing");
    await p.move("m2", "Phishing");
    expect(calls.filter((c) => c.method === "POST" && c.url.endsWith("/me/mailFolders"))).toHaveLength(1);
    const moves = calls.filter((c) => c.url.endsWith("/move"));
    expect(moves.map((m) => m.body)).toEqual([{ destinationId: "F1" }, { destinationId: "F1" }]);
    expect(calls.some((c) => c.method === "DELETE" || c.url.includes("/permanentDelete"))).toBe(false);
  });

  it("escapes quotes in folder names used in an OData filter", async () => {
    const { p, calls } = provider(() => ({ json: { value: [{ id: "F", displayName: "O'Brien" }] } }));
    await p.ensureFolder("O'Brien");
    expect(decodeURIComponent(calls[0]!.url)).toContain("displayName eq 'O''Brien'");
  });

  it("unmove returns the message to the inbox", async () => {
    const { p, calls } = provider(() => ({ json: {} }));
    await p.unmove("m1", "Phishing");
    expect(calls[0]!.url).toBe(`${G}/me/messages/m1/move`);
    expect(calls[0]!.body).toEqual({ destinationId: "inbox" });
  });

  it("addLabel adds an Outlook category without dropping the existing ones", async () => {
    const { p, calls } = provider((c) => (c.method === "GET" ? { json: { categories: ["Blue category"] } } : { json: {} }));
    await p.addLabel("m1", "Suspicious");
    await p.addLabel("m1", "Blue category"); // already present: no duplicate
    const patches = calls.filter((c) => c.method === "PATCH");
    expect(patches[0]!.body).toEqual({ categories: ["Blue category", "Suspicious"] });
    expect(patches[1]!.body).toEqual({ categories: ["Blue category"] });
  });

  it("getLabelNames reports the containing folder's name and the categories", async () => {
    const { p } = provider((c) => c.url.includes("/mailFolders/F9") ? { json: { displayName: "Phishing" } } : { json: { categories: ["Suspicious"], parentFolderId: "F9" } });
    expect(await p.getLabelNames("m1")).toEqual(["Phishing", "Suspicious"]);
  });

  it("delta polling returns changed ids and a token to resume from", async () => {
    const { p, calls } = provider((c) => c.url.includes("deltatoken") ? { json: { value: [{ id: "n1" }], "@odata.deltaLink": `${G}/delta?deltatoken=T2` } } : { json: { value: [{ id: "a" }, { id: "b" }], "@odata.deltaLink": `${G}/delta?deltatoken=T1` } });
    const first = await p.deltaInbox();
    expect(first).toEqual({ ids: ["a", "b"], next: `${G}/delta?deltatoken=T1` });
    expect(await p.deltaInbox(first.next)).toEqual({ ids: ["n1"], next: `${G}/delta?deltatoken=T2` });
    expect(calls[1]!.url).toBe(`${G}/delta?deltatoken=T1`);
  });

  it("refuses a delta link that points anywhere but Graph (no token leakage)", async () => {
    const { p, calls } = provider(() => ({ json: {} }));
    await expect(p.deltaInbox("https://evil.example/steal")).rejects.toThrow(/graph/i);
    expect(calls).toHaveLength(0);
  });

  it("surfaces API errors with the status", async () => {
    const { p } = provider(() => ({ status: 403, text: "denied" }));
    await expect(p.fetchRaw("x")).rejects.toThrow(/403/);
  });
});

describe("Microsoft OAuth", () => {
  const cfg: OAuthConfig = { clientId: "cid", ...microsoftEndpoints("contoso.onmicrosoft.com"), scope: MICROSOFT_SCOPE, redirectHost: "localhost" };
  it("builds a tenant-specific authorization URL for Mail.ReadWrite + offline access with PKCE", () => {
    const u = new URL(buildAuthUrl(cfg, "st", "ch"));
    expect(u.origin + u.pathname).toBe("https://login.microsoftonline.com/contoso.onmicrosoft.com/oauth2/v2.0/authorize");
    expect(u.searchParams.get("scope")).toBe("offline_access Mail.ReadWrite");
    expect(u.searchParams.get("redirect_uri")).toBe("http://localhost:53682/callback");
    expect(u.searchParams.get("code_challenge_method")).toBe("S256");
  });
  it("Google defaults are unchanged", () => {
    const u = new URL(buildAuthUrl({ clientId: "g", clientSecret: "s" }, "st", "ch"));
    expect(u.origin).toBe("https://accounts.google.com");
    expect(u.searchParams.get("redirect_uri")).toBe("http://127.0.0.1:53682/callback");
  });
  it("persists a rotated refresh token, omits an absent client secret, and reports revocation", async () => {
    const bodies: string[] = [];
    let respond: { status: number; json: any } = { status: 200, json: { access_token: "a2", expires_in: 3600, refresh_token: "r2" } };
    const f: FetchLike = async (_u, init) => { bodies.push(init!.body!); return { ok: respond.status < 300, status: respond.status, json: async () => respond.json, text: async () => JSON.stringify(respond.json) }; };
    const tokens = { refresh_token: "r1" };
    let saved: unknown, revoked = 0;
    const get = tokenSource(cfg, tokens, (t) => { saved = { ...t }; }, f, () => { revoked++; });
    expect(await get()).toBe("a2");
    expect(tokens.refresh_token).toBe("r2");
    expect((saved as { refresh_token: string }).refresh_token).toBe("r2");
    expect(bodies[0]).not.toContain("client_secret");
    expect(bodies[0]).toContain("scope=offline_access");
    tokens.refresh_token = "r2"; (tokens as any).expires_at = 0;
    respond = { status: 400, json: { error: "invalid_grant", error_description: "revoked" } };
    await expect(get()).rejects.toThrow(/invalid_grant/);
    expect(revoked).toBe(1);
  });
});

describe("GraphProvider.resolveId", () => {
  it("translates an Outlook REST id into the immutable id used for scans", async () => {
    const { p, calls } = provider(() => ({ json: { value: [{ sourceId: "REST1", targetId: "IMM1" }] } }));
    expect(await p.resolveId("REST1", "outlook_rest")).toBe("IMM1");
    expect(calls[0]!.url).toBe(`${G}/me/translateExchangeIds`);
    expect(calls[0]!.body).toEqual({ inputIds: ["REST1"], sourceIdType: "restId", targetIdType: "restImmutableEntryId" });
  });
  it("passes ids through when no translation is requested, and rejects unknown formats", async () => {
    const { p, calls } = provider(() => ({ json: {} }));
    expect(await p.resolveId("X", undefined)).toBe("X");
    await expect(p.resolveId("X", "ews_magic")).rejects.toThrow(/format/i);
    expect(calls).toHaveLength(0);
  });
  it("fails clearly when Graph returns no translation", async () => {
    const { p } = provider(() => ({ json: { value: [{ sourceId: "R", targetId: "" }] } }));
    await expect(p.resolveId("R", "outlook_rest")).rejects.toThrow(/translate/i);
  });
});
