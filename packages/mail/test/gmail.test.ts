import { describe, it, expect } from "vitest";
import { GmailProvider, type FetchLike } from "../src/gmail.ts";
import { buildAuthUrl, tokenSource } from "../src/oauth.ts";

function fakeGmail() {
  const calls: { method: string; url: string; body?: any }[] = [];
  const labels = [{ id: "INBOX", name: "INBOX" }];
  const f: FetchLike = async (url, init) => {
    const method = init?.method ?? "GET";
    const body = init?.body ? JSON.parse(init.body) : undefined;
    calls.push({ method, url, body });
    const ok = (j: unknown) => ({ ok: true, status: 200, json: async () => j, text: async () => JSON.stringify(j) });
    if (url.endsWith("/labels") && method === "GET") return ok({ labels });
    if (url.endsWith("/labels") && method === "POST") { const l = { id: "L" + labels.length, name: body.name }; labels.push(l); return ok(l); }
    if (url.includes("format=raw")) return ok({ raw: Buffer.from("Subject: hi\r\n\r\nbody").toString("base64url") });
    if (url.includes("format=minimal")) return ok({ labelIds: ["INBOX", "L1"] });
    if (url.includes("labelIds=INBOX")) return ok({ messages: [{ id: "a" }, { id: "b" }] });
    return ok({});
  };
  return { f, calls };
}

describe("GmailProvider", () => {
  it("fetchRaw decodes base64url MIME", async () => {
    const { f } = fakeGmail();
    const g = new GmailProvider(async () => "tok", f);
    expect((await g.fetchRaw("m1")).toString()).toContain("Subject: hi");
  });
  it("creates a label once and reuses it; move adds it and removes INBOX, never deletes", async () => {
    const { f, calls } = fakeGmail();
    const g = new GmailProvider(async () => "tok", f);
    await g.move("m1", "Phishing");
    await g.move("m2", "Phishing");
    expect(calls.filter((c) => c.method === "POST" && c.url.endsWith("/labels"))).toHaveLength(1);
    const mods = calls.filter((c) => c.url.endsWith("/modify"));
    expect(mods).toHaveLength(2);
    expect(mods[0]!.body).toEqual({ addLabelIds: ["L1"], removeLabelIds: ["INBOX"] });
    expect(calls.some((c) => c.method === "DELETE" || c.url.includes("/trash"))).toBe(false);
  });
  it("addLabel keeps the message in the inbox", async () => {
    const { f, calls } = fakeGmail();
    await new GmailProvider(async () => "tok", f).addLabel("m1", "Suspicious");
    expect(calls.find((c) => c.url.endsWith("/modify"))!.body).toEqual({ addLabelIds: ["L1"] });
  });
  it("lists inbox ids and resolves label names without creating labels", async () => {
    const { f, calls } = fakeGmail();
    const g = new GmailProvider(async () => "tok", f);
    expect(await g.listRecentInbox()).toEqual(["a", "b"]);
    await g.ensureFolder("Phishing");
    expect(await g.getLabelNames("a")).toEqual(["INBOX", "Phishing"]);
    expect(calls.filter((c) => c.method === "POST" && c.url.endsWith("/labels"))).toHaveLength(1);
  });
  it("surfaces API errors", async () => {
    const f: FetchLike = async () => ({ ok: false, status: 403, json: async () => ({}), text: async () => "denied" });
    await expect(new GmailProvider(async () => "t", f).fetchRaw("x")).rejects.toThrow(/403/);
  });
});

describe("oauth", () => {
  it("auth URL requests gmail.modify, offline access and PKCE", () => {
    const u = new URL(buildAuthUrl({ clientId: "cid", clientSecret: "s" }, "st", "ch"));
    expect(u.searchParams.get("scope")).toBe("https://www.googleapis.com/auth/gmail.modify");
    expect(u.searchParams.get("access_type")).toBe("offline");
    expect(u.searchParams.get("code_challenge_method")).toBe("S256");
  });
  it("tokenSource refreshes only when expired and persists the result", async () => {
    let n = 0, saved = 0;
    const f: FetchLike = async () => { n++; return { ok: true, status: 200, json: async () => ({ access_token: "new", expires_in: 3600 }), text: async () => "" }; };
    const tokens = { refresh_token: "r", access_token: "old", expires_at: Date.now() - 1 };
    const get = tokenSource({ clientId: "c", clientSecret: "s" }, tokens, () => saved++, f);
    expect(await get()).toBe("new");
    expect(await get()).toBe("new");
    expect(n).toBe(1);
    expect(saved).toBe(1);
  });
});
