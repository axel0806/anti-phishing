import { describe, it, expect } from "vitest";
import { GmailProvider, type FetchLike } from "../src/gmail.ts";

const ok = (j: unknown) => ({ ok: true, status: 200, json: async () => j, text: async () => JSON.stringify(j) });

describe("gmail minors", () => {
  it("finds an existing label case-insensitively instead of creating a conflicting one", async () => {
    const calls: string[] = [];
    const f: FetchLike = async (url, init) => {
      calls.push((init?.method ?? "GET") + " " + url);
      if (url.endsWith("/labels")) return ok({ labels: [{ id: "L9", name: "phishing" }] });
      return ok({});
    };
    const g = new GmailProvider(async () => "t", f);
    expect(await g.ensureFolder("Phishing")).toBe("L9");
    expect(calls.some((c) => c.startsWith("POST") && c.endsWith("/labels"))).toBe(false);
  });
  it("follows nextPageToken up to the requested count", async () => {
    const f: FetchLike = async (url) => {
      if (url.includes("pageToken=p2")) return ok({ messages: [{ id: "c" }, { id: "d" }] });
      return ok({ messages: [{ id: "a" }, { id: "b" }], nextPageToken: "p2" });
    };
    const g = new GmailProvider(async () => "t", f);
    expect(await g.listRecentInbox(3)).toEqual(["a", "b", "c"]);
    expect(await g.listRecentInbox(10)).toEqual(["a", "b", "c", "d"]);
  });
  it("forgets cached label ids after a 404 so a deleted label is recreated", async () => {
    let deleted = false, creates = 0;
    const f: FetchLike = async (url, init) => {
      const m = init?.method ?? "GET";
      if (url.endsWith("/labels") && m === "GET") return ok({ labels: deleted ? [] : [{ id: "L1", name: "Phishing" }] });
      if (url.endsWith("/labels") && m === "POST") { creates++; return ok({ id: "L2", name: "Phishing" }); }
      if (url.endsWith("/modify") && JSON.stringify(init?.body).includes("L1") && deleted) return { ok: false, status: 400, json: async () => ({}), text: async () => "bad label" };
      return ok({});
    };
    const g = new GmailProvider(async () => "t", f);
    await g.move("m1", "Phishing");
    deleted = true;
    await g.move("m2", "Phishing");
    expect(creates).toBe(1);
  });
});

describe("unmove", () => {
  it("removes the folder label and puts the message back in the inbox, never deleting", async () => {
    const bodies: unknown[] = [];
    const f: FetchLike = async (url, init) => {
      if (url.endsWith("/labels")) return ok({ labels: [{ id: "L7", name: "Phishing" }] });
      if (url.endsWith("/modify")) bodies.push(JSON.parse(init!.body!));
      return ok({});
    };
    await new GmailProvider(async () => "t", f).unmove("m1", "Phishing");
    expect(bodies).toEqual([{ addLabelIds: ["INBOX"], removeLabelIds: ["L7"] }]);
  });
  it("is a no-op when the folder label does not exist", async () => {
    const calls: string[] = [];
    const f: FetchLike = async (url, init) => { calls.push((init?.method ?? "GET") + " " + url); return ok({ labels: [] }); };
    await new GmailProvider(async () => "t", f).unmove("m1", "Phishing");
    expect(calls.some((c) => c.includes("/modify") || c.startsWith("POST"))).toBe(false);
  });
});
