import { describe, it, expect } from "vitest";
import { fetchVerdict } from "../src/background.ts";

describe("fetchVerdict", () => {
  it("returns the verdict JSON, encoding the id", async () => {
    let url = "";
    const f = (async (u: string) => { url = u; return { ok: true, json: async () => ({ action: "none" }) }; }) as unknown as typeof fetch;
    expect(await fetchVerdict("a/b", f)).toEqual({ action: "none" });
    expect(url).toBe("http://127.0.0.1:8787/v1/messages/a%2Fb/verdict");
  });
  it("returns null on 404 and when the server is down", async () => {
    expect(await fetchVerdict("x", (async () => ({ ok: false })) as unknown as typeof fetch)).toBeNull();
    expect(await fetchVerdict("x", (async () => { throw new Error("down"); }) as unknown as typeof fetch)).toBeNull();
  });
});
