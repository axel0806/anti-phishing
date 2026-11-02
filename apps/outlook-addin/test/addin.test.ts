import { inflateSync } from "node:zlib";
import { describe, expect, it } from "vitest";
import { ADDIN_ID, renderManifest } from "../src/manifest.ts";
import { clearToken, connectionFromStorage, restIdFor, saveToken } from "../src/helpers.ts";
import { solidPng } from "../src/png.ts";

const mem = () => { const m = new Map<string, string>(); return { getItem: (k: string) => m.get(k) ?? null, setItem: (k: string, v: string) => void m.set(k, v), removeItem: (k: string) => void m.delete(k) }; };

describe("renderManifest", () => {
  const xml = renderManifest("https://phish.example");
  it("points every URL at the server's /addin/ folder and requests read-only access", () => {
    expect(xml).toContain(`<Id>${ADDIN_ID}</Id>`);
    expect(xml).toContain('<SourceLocation DefaultValue="https://phish.example/addin/taskpane.html"/>');
    expect(xml).toContain('<IconUrl DefaultValue="https://phish.example/addin/icon-64.png"/>');
    expect(xml).toContain("<Permissions>ReadItem</Permissions>");
    expect(xml).toContain('<AppDomain>https://phish.example</AppDomain>');
    expect(xml).not.toMatch(/ReadWriteItem|ReadWriteMailbox/);
  });
  it("is well-formed: balanced tags, one root, no leftover placeholders", () => {
    expect(xml.startsWith("<?xml")).toBe(true);
    expect(xml).not.toMatch(/\{\{|\}\}/);
    const open = (xml.match(/<(?!\/|\?|!)[A-Za-z][^>]*[^/]>/g) ?? []).length, close = (xml.match(/<\/[A-Za-z]+>/g) ?? []).length;
    expect(open).toBe(close);
  });
  it("normalises the origin and refuses anything that is not a plain https origin", () => {
    expect(renderManifest("https://phish.example/")).toContain("https://phish.example/addin/taskpane.html");
    expect(renderManifest("https://phish.example/some/path?x=1")).toContain("https://phish.example/addin/taskpane.html");
    for (const bad of ["http://phish.example", "ftp://x.com", "not a url", "javascript:alert(1)", 'https://x.com"><script>']) {
      expect(() => renderManifest(bad), bad).toThrow();
    }
  });
  it("allows plain http only for localhost development", () => {
    expect(() => renderManifest("http://localhost:3000")).not.toThrow();
  });
  it("escapes XML-significant characters that survive URL parsing", () => {
    const out = renderManifest("https://a.example:8443");
    expect(out).toContain("https://a.example:8443/addin/");
    expect(renderManifest("https://x.example", { displayName: 'A & B <"C">' })).toContain('DefaultValue="A &amp; B &lt;&quot;C&quot;&gt;"');
  });
});

describe("token storage", () => {
  it("builds a connection to the page's own origin with the saved token", () => {
    const s = mem();
    expect(connectionFromStorage(s, "https://phish.example")).toEqual({ serverUrl: "https://phish.example", serverId: null, token: "" });
    saveToken(s, "  v1.abc  ");
    expect(connectionFromStorage(s, "https://phish.example").token).toBe("v1.abc");
    clearToken(s);
    expect(connectionFromStorage(s, "https://phish.example").token).toBe("");
  });
  it("copes with storage that throws (private mode)", () => {
    const broken = { getItem: () => { throw new Error("denied"); }, setItem: () => { throw new Error("denied"); }, removeItem: () => { throw new Error("denied"); } };
    expect(connectionFromStorage(broken, "https://x.example").token).toBe("");
    expect(() => saveToken(broken, "t")).not.toThrow();
  });
});

describe("restIdFor", () => {
  it("converts the Outlook item id to a REST id", () => {
    const calls: unknown[][] = [];
    expect(restIdFor("EWS-ID", (...a) => { calls.push(a); return "REST-ID"; })).toBe("REST-ID");
    expect(calls[0]![0]).toBe("EWS-ID");
  });
  it("returns null when there is no item (compose mode, nothing selected) or the conversion fails", () => {
    expect(restIdFor(undefined, () => "x")).toBeNull();
    expect(restIdFor("EWS", () => { throw new Error("nope"); })).toBeNull();
  });
});

describe("solidPng", () => {
  it("produces a valid square PNG of the requested size", () => {
    const png = solidPng(32, [10, 120, 200]);
    expect(png.subarray(0, 8).toString("hex")).toBe("89504e470d0a1a0a");
    expect(png.readUInt32BE(16)).toBe(32); // IHDR width
    expect(png.readUInt32BE(20)).toBe(32); // IHDR height
    const idatStart = png.indexOf("IDAT") + 4, idatLen = png.readUInt32BE(png.indexOf("IDAT") - 4);
    const raw = inflateSync(png.subarray(idatStart, idatStart + idatLen));
    expect(raw.length).toBe(32 * (1 + 32 * 4)); // a filter byte plus RGBA per pixel, per row
    expect(Array.from(raw.subarray(1, 5))).toEqual([10, 120, 200, 255]);
  });
});
