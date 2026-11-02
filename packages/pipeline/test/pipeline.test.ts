import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { DEFAULT_SETTINGS } from "@ap/shared";
import { scanRaw, actionFor } from "../src/index.ts";

const eml = (p: string) => readFileSync(new URL("../../../corpus/" + p, import.meta.url));

describe("pipeline", () => {
  it("flags the spoofed PayPal email as phishing, with explanations", async () => {
    const v = await scanRaw(eml("phishing/paypal-spoof.eml"), "a", DEFAULT_SETTINGS);
    expect(v.verdict).toBe("phishing");
    expect(v.flags.map((f) => f.id)).toEqual(expect.arrayContaining(["spf_fail", "lookalike_domain", "link_text_mismatch"]));
    expect(actionFor(v, DEFAULT_SETTINGS)).toBe("move_to_phishing");
  });
  it("shadow mode scores but takes no action", async () => {
    const s = { ...DEFAULT_SETTINGS, shadowMode: true };
    const v = await scanRaw(eml("phishing/paypal-spoof.eml"), "a", s);
    expect(v.verdict).toBe("phishing");
    expect(actionFor(v, s)).toBe("none");
  });
  it("leaves legitimate mail alone, even urgent-sounding newsletters", async () => {
    expect((await scanRaw(eml("legit/lunch.eml"), "b", DEFAULT_SETTINGS)).verdict).toBe("safe");
    expect((await scanRaw(eml("legit/newsletter.eml"), "c", DEFAULT_SETTINGS)).verdict).toBe("safe");
  });
  it("allowlist short-circuits authenticated mail to safe, is ignored for a spoof that fails DMARC, and blocklist wins to phishing", async () => {
    const allowAlice = { ...DEFAULT_SETTINGS, allowlist: [{ matchType: "domain" as const, value: "company.example" }] };
    expect((await scanRaw(eml("legit/lunch.eml"), "b", allowAlice)).verdict).toBe("safe");
    const allowSpoof = { ...DEFAULT_SETTINGS, allowlist: [{ matchType: "domain" as const, value: "paypa1-secure.net" }] };
    expect((await scanRaw(eml("phishing/paypal-spoof.eml"), "a", allowSpoof)).verdict).toBe("phishing");
    const block = { ...DEFAULT_SETTINGS, blocklist: [{ matchType: "address" as const, value: "alice@company.example" }] };
    expect((await scanRaw(eml("legit/lunch.eml"), "b", block)).verdict).toBe("phishing");
  });
});
