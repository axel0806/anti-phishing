// @vitest-environment happy-dom
import { describe, expect, it } from "vitest";
import { renderBanner, BANNER_ATTR } from "../src/render.ts";
import { bannerModel, type VerdictDto } from "../src/banner.ts";

const dto = (o: Partial<VerdictDto["verdict"]> = {}, shadow = false): VerdictDto => ({
  action: "none", shadow,
  verdict: { score: 72, verdict: "phishing", flags: [{ id: "spf_fail", weight: 20, evidence: "SPF fail" }], ...o },
});

describe("renderBanner", () => {
  it("shows the verdict, reasons, AI assessment and shadow note", () => {
    const m = bannerModel(dto({ aiExplanation: "Fake invoice." }, true))!;
    const el = renderBanner(m);
    expect(el.hasAttribute(BANNER_ATTR)).toBe(true);
    expect(el.getAttribute("role")).toBe("alert");
    expect(el.textContent).toContain("Likely phishing (risk score 72/100)");
    expect(el.querySelectorAll("li")).toHaveLength(1);
    expect(el.textContent).toContain("AI assessment: Fake invoice.");
    expect(el.textContent).toContain("not moved");
  });

  it("treats hostile sender text and model output as plain text, never markup", () => {
    const evil = '<img src=x onerror="window.pwned=1"><script>window.pwned=2</script>';
    const m = bannerModel(dto({ flags: [{ id: "lookalike_domain", weight: 35, evidence: evil }], aiExplanation: evil }))!;
    const el = renderBanner(m);
    expect(el.querySelector("img")).toBeNull();
    expect(el.querySelector("script")).toBeNull();
    expect(el.innerHTML).not.toContain("<img");
    expect(el.textContent).toContain(evil); // shown literally
    expect((globalThis as { pwned?: unknown }).pwned).toBeUndefined();
  });

  it("uses a different colour for suspicious than for phishing", () => {
    const a = renderBanner(bannerModel(dto())!), b = renderBanner(bannerModel(dto({ verdict: "suspicious", score: 40 }))!);
    expect(a.style.cssText).not.toBe(b.style.cssText);
  });
});
