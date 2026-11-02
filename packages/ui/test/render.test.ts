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

describe("renderBanner feedback buttons", () => {
  const model = () => bannerModel(dto())!;
  const click = (el: HTMLElement, label: string) => (Array.from(el.querySelectorAll("button")).find((b) => b.textContent === label) as HTMLButtonElement).click();

  it("has no buttons unless a feedback handler is supplied", () => {
    expect(renderBanner(model()).querySelectorAll("button")).toHaveLength(0);
  });
  it("offers both choices; a click sends the label once, disables the buttons and shows the outcome", async () => {
    const sent: string[] = [];
    const el = renderBanner(model(), document, { onFeedback: async (l) => { sent.push(l); return { ok: true, mailAction: "restored" }; } });
    expect(Array.from(el.querySelectorAll("button")).map((b) => b.textContent)).toEqual(["Not phishing", "Report phishing"]);
    click(el, "Not phishing");
    click(el, "Not phishing"); // a double click must not send twice
    await new Promise((r) => setTimeout(r, 0));
    expect(sent).toEqual(["not_phishing"]);
    expect(Array.from(el.querySelectorAll("button")).every((b) => b.disabled)).toBe(true);
    expect(el.textContent).toMatch(/moved back to your inbox/i);
  });
  it("says so when the feedback could not be saved, and lets the user try again", async () => {
    let n = 0;
    const el = renderBanner(model(), document, { onFeedback: async () => ({ ok: ++n > 1 }) });
    click(el, "Report phishing");
    await new Promise((r) => setTimeout(r, 0));
    expect(el.textContent).toMatch(/could not be saved/i);
    expect(Array.from(el.querySelectorAll("button")).every((b) => !b.disabled)).toBe(true);
    click(el, "Report phishing");
    await new Promise((r) => setTimeout(r, 0));
    expect(el.textContent).toMatch(/thanks/i);
  });
  it("survives a handler that throws", async () => {
    const el = renderBanner(model(), document, { onFeedback: async () => { throw new Error("boom"); } });
    click(el, "Not phishing");
    await new Promise((r) => setTimeout(r, 0));
    expect(el.textContent).toMatch(/could not be saved/i);
  });
});
