import { describe, it, expect } from "vitest";
import { runCorpus } from "./run.ts";

describe("corpus gate (Phase 1: recall >= 80%, FPR <= 2%)", () => {
  it("meets the gate on the checked-in fixtures", async () => {
    const r = await runCorpus();
    expect(r.total).toBeGreaterThanOrEqual(3);
    expect(r.recall).toBeGreaterThanOrEqual(0.8);
    expect(r.fpr).toBeLessThanOrEqual(0.02);
  });
});
