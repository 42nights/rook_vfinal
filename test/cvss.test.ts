import { describe, it, expect } from "vitest";
import { computeCvss } from "../lib/scanner/cvss";

describe("computeCvss", () => {
  it("scores remote unauthenticated full-impact as 9.8 critical", () => {
    const r = computeCvss({ AV: "N", AC: "L", PR: "N", UI: "N", S: "U", C: "H", I: "H", A: "H" });
    expect(r.score).toBe(9.8);
    expect(r.severity).toBe("critical");
    expect(r.vector).toBe("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  });

  it("scores scope-changed RCE as 10.0", () => {
    const r = computeCvss({ AV: "N", AC: "L", PR: "N", UI: "N", S: "C", C: "H", I: "H", A: "H" });
    expect(r.score).toBe(10);
    expect(r.severity).toBe("critical");
  });

  it("scores a local low-impact info leak in the low/medium band", () => {
    const r = computeCvss({ AV: "L", AC: "H", PR: "L", UI: "R", S: "U", C: "L", I: "N", A: "N" });
    expect(r.score).toBeLessThan(4);
    expect(["low", "none"]).toContain(r.severity);
  });
});
