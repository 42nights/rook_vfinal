// CVSS v3.1 base-score computation. Deterministic — given the metric vector we
// compute the score + severity rating exactly per the spec formula.

export type CvssMetrics = {
  AV: "N" | "A" | "L" | "P";
  AC: "L" | "H";
  PR: "N" | "L" | "H";
  UI: "N" | "R";
  S: "U" | "C";
  C: "N" | "L" | "H";
  I: "N" | "L" | "H";
  A: "N" | "L" | "H";
};

const AV_W = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 };
const AC_W = { L: 0.77, H: 0.44 };
const UI_W = { N: 0.85, R: 0.62 };
const CIA_W = { N: 0, L: 0.22, H: 0.56 };
const PR_W_U = { N: 0.85, L: 0.62, H: 0.27 };
const PR_W_C = { N: 0.85, L: 0.68, H: 0.5 };

const roundUp1 = (x: number) => Math.ceil(x * 10) / 10;

export type CvssResult = { vector: string; score: number; severity: "none" | "low" | "medium" | "high" | "critical" };

export function computeCvss(m: CvssMetrics): CvssResult {
  const iscBase = 1 - (1 - CIA_W[m.C]) * (1 - CIA_W[m.I]) * (1 - CIA_W[m.A]);
  const impact = m.S === "U" ? 6.42 * iscBase : 7.52 * (iscBase - 0.029) - 3.25 * Math.pow(iscBase - 0.02, 15);
  const prW = m.S === "U" ? PR_W_U[m.PR] : PR_W_C[m.PR];
  const exploitability = 8.22 * AV_W[m.AV] * AC_W[m.AC] * prW * UI_W[m.UI];

  let score: number;
  if (impact <= 0) score = 0;
  else if (m.S === "U") score = roundUp1(Math.min(impact + exploitability, 10));
  else score = roundUp1(Math.min(1.08 * (impact + exploitability), 10));

  const vector = `CVSS:3.1/AV:${m.AV}/AC:${m.AC}/PR:${m.PR}/UI:${m.UI}/S:${m.S}/C:${m.C}/I:${m.I}/A:${m.A}`;
  return { vector, score, severity: rate(score) };
}

export function rate(score: number): CvssResult["severity"] {
  if (score === 0) return "none";
  if (score < 4) return "low";
  if (score < 7) return "medium";
  if (score < 9) return "high";
  return "critical";
}

// Coerce an arbitrary object (e.g. from the enrichment LLM) into valid metrics.
export function coerceMetrics(o: any): CvssMetrics {
  const pick = <T extends string>(v: any, allowed: T[], dflt: T): T => (allowed.includes(v) ? v : dflt);
  return {
    AV: pick(o?.AV, ["N", "A", "L", "P"], "N"),
    AC: pick(o?.AC, ["L", "H"], "L"),
    PR: pick(o?.PR, ["N", "L", "H"], "N"),
    UI: pick(o?.UI, ["N", "R"], "N"),
    S: pick(o?.S, ["U", "C"], "U"),
    C: pick(o?.C, ["N", "L", "H"], "L"),
    I: pick(o?.I, ["N", "L", "H"], "L"),
    A: pick(o?.A, ["N", "L", "H"], "N"),
  };
}
