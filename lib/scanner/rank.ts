import type { Candidate } from "./static-scan";

// Importance ranking. The spec's Bradley-Terry + Sonnet-judge ranker degrades to
// a deterministic heuristic in local mode (documented tradeoff, spec §8.3):
// severity weight of the class × the scanner's confidence.
const CLASS_WEIGHT: Record<string, number> = {
  "injection-cmd": 1.0,
  "deserialization-rce": 0.97,
  "injection-sql": 0.95,
  "auth-bypass": 0.92,
  "ssti": 0.88,
  "idor": 0.82,
  "ssrf": 0.82,
  "path-traversal": 0.8,
  "secrets-in-source": 0.72,
  "xss": 0.62,
  "jwt-misconfig": 0.6,
  "cors-misconfig": 0.5,
  "crypto-weak": 0.45,
  "open-redirect": 0.42,
  "info-leak": 0.4,
};

export function classWeight(category: string): number {
  return CLASS_WEIGHT[category] ?? 0.5;
}

export type RankedCandidate = Candidate & { rankScore: number };

// Candidates the scanner itself had near-zero confidence in are noise — don't
// spend exploit budget on them.
const MIN_CONFIDENCE = 0.2;

export function rankCandidates(cands: Candidate[]): RankedCandidate[] {
  return cands
    .filter((c) => c.confidence >= MIN_CONFIDENCE)
    .map((c) => ({ ...c, rankScore: 0.5 * c.confidence + 0.5 * classWeight(c.category) }))
    .sort((a, b) => b.rankScore - a.rankScore);
}
