import { describe, it, expect } from "vitest";
import type { FindingRow } from "../lib/scans";
import { countBySeverity, meetsInlineThreshold } from "../lib/github/pr-commenter";

function f(severity: FindingRow["severity"]): FindingRow {
  return {
    _id: "f1", scan_id: "s1", repo_id: "r1", category: "x", title: "t", severity, status: "validated",
    confidence: 1, file_path: "a.ts", start_line: 1, end_line: 1, vulnerable_code: null, summary: null,
    impact: null, cvss_vector: null, cvss_score: null, exploit_script: null, exploit_transcript_json: null,
    disconfirm_reason: null, recommended_fix: null, consistency_note: null, history_json: null,
    rank_score: 0, source: "agent", issue_url: null, created_at: 0,
  };
}

describe("countBySeverity", () => {
  it("buckets by severity (info folded into low)", () => {
    const c = countBySeverity([f("critical"), f("high"), f("high"), f("medium"), f("low"), f("info")]);
    expect(c).toEqual({ critical: 1, high: 2, medium: 1, low: 2 });
  });
});

describe("meetsInlineThreshold (default medium)", () => {
  it("comments medium and above inline, never low/info (acceptance: no low clutter)", () => {
    expect(meetsInlineThreshold("critical")).toBe(true);
    expect(meetsInlineThreshold("high")).toBe(true);
    expect(meetsInlineThreshold("medium")).toBe(true);
    expect(meetsInlineThreshold("low")).toBe(false);
    expect(meetsInlineThreshold("info")).toBe(false);
  });
});
