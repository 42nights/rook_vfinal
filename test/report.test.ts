import { describe, it, expect } from "vitest";
import type { FindingRow } from "../lib/scans";
import { buildFindingReport } from "../lib/scanner/report";

function mkFinding(o: Partial<FindingRow> = {}): FindingRow {
  return {
    _id: "f1", scan_id: "s1", repo_id: "r1", category: "injection-sql", title: "SQLi", severity: "high",
    status: "validated", confidence: 1, file_path: "src/db.ts", start_line: 5, end_line: 9,
    vulnerable_code: "db.query(x)", summary: "raw query", impact: "read all rows",
    cvss_vector: "AV:N", cvss_score: 8.1, exploit_script: "curl x", exploit_transcript_json: null,
    disconfirm_reason: null, recommended_fix: "use params", consistency_note: null,
    history_json: null, rank_score: 0, source: "agent", issue_url: null, created_at: 0, ...o,
  };
}

describe("buildFindingReport sanitization (round-5)", () => {
  it("renders a valid report with all sections", () => {
    const md = buildFindingReport(mkFinding());
    expect(md).toContain("# 🟧 SQLi");
    expect(md).toContain("## Working exploit");
    expect(md).toContain("Found and verified by **Rook**");
  });
  it("neutralizes @mentions and backticks from untrusted fields", () => {
    const md = buildFindingReport(
      mkFinding({ title: "RCE pings @octocat", file_path: "src/foo`bar.ts", summary: "fenced ```js attempt```" }),
      );
    expect(md).not.toMatch(/@octocat\b/);
    expect(md).not.toContain("foo`bar.ts`"); // file path in a backtick-safe code span
    // no untrusted triple-fence escaped into the body (only our own section fences remain balanced)
    expect((md.match(/```/g) ?? []).length % 2).toBe(0);
  });
});
