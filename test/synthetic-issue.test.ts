import { describe, it, expect } from "vitest";
import type { FindingRow } from "../lib/scans";
import { buildSyntheticIssue, suggestedTestPath } from "../lib/github/synthetic-issue";

function mkFinding(o: Partial<FindingRow> = {}): FindingRow {
  return {
    _id: "f7", scan_id: "s3", repo_id: "r2", category: "injection-sql", title: "SQL injection in user lookup",
    severity: "high", status: "validated", confidence: 0.95, file_path: "src/api/users.ts",
    start_line: 42, end_line: 48, vulnerable_code: "x", summary: "s", impact: "i",
    cvss_vector: null, cvss_score: 8.6, exploit_script: "curl 'http://t/api/users?id=1 OR 1=1'",
    exploit_transcript_json: null, disconfirm_reason: null,
    recommended_fix: "```diff\n- raw\n+ parameterized\n```", consistency_note: null,
    history_json: null, rank_score: 0.9, source: "agent", issue_url: null, created_at: 0, ...o,
  };
}

describe("suggestedTestPath", () => {
  it("matches the file's language", () => {
    expect(suggestedTestPath("a/b/users.ts", "injection-sql")).toBe("test/security/injection-sql.test.ts");
    expect(suggestedTestPath("a/b/views.py", "idor")).toBe("tests/security/test_idor.py");
    expect(suggestedTestPath("a/b/h.go", "ssrf")).toBe("security/ssrf_test.go");
    expect(suggestedTestPath("a/app.js", "xss")).toBe("test/security/xss.test.js");
  });
});

describe("buildSyntheticIssue (spec §6.2)", () => {
  it("includes source/PR, vulnerability, where, exploit, acceptance criteria, suggested fix", () => {
    const body = buildSyntheticIssue(mkFinding(), 482);
    expect(body).toContain("**Source:** Rook finding #7 on PR #482");
    expect(body).toContain("**Vulnerability:** injection-sql — SQL injection in user lookup");
    expect(body).toContain("`src/api/users.ts` at lines 42-48");
    expect(body).toContain("curl 'http://t/api/users?id=1 OR 1=1'");
    expect(body).toContain("After your fix, it must fail.");
    expect(body).toContain("**Acceptance criteria:**");
    expect(body).toContain("test/security/injection-sql.test.ts");
    expect(body).toContain("**Suggested fix from Rook:**");
    expect(body).toContain("You may deviate");
  });
  it("omits the PR reference when not from a PR", () => {
    expect(buildSyntheticIssue(mkFinding(), null)).toContain("**Source:** Rook finding #7\n");
  });
  it("neutralizes @mentions and backticks from untrusted title/file_path (round-4)", () => {
    const body = buildSyntheticIssue(
      mkFinding({ title: "RCE pings @octocat", file_path: "src/foo`bar.ts" }),
      5,
    );
    expect(body).not.toMatch(/@octocat\b/); // mention dead (zero-width space inserted)
    expect(body).toContain("octocat"); // text preserved
    expect(body).not.toContain("foo`bar.ts`"); // backtick neutralized, span intact
  });
  it("uses a static-evidence body for secrets-in-source (no HTTP exploit to flip)", () => {
    const body = buildSyntheticIssue(
      mkFinding({ category: "secrets-in-source", exploit_script: "# Secret located at server.js:10" }),
      1,
    );
    expect(body).toContain("Evidence (located by Rook static analysis)");
    expect(body).toContain("removed from source");
    expect(body).not.toContain("returns a non-200 response");
  });
});
