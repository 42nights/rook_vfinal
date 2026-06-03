import { describe, it, expect } from "vitest";
import type { FindingRow } from "../lib/scans";
import {
  renderInlineComment,
  renderSummaryReview,
  severityEmoji,
  summaryEvent,
  mdText,
  codeSpan,
} from "../lib/github/comment-templates";

function mkFinding(o: Partial<FindingRow> = {}): FindingRow {
  return {
    _id: "finding1",
    scan_id: "scan10",
    repo_id: "repo2",
    category: "injection-sql",
    title: "SQL injection in user lookup",
    severity: "high",
    status: "validated",
    confidence: 0.95,
    file_path: "src/api/users.ts",
    start_line: 42,
    end_line: 48,
    vulnerable_code: "db.query(`SELECT * FROM users WHERE id=${id}`)",
    summary: "Untrusted `id` flows into a raw SQL string.",
    impact: "An attacker can read the entire users table.",
    cvss_vector: "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    cvss_score: 8.6,
    exploit_script: "curl 'http://t/api/users?id=1%20OR%201=1'",
    exploit_transcript_json: JSON.stringify({ command: "curl 'http://t/api/users?id=1 OR 1=1'", evidence: "200 with 5000 rows returned" }),
    disconfirm_reason: null,
    recommended_fix: "```diff\n- db.query(`SELECT * FROM users WHERE id=${id}`)\n+ db.query('SELECT * FROM users WHERE id=?', [id])\n```",
    consistency_note: "Parameterized correctly in `src/api/posts.ts:20`.",
    history_json: JSON.stringify({ commit: "abc1234567def", author: "alice", date: "2026-05-01" }),
    rank_score: 0.9,
    source: "agent",
    issue_url: null,
    created_at: 0,
    ...o,
  };
}

const links = { otisFixUrl: "https://rook.42nights.dev/findings/1/fix?return_to=github", rookFindingUrl: "https://rook.42nights.dev/scans/10/findings/1" };

describe("untrusted-text sanitizers (round-3)", () => {
  it("mdText neutralizes triple-fences and @mentions in prose", () => {
    const out = mdText("Use prepared statements not ```raw``` — ping @admin and @ci-bot");
    expect(out).not.toContain("```");
    // @ is followed by a zero-width space, so it no longer mentions
    expect(out).not.toMatch(/@admin\b/);
    expect(out).not.toMatch(/@ci-bot\b/);
    expect(out).toContain("admin"); // visible text preserved
  });
  it("codeSpan neutralizes backticks so an inline span can't break out", () => {
    expect(codeSpan("foo`bar` baz")).toBe("`fooʼbarʼ baz`");
  });
});

describe("renderInlineComment @mention safety (round-3)", () => {
  it("does not emit a live @mention from an LLM-generated title", () => {
    const md = renderInlineComment(mkFinding({ title: "SQLi gives @admin DB access" }), links);
    expect(md).not.toMatch(/@admin\b/);
    expect(md).toContain("admin");
  });
});

describe("severityEmoji", () => {
  it("maps each severity", () => {
    expect(severityEmoji("critical")).toBe("🔴");
    expect(severityEmoji("high")).toBe("🟠");
    expect(severityEmoji("medium")).toBe("🟡");
    expect(severityEmoji("low")).toBe("⚪");
    expect(severityEmoji("whatever")).toBe("⚪");
  });
});

describe("renderInlineComment", () => {
  const md = renderInlineComment(mkFinding(), links);
  it("has the badge, category, title, impact, and CVSS", () => {
    expect(md).toContain("🟠 HIGH · injection-sql");
    expect(md).toContain("SQL injection in user lookup");
    expect(md).toContain("**Why this matters:** An attacker can read the entire users table.");
    expect(md).toContain("CVSS 8.6");
  });
  it("has a collapsible plan-to-fix with the diff", () => {
    expect(md).toContain("📋 Plan to fix");
    expect(md).toContain("```diff");
    expect(md).toContain("db.query('SELECT * FROM users WHERE id=?', [id])");
  });
  it("shows the confirmed exploit and the Otis CTA", () => {
    expect(md).toContain("Working exploit confirmed");
    expect(md).toContain("curl 'http://t/api/users?id=1 OR 1=1'");
    expect(md).toContain(`[ 🔧 Have Otis fix this ](${links.otisFixUrl})`);
    expect(md).toContain(links.rookFindingUrl);
  });
  it("omits the exploit block when there's no transcript", () => {
    const md2 = renderInlineComment(mkFinding({ exploit_transcript_json: null }), links);
    expect(md2).not.toContain("Working exploit confirmed");
  });
  it("does not let a ``` in a field break out of the comment's fences", () => {
    const evil = renderInlineComment(mkFinding({ summary: "```js\nalert(1)\n``` then more" }), links);
    // The injected closing fence is neutralized, so the body stays one block.
    expect(evil).not.toContain("```js\nalert(1)\n```");
  });
  it("omits the Otis CTA + finding links when links is null (self-hosted)", () => {
    const md2 = renderInlineComment(mkFinding(), null);
    expect(md2).not.toContain("Have Otis fix this");
    expect(md2).not.toContain("Open finding in Rook");
    expect(md2).toContain("CVSS 8.6"); // CVSS still shown
  });
  it("renders exploit evidence in a fenced block so a backtick can't break out", () => {
    const md2 = renderInlineComment(
      mkFinding({ exploit_transcript_json: JSON.stringify({ command: "curl x", evidence: "resp with ` backtick **bold**" }) }),
      links,
    );
    expect(md2).toContain("Response:");
    // evidence is in a ```text fence, NOT an inline `code span` it could escape
    expect(md2).toContain("```text");
    expect(md2).not.toContain("Response: `resp with `");
  });
  it("renders a git-blame author in a code span, never as an @mention", () => {
    const md2 = renderInlineComment(mkFinding({ history_json: JSON.stringify({ commit: "deadbeef99", author: "evil-handle", date: "2026-01-01" }) }), links);
    expect(md2).toContain("by `evil-handle`");
    expect(md2).not.toContain("@evil-handle");
  });
});

describe("renderSummaryReview", () => {
  const base = { inlinePosted: 1, fileCount: 3, durationS: 12, costUsd: null, links: { rookScanUrl: "u", rookSettingsUrl: "s" } };
  it("renders the counts table and a clean verdict when empty", () => {
    const md = renderSummaryReview({ ...base, counts: { critical: 0, high: 0, medium: 0, low: 0 } });
    expect(md).toContain("| 🔴 Critical | 0 |");
    expect(md).toContain("**No findings.** Looks clean. ✅");
    expect(md).toContain("scanned 3 files in 12s");
  });
  it("recommends addressing crit/high", () => {
    const md = renderSummaryReview({ ...base, counts: { critical: 1, high: 0, medium: 0, low: 0 } });
    expect(md).toContain("address the critical/high findings before merging");
  });
  it("does not claim items were 'annotated inline' when nothing was posted inline (advisory-only)", () => {
    const md = renderSummaryReview({ ...base, inlinePosted: 0, counts: { critical: 0, high: 0, medium: 2, low: 0 } });
    expect(md).not.toContain("annotated inline");
    expect(md).toContain("none could be anchored to a line in this diff");
  });
});

describe("summaryEvent", () => {
  it("requests changes only when there's a critical/high", () => {
    expect(summaryEvent({ critical: 1, high: 0, medium: 0, low: 0 })).toBe("REQUEST_CHANGES");
    expect(summaryEvent({ critical: 0, high: 2, medium: 0, low: 0 })).toBe("REQUEST_CHANGES");
    expect(summaryEvent({ critical: 0, high: 0, medium: 3, low: 9 })).toBe("COMMENT");
    expect(summaryEvent({ critical: 0, high: 0, medium: 0, low: 0 })).toBe("COMMENT");
  });
});
