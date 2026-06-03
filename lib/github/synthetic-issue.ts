import type { FindingRow } from "../scans";
import { safeParse } from "../utils";
import { mdText, codeSpan, fence } from "./md";

// The synthetic GitHub Issue body Otis receives (spec §6.2): a user-filed-bug
// shape with explicit acceptance criteria, the exploit as the failing test, and
// the suggested fix inline. Otis's UNDERSTAND phase consumes exactly this.
// Pure (no DB) so it's unit-testable and reusable by both the issue + handoff.

// Suggested test path for the acceptance criteria — mirrors the scanned file's
// language so the criterion reads naturally.
export function suggestedTestPath(filePath: string | null, category: string): string {
  const ext = (filePath ?? "").match(/\.([a-z]+)$/i)?.[1]?.toLowerCase();
  const slug = category.replace(/[^a-z0-9]+/gi, "-");
  if (ext === "py") return `tests/security/test_${slug.replace(/-/g, "_")}.py`;
  if (ext === "go") return `security/${slug}_test.go`;
  if (ext === "rb") return `spec/security/${slug}_spec.rb`;
  return `test/security/${slug}.test.${ext === "js" || ext === "jsx" ? "js" : "ts"}`;
}

export function buildSyntheticIssue(finding: FindingRow, prNumber?: number | null): string {
  const transcript = finding.exploit_transcript_json
    ? safeParse<{ command?: string }>(finding.exploit_transcript_json)
    : null;
  const command = finding.exploit_script || transcript?.command || "(see finding)";
  const isHttpExploit = finding.category !== "secrets-in-source" && !command.trim().startsWith("#");
  // file_path goes in an inline code span (codeSpan neutralizes a stray backtick).
  const where = finding.file_path
    ? `${codeSpan(finding.file_path)}${finding.start_line ? ` at lines ${finding.start_line}-${finding.end_line ?? finding.start_line}` : ""}`
    : "(see finding)";

  const lines: string[] = [];
  lines.push(`**Source:** Rook finding #${finding._id}${prNumber ? ` on PR #${prNumber}` : ""}`);
  lines.push("");
  // category + title are LLM-derived → mdText (fence + @mention safe) before they
  // land in the GitHub issue body, where @mentions DO ping users.
  lines.push(`**Vulnerability:** ${mdText(finding.category)} — ${mdText(finding.title)}`);
  lines.push("");
  lines.push(`**Where:** ${where}`);
  lines.push("");
  if (isHttpExploit) {
    lines.push("**Working exploit (verified by Rook):**");
    lines.push(fence("bash", command));
    lines.push("");
    lines.push("The above exploit currently succeeds. After your fix, it must fail.");
    lines.push("");
    lines.push("**Acceptance criteria:**");
    lines.push("1. The exploit command above returns a non-200 response (or a 200 that no longer leaks data).");
    lines.push("2. The existing test suite still passes.");
    lines.push(`3. A new test exists at ${codeSpan(suggestedTestPath(finding.file_path, finding.category))} that asserts the exploit no longer succeeds.`);
  } else {
    lines.push("**Evidence (located by Rook static analysis):**");
    lines.push(fence("text", command));
    lines.push("");
    lines.push("**Acceptance criteria:**");
    lines.push("1. The flagged credential/issue is removed from source (and rotated if it was a live secret).");
    lines.push("2. The existing test suite still passes.");
  }
  if (finding.recommended_fix && finding.recommended_fix.trim()) {
    lines.push("");
    lines.push("**Suggested fix from Rook:**");
    const fix = finding.recommended_fix.trim();
    const looksLikeDiff = /^[+-@]/m.test(fix) && /\n[+-]/.test(fix);
    lines.push(looksLikeDiff ? fence("diff", fix) : mdText(fix));
    lines.push("");
    lines.push("You may deviate from the suggested fix if you find a better one.");
  }
  return lines.join("\n");
}
