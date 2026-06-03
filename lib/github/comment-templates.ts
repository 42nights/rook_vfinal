import type { FindingRow } from "../scans";
import { safeParse } from "../utils";
import { fence, mdText, codeSpan } from "./md";

// Re-export the markdown sanitizers so existing importers (tests, pr-commenter)
// keep working; the canonical home is ./md.
export { mdText, codeSpan } from "./md";

// PR comment rendering (spec §4). Two surfaces: one inline review comment per
// finding (anchored to file:line) and one summary review per PR. Built from the
// real FindingRow shape — fields the finding doesn't carry are simply omitted.

export type SeverityCounts = { critical: number; high: number; medium: number; low: number };

const SEV_EMOJI: Record<string, string> = {
  critical: "🔴",
  high: "🟠",
  medium: "🟡",
  low: "⚪",
  info: "⚪",
};

export function severityEmoji(severity: string): string {
  return SEV_EMOJI[severity] ?? "⚪";
}

// Base URL for the Rook dashboard links embedded in comments.
export function rookPublicUrl(): string {
  return (process.env.ROOK_PUBLIC_URL ?? "http://localhost:3000").replace(/\/$/, "");
}

type Transcript = { command?: string; evidence?: string; output?: string; outcome?: string };
type History = { commit?: string; author?: string; date?: string };

function excerpt(s: string, n = 200): string {
  const one = s.replace(/\s+/g, " ").trim();
  return one.length > n ? one.slice(0, n) + "…" : one;
}

export type InlineLinks = { otisFixUrl: string; rookFindingUrl: string };

// One inline review comment for a single finding (spec §4.1). `links` is null
// when there's no reachable backend (self-hosted ephemeral scan) — the CTA/finding
// links are then omitted rather than pointing at a backend that lacks this finding.
export function renderInlineComment(f: FindingRow, links: InlineLinks | null): string {
  const sev = (f.severity || "medium").toLowerCase();
  const transcript = f.exploit_transcript_json ? (safeParse<Transcript>(f.exploit_transcript_json) ?? null) : null;
  const history = f.history_json ? (safeParse<History>(f.history_json) ?? null) : null;

  const lines: string[] = [];
  lines.push(`🛡️ **${severityEmoji(sev)} ${sev.toUpperCase()} · ${f.category}**`);
  lines.push("");
  lines.push(`**${mdText(f.title)}**`);
  if (f.summary) {
    lines.push("");
    lines.push(mdText(f.summary));
  }
  if (f.impact) {
    lines.push("");
    lines.push(`**Why this matters:** ${mdText(f.impact)}`);
  }

  // Plan to fix
  lines.push("");
  lines.push("<details>");
  lines.push("<summary>📋 Plan to fix</summary>");
  lines.push("");
  if (f.recommended_fix && f.recommended_fix.trim()) {
    // recommended_fix may be a unified diff, prose, or (from presentFix) prose
    // with a leading note. Render a diff fence when it looks like a diff.
    const looksLikeDiff = /^[+-@]/m.test(f.recommended_fix) && /\n[+-]/.test(f.recommended_fix);
    lines.push(looksLikeDiff ? fence("diff", f.recommended_fix.trim()) : mdText(f.recommended_fix.trim()));
  } else {
    lines.push("_No automated fix suggestion — review manually._");
  }
  if (transcript?.command) {
    lines.push("");
    lines.push("**Working exploit confirmed:**");
    lines.push(fence("bash", transcript.command));
    const ev = transcript.evidence || transcript.output;
    // Fenced block, NOT an inline `code span`: the evidence is an attacker-
    // controllable HTTP response body, and a single backtick in it would break
    // out of an inline span. A backtick inside a fence is harmless.
    if (ev) {
      lines.push("Response:");
      lines.push(fence("text", excerpt(ev)));
    }
  }
  lines.push("");
  lines.push("</details>");

  // Codebase context (only when we have something to show)
  if (f.consistency_note || history?.commit) {
    lines.push("");
    lines.push("<details>");
    lines.push("<summary>📂 Codebase context</summary>");
    lines.push("");
    if (f.consistency_note) lines.push(mdText(f.consistency_note));
    if (history?.commit) {
      // Render the author in a code span (NOT `@name`): a git commit author is
      // attacker-controlled — a code span suppresses @mention AND, via codeSpan(),
      // neutralizes a stray backtick that would otherwise break the span.
      const who = history.author ? ` by ${codeSpan(history.author)}` : "";
      const when = history.date ? ` on ${history.date}` : "";
      lines.push(`History: introduced in \`${history.commit.slice(0, 10)}\`${who}${when}.`);
    }
    lines.push("");
    lines.push("</details>");
  }

  // Footer: the Otis CTA + finding link render ONLY when a reachable backend
  // serves this finding (links != null). Self-hosted ephemeral scans pass null,
  // so the comment never carries a dead link to a backend that never held it.
  const cvss = f.cvss_score != null ? `_CVSS ${f.cvss_score}${f.cvss_vector ? ` (${f.cvss_vector})` : ""}_` : "";
  lines.push("");
  lines.push("---");
  if (links) {
    lines.push(`**[ 🔧 Have Otis fix this ](${links.otisFixUrl})** · [Open finding in Rook](${links.rookFindingUrl})${cvss ? ` · ${cvss}` : ""}`);
  } else if (cvss) {
    lines.push(cvss);
  }

  return lines.join("\n");
}

export type SummaryLinks = { rookScanUrl: string; rookSettingsUrl: string };

// The one-per-PR summary review body (spec §4.2 / §4.3 "no findings").
export function renderSummaryReview(opts: {
  counts: SeverityCounts;
  inlinePosted: number;
  fileCount: number;
  durationS: number;
  costUsd?: number | null;
  links: SummaryLinks;
}): string {
  const { counts, inlinePosted, fileCount, durationS, costUsd, links } = opts;
  const anyCriticalOrHigh = counts.critical > 0 || counts.high > 0;
  const anyMedium = counts.medium > 0;
  const total = counts.critical + counts.high + counts.medium + counts.low;
  // Whether anything was ACTUALLY annotated inline. An OSV advisory (no
  // file_path) bumps the medium count but can't be posted inline, so the text
  // must key on real inline posts, not just the counts.
  const annotated = inlinePosted > 0;

  const lines: string[] = [];
  lines.push("🛡️ **Rook scanned this PR**");
  lines.push("");
  lines.push("| Severity | Count |");
  lines.push("|---|---|");
  lines.push(`| 🔴 Critical | ${counts.critical} |`);
  lines.push(`| 🟠 High | ${counts.high} |`);
  lines.push(`| 🟡 Medium | ${counts.medium} |`);
  lines.push(`| ⚪ Low | ${counts.low} |`);
  lines.push("");
  const inlineNote = annotated
    ? " Each exploit-confirmed finding is annotated inline with a recommended fix and a \"Have Otis fix this\" link."
    : " See the findings listed below (none could be anchored to a line in this diff).";
  if (anyCriticalOrHigh) {
    lines.push(`**Recommendation:** address the critical/high findings before merging.${inlineNote}`);
  } else if (anyMedium) {
    lines.push(`No critical findings. Medium-severity items to consider before merging.${inlineNote}`);
  } else if (total > 0) {
    lines.push("Only low-severity items, kept in the dashboard rather than inline. Looks reasonable. ✅");
  } else {
    lines.push("**No findings.** Looks clean. ✅");
  }
  lines.push("");
  lines.push("<details>");
  lines.push("<summary>How Rook works</summary>");
  lines.push("");
  lines.push(
    "Rook scans for ~22 vulnerability classes — auth bypass, SSRF, IDOR, SQL injection, prototype pollution, CSRF, JWT misconfig, and more. Every reported finding is validated with a working exploit in a sandboxed environment before being surfaced. False positives are dropped, not shown.",
  );
  lines.push("");
  lines.push(`[Open Rook dashboard](${links.rookScanUrl}) · [Configure for this repo](${links.rookSettingsUrl})`);
  lines.push("");
  lines.push("</details>");
  lines.push("");
  lines.push("---");
  const cost = costUsd != null ? ` · cost $${costUsd.toFixed(2)}` : "";
  const scanned = fileCount > 0 ? `scanned ${fileCount} file${fileCount === 1 ? "" : "s"}` : "scanned the PR diff";
  lines.push(`_Rook — ${scanned} in ${durationS}s${cost}_`);

  return lines.join("\n");
}

// REQUEST_CHANGES when there's a critical/high finding, else a plain COMMENT.
export function summaryEvent(counts: SeverityCounts): "REQUEST_CHANGES" | "COMMENT" {
  return counts.critical > 0 || counts.high > 0 ? "REQUEST_CHANGES" : "COMMENT";
}
