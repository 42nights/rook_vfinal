import { Octokit } from "@octokit/rest";
import { appOctokit, isAppConfigured } from "./app";
import type { FindingRow } from "../scans";
import {
  renderInlineComment,
  renderSummaryReview,
  summaryEvent,
  rookPublicUrl,
  mdText,
  codeSpan,
  type SeverityCounts,
} from "./comment-templates";

// Posts a PR's findings as GitHub review comments (spec §4). Inline comment per
// finding above the severity threshold (anchored to file:line), plus one summary
// review. Uses the App installation token when configured, else GITHUB_TOKEN.

const SEV_RANK: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

// Inline-comment threshold: only severity >= this is annotated inline; the rest
// stays in the dashboard (spec §1). Default medium.
export function minInlineRank(): number {
  return SEV_RANK[(process.env.ROOK_PR_MIN_SEVERITY ?? "medium").toLowerCase()] ?? 2;
}

// Does this severity clear the inline-comment threshold? (Acceptance: low-only
// findings never clutter the PR inline — they stay in the dashboard / summary.)
export function meetsInlineThreshold(severity: string): boolean {
  return (SEV_RANK[(severity || "medium").toLowerCase()] ?? 0) >= minInlineRank();
}

function octokitFor(installationId?: number): Octokit | null {
  if (installationId && isAppConfigured()) return appOctokit(installationId);
  if (process.env.GITHUB_TOKEN) return new Octokit({ auth: process.env.GITHUB_TOKEN });
  return null;
}

export function countBySeverity(findings: FindingRow[]): SeverityCounts {
  const c: SeverityCounts = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const f of findings) {
    const s = (f.severity || "medium").toLowerCase();
    if (s === "critical") c.critical++;
    else if (s === "high") c.high++;
    else if (s === "medium") c.medium++;
    else c.low++; // low + info both shown as "low" in the summary table
  }
  return c;
}

export type PrCommentTarget = {
  owner: string;
  repo: string;
  prNumber: number;
  headSha: string;
  installationId?: number;
};

export type PrCommentResult = {
  ok: boolean;
  reason?: string;
  inlinePosted: number;
  inlineFailed: number;
  summaryPosted: boolean;
};

// `reportable` are the findings worth surfacing (validated + advisory). `total`
// is the file count for the footer; durationS/costUsd are display-only.
// `overrideSummary`: when set, skips inline comments and uses this body verbatim
// (used by the budget-exceeded gate to post a single explanatory review).
export async function postPrComments(
  target: PrCommentTarget,
  reportable: FindingRow[],
  meta: { fileCount: number; durationS: number; costUsd?: number | null; overrideSummary?: string },
): Promise<PrCommentResult> {
  const ok = octokitFor(target.installationId);
  if (!ok) {
    return { ok: false, reason: "no GitHub credential (App installation or GITHUB_TOKEN)", inlinePosted: 0, inlineFailed: 0, summaryPosted: false };
  }

  // Budget-exceeded (or any override): skip inline comments, post one review.
  if (meta.overrideSummary) {
    let summaryPosted = false;
    try {
      await ok.pulls.createReview({
        owner: target.owner,
        repo: target.repo,
        pull_number: target.prNumber,
        commit_id: target.headSha,
        event: "COMMENT",
        body: meta.overrideSummary,
      });
      summaryPosted = true;
    } catch { /* swallow */ }
    return { ok: summaryPosted, inlinePosted: 0, inlineFailed: 0, summaryPosted };
  }

  const counts = countBySeverity(reportable);
  const inlineTargets = reportable.filter(
    (f) => meetsInlineThreshold(f.severity) && f.file_path && (f.start_line || f.end_line),
  );

  let inlinePosted = 0;
  let inlineFailed = 0;
  const offDiff: FindingRow[] = [];
  const base = rookPublicUrl();
  // Omit the Otis CTA / finding links when OTIS_URL is unset (no integration
  // configured) or when ROOK_OTIS_CTA=false is an explicit override. Both are
  // treated the same: don't render "Have Otis fix this" if Otis can't receive it.
  const ctaEnabled = !!process.env.OTIS_URL && process.env.ROOK_OTIS_CTA !== "false";

  for (const f of inlineTargets) {
    const links = ctaEnabled
      ? {
          otisFixUrl: `${base}/findings/${f._id}/fix?return_to=github`,
          rookFindingUrl: `${base}/scans/${f.scan_id}/findings/${f._id}`,
        }
      : null;
    const body = renderInlineComment(f, links);
    const line = (f.end_line || f.start_line) as number;
    try {
      await ok.pulls.createReviewComment({
        owner: target.owner,
        repo: target.repo,
        pull_number: target.prNumber,
        commit_id: target.headSha,
        path: f.file_path as string,
        line,
        side: "RIGHT",
        body,
      });
      inlinePosted++;
    } catch (e: any) {
      // GitHub 422 = the line isn't in the PR diff → fall back to listing the
      // finding in the summary so it's never silently dropped. Any OTHER status
      // (401/403 bad scope, 5xx) is NOT an off-diff miss — abort with a real
      // reason rather than mislabeling every finding as "outside the diff".
      const status = e?.status ?? e?.response?.status;
      if (status === 422) {
        inlineFailed++;
        offDiff.push(f);
      } else {
        return {
          ok: false,
          reason: `GitHub API error posting inline comment (status ${status ?? "unknown"})`,
          inlinePosted,
          inlineFailed,
          summaryPosted: false,
        };
      }
    }
  }

  // Summary review.
  let summaryBody = renderSummaryReview({
    counts,
    inlinePosted,
    fileCount: meta.fileCount,
    durationS: meta.durationS,
    costUsd: meta.costUsd ?? null,
    links: {
      rookScanUrl: reportable[0] ? `${base}/scans/${reportable[0].scan_id}` : base,
      rookSettingsUrl: `${base}/settings`,
    },
  });
  // List every threshold-meeting finding NOT annotated inline: off-diff failures
  // (422) AND findings with no anchorable location (e.g. OSV advisories with no
  // file_path). Otherwise the summary's "see findings listed below" lists nothing.
  const noLocation = reportable.filter(
    (f) => meetsInlineThreshold(f.severity) && !(f.file_path && (f.start_line || f.end_line)),
  );
  const notInlined = [...offDiff, ...noLocation];
  if (notInlined.length > 0) {
    summaryBody +=
      "\n\n**Findings not annotated inline** (no matching line in this diff):\n" +
      notInlined
        .map((f) => `- ${f.severity} · ${f.category} — ${mdText(f.title)}${f.file_path ? ` (${codeSpan(`${f.file_path}:${f.start_line ?? "?"}`)})` : ""}`)
        .join("\n");
  }

  let summaryPosted = false;
  try {
    await ok.pulls.createReview({
      owner: target.owner,
      repo: target.repo,
      pull_number: target.prNumber,
      commit_id: target.headSha,
      event: summaryEvent(counts),
      body: summaryBody,
    });
    summaryPosted = true;
  } catch {
    // A failed REQUEST_CHANGES (e.g. you can't request changes on your own PR)
    // shouldn't lose the summary — retry as a plain comment.
    try {
      await ok.pulls.createReview({
        owner: target.owner,
        repo: target.repo,
        pull_number: target.prNumber,
        commit_id: target.headSha,
        event: "COMMENT",
        body: summaryBody,
      });
      summaryPosted = true;
    } catch {
      /* leave summaryPosted false */
    }
  }

  return { ok: summaryPosted || inlinePosted > 0, inlinePosted, inlineFailed, summaryPosted };
}
