import "../lib/local-mode";
import { runPrPipeline } from "../lib/pr-pipeline";

// Self-hosted PR scan (spec §9.4 / §2 Option A). Runs inside a GitHub Action on
// the customer's infra with the customer's ANTHROPIC_API_KEY and GITHUB_TOKEN.
// Same PR-focused pipeline + comment output as the hosted GitHub App path; the
// only difference is the credential (the Action's GITHUB_TOKEN, not an App
// installation token).
//
// Env (set by .github/workflows/rook.yml):
//   GITHUB_REPOSITORY  owner/name
//   PR_NUMBER          the pull request number
//   HEAD_SHA, BASE_SHA the PR head/base commit SHAs
//   GITHUB_TOKEN       used to fetch the repo + post comments
//   ANTHROPIC_API_KEY  + ROOK_MODE=cloud for the LLM phases
async function main() {
  const repoFull = process.env.GITHUB_REPOSITORY ?? "";
  const prNumber = Number(process.env.PR_NUMBER);
  const headSha = process.env.HEAD_SHA || process.env.GITHUB_SHA || "";
  const baseSha = process.env.BASE_SHA || "";
  const token = process.env.GITHUB_TOKEN;

  const [owner, name] = repoFull.split("/");
  if (!owner || !name || !Number.isInteger(prNumber) || prNumber <= 0 || !headSha || !baseSha) {
    console.error(
      "scan-pr: missing inputs. Need GITHUB_REPOSITORY (owner/name), PR_NUMBER, HEAD_SHA, BASE_SHA.",
    );
    process.exit(1);
  }
  if (!token) console.warn("scan-pr: GITHUB_TOKEN not set — private fetch + comment posting will fail.");

  console.log(`Rook scan-pr: ${owner}/${name} PR #${prNumber} (${baseSha.slice(0, 8)}..${headSha.slice(0, 8)})`);
  const result = await runPrPipeline({ owner, name, prNumber, headSha, baseSha, token });
  console.log(
    `Done: status=${result.status}` +
      (result.comment ? ` · inline=${result.comment.inlinePosted} failed=${result.comment.inlineFailed} summary=${result.comment.summaryPosted}` : ""),
  );
  // A scan crash is a hard failure; a finished scan that couldn't post comments
  // (e.g. token lacks PR write) is surfaced but non-fatal so the job doesn't red
  // over a permissions nit.
  if (result.status === "scan-error") {
    console.error(result.error ?? "scan failed");
    process.exit(1);
  }
}

main().catch((e) => {
  console.error("scan-pr failed:", e?.message ?? e);
  process.exit(1);
});
