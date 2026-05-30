import { Octokit } from "@octokit/rest";
import { appOctokit, isAppConfigured } from "./app";
import type { FindingRow } from "../scans";
import { buildFindingReport } from "../scanner/report";

// Open a GitHub Issue for a validated finding. Uses the GitHub App installation
// when configured; otherwise a personal token (GITHUB_TOKEN). No-ops (returns
// null) when neither is available — the finding still lives in the dashboard.

function octokit(installationId?: number): Octokit | null {
  if (installationId && isAppConfigured()) return appOctokit(installationId);
  if (process.env.GITHUB_TOKEN) return new Octokit({ auth: process.env.GITHUB_TOKEN });
  return null;
}

const SEV_LABEL: Record<string, string> = { critical: "security:critical", high: "security:high", medium: "security:medium", low: "security:low" };

export async function openIssue(
  owner: string,
  repo: string,
  finding: FindingRow,
  installationId?: number,
): Promise<{ url: string; number: number } | null> {
  const ok = octokit(installationId);
  if (!ok) return null;
  try {
    const res = await ok.issues.create({
      owner,
      repo,
      title: `[Rook] ${finding.title}`,
      body: buildFindingReport(finding),
      labels: ["rook", SEV_LABEL[finding.severity] ?? "security"],
    });
    return { url: res.data.html_url, number: res.data.number };
  } catch {
    return null;
  }
}
