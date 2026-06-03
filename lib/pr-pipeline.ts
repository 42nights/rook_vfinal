import { startScanForPr } from "./scan-runner";
import { listValidated, listFindings, updateScan, priorPostedPrScan } from "./scans";
import { getRepoByName } from "./repos";
import { installationToken } from "./github/app";
import { postPrComments, type PrCommentResult } from "./github/pr-commenter";
import { checkBudget, recordScanCost } from "./budget";
import { emitDeploymentEvent } from "./castle/events";
import { tenant } from "./tenant";

export type PrPipelineInput = {
  owner: string;
  name: string;
  prNumber: number;
  headSha: string;
  baseSha: string;
  installationId?: number;
  token?: string;
};

export type PrPipelineResult = {
  scanId: string | null;
  status: "posted" | "failed" | "scan-error" | "no-credential" | "deduped";
  comment?: PrCommentResult;
  error?: string;
};

declare global {
  // eslint-disable-next-line no-var
  var __rook_pr_inflight: Set<string> | undefined;
}
function prInflight(): Set<string> {
  return (globalThis.__rook_pr_inflight ??= new Set());
}

export async function runPrPipeline(input: PrPipelineInput): Promise<PrPipelineResult> {
  const t0 = Date.now();
  const key = `${input.owner}/${input.name}#${input.prNumber}@${input.headSha}`;

  const existing = await getRepoByName(input.owner, input.name);
  if (existing && await priorPostedPrScan(existing._id, input.prNumber, input.headSha)) {
    return { scanId: null, status: "deduped" };
  }
  if (prInflight().has(key)) return { scanId: null, status: "deduped" };
  prInflight().add(key);
  try {
    return await runPipelineInner(input, t0);
  } finally {
    prInflight().delete(key);
  }
}

async function runPipelineInner(input: PrPipelineInput, t0: number): Promise<PrPipelineResult> {
  const prUrl = `https://github.com/${input.owner}/${input.name}/pull/${input.prNumber}`;

  const token =
    input.token ?? (input.installationId ? ((await installationToken(input.installationId)) ?? undefined) : undefined);
  if (input.installationId && !token) {
    console.warn(
      `[pr-pipeline] could not mint an installation token for ${input.owner}/${input.name} (installation ${input.installationId}); private-repo fetch will fail.`,
    );
  }

  const budget = await checkBudget(tenant.slug);
  if (!budget.ok) {
    const deploymentId = process.env.CASTLE_DEPLOYMENT_ID ?? "unknown";
    try {
      await postPrComments(
        { owner: input.owner, repo: input.name, prNumber: input.prNumber, headSha: input.headSha, installationId: input.installationId },
        [],
        {
          fileCount: 0,
          durationS: 0,
          costUsd: null,
          overrideSummary: `Rook is over its daily budget for ${tenant.slug ?? "this deployment"}. Re-run manually or raise the budget at admin.42nights.dev/deployments/${deploymentId}.`,
        },
      );
    } catch { /* best-effort */ }
    void emitDeploymentEvent({
      kind: "budget_exceeded",
      tenant: tenant.slug,
      spent_usd: budget.spent,
      budget_usd: budget.budget,
    });
    return { scanId: null, status: "failed", error: `daily budget exceeded (spent $${budget.spent.toFixed(4)}, limit $${budget.budget})` };
  }

  void emitDeploymentEvent({
    kind: "scan_started",
    scan_id: `${input.owner}/${input.name}#${input.prNumber}@${input.headSha}`,
    pr_url: prUrl,
    created_at: new Date().toISOString(),
  });

  let scanId: string | null = null;
  try {
    const { scan, done } = await startScanForPr({
      owner: input.owner,
      name: input.name,
      prNumber: input.prNumber,
      headSha: input.headSha,
      baseSha: input.baseSha,
      installationId: input.installationId,
      token,
    });
    scanId = scan._id;
    await done;
  } catch (e: unknown) {
    if (scanId != null) await updateScan(scanId, { pr_comment_state: "failed" });
    const msg = e instanceof Error ? e.message : String(e);
    return { scanId, status: "scan-error", error: msg };
  }

  const durationMs = Date.now() - t0;
  const costUsd: number | null = null;
  await recordScanCost(scanId, tenant.slug, costUsd);

  const reportable = await listValidated(scanId);
  const allFindings = await listFindings(scanId);
  const fileCount = new Set(allFindings.map((f) => f.file_path).filter(Boolean)).size;
  const durationS = Math.max(1, Math.round(durationMs / 1000));

  void emitDeploymentEvent({
    kind: "scan_completed",
    scan_id: String(scanId),
    findings_count: reportable.length,
    cost_usd: costUsd,
    duration_ms: durationMs,
    pr_url: prUrl,
  });

  const comment = await postPrComments(
    { owner: input.owner, repo: input.name, prNumber: input.prNumber, headSha: input.headSha, installationId: input.installationId },
    reportable,
    { fileCount, durationS, costUsd },
  );

  if (!comment.ok && comment.reason?.includes("no GitHub credential")) {
    await updateScan(scanId, { pr_comment_state: "failed" });
    return { scanId, status: "no-credential", comment };
  }
  const posted = comment.summaryPosted;
  await updateScan(scanId, { pr_comment_state: posted ? "posted" : "failed" });
  return { scanId, status: posted ? "posted" : "failed", comment };
}
