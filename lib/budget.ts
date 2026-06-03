import { convex, api } from "./db/convex-client";

// Daily spend tracking + pre-scan budget gate (Castle playbook §4.4.4).
// ROOK_DAILY_BUDGET_USD defaults to 50. Set to 0 to disable all scans.
// Costs are recorded per tenant (null for the default/solo deployment).

const DEFAULT_BUDGET_USD = 50;

function budgetUsd(): number {
  const v = Number(process.env.ROOK_DAILY_BUDGET_USD ?? DEFAULT_BUDGET_USD);
  return isFinite(v) ? v : DEFAULT_BUDGET_USD;
}

function todayStartMs(): number {
  const d = new Date();
  d.setUTCHours(0, 0, 0, 0);
  return d.getTime();
}

export async function todaySpendUsd(tenant: string | null): Promise<number> {
  return convex.query(api.scanCosts.todaySpend, {
    tenant: tenant ?? undefined,
    since: todayStartMs(),
  });
}

export async function checkBudget(tenant: string | null): Promise<{
  ok: boolean;
  spent: number;
  budget: number;
}> {
  const budget = budgetUsd();
  const spent = await todaySpendUsd(tenant);
  return { ok: spent < budget, spent, budget };
}

export async function recordScanCost(
  scanId: string,
  tenant: string | null,
  costUsd: number | null,
): Promise<void> {
  await convex.mutation(api.scanCosts.insert, {
    scan_id: scanId,
    tenant: tenant ?? undefined,
    cost_usd: costUsd ?? undefined,
    created_at: Date.now(),
  });
}
