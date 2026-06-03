// Fail-quiet Castle backlink. Posts deployment events to the Castle platform
// when CASTLE_API_URL + CASTLE_DEPLOYMENT_ID are set; no-ops silently otherwise.

export type CastleEvent =
  | { kind: "scan_started"; scan_id: string; pr_url?: string; created_at: string }
  | { kind: "scan_completed"; scan_id: string; findings_count: number; cost_usd: number | null; duration_ms: number; pr_url?: string }
  | { kind: "finding_posted"; scan_id: string; severity: string; vuln_class: string }
  | { kind: "budget_exceeded"; tenant: string | null; spent_usd: number; budget_usd: number };

export async function emitDeploymentEvent(event: CastleEvent): Promise<void> {
  const apiUrl = process.env.CASTLE_API_URL;
  const deploymentId = process.env.CASTLE_DEPLOYMENT_ID;
  if (!apiUrl || !deploymentId) return;

  const url = `${apiUrl.replace(/\/$/, "")}/deployments/${deploymentId}/events`;
  const headers: Record<string, string> = { "content-type": "application/json" };
  if (process.env.CASTLE_WEBHOOK_SECRET) {
    headers["x-castle-secret"] = process.env.CASTLE_WEBHOOK_SECRET;
  }

  for (let attempt = 0; attempt < 2; attempt++) {
    try {
      const res = await fetch(url, {
        method: "POST",
        headers,
        body: JSON.stringify(event),
      });
      if (res.ok) return;
      // Non-2xx on first attempt: retry once
      if (attempt === 0) continue;
    } catch {
      if (attempt === 0) continue;
    }
    // Second attempt failed — swallow silently
  }
}
