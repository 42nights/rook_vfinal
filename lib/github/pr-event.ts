import { parseRepoRef } from "../git";
import type { PrPipelineInput } from "../pr-pipeline";

// Pure parse of a GitHub `pull_request` webhook payload into a scan trigger.
// Kept separate from the route handler so it's unit-testable without a request.

const PR_ACTIONS = new Set(["opened", "synchronize", "reopened"]);

export type PrTrigger =
  | { kind: "scan"; input: PrPipelineInput }
  | { kind: "ignore"; reason: string };

export function parsePullRequestTrigger(payload: unknown): PrTrigger {
  const p = (payload ?? {}) as Record<string, any>;
  const action = String(p.action ?? "");
  if (!PR_ACTIONS.has(action)) return { kind: "ignore", reason: `pull_request.${action || "unknown"}` };

  const parsed = parseRepoRef(String(p.repository?.full_name ?? ""));
  const pr = p.pull_request;
  if (!parsed || parsed.local || !pr?.number || !pr?.head?.sha || !pr?.base?.sha) {
    return { kind: "ignore", reason: "malformed pull_request payload" };
  }
  return {
    kind: "scan",
    input: {
      owner: parsed.owner,
      name: parsed.name,
      prNumber: Number(pr.number),
      headSha: String(pr.head.sha),
      baseSha: String(pr.base.sha),
      installationId: p.installation?.id ? Number(p.installation.id) : undefined,
    },
  };
}
