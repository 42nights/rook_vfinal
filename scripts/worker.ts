/**
 * Rook scan worker — polls Convex for pending scans and runs them.
 *
 * Run with:
 *   node --env-file=.env.local -r tsx/cjs scripts/worker.ts
 * or via npm:
 *   npm run worker
 *
 * Required env: NEXT_PUBLIC_CONVEX_URL, ANTHROPIC_API_KEY, ROOK_MODE=cloud
 */
import "../lib/local-mode";
import { convex, api } from "../lib/db/convex-client";
import { getScan, setScanStatus, setScanError } from "../lib/scans";
import { runScan } from "../lib/scan-runner";
import type { Id } from "../convex/_generated/dataModel";

const POLL_MS = Number(process.env.WORKER_POLL_MS ?? 2000);

async function claimOldestPending(): Promise<string | null> {
  // Query for the oldest pending scan
  let docs: Array<{ _id: Id<"scans">; status: string; created_at: number }>;
  try {
    docs = await convex.query(api.scans.list, {});
  } catch (err) {
    console.error("[worker] Convex query failed:", err);
    return null;
  }

  const pending = docs
    .filter((d) => d.status === "pending")
    .sort((a, b) => a.created_at - b.created_at);

  if (pending.length === 0) return null;
  const scan = pending[0];

  // Atomically claim: patch status to "bootstrap" so other workers skip it
  try {
    await convex.mutation(api.scans.patch, {
      id: scan._id,
      patchJson: JSON.stringify({ status: "bootstrap", phase: "Claimed by worker", updated_at: Date.now() }),
    });
  } catch {
    // Another worker may have claimed it simultaneously — skip
    return null;
  }

  // Verify we actually claimed it (re-read)
  const claimed = await getScan(scan._id as unknown as string);
  if (!claimed || claimed.status !== "bootstrap") return null;

  return scan._id as unknown as string;
}

async function processOne(scanId: string): Promise<void> {
  console.log(`[worker] running scan ${scanId}`);
  try {
    await runScan(scanId);
    console.log(`[worker] scan ${scanId} done`);
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error(`[worker] scan ${scanId} failed: ${msg}`);
    try {
      await setScanError(scanId, msg);
    } catch {
      /* best-effort */
    }
  }
}

async function loop(): Promise<void> {
  console.log("[worker] starting — polling every", POLL_MS, "ms");
  while (true) {
    const scanId = await claimOldestPending();
    if (scanId) {
      await processOne(scanId);
    } else {
      await new Promise((r) => setTimeout(r, POLL_MS));
    }
  }
}

loop().catch((err) => {
  console.error("[worker] fatal:", err);
  process.exit(1);
});
