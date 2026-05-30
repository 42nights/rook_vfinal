import "./local-mode";
import { db } from "./db";
import {
  createScan,
  getScan,
  updateScan,
  setScanStatus,
  setScanError,
  scanLog,
  insertFinding,
  type ScanRow,
} from "./scans";
import { getRepo, createRepo, updateRepo, type RepoRow } from "./repos";
import { parseRepoRef, checkout, repoDir } from "./git";
import { buildCorpus } from "./scanner/corpus";
import { inferThreatModel, threatModelToText } from "./scanner/threat-model";
import { detectFramework, startTarget } from "./scanner/bootstrap";
import { staticScan } from "./scanner/static-scan";
import { rankCandidates, classWeight } from "./scanner/rank";
import { synthesizeAndValidate } from "./scanner/exploit";
import { enrichFinding } from "./scanner/enrich";
import { defaultClasses } from "./scanner/vuln-classes";
import { parseDependencies } from "./code/deps";
import { publish } from "./progress";
import type { Severity } from "./scans";

const MAX_EXPLOIT = Number(process.env.ROOK_MAX_FINDINGS ?? 12);

declare global {
  // eslint-disable-next-line no-var
  var __rook_scan_inflight: Set<number> | undefined;
  // eslint-disable-next-line no-var
  var __rook_repo_inflight: Map<number, Promise<void>> | undefined;
  // eslint-disable-next-line no-var
  var __rook_scan_ports: Set<number> | undefined;
  // eslint-disable-next-line no-var
  var __rook_repo_queue_depth: Map<number, number> | undefined;
}
function inflight(): Set<number> {
  if (!globalThis.__rook_scan_inflight) globalThis.__rook_scan_inflight = new Set();
  return globalThis.__rook_scan_inflight;
}
function repoInflight(): Map<number, Promise<void>> {
  if (!globalThis.__rook_repo_inflight) globalThis.__rook_repo_inflight = new Map();
  return globalThis.__rook_repo_inflight;
}
// Scan targets occupy 4600-5598; replays draw from 5600-5699 (see replay/route.ts).
function acquireScanPort(): number | null {
  const used = (globalThis.__rook_scan_ports ??= new Set());
  for (let p = 4600; p <= 5598; p++) {
    if (!used.has(p)) {
      used.add(p);
      return p;
    }
  }
  return null;
}
function releaseScanPort(port: number): void {
  globalThis.__rook_scan_ports?.delete(port);
}
function repoQueueDepth(): Map<number, number> {
  return (globalThis.__rook_repo_queue_depth ??= new Map());
}
export function isScanning(scanId: number): boolean {
  return inflight().has(scanId);
}

// Start a scan for a repo reference (owner/repo | url | local path). Returns the
// scan row immediately; the pipeline runs in the returned promise. Concurrent
// scans of the SAME repo are serialized — they share one workspace clone dir,
// so running two at once would corrupt it.
const MAX_CONCURRENT_SCANS = Number(process.env.ROOK_MAX_CONCURRENT_SCANS ?? 3);

export class TooManyError extends Error {
  constructor() {
    super("Too many concurrent scans in flight. Try again shortly.");
    this.name = "TooManyError";
  }
}

const MAX_REPO_QUEUE_DEPTH = 3;

// Shared enqueue logic: createScan FIRST (can throw), then increment depth so
// the finally-decrement in the done chain is always paired with the increment.
function enqueue(repoId: number, scanId: number): Promise<void> {
  const depth = repoQueueDepth().get(repoId) ?? 0;
  repoQueueDepth().set(repoId, depth + 1);
  inflight().add(scanId);
  const prior = repoInflight().get(repoId) ?? Promise.resolve();
  let done: Promise<void>;
  done = prior
    .catch(() => {})
    .then(() => runScan(scanId))
    .finally(() => {
      inflight().delete(scanId);
      const d = repoQueueDepth().get(repoId) ?? 1;
      if (d <= 1) repoQueueDepth().delete(repoId);
      else repoQueueDepth().set(repoId, d - 1);
      if (repoInflight().get(repoId) === done) repoInflight().delete(repoId);
    });
  repoInflight().set(repoId, done);
  return done;
}

export async function startScan(input: string): Promise<{ scan: ScanRow; repo: RepoRow; done: Promise<void> }> {
  const ref = parseRepoRef(input);
  if (!ref) throw new Error(`Could not parse repo reference: ${input}`);
  const repo = createRepo({ owner: ref.owner, name: ref.name, sourceUrl: ref.cloneUrl });
  if (!repoInflight().has(repo.id) && repoInflight().size >= MAX_CONCURRENT_SCANS) throw new TooManyError();
  const depth = repoQueueDepth().get(repo.id) ?? 0;
  if (depth >= MAX_REPO_QUEUE_DEPTH) throw new TooManyError();
  // createScan (DB write) runs before we touch queue depth — if it throws, no
  // increment happens and there's nothing to roll back.
  const scan = createScan(repo.id);
  const done = enqueue(repo.id, scan.id);
  return { scan, repo, done };
}

export async function startScanForRepo(repoId: number): Promise<{ scan: ScanRow; done: Promise<void> }> {
  if (!repoInflight().has(repoId) && repoInflight().size >= MAX_CONCURRENT_SCANS) throw new TooManyError();
  const depth = repoQueueDepth().get(repoId) ?? 0;
  if (depth >= MAX_REPO_QUEUE_DEPTH) throw new TooManyError();
  // createScan (DB write) runs before we touch queue depth — if it throws, no
  // increment happens and there's nothing to roll back.
  const scan = createScan(repoId);
  const done = enqueue(repoId, scan.id);
  return { scan, done };
}

async function runScan(scanId: number): Promise<void> {
  const scan = getScan(scanId)!;
  const repo = getRepo(scan.repo_id)!;
  const sevFromScore = (s: number): Severity =>
    s >= 9 ? "critical" : s >= 7 ? "high" : s >= 4 ? "medium" : s >= 0.1 ? "low" : "info";

  try {
    // Phase 1 — bootstrap -------------------------------------------------
    setScanStatus(scanId, "bootstrap", "Cloning & bootstrapping", 0.03);
    const ref = parseRepoRef(repo.source_url)!;
    const { dir, headSha, defaultBranch } = await checkout(ref, (m) => scanLog(scanId, "info", m));
    // Persist repo provenance (was silently discarded) so the UI/API can show the
    // scanned commit and branch.
    updateRepo(repo.id, { head_sha: headSha, default_branch: defaultBranch });
    const framework = detectFramework(dir);
    updateScan(scanId, { framework });
    scanLog(scanId, "info", `framework: ${framework}`);

    const corpus = buildCorpus(dir);
    scanLog(scanId, "info", `corpus: ${corpus.files.length} files`);

    // Phase 2 — threat model ----------------------------------------------
    setScanStatus(scanId, "threat-model", "Building threat model", 0.15);
    const threat = await inferThreatModel(corpus);
    const threatText = threatModelToText(threat);
    updateScan(scanId, { threat_model_json: JSON.stringify(threat) });
    scanLog(scanId, "info", `threat model: ${threat.ingress.length} ingress points`);

    // Everything that depends on the running target is wrapped so the child is
    // ALWAYS torn down and the port is ALWAYS released — even if startTarget or
    // any scan/exploit/enrich step throws.
    let verified = 0;
    let falsePos = 0;
    // Acquire port as the first statement inside the try so the finally below
    // always pairs the release with the acquire. acquireScanPort returns null
    // when the pool is exhausted — only release when a port was actually acquired.
    let targetPort: number | null = null;
    let target: Awaited<ReturnType<typeof startTarget>> | null = null;
    try {
      // Start the target app for the dynamic phase (best-effort). Acquire a port
      // from the shared allocator so concurrent scans of different repos never
      // collide. Replays occupy 5600-5699 (see replay/route.ts); we stay below.
      targetPort = acquireScanPort();
      if (targetPort) {
        target = await startTarget(dir, framework, { port: targetPort, onLog: (m) => scanLog(scanId, "info", m) });
        if (target) updateScan(scanId, { target_url: target.url });
      } else {
        scanLog(scanId, "info", "no free scan port, skipping dynamic phase");
      }

      // Phase 3 — static vuln-class fan-out ---------------------------------
      setScanStatus(scanId, "scanning", "Scanning vulnerability classes", 0.3);
      const classes = defaultClasses();
      const candidates = await staticScan(classes, threatText, corpus, (done, total, label) => {
        setScanStatus(scanId, "scanning", `Scanning: ${label}`, 0.3 + 0.25 * (done / total));
      });
      const ranked = rankCandidates(candidates).slice(0, MAX_EXPLOIT);
      updateScan(scanId, { candidate_count: candidates.length });
      scanLog(scanId, "info", `${candidates.length} candidates, exploiting top ${ranked.length}`);

      // Phase 4+5 — exploit synthesis + enrichment --------------------------
      setScanStatus(scanId, "exploiting", "Synthesizing exploits", 0.55);
      for (let i = 0; i < ranked.length; i++) {
        const c = ranked[i];
        setScanStatus(scanId, "exploiting", `Exploiting: ${c.categoryLabel}`, 0.55 + 0.3 * (i / Math.max(1, ranked.length)));
        const outcome = await synthesizeAndValidate(c, target?.url ?? null);

        if (outcome.status === "disconfirmed") {
          falsePos++;
          insertFinding({
            scan_id: scanId, repo_id: repo.id, category: c.category, title: c.title,
            severity: "info", status: "disconfirmed", confidence: c.confidence,
            file_path: c.file, start_line: c.startLine, end_line: c.endLine, vulnerable_code: c.code,
            summary: c.description, disconfirm_reason: outcome.disconfirmReason, rank_score: c.rankScore,
          });
          scanLog(scanId, "info", `disconfirmed (${c.category}): ${outcome.disconfirmReason}`);
          continue;
        }

        if (outcome.status === "inconclusive") {
          const w = classWeight(c.category);
          const inconclusiveSev: Severity = w >= 0.85 ? "high" : w >= 0.6 ? "medium" : "low";
          insertFinding({
            scan_id: scanId, repo_id: repo.id, category: c.category, title: c.title,
            severity: inconclusiveSev, status: "inconclusive", confidence: c.confidence,
            file_path: c.file, start_line: c.startLine, end_line: c.endLine, vulnerable_code: c.code,
            summary: c.description, disconfirm_reason: outcome.disconfirmReason, rank_score: c.rankScore,
          });
          continue;
        }

        // validated → enrich + CVSS + history. Enrichment is best-effort: if it
        // throws (LLM down/timeout/parse error) we MUST still persist the confirmed
        // finding — it carries a real working exploit. Fall back to candidate
        // fields and a class-weight severity (no fabricated CVSS) on failure.
        setScanStatus(scanId, "enriching", `Enriching: ${c.categoryLabel}`, 0.55 + 0.3 * (i / Math.max(1, ranked.length)));
        let e: Awaited<ReturnType<typeof enrichFinding>> | null = null;
        try {
          e = await enrichFinding(c, outcome, dir);
        } catch (err: any) {
          scanLog(scanId, "warn", `enrichment failed for ${c.category}; storing finding with raw exploit: ${err?.message ?? err}`);
        }
        verified++;
        const w = classWeight(c.category);
        insertFinding({
          scan_id: scanId, repo_id: repo.id, category: c.category, title: e?.title || c.title,
          severity: e ? sevFromScore(e.cvss.score) : w >= 0.85 ? "high" : "medium",
          status: "validated", confidence: Math.max(c.confidence, 0.9),
          file_path: c.file, start_line: c.startLine, end_line: c.endLine, vulnerable_code: c.code,
          summary: e?.summary || c.description, impact: e?.impact, cvss_vector: e?.cvss.vector ?? null, cvss_score: e?.cvss.score ?? null,
          exploit_script: outcome.exploitScript, exploit_transcript_json: outcome.transcript ? JSON.stringify(outcome.transcript) : null,
          recommended_fix: e?.recommendedFix, consistency_note: e?.consistencyNote,
          history_json: e?.history ? JSON.stringify(e.history) : null, rank_score: c.rankScore,
        });
        scanLog(scanId, "info", `VALIDATED (${c.category}): ${e?.title || c.title}${e ? ` [CVSS ${e.cvss.score}]` : " [enrichment unavailable]"}`);
      }
    } finally {
      if (target) {
        target.stop();
        target.cleanup();
      }
      if (targetPort !== null) releaseScanPort(targetPort);
    }

    // Phase 6 — supply chain (OSV) ----------------------------------------
    setScanStatus(scanId, "reporting", "Supply-chain & reporting", 0.9);
    await osvFindings(scanId, repo.id, dir);

    persistCounts(scanId);
    setScanStatus(scanId, "done", "Done", 1);
    publish({ scanId, status: "done", phase: "Done", progress: 1, done: true });
    scanLog(scanId, "info", `done: ${verified} validated, ${falsePos} disconfirmed (dropped)`);
  } catch (err: any) {
    // Persist whatever was found before the failure so the scan isn't left at 0.
    try {
      persistCounts(scanId);
    } catch {
      /* ignore */
    }
    setScanError(scanId, err?.message ?? String(err));
    throw err;
  }
}

// Counts come straight from the findings table (source of truth), so they're
// accurate whether the scan finished or errored partway.
function persistCounts(scanId: number) {
  const row = db
    .prepare(
      `SELECT
         SUM(CASE WHEN status IN ('validated','advisory') THEN 1 ELSE 0 END) AS shipped,
         SUM(CASE WHEN status='validated' THEN 1 ELSE 0 END) AS verified,
         SUM(CASE WHEN status='disconfirmed' THEN 1 ELSE 0 END) AS dropped
       FROM findings WHERE scan_id = ?`,
    )
    .get(scanId) as { shipped: number | null; verified: number | null; dropped: number | null };
  updateScan(scanId, {
    findings_count: row.shipped ?? 0,
    verified_count: row.verified ?? 0,
    false_positive_count: row.dropped ?? 0,
  });
}

async function osvFindings(scanId: number, repoId: number, dir: string) {
  try {
    const deps = parseDependencies(dir);
    if (!deps.length) return;
    const { lookupVulns } = await import("./code/osv");
    const vulns = await lookupVulns(deps);
    for (const d of deps) {
      const v = vulns.get(`${d.ecosystem}:${d.name}`);
      if (v && v.length) {
        insertFinding({
          scan_id: scanId, repo_id: repoId, category: "dependency-vuln",
          title: `Vulnerable dependency: ${d.name}${d.version ? "@" + d.version : ""}`,
          // OSV's querybatch returns advisory IDs but not severity, so we can't
          // accurately rate these — default to medium. status='advisory' keeps
          // them OUT of the exploit-confirmed "validated" bucket.
          severity: "medium", status: "advisory", confidence: 1, source: "osv",
          summary: `OSV reports known vulnerabilities for ${d.name}: ${v.map((x) => x.id).join(", ")} (review each advisory for severity)`,
          impact: "A known-vulnerable dependency is in use. Upgrade to a patched version.",
          recommended_fix: `Upgrade ${d.name} to a non-vulnerable version (see ${v.map((x) => x.id).join(", ")}).`,
        });
      }
    }
  } catch {
    /* OSV off or unreachable */
  }
}
