import "./local-mode";
import {
  createScan,
  getScan,
  updateScan,
  setScanStatus,
  setScanError,
  scanLog,
  insertFinding,
  latestThreatModelJson,
  persistCounts,
  type ScanRow,
} from "./scans";
import { getRepo, createRepo, updateRepo, type RepoRow } from "./repos";
import { parseRepoRef, checkout, checkoutPr, repoDir, type RepoRef } from "./git";
import { buildCorpus } from "./scanner/corpus";
import { langForPath } from "./code/langs";
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
  var __rook_scan_inflight: Set<string> | undefined;
  // eslint-disable-next-line no-var
  var __rook_repo_inflight: Map<string, Promise<void>> | undefined;
  // eslint-disable-next-line no-var
  var __rook_scan_ports: Set<number> | undefined;
  // eslint-disable-next-line no-var
  var __rook_repo_queue_depth: Map<string, number> | undefined;
}
function inflight(): Set<string> {
  if (!globalThis.__rook_scan_inflight) globalThis.__rook_scan_inflight = new Set();
  return globalThis.__rook_scan_inflight;
}
function repoInflight(): Map<string, Promise<void>> {
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
function repoQueueDepth(): Map<string, number> {
  return (globalThis.__rook_repo_queue_depth ??= new Map());
}
export function isScanning(scanId: string): boolean {
  return inflight().has(scanId);
}

const MAX_CONCURRENT_SCANS = Number(process.env.ROOK_MAX_CONCURRENT_SCANS ?? 3);

export class TooManyError extends Error {
  constructor() {
    super("Too many concurrent scans in flight. Try again shortly.");
    this.name = "TooManyError";
  }
}

const MAX_REPO_QUEUE_DEPTH = 3;

export type PrContext = {
  owner: string;
  name: string;
  prNumber: number;
  headSha: string;
  baseSha: string;
  installationId?: number;
  token?: string;
};

function enqueue(repoId: string, scanId: string, prContext?: PrContext): Promise<void> {
  const depth = repoQueueDepth().get(repoId) ?? 0;
  repoQueueDepth().set(repoId, depth + 1);
  inflight().add(scanId);
  const prior = repoInflight().get(repoId) ?? Promise.resolve();
  let done: Promise<void>;
  done = prior
    .catch(() => {})
    .then(() => runScan(scanId, prContext))
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
  const repo = await createRepo({ owner: ref.owner, name: ref.name, sourceUrl: ref.cloneUrl });
  if (!repoInflight().has(repo._id) && repoInflight().size >= MAX_CONCURRENT_SCANS) throw new TooManyError();
  const depth = repoQueueDepth().get(repo._id) ?? 0;
  if (depth >= MAX_REPO_QUEUE_DEPTH) throw new TooManyError();
  const scan = await createScan(repo._id);
  const done = enqueue(repo._id, scan._id);
  return { scan, repo, done };
}

export async function startScanForRepo(repoId: string): Promise<{ scan: ScanRow; done: Promise<void> }> {
  if (!repoInflight().has(repoId) && repoInflight().size >= MAX_CONCURRENT_SCANS) throw new TooManyError();
  const depth = repoQueueDepth().get(repoId) ?? 0;
  if (depth >= MAX_REPO_QUEUE_DEPTH) throw new TooManyError();
  const scan = await createScan(repoId);
  const done = enqueue(repoId, scan._id);
  return { scan, done };
}

export async function startScanForPr(pr: PrContext): Promise<{ scan: ScanRow; repo: RepoRow; done: Promise<void> }> {
  const repo = await createRepo({ owner: pr.owner, name: pr.name, sourceUrl: `https://github.com/${pr.owner}/${pr.name}.git` });
  if (!repoInflight().has(repo._id) && repoInflight().size >= MAX_CONCURRENT_SCANS) throw new TooManyError();
  const depth = repoQueueDepth().get(repo._id) ?? 0;
  if (depth >= MAX_REPO_QUEUE_DEPTH) throw new TooManyError();
  const scan = await createScan(repo._id);
  await updateScan(scan._id, {
    pr_number: pr.prNumber,
    pr_base_sha: pr.baseSha,
    pr_head_sha: pr.headSha,
    installation_id: pr.installationId ?? null,
  });
  const done = enqueue(repo._id, scan._id, pr);
  return { scan, repo, done };
}

export async function runScan(scanId: string, prContext?: PrContext): Promise<void> {
  const scan = (await getScan(scanId))!;
  const repo = (await getRepo(scan.repo_id))!;
  const sevFromScore = (s: number): Severity =>
    s >= 9 ? "critical" : s >= 7 ? "high" : s >= 4 ? "medium" : s >= 0.1 ? "low" : "info";

  try {
    // Phase 1 — bootstrap -------------------------------------------------
    await setScanStatus(scanId, "bootstrap", prContext ? `Fetching PR #${prContext.prNumber}` : "Cloning & bootstrapping", 0.03);
    let dir: string;
    let changedCode: string[] | null = null;
    if (prContext) {
      const ref: RepoRef = {
        owner: prContext.owner,
        name: prContext.name,
        cloneUrl: `https://github.com/${prContext.owner}/${prContext.name}.git`,
        local: false,
        token: prContext.token,
      };
      const co = await checkoutPr(ref, { headSha: prContext.headSha, baseSha: prContext.baseSha }, (m) => scanLog(scanId, "info", m));
      dir = co.dir;
      await updateRepo(repo._id, { head_sha: co.headSha });
      changedCode = co.changedFiles.filter((p) => {
        const info = langForPath(p);
        return info != null && !info.isDoc;
      });
      await scanLog(scanId, "info", `PR diff: ${co.changedFiles.length} changed file(s), ${changedCode.length} code`);
    } else {
      const ref = parseRepoRef(repo.source_url)!;
      const co = await checkout(ref, (m) => scanLog(scanId, "info", m));
      dir = co.dir;
      await updateRepo(repo._id, { head_sha: co.headSha, default_branch: co.defaultBranch });
    }
    const framework = detectFramework(dir);
    await updateScan(scanId, { framework });
    await scanLog(scanId, "info", `framework: ${framework}`);

    const corpus = buildCorpus(dir, prContext ? { only: changedCode ?? [] } : {});
    await scanLog(scanId, "info", `corpus: ${corpus.files.length} files${prContext ? " (PR-focused)" : ""}`);

    if (prContext && corpus.files.length === 0) {
      await scanLog(scanId, "info", "PR touched no scannable code — nothing to scan");
      await setScanStatus(scanId, "done", "No scannable code in diff", 1);
      await persistCounts(scanId);
      return;
    }

    // Phase 2 — threat model ----------------------------------------------
    await setScanStatus(scanId, "threat-model", "Building threat model", 0.15);
    let threatText: string;
    const reused = prContext ? await latestThreatModelJson(repo._id) : null;
    if (reused) {
      try {
        threatText = threatModelToText(JSON.parse(reused));
        await updateScan(scanId, { threat_model_json: reused });
        await scanLog(scanId, "info", "reused threat model from last full scan");
      } catch {
        const threat = await inferThreatModel(corpus);
        threatText = threatModelToText(threat);
        await updateScan(scanId, { threat_model_json: JSON.stringify(threat) });
      }
    } else {
      const threat = await inferThreatModel(corpus);
      threatText = threatModelToText(threat);
      await updateScan(scanId, { threat_model_json: JSON.stringify(threat) });
      await scanLog(scanId, "info", `threat model: ${threat.ingress.length} ingress points`);
    }

    let verified = 0;
    let falsePos = 0;
    let targetPort: number | null = null;
    let target: Awaited<ReturnType<typeof startTarget>> | null = null;
    try {
      targetPort = acquireScanPort();
      if (targetPort) {
        target = await startTarget(dir, framework, { port: targetPort, onLog: (m) => scanLog(scanId, "info", m) });
        if (target) await updateScan(scanId, { target_url: target.url });
      } else {
        await scanLog(scanId, "info", "no free scan port, skipping dynamic phase");
      }

      // Phase 3 — static vuln-class fan-out ---------------------------------
      await setScanStatus(scanId, "scanning", "Scanning vulnerability classes", 0.3);
      const classes = defaultClasses();
      const candidates = await staticScan(classes, threatText, corpus, (done, total, label) => {
        setScanStatus(scanId, "scanning", `Scanning: ${label}`, 0.3 + 0.25 * (done / total));
      });
      const ranked = rankCandidates(candidates).slice(0, MAX_EXPLOIT);
      await updateScan(scanId, { candidate_count: candidates.length });
      await scanLog(scanId, "info", `${candidates.length} candidates, exploiting top ${ranked.length}`);

      // Phase 4+5 — exploit synthesis + enrichment --------------------------
      await setScanStatus(scanId, "exploiting", "Synthesizing exploits", 0.55);
      for (let i = 0; i < ranked.length; i++) {
        const c = ranked[i];
        await setScanStatus(scanId, "exploiting", `Exploiting: ${c.categoryLabel}`, 0.55 + 0.3 * (i / Math.max(1, ranked.length)));
        const outcome = await synthesizeAndValidate(c, target?.url ?? null);

        if (outcome.status === "disconfirmed") {
          falsePos++;
          await insertFinding({
            scan_id: scanId, repo_id: repo._id, category: c.category, title: c.title,
            severity: "info", status: "disconfirmed", confidence: c.confidence,
            file_path: c.file, start_line: c.startLine, end_line: c.endLine, vulnerable_code: c.code,
            summary: c.description, disconfirm_reason: outcome.disconfirmReason, rank_score: c.rankScore,
          });
          await scanLog(scanId, "info", `disconfirmed (${c.category}): ${outcome.disconfirmReason}`);
          continue;
        }

        if (outcome.status === "inconclusive") {
          const w = classWeight(c.category);
          const inconclusiveSev: Severity = w >= 0.85 ? "high" : w >= 0.6 ? "medium" : "low";
          await insertFinding({
            scan_id: scanId, repo_id: repo._id, category: c.category, title: c.title,
            severity: inconclusiveSev, status: "inconclusive", confidence: c.confidence,
            file_path: c.file, start_line: c.startLine, end_line: c.endLine, vulnerable_code: c.code,
            summary: c.description, disconfirm_reason: outcome.disconfirmReason, rank_score: c.rankScore,
          });
          continue;
        }

        // validated → enrich + CVSS + history
        await setScanStatus(scanId, "enriching", `Enriching: ${c.categoryLabel}`, 0.55 + 0.3 * (i / Math.max(1, ranked.length)));
        let e: Awaited<ReturnType<typeof enrichFinding>> | null = null;
        try {
          e = await enrichFinding(c, outcome, dir);
        } catch (err: unknown) {
          const msg = err instanceof Error ? err.message : String(err);
          await scanLog(scanId, "warn", `enrichment failed for ${c.category}; storing finding with raw exploit: ${msg}`);
        }
        verified++;
        const w = classWeight(c.category);
        await insertFinding({
          scan_id: scanId, repo_id: repo._id, category: c.category, title: e?.title || c.title,
          severity: e ? sevFromScore(e.cvss.score) : w >= 0.85 ? "high" : "medium",
          status: "validated", confidence: Math.max(c.confidence, 0.9),
          file_path: c.file, start_line: c.startLine, end_line: c.endLine, vulnerable_code: c.code,
          summary: e?.summary || c.description, impact: e?.impact, cvss_vector: e?.cvss.vector ?? null, cvss_score: e?.cvss.score ?? null,
          exploit_script: outcome.exploitScript, exploit_transcript_json: outcome.transcript ? JSON.stringify(outcome.transcript) : null,
          recommended_fix: e?.recommendedFix, consistency_note: e?.consistencyNote,
          history_json: e?.history ? JSON.stringify(e.history) : null, rank_score: c.rankScore,
        });
        await scanLog(scanId, "info", `VALIDATED (${c.category}): ${e?.title || c.title}${e ? ` [CVSS ${e.cvss.score}]` : " [enrichment unavailable]"}`);
      }
    } finally {
      if (target) {
        target.stop();
        target.cleanup();
      }
      if (targetPort !== null) releaseScanPort(targetPort);
    }

    // Phase 6 — supply chain (OSV) ----------------------------------------
    await setScanStatus(scanId, "reporting", "Supply-chain & reporting", 0.9);
    await osvFindings(scanId, repo._id, dir);

    await persistCounts(scanId);
    await setScanStatus(scanId, "done", "Done", 1);
    publish({ scanId, status: "done", phase: "Done", progress: 1, done: true });
    await scanLog(scanId, "info", `done: ${verified} validated, ${falsePos} disconfirmed (dropped)`);
  } catch (err: unknown) {
    try {
      await persistCounts(scanId);
    } catch {
      /* ignore */
    }
    const msg = err instanceof Error ? err.message : String(err);
    await setScanError(scanId, msg);
    throw err;
  }
}

async function osvFindings(scanId: string, repoId: string, dir: string) {
  try {
    const deps = parseDependencies(dir);
    if (!deps.length) return;
    const { lookupVulns } = await import("./code/osv");
    const vulns = await lookupVulns(deps);
    for (const d of deps) {
      const v = vulns.get(`${d.ecosystem}:${d.name}`);
      if (v && v.length) {
        await insertFinding({
          scan_id: scanId, repo_id: repoId, category: "dependency-vuln",
          title: `Vulnerable dependency: ${d.name}${d.version ? "@" + d.version : ""}`,
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
