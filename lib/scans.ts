import { convex, api } from "./db/convex-client";
import { now } from "./repos";
import { publish } from "./progress";
import { scrubSecrets } from "./code/scrubber";
import type { Id } from "../convex/_generated/dataModel";

export type ScanStatus =
  | "pending"
  | "bootstrap"
  | "threat-model"
  | "scanning"
  | "exploiting"
  | "enriching"
  | "reporting"
  | "done"
  | "error";

export type ScanRow = {
  _id: string;
  repo_id: string;
  status: ScanStatus;
  phase: string | null;
  progress: number;
  error_message: string | null;
  threat_model_json: string | null;
  framework: string | null;
  target_url: string | null;
  pr_number: number | null;
  pr_base_sha: string | null;
  pr_head_sha: string | null;
  installation_id: number | null;
  pr_comment_state: string | null;
  findings_count: number;
  candidate_count: number;
  verified_count: number;
  false_positive_count: number;
  created_at: number;
  updated_at: number;
};

export type FindingStatus =
  | "candidate"
  | "validated"
  | "advisory"
  | "disconfirmed"
  | "inconclusive";
export type Severity = "critical" | "high" | "medium" | "low" | "info";

export type FindingRow = {
  _id: string;
  scan_id: string;
  repo_id: string;
  category: string;
  title: string;
  severity: Severity;
  status: FindingStatus;
  confidence: number;
  file_path: string | null;
  start_line: number | null;
  end_line: number | null;
  vulnerable_code: string | null;
  summary: string | null;
  impact: string | null;
  cvss_vector: string | null;
  cvss_score: number | null;
  exploit_script: string | null;
  exploit_transcript_json: string | null;
  disconfirm_reason: string | null;
  recommended_fix: string | null;
  consistency_note: string | null;
  history_json: string | null;
  rank_score: number;
  source: string;
  issue_url: string | null;
  created_at: number;
};

type ConvexScanDoc = {
  _id: Id<"scans">;
  repo_id: string;
  status: string;
  phase?: string;
  progress: number;
  error_message?: string;
  threat_model_json?: string;
  framework?: string;
  target_url?: string;
  pr_number?: number;
  pr_base_sha?: string;
  pr_head_sha?: string;
  installation_id?: number;
  pr_comment_state?: string;
  findings_count: number;
  candidate_count: number;
  verified_count: number;
  false_positive_count: number;
  created_at: number;
  updated_at: number;
};

type ConvexFindingDoc = {
  _id: Id<"findings">;
  scan_id: string;
  repo_id: string;
  category: string;
  title: string;
  severity: string;
  status: string;
  confidence: number;
  file_path?: string;
  start_line?: number;
  end_line?: number;
  vulnerable_code?: string;
  summary?: string;
  impact?: string;
  cvss_vector?: string;
  cvss_score?: number;
  exploit_script?: string;
  exploit_transcript_json?: string;
  disconfirm_reason?: string;
  recommended_fix?: string;
  consistency_note?: string;
  history_json?: string;
  rank_score: number;
  source: string;
  issue_url?: string;
  created_at: number;
};

function scanToRow(doc: ConvexScanDoc): ScanRow {
  return {
    _id: doc._id as unknown as string,
    repo_id: doc.repo_id,
    status: doc.status as ScanStatus,
    phase: doc.phase ?? null,
    progress: doc.progress,
    error_message: doc.error_message ?? null,
    threat_model_json: doc.threat_model_json ?? null,
    framework: doc.framework ?? null,
    target_url: doc.target_url ?? null,
    pr_number: doc.pr_number ?? null,
    pr_base_sha: doc.pr_base_sha ?? null,
    pr_head_sha: doc.pr_head_sha ?? null,
    installation_id: doc.installation_id ?? null,
    pr_comment_state: doc.pr_comment_state ?? null,
    findings_count: doc.findings_count,
    candidate_count: doc.candidate_count,
    verified_count: doc.verified_count,
    false_positive_count: doc.false_positive_count,
    created_at: doc.created_at,
    updated_at: doc.updated_at,
  };
}

function findingToRow(doc: ConvexFindingDoc): FindingRow {
  return {
    _id: doc._id as unknown as string,
    scan_id: doc.scan_id,
    repo_id: doc.repo_id,
    category: doc.category,
    title: doc.title,
    severity: doc.severity as Severity,
    status: doc.status as FindingStatus,
    confidence: doc.confidence,
    file_path: doc.file_path ?? null,
    start_line: doc.start_line ?? null,
    end_line: doc.end_line ?? null,
    vulnerable_code: doc.vulnerable_code ?? null,
    summary: doc.summary ?? null,
    impact: doc.impact ?? null,
    cvss_vector: doc.cvss_vector ?? null,
    cvss_score: doc.cvss_score ?? null,
    exploit_script: doc.exploit_script ?? null,
    exploit_transcript_json: doc.exploit_transcript_json ?? null,
    disconfirm_reason: doc.disconfirm_reason ?? null,
    recommended_fix: doc.recommended_fix ?? null,
    consistency_note: doc.consistency_note ?? null,
    history_json: doc.history_json ?? null,
    rank_score: doc.rank_score,
    source: doc.source,
    issue_url: doc.issue_url ?? null,
    created_at: doc.created_at,
  };
}

export async function createScan(repoId: string): Promise<ScanRow> {
  const ts = now();
  const id = await convex.mutation(api.scans.insert, {
    repo_id: repoId,
    created_at: ts,
    updated_at: ts,
  });
  return (await getScan(id as unknown as string))!;
}

export async function getScan(id: string): Promise<ScanRow | null> {
  // A malformed / wrong-table id string fails Convex's v.id("scans") validation
  // and throws rather than returning null; treat that as not-found so callers'
  // null guards (notFound()/404) run instead of surfacing a 500.
  let doc;
  try {
    doc = await convex.query(api.scans.getById, { id: id as Id<"scans"> });
  } catch {
    return null;
  }
  return doc ? scanToRow(doc as ConvexScanDoc) : null;
}

export async function listScans(): Promise<ScanRow[]> {
  const docs = await convex.query(api.scans.list, {});
  return (docs as ConvexScanDoc[]).map(scanToRow);
}

export async function listScansForRepo(repoId: string): Promise<ScanRow[]> {
  const docs = await convex.query(api.scans.listForRepo, { repo_id: repoId });
  return (docs as ConvexScanDoc[]).map(scanToRow);
}

export async function updateScan(
  id: string,
  fields: Partial<Omit<ScanRow, "_id">>,
): Promise<void> {
  const patch: Record<string, unknown> = { updated_at: now() };
  for (const [k, v] of Object.entries(fields)) {
    // Convex uses undefined to represent absent optional fields; null needs mapping
    if (v === null) {
      // omit null patches for optional fields — Convex doesn't store null; absence is null
    } else if (v !== undefined) {
      patch[k] = v;
    }
  }
  await convex.mutation(api.scans.patch, {
    id: id as Id<"scans">,
    patchJson: JSON.stringify(patch),
  });
}

export async function setScanStatus(
  id: string,
  status: ScanStatus,
  phase?: string,
  progress?: number,
): Promise<void> {
  const fields: Partial<Omit<ScanRow, "_id">> = { status };
  if (phase !== undefined) fields.phase = phase;
  if (progress !== undefined) fields.progress = progress;
  await updateScan(id, fields);
  publish({ scanId: id, status, phase: phase ?? status, progress: progress ?? 0 });
}

export async function setScanError(id: string, message: string): Promise<void> {
  await updateScan(id, { status: "error", error_message: message.slice(0, 1000) });
  publish({ scanId: id, status: "error", phase: "Error", progress: 0, error: message.slice(0, 300), done: true });
}

export async function scanLog(
  scanId: string,
  level: string,
  message: string,
): Promise<void> {
  await convex.mutation(api.scanLog.insert, {
    scan_id: scanId,
    ts: now(),
    level,
    message,
  });
}

export async function insertFinding(
  f: Partial<FindingRow> & {
    scan_id: string;
    repo_id: string;
    category: string;
    title: string;
  },
): Promise<string> {
  const safeCode = f.vulnerable_code
    ? scrubSecrets(f.vulnerable_code).text
    : undefined;
  const safeTitle = scrubSecrets(f.title).text;
  const safeSummary = f.summary ? scrubSecrets(f.summary).text : undefined;
  const safeDisconfirmReason = f.disconfirm_reason
    ? scrubSecrets(f.disconfirm_reason).text
    : undefined;

  const id = await convex.mutation(api.findings.insert, {
    scan_id: f.scan_id,
    repo_id: f.repo_id,
    category: f.category,
    title: safeTitle,
    severity: f.severity ?? "medium",
    status: f.status ?? "candidate",
    confidence: f.confidence ?? 0.5,
    file_path: f.file_path ?? undefined,
    start_line: f.start_line ?? undefined,
    end_line: f.end_line ?? undefined,
    vulnerable_code: safeCode,
    summary: safeSummary,
    impact: f.impact ?? undefined,
    cvss_vector: f.cvss_vector ?? undefined,
    cvss_score: f.cvss_score ?? undefined,
    exploit_script: f.exploit_script ?? undefined,
    exploit_transcript_json: f.exploit_transcript_json ?? undefined,
    disconfirm_reason: safeDisconfirmReason,
    recommended_fix: f.recommended_fix ?? undefined,
    consistency_note: f.consistency_note ?? undefined,
    history_json: f.history_json ?? undefined,
    rank_score: f.rank_score ?? 0,
    source: f.source ?? "agent",
    issue_url: f.issue_url ?? undefined,
    created_at: now(),
  });
  return id as unknown as string;
}

export async function updateFinding(
  id: string,
  fields: Partial<FindingRow>,
): Promise<void> {
  const patch: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(fields)) {
    if (v !== undefined && v !== null) patch[k] = v;
  }
  if (Object.keys(patch).length === 0) return;
  await convex.mutation(api.findings.patch, {
    id: id as Id<"findings">,
    patchJson: JSON.stringify(patch),
  });
}

export async function getFinding(id: string): Promise<FindingRow | null> {
  // See getScan: a bad id string fails v.id("findings") validation and throws;
  // treat as not-found so callers' null guards run.
  let doc;
  try {
    doc = await convex.query(api.findings.getById, { id: id as Id<"findings"> });
  } catch {
    return null;
  }
  return doc ? findingToRow(doc as ConvexFindingDoc) : null;
}

export async function listFindings(scanId: string): Promise<FindingRow[]> {
  const docs = await convex.query(api.findings.listByScan, { scan_id: scanId });
  return (docs as ConvexFindingDoc[]).map(findingToRow);
}

export async function listValidated(scanId: string): Promise<FindingRow[]> {
  const all = await listFindings(scanId);
  return all.filter((f) => f.status === "validated" || f.status === "advisory");
}

export async function latestThreatModelJson(
  repoId: string,
): Promise<string | null> {
  return convex.query(api.scans.latestDoneThreatModel, { repo_id: repoId });
}

export async function priorPostedPrScan(
  repoId: string,
  prNumber: number,
  headSha: string,
): Promise<boolean> {
  return convex.query(api.scans.priorPostedPrScan, {
    repo_id: repoId,
    pr_number: prNumber,
    pr_head_sha: headSha,
  });
}

export type ScanLogRow = {
  _id: string;
  scan_id: string;
  ts: number;
  level: string;
  message: string;
};

export async function getScanLog(scanId: string): Promise<ScanLogRow[]> {
  // listByScan may not exist in older Convex deployments — return empty rather than 500.
  let docs: unknown[];
  try {
    docs = await convex.query(api.scanLog.listByScan, { scan_id: scanId });
  } catch {
    return [];
  }
  return (docs as ScanLogRow[]).map((d) => ({
    _id: d._id as unknown as string,
    scan_id: d.scan_id,
    ts: d.ts,
    level: d.level,
    message: d.message,
  }));
}

export async function persistCounts(scanId: string): Promise<void> {
  const counts = await convex.query(api.scans.getFindingCounts, {
    scan_id: scanId,
  });
  await updateScan(scanId, {
    findings_count: counts.shipped,
    verified_count: counts.verified,
    false_positive_count: counts.dropped,
  });
}
