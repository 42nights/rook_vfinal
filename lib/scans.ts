import { db } from "./db";
import { now } from "./repos";
import { publish } from "./progress";
import { scrubSecrets } from "./code/scrubber";

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
  id: number;
  repo_id: number;
  status: ScanStatus;
  phase: string | null;
  progress: number;
  error_message: string | null;
  threat_model_json: string | null;
  framework: string | null;
  target_url: string | null;
  findings_count: number;
  candidate_count: number;
  verified_count: number;
  false_positive_count: number;
  created_at: number;
  updated_at: number;
};

// "validated" is reserved for findings with a real confirmed exploit. "advisory"
// is for OSV dependency vulns (known CVEs with no synthesized exploit) — shipped,
// but never claimed as exploit-proven.
export type FindingStatus = "candidate" | "validated" | "advisory" | "disconfirmed" | "inconclusive";
export type Severity = "critical" | "high" | "medium" | "low" | "info";

export type FindingRow = {
  id: number;
  scan_id: number;
  repo_id: number;
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

export function createScan(repoId: number): ScanRow {
  const ts = now();
  const info = db
    .prepare(`INSERT INTO scans (repo_id, status, progress, created_at, updated_at) VALUES (?, 'pending', 0, ?, ?)`)
    .run(repoId, ts, ts);
  return getScan(Number(info.lastInsertRowid))!;
}

export function getScan(id: number): ScanRow | null {
  return (db.prepare("SELECT * FROM scans WHERE id = ?").get(id) as ScanRow) ?? null;
}

export function listScans(): ScanRow[] {
  return db.prepare("SELECT * FROM scans ORDER BY created_at DESC").all() as ScanRow[];
}

export function listScansForRepo(repoId: number): ScanRow[] {
  return db.prepare("SELECT * FROM scans WHERE repo_id = ? ORDER BY created_at DESC").all(repoId) as ScanRow[];
}

export function updateScan(id: number, fields: Partial<ScanRow>) {
  const keys = Object.keys(fields);
  if (keys.length === 0) return;
  const set = keys.map((k) => `${k} = ?`).join(", ");
  const values = keys.map((k) => (fields as Record<string, unknown>)[k]);
  db.prepare(`UPDATE scans SET ${set}, updated_at = ? WHERE id = ?`).run(...values, now(), id);
}

export function setScanStatus(id: number, status: ScanStatus, phase?: string, progress?: number) {
  const fields: Partial<ScanRow> = { status };
  if (phase !== undefined) fields.phase = phase;
  if (progress !== undefined) fields.progress = progress;
  updateScan(id, fields);
  publish({ scanId: id, status, phase: phase ?? status, progress: progress ?? 0 });
}

export function setScanError(id: number, message: string) {
  updateScan(id, { status: "error", error_message: message.slice(0, 1000) });
  publish({ scanId: id, status: "error", phase: "Error", progress: 0, error: message.slice(0, 300), done: true });
}

export function scanLog(scanId: number, level: string, message: string) {
  db.prepare(`INSERT INTO scan_log (scan_id, ts, level, message) VALUES (?, ?, ?, ?)`).run(scanId, now(), level, message);
}


export function insertFinding(f: Partial<FindingRow> & { scan_id: number; repo_id: number; category: string; title: string }): number {
  const cols = [
    "scan_id", "repo_id", "category", "title", "severity", "status", "confidence",
    "file_path", "start_line", "end_line", "vulnerable_code", "summary", "impact",
    "cvss_vector", "cvss_score", "exploit_script", "exploit_transcript_json",
    "disconfirm_reason", "recommended_fix", "consistency_note", "history_json",
    "rank_score", "source", "created_at",
  ];
  // Redact credential-shaped strings from EVERY stored free-text field — code,
  // title, and summary all originate from LLM output over untrusted repo source
  // and flow to the DB / report / GitHub issue / Otis. (Validated findings are
  // already scrubbed in enrich; this also covers candidate/inconclusive/
  // disconfirmed rows. scrubSecrets is idempotent, so double-scrubbing is safe.)
  const safeCode = f.vulnerable_code ? scrubSecrets(f.vulnerable_code).text : null;
  const safeTitle = scrubSecrets(f.title).text;
  const safeSummary = f.summary ? scrubSecrets(f.summary).text : null;
  // disconfirm_reason can quote a response snippet ("target returned …") — scrub it too.
  const safeDisconfirmReason = f.disconfirm_reason ? scrubSecrets(f.disconfirm_reason).text : null;
  const vals = [
    f.scan_id, f.repo_id, f.category, safeTitle, f.severity ?? "medium", f.status ?? "candidate", f.confidence ?? 0.5,
    f.file_path ?? null, f.start_line ?? null, f.end_line ?? null, safeCode, safeSummary, f.impact ?? null,
    f.cvss_vector ?? null, f.cvss_score ?? null, f.exploit_script ?? null, f.exploit_transcript_json ?? null,
    safeDisconfirmReason, f.recommended_fix ?? null, f.consistency_note ?? null, f.history_json ?? null,
    f.rank_score ?? 0, f.source ?? "agent", now(),
  ];
  const info = db
    .prepare(`INSERT INTO findings (${cols.join(", ")}) VALUES (${cols.map(() => "?").join(", ")})`)
    .run(...vals);
  return Number(info.lastInsertRowid);
}

export function updateFinding(id: number, fields: Partial<FindingRow>) {
  const keys = Object.keys(fields);
  if (keys.length === 0) return;
  const set = keys.map((k) => `${k} = ?`).join(", ");
  const values = keys.map((k) => (fields as Record<string, unknown>)[k]);
  db.prepare(`UPDATE findings SET ${set} WHERE id = ?`).run(...values, id);
}

export function getFinding(id: number): FindingRow | null {
  return (db.prepare("SELECT * FROM findings WHERE id = ?").get(id) as FindingRow) ?? null;
}

export function listFindings(scanId: number): FindingRow[] {
  return db
    .prepare("SELECT * FROM findings WHERE scan_id = ? ORDER BY rank_score DESC, cvss_score DESC")
    .all(scanId) as FindingRow[];
}

// Findings worth shipping: exploit-confirmed (validated) + OSV advisories.
export function listValidated(scanId: number): FindingRow[] {
  return listFindings(scanId).filter((f) => f.status === "validated" || f.status === "advisory");
}
