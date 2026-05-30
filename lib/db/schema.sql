PRAGMA foreign_keys = ON;
PRAGMA journal_mode = WAL;

CREATE TABLE IF NOT EXISTS repos (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  owner TEXT NOT NULL,
  name TEXT NOT NULL,
  full_name TEXT NOT NULL UNIQUE,
  source_url TEXT NOT NULL,
  default_branch TEXT,
  head_sha TEXT,
  framework TEXT,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS scans (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  repo_id INTEGER NOT NULL REFERENCES repos(id) ON DELETE CASCADE,
  status TEXT NOT NULL DEFAULT 'pending',   -- pending|bootstrap|threat-model|scanning|exploiting|enriching|reporting|done|error
  phase TEXT,
  progress REAL NOT NULL DEFAULT 0,
  error_message TEXT,
  threat_model_json TEXT,
  framework TEXT,
  target_url TEXT,
  findings_count INTEGER NOT NULL DEFAULT 0,
  candidate_count INTEGER NOT NULL DEFAULT 0,
  verified_count INTEGER NOT NULL DEFAULT 0,
  false_positive_count INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_scans_repo ON scans(repo_id);
CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status);

CREATE TABLE IF NOT EXISTS findings (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  repo_id INTEGER NOT NULL REFERENCES repos(id) ON DELETE CASCADE,
  category TEXT NOT NULL,                    -- injection-sql, idor, xss, ...
  title TEXT NOT NULL,
  severity TEXT NOT NULL DEFAULT 'medium',   -- critical|high|medium|low|info
  status TEXT NOT NULL DEFAULT 'candidate',  -- candidate|validated|disconfirmed|inconclusive|advisory
  confidence REAL NOT NULL DEFAULT 0.5,
  file_path TEXT,
  start_line INTEGER,
  end_line INTEGER,
  vulnerable_code TEXT,
  summary TEXT,
  impact TEXT,
  cvss_vector TEXT,
  cvss_score REAL,
  exploit_script TEXT,
  exploit_transcript_json TEXT,             -- {input, response, outcome, evidence}
  disconfirm_reason TEXT,
  recommended_fix TEXT,                     -- unified diff
  consistency_note TEXT,
  history_json TEXT,                        -- {commit, author, date}
  rank_score REAL NOT NULL DEFAULT 0,
  source TEXT NOT NULL DEFAULT 'agent',     -- agent|osv
  issue_url TEXT,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);

CREATE TABLE IF NOT EXISTS scan_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  ts INTEGER NOT NULL,
  level TEXT NOT NULL DEFAULT 'info',
  message TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_scanlog_scan ON scan_log(scan_id, ts);
