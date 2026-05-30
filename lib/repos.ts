import { db } from "./db";

export const now = () => Date.now();

export type RepoRow = {
  id: number;
  owner: string;
  name: string;
  full_name: string;
  source_url: string;
  default_branch: string | null;
  head_sha: string | null;
  framework: string | null;
  created_at: number;
  updated_at: number;
};

export function normalizeFullName(owner: string, name: string): string {
  return `${owner}/${name}`.toLowerCase();
}

export function getRepo(id: number): RepoRow | null {
  return (db.prepare("SELECT * FROM repos WHERE id = ?").get(id) as RepoRow) ?? null;
}

export function getRepoByName(owner: string, name: string): RepoRow | null {
  return (db.prepare("SELECT * FROM repos WHERE full_name = ?").get(normalizeFullName(owner, name)) as RepoRow) ?? null;
}

export function createRepo(args: { owner: string; name: string; sourceUrl: string }): RepoRow {
  const existing = getRepoByName(args.owner, args.name);
  if (existing) return existing;
  const ts = now();
  const info = db
    .prepare(`INSERT INTO repos (owner, name, full_name, source_url, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)`)
    .run(args.owner, args.name, normalizeFullName(args.owner, args.name), args.sourceUrl, ts, ts);
  return getRepo(Number(info.lastInsertRowid))!;
}

export function updateRepo(id: number, fields: Partial<RepoRow>) {
  const keys = Object.keys(fields);
  if (keys.length === 0) return;
  const set = keys.map((k) => `${k} = ?`).join(", ");
  const values = keys.map((k) => (fields as Record<string, unknown>)[k]);
  db.prepare(`UPDATE repos SET ${set}, updated_at = ? WHERE id = ?`).run(...values, now(), id);
}

export function listRepos(): RepoRow[] {
  return db.prepare("SELECT * FROM repos ORDER BY updated_at DESC").all() as RepoRow[];
}
