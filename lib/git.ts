import fs from "node:fs";
import path from "node:path";
import { simpleGit } from "simple-git";
import { PATHS } from "./db";

// Resolve a user-supplied repo reference into { owner, name, cloneUrl } or a
// local path. Accepts: full GitHub URLs, github.com/owner/repo, owner/repo, and
// absolute local filesystem paths (for self-hosting against a working copy).

export type RepoRef = {
  owner: string;
  name: string;
  cloneUrl: string;
  local: boolean;
  // Installation token for private-repo clones (GitHub App). Never stored.
  token?: string;
};

export function parseRepoRef(input: string): RepoRef | null {
  const raw = input.trim();
  const isUrl = /^(https?:\/\/|git@)/i.test(raw);
  // Local path: anything that resolves to an existing directory on disk.
  if (!isUrl) {
    const candidate = raw
      .replace(/^file:\/\//, "")
      .replace(/^~/, process.env.HOME ?? "~");
    const abs = path.resolve(candidate);
    if (fs.existsSync(abs) && fs.statSync(abs).isDirectory()) {
      return { owner: "local", name: path.basename(abs), cloneUrl: abs, local: true };
    }
  }
  // github URL or owner/repo
  const cleaned = raw
    .replace(/^https?:\/\/(www\.)?github\.com\//i, "")
    .replace(/^git@github\.com:/i, "")
    .replace(/\.git$/i, "")
    .replace(/\/$/, "");
  const m = cleaned.match(/^([\w.-]+)\/([\w.-]+)/);
  if (!m) return null;
  const owner = m[1];
  const name = m[2];
  return {
    owner,
    name,
    cloneUrl: `https://github.com/${owner}/${name}.git`,
    local: false,
  };
}

export function workspacePath(owner: string, name: string): string {
  return path.join(PATHS.WORKSPACES_DIR, `${owner}__${name}`.replace(/[^\w.-]+/g, "_"));
}

// Local-path scanning walks + can start an arbitrary directory, so it is NEVER
// allowed from untrusted API input unless the operator allowlists base dirs via
// ROOK_LOCAL_ROOTS. The CLI bypasses this; remote (github) refs are always ok.
export function localRoots(): string[] {
  const v = process.env.ROOK_LOCAL_ROOTS;
  if (!v) return [];
  return v
    .split(",")
    .map((s) => path.resolve(s.trim().replace(/^~/, process.env.HOME ?? "~")))
    .filter(Boolean);
}

export function isRefAllowedFromApi(ref: RepoRef): boolean {
  if (!ref.local) return true;
  const roots = localRoots();
  if (roots.length === 0) return false;
  const abs = path.resolve(ref.cloneUrl);
  return roots.some((r) => abs === r || abs.startsWith(r + path.sep));
}

// The on-disk root for a repo: the workspace clone for remote repos, or the
// original path for local refs. Returns null if nothing is on disk.
export function repoDir(repo: { owner: string; name: string; source_url: string }): string | null {
  if (repo.owner === "local") {
    return fs.existsSync(repo.source_url) ? repo.source_url : null;
  }
  const dir = workspacePath(repo.owner, repo.name);
  return fs.existsSync(dir) ? dir : null;
}

export type CheckoutResult = { dir: string; headSha: string | null; defaultBranch: string | null };

// Clone (or refresh) a repo into the workspaces dir. For local refs we just
// point at the existing path. Shallow clone to keep it fast.
export async function checkout(
  ref: RepoRef,
  onLog?: (msg: string) => void,
): Promise<CheckoutResult> {
  if (ref.local) {
    const headSha = await safeHead(ref.cloneUrl);
    return { dir: ref.cloneUrl, headSha, defaultBranch: null };
  }
  const dir = workspacePath(ref.owner, ref.name);
  if (fs.existsSync(dir)) {
    fs.rmSync(dir, { recursive: true, force: true });
  }
  fs.mkdirSync(dir, { recursive: true });
  onLog?.(`cloning ${ref.cloneUrl}`);
  // Abort a clone that hangs (slow network / a giant repo) instead of stalling
  // the whole pipeline forever. Tunable via GIT_CLONE_TIMEOUT_MS.
  const cloneTimeout = Number(process.env.GIT_CLONE_TIMEOUT_MS ?? 300000);
  const git = simpleGit({ timeout: { block: cloneTimeout } });
  // Use an authenticated URL for private repos; keep the token out of source_url.
  const cloneUrl = ref.token ? `https://x-access-token:${ref.token}@github.com/${ref.owner}/${ref.name}.git` : ref.cloneUrl;
  try {
    await git.clone(cloneUrl, dir, ["--depth", "1", "--single-branch"]);
  } catch (e: any) {
    // simple-git embeds the full clone command (incl. the x-access-token URL) in
    // its error message. Strip the token before it can reach logs / DB / SSE.
    throw new Error(String(e?.message ?? e).replace(/x-access-token:[^@\s]+@/gi, "x-access-token:«redacted»@"));
  }
  const headSha = await safeHead(dir);
  let defaultBranch: string | null = null;
  try {
    defaultBranch = (await simpleGit(dir).revparse(["--abbrev-ref", "HEAD"])).trim();
  } catch {
    /* shallow clone may detach; ignore */
  }
  return { dir, headSha, defaultBranch };
}

async function safeHead(dir: string): Promise<string | null> {
  try {
    return (await simpleGit(dir).revparse(["HEAD"])).trim();
  } catch {
    return null;
  }
}
