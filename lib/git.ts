import fs from "node:fs";
import path from "node:path";
import { simpleGit } from "simple-git";

const DATA_DIR = path.resolve(process.cwd(), "data");
const WORKSPACES_DIR = path.join(DATA_DIR, "workspaces");

const PATHS = { DATA_DIR, WORKSPACES_DIR };

// Lazily create the workspaces dir only when we actually clone. Doing this at
// module-eval time crashes the import on read-only serverless filesystems
// (Vercel allows writes only under /tmp), which would 500 any route that
// transitively imports this module.
function ensureWorkspacesDir(): void {
  if (!fs.existsSync(WORKSPACES_DIR)) fs.mkdirSync(WORKSPACES_DIR, { recursive: true });
}

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
  ensureWorkspacesDir();
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

export type PrCheckoutResult = { dir: string; headSha: string; changedFiles: string[] };

// Check out a pull request and compute its changed files. Fetches ONLY the two
// commits we need (PR head + base) shallowly — fast even on a huge repo — then
// `git diff base head --name-only` for the touched paths. The working tree is
// left at the PR head so the dynamic phase runs the PR's code.
//
// `token` (App installation token) authenticates private-repo fetches and is
// kept out of any stored URL; clone-time errors are scrubbed of it.
export async function checkoutPr(
  ref: RepoRef,
  pr: { headSha: string; baseSha: string },
  onLog?: (msg: string) => void,
): Promise<PrCheckoutResult> {
  if (ref.local) throw new Error("checkoutPr is for remote (GitHub) refs only");
  ensureWorkspacesDir();
  const dir = workspacePath(ref.owner, ref.name);
  if (fs.existsSync(dir)) fs.rmSync(dir, { recursive: true, force: true });
  fs.mkdirSync(dir, { recursive: true });
  const fetchTimeout = Number(process.env.GIT_CLONE_TIMEOUT_MS ?? 300000);
  const git = simpleGit(dir, { timeout: { block: fetchTimeout } });
  const remoteUrl = ref.token
    ? `https://x-access-token:${ref.token}@github.com/${ref.owner}/${ref.name}.git`
    : ref.cloneUrl;
  const scrub = (s: string) => s.replace(/x-access-token:[^@\s]+@/gi, "x-access-token:«redacted»@");
  onLog?.(`fetching PR head ${pr.headSha.slice(0, 8)} + base ${pr.baseSha.slice(0, 8)}`);
  try {
    await git.init();
    await git.addRemote("origin", remoteUrl);
    // Fetch the two specific commits (GitHub allows want-by-sha for reachable
    // commits — PR head/base always are). Shallow: just the trees we diff.
    await git.fetch(["--depth", "1", "origin", pr.headSha, pr.baseSha]);
    await git.raw(["checkout", "--detach", pr.headSha]);
  } catch (e: any) {
    throw new Error(scrub(String(e?.message ?? e)));
  }
  // Two-dot diff: compares the two trees directly (no merge-base needed, so it
  // works with the shallow fetch above). On failure, fall back to diffing the
  // head against the empty tree — i.e. ALL files at head — so a diff hiccup
  // degrades to a full focused scan rather than silently scanning nothing.
  const EMPTY_TREE = "4b825dc642cb6eb9a060e54bf8d69288fbee4904";
  let changedFiles: string[] = [];
  try {
    const out = await git.raw(["diff", "--name-only", pr.baseSha, pr.headSha]);
    changedFiles = out.split("\n").map((s) => s.trim()).filter(Boolean);
  } catch (e: any) {
    onLog?.(`diff vs base failed (${scrub(String(e?.message ?? e))}); falling back to all files at head`);
    try {
      const out = await git.raw(["diff", "--name-only", EMPTY_TREE, pr.headSha]);
      changedFiles = out.split("\n").map((s) => s.trim()).filter(Boolean);
    } catch {
      /* leave empty — runScan will report no findings */
    }
  }
  return { dir, headSha: pr.headSha, changedFiles };
}
