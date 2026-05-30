import fs from "node:fs";
import path from "node:path";
import { MAX_FILE_BYTES } from "../constants";

// Gitignore-aware filesystem walk. Pragmatic subset of gitignore semantics
// (the common cases) plus a default skip set for vendored / build dirs and
// binary file types. Returns repo-relative posix paths.

export type WalkedFile = { path: string; abs: string; size: number };

const SKIP_DIRS = new Set([
  ".git",
  "node_modules",
  ".next",
  "dist",
  "build",
  "out",
  "target",
  "vendor",
  "__pycache__",
  ".venv",
  "venv",
  "env",
  ".pytest_cache",
  ".mypy_cache",
  ".idea",
  ".vscode",
  "coverage",
  ".turbo",
  ".cache",
  "bin",
  "obj",
  "Pods",
  ".gradle",
  "DerivedData",
]);

const BINARY_EXT = new Set([
  "png", "jpg", "jpeg", "gif", "webp", "svg", "ico", "bmp", "tiff",
  "pdf", "zip", "gz", "tar", "rar", "7z", "bz2", "xz",
  "mp3", "mp4", "wav", "mov", "avi", "mkv", "flac", "ogg", "webm",
  "woff", "woff2", "ttf", "otf", "eot",
  "wasm", "so", "dylib", "dll", "exe", "bin", "o", "a", "class", "jar",
  "lock", "map", "min.js", "min.css",
  "pyc", "pyo", "node", "db", "sqlite", "sqlite3", "ds_store",
]);

type Matcher = (relPosix: string, isDir: boolean) => boolean;

// Bounds so an adversarial .gitignore can't OOM or ReDoS the walker.
const GITIGNORE_MAX_BYTES = 256 * 1024;
const MAX_PATTERNS = 2000;
const MAX_PATTERN_LEN = 200;

function loadGitignore(root: string): Matcher {
  const file = path.join(root, ".gitignore");
  if (!fs.existsSync(file)) return () => false;
  let raw: string;
  try {
    if (fs.statSync(file).size > GITIGNORE_MAX_BYTES) return () => false;
    raw = fs.readFileSync(file, "utf8");
  } catch {
    return () => false;
  }
  const patterns = raw
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => l && !l.startsWith("#") && !l.startsWith("!") && l.length <= MAX_PATTERN_LEN)
    .slice(0, MAX_PATTERNS);
  const matchers = patterns.map(toMatcher).filter(Boolean) as Matcher[];
  return (rel, isDir) => matchers.some((m) => m(rel, isDir));
}

function toMatcher(pat: string): Matcher | null {
  let p = pat;
  const dirOnly = p.endsWith("/");
  if (dirOnly) p = p.slice(0, -1);
  const anchored = p.startsWith("/");
  if (anchored) p = p.slice(1);
  // Collapse runs of '*' to a single '*' before translating — adjacent
  // `[^/]*[^/]*…` is what makes the regex backtrack catastrophically.
  p = p.replace(/\*+/g, "*");
  let rx: RegExp;
  try {
    rx = new RegExp(
      "^" +
        p
          .replace(/[.+^${}()|[\]\\]/g, "\\$&")
          .replace(/\*/g, "[^/]*")
          .replace(/\?/g, "[^/]") +
        "$",
    );
  } catch {
    return null;
  }
  return (rel) => {
    const segments = rel.split("/");
    if (anchored) return rx.test(rel) || rx.test(segments[0]);
    // Unanchored: match any path segment or basename.
    return segments.some((s) => rx.test(s)) || rx.test(rel);
  };
}

function isBinaryPath(p: string): boolean {
  const base = (p.split("/").pop() ?? "").toLowerCase();
  const ext = base.includes(".") ? base.split(".").pop()! : "";
  if (BINARY_EXT.has(ext)) return true;
  if (base.endsWith(".min.js") || base.endsWith(".min.css")) return true;
  return false;
}

// Quick binary sniff: NUL byte in the first 8KB.
function looksBinary(abs: string): boolean {
  try {
    const fd = fs.openSync(abs, "r");
    const buf = Buffer.alloc(8192);
    const n = fs.readSync(fd, buf, 0, 8192, 0);
    fs.closeSync(fd);
    for (let i = 0; i < n; i++) if (buf[i] === 0) return true;
  } catch {
    return true;
  }
  return false;
}

export function walkRepo(root: string): WalkedFile[] {
  const ignore = loadGitignore(root);
  const out: WalkedFile[] = [];

  const visit = (dir: string) => {
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const e of entries) {
      const abs = path.join(dir, e.name);
      const rel = path.relative(root, abs).split(path.sep).join("/");
      if (e.isDirectory()) {
        if (SKIP_DIRS.has(e.name)) continue;
        if (ignore(rel, true)) continue;
        visit(abs);
      } else if (e.isFile()) {
        if (isBinaryPath(rel)) continue;
        if (ignore(rel, false)) continue;
        let size = 0;
        try {
          size = fs.statSync(abs).size;
        } catch {
          continue;
        }
        if (size === 0 || size > MAX_FILE_BYTES) continue;
        if (looksBinary(abs)) continue;
        out.push({ path: rel, abs, size });
      }
    }
  };

  visit(root);
  out.sort((a, b) => a.path.localeCompare(b.path));
  return out;
}
