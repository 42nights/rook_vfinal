import fs from "node:fs";
import path from "node:path";

export type Dependency = {
  ecosystem: string; // npm | pip | go | cargo | ruby | php
  name: string;
  version: string | null;
  kind: "prod" | "dev";
};

const MAX_READ_BYTES = 2 * 1024 * 1024;
const read = (p: string): string | null => {
  try {
    if (fs.statSync(p).size > MAX_READ_BYTES) return null;
    return fs.readFileSync(p, "utf8");
  } catch {
    return null;
  }
};

export function parseDependencies(root: string): Dependency[] {
  const out: Dependency[] = [];
  out.push(...npm(root));
  out.push(...pip(root));
  out.push(...go(root));
  out.push(...cargo(root));
  out.push(...ruby(root));
  out.push(...php(root));
  // de-dupe by ecosystem+name+kind
  const seen = new Set<string>();
  return out.filter((d) => {
    const k = `${d.ecosystem}:${d.name}:${d.kind}`;
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
}

function npm(root: string): Dependency[] {
  const raw = read(path.join(root, "package.json"));
  if (!raw) return [];
  try {
    const pkg = JSON.parse(raw);
    const out: Dependency[] = [];
    for (const [name, version] of Object.entries(pkg.dependencies ?? {})) {
      out.push({ ecosystem: "npm", name, version: String(version), kind: "prod" });
    }
    for (const [name, version] of Object.entries(pkg.devDependencies ?? {})) {
      out.push({ ecosystem: "npm", name, version: String(version), kind: "dev" });
    }
    return out;
  } catch {
    return [];
  }
}

function pip(root: string): Dependency[] {
  const out: Dependency[] = [];
  const req = read(path.join(root, "requirements.txt"));
  if (req) {
    for (const line of req.split("\n")) {
      const l = line.trim();
      if (!l || l.startsWith("#") || l.startsWith("-")) continue;
      const m = l.match(/^([A-Za-z0-9_.\-]+)\s*([=<>!~]=?.*)?$/);
      if (m) out.push({ ecosystem: "pip", name: m[1], version: m[2]?.trim() || null, kind: "prod" });
    }
  }
  const pyproject = read(path.join(root, "pyproject.toml"));
  if (pyproject) {
    // PEP 621 [project] dependencies = ["x>=1", ...]
    const block = pyproject.match(/dependencies\s*=\s*\[([\s\S]*?)\]/);
    if (block) {
      for (const m of block[1].matchAll(/["']([^"']+)["']/g)) {
        const dm = m[1].match(/^([A-Za-z0-9_.\-]+)\s*(.*)$/);
        if (dm) out.push({ ecosystem: "pip", name: dm[1], version: dm[2]?.trim() || null, kind: "prod" });
      }
    }
    // poetry [tool.poetry.dependencies]
    for (const m of pyproject.matchAll(/^\s*([A-Za-z0-9_.\-]+)\s*=\s*["']([^"']+)["']/gm)) {
      if (m[1].toLowerCase() === "python") continue;
      out.push({ ecosystem: "pip", name: m[1], version: m[2], kind: "prod" });
    }
  }
  return out;
}

function go(root: string): Dependency[] {
  const raw = read(path.join(root, "go.mod"));
  if (!raw) return [];
  const out: Dependency[] = [];
  // require ( ... ) block and single-line requires.
  const blockMatch = raw.match(/require\s*\(([\s\S]*?)\)/);
  const lines = blockMatch ? blockMatch[1].split("\n") : [];
  for (const m of raw.matchAll(/^\s*require\s+(\S+)\s+(\S+)/gm)) lines.push(`${m[1]} ${m[2]}`);
  for (const line of lines) {
    const m = line.trim().match(/^(\S+)\s+(\S+)/);
    if (m && !m[1].startsWith("//")) {
      out.push({ ecosystem: "go", name: m[1], version: m[2], kind: "prod" });
    }
  }
  return out;
}

function cargo(root: string): Dependency[] {
  const raw = read(path.join(root, "Cargo.toml"));
  if (!raw) return [];
  const out: Dependency[] = [];
  const sections = raw.split(/^\[/m);
  for (const sec of sections) {
    const isDev = /^dev-dependencies\]/.test(sec);
    const isProd = /^dependencies\]/.test(sec);
    if (!isDev && !isProd) continue;
    for (const m of sec.matchAll(/^\s*([A-Za-z0-9_\-]+)\s*=\s*(?:["']([^"']+)["']|\{[^}]*version\s*=\s*["']([^"']+)["'])/gm)) {
      out.push({
        ecosystem: "cargo",
        name: m[1],
        version: m[2] ?? m[3] ?? null,
        kind: isDev ? "dev" : "prod",
      });
    }
  }
  return out;
}

function ruby(root: string): Dependency[] {
  const raw = read(path.join(root, "Gemfile"));
  if (!raw) return [];
  const out: Dependency[] = [];
  for (const m of raw.matchAll(/^\s*gem\s+["']([^"']+)["'](?:\s*,\s*["']([^"']+)["'])?/gm)) {
    out.push({ ecosystem: "ruby", name: m[1], version: m[2] ?? null, kind: "prod" });
  }
  return out;
}

function php(root: string): Dependency[] {
  const raw = read(path.join(root, "composer.json"));
  if (!raw) return [];
  try {
    const pkg = JSON.parse(raw);
    const out: Dependency[] = [];
    for (const [name, version] of Object.entries(pkg.require ?? {})) {
      if (name === "php") continue;
      out.push({ ecosystem: "php", name, version: String(version), kind: "prod" });
    }
    for (const [name, version] of Object.entries(pkg["require-dev"] ?? {})) {
      out.push({ ecosystem: "php", name, version: String(version), kind: "dev" });
    }
    return out;
  } catch {
    return [];
  }
}
