import type { Dependency } from "./deps";

// OSV (osv.dev) dependency-vulnerability lookup. Deterministic tooling, not the
// LLM. Opt-in: only runs when ROOK_OSV=true (the local-mode guard whitelists
// api.osv.dev in that case). Off by default to honor zero-cloud-touch.

export const OSV_ENABLED = process.env.ROOK_OSV === "true";

const ECOSYSTEM: Record<string, string> = {
  npm: "npm",
  pip: "PyPI",
  go: "Go",
  cargo: "crates.io",
  ruby: "RubyGems",
  php: "Packagist",
};

export type OsvVuln = { id: string; summary?: string };
export type OsvResult = { name: string; ecosystem: string; vulns: OsvVuln[] };

function cleanVersion(v: string | null): string | null {
  if (!v) return null;
  const m = v.replace(/^[\^~>=<\s]+/, "").match(/\d+\.\d+(\.\d+)?/);
  return m ? m[0] : null;
}

// Returns a map keyed by `${ecosystem}:${name}` → vuln list (only entries with vulns).
export async function lookupVulns(deps: Dependency[]): Promise<Map<string, OsvVuln[]>> {
  const out = new Map<string, OsvVuln[]>();
  if (!OSV_ENABLED || deps.length === 0) return out;

  const queries = deps.map((d) => {
    const eco = ECOSYSTEM[d.ecosystem];
    const version = cleanVersion(d.version);
    const q: any = { package: { name: d.name, ecosystem: eco } };
    if (version) q.version = version;
    return { q, dep: d, eco };
  });

  try {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), 20000);
    let res: Response;
    try {
      res = await fetch("https://api.osv.dev/v1/querybatch", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ queries: queries.map((x) => x.q) }),
        signal: ctrl.signal,
      });
    } finally {
      clearTimeout(t);
    }
    if (!res.ok) return out;
    const json = (await res.json()) as { results?: Array<{ vulns?: Array<{ id: string }> }> };
    const results = json.results ?? [];
    results.forEach((r, i) => {
      const vulns = (r.vulns ?? []).map((v) => ({ id: v.id }));
      if (vulns.length) {
        const dep = queries[i].dep;
        out.set(`${dep.ecosystem}:${dep.name}`, vulns);
      }
    });
  } catch {
    // Network blocked or OSV down — return what we have (likely empty).
  }
  return out;
}
