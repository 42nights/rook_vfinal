import "../lib/local-mode";
import path from "node:path";
import { parseDependencies } from "../lib/code/deps";
import { lookupVulns, OSV_ENABLED } from "../lib/code/osv";

// Exercises the OSV supply-chain integration against the real api.osv.dev.
// Run with: ROOK_OSV=true npx tsx scripts/osv-check.ts [dir]
async function main() {
  const dir = path.resolve(process.argv[2] ?? "fixtures/vuln-deps");
  console.log(`OSV enabled: ${OSV_ENABLED} (set ROOK_OSV=true to allow api.osv.dev)`);
  const deps = parseDependencies(dir);
  console.log(`dependencies in ${dir}:`, deps.map((d) => `${d.name}@${d.version}`).join(", "));
  const vulns = await lookupVulns(deps);
  if (vulns.size === 0) {
    console.log("No vulnerabilities found (OSV disabled, network blocked, or deps are clean).");
  } else {
    console.log(`\nKnown vulnerabilities (OSV):`);
    for (const [key, v] of vulns) {
      console.log(`  ${key} → ${v.map((x) => x.id).join(", ")}`);
    }
  }
  process.exit(0);
}

main().catch((e) => {
  console.error("osv-check failed:", e?.message ?? e);
  process.exit(1);
});
