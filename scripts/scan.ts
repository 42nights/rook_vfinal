import "../lib/local-mode";
import { startScan } from "../lib/scan-runner";
import { subscribe } from "../lib/progress";
import { listFindings, getScan } from "../lib/scans";

async function main() {
  const ref = process.argv[2];
  if (!ref) {
    console.error("usage: npm run scan -- <owner/repo | url | /local/path>");
    process.exit(1);
  }
  const t0 = Date.now();
  const { scan, repo, done } = await startScan(ref);
  console.log(`scanning ${repo.owner}/${repo.name} (scan ${scan.id})`);
  let last = "";
  subscribe(scan.id, (e) => {
    const line = `[${String(Math.round(e.progress * 100)).padStart(3)}%] ${e.phase}`;
    if (line !== last) {
      console.log(line);
      last = line;
    }
  });

  try {
    await done;
  } catch (err: any) {
    console.error("\nScan failed:", err?.message ?? err);
    process.exit(1);
  }

  const s = getScan(scan.id)!;
  const findings = listFindings(scan.id);
  console.log(`\n── Done in ${((Date.now() - t0) / 1000).toFixed(1)}s ──`);
  console.log(`candidates: ${s.candidate_count} · validated: ${s.verified_count} · disconfirmed(dropped): ${s.false_positive_count}`);
  console.log("\nFindings:");
  for (const f of findings) {
    const tag = f.status === "validated" ? "✓ VALIDATED" : f.status === "disconfirmed" ? "✗ dropped" : f.status === "inconclusive" ? "? human" : f.status;
    console.log(`  [${tag}] ${f.severity.toUpperCase().padEnd(8)} ${f.category.padEnd(18)} ${f.title}${f.cvss_score != null ? ` (CVSS ${f.cvss_score})` : ""}`);
    if (f.status === "validated" && f.exploit_script) console.log(`       exploit: ${f.exploit_script.slice(0, 110)}`);
  }
  process.exit(0);
}

main();
