import "../lib/local-mode";
import http from "node:http";
import { getFinding, listFindings } from "../lib/scans";
import { sendToOtis } from "../lib/otis";

// Exercises the "Send to Otis" wire against a stub that implements 42n-bot's
// REAL intake contract (POST /api/issues/fix {owner, repo, issue_number}).
// Run with: OTIS_URL=http://127.0.0.1:4788 npx tsx scripts/otis-demo.ts [findingId]
async function main() {
  const port = Number(new URL(process.env.OTIS_URL ?? "http://127.0.0.1:4788").port || 4788);

  let received: Record<string, unknown> | null = null;
  const stub = http.createServer((req, res) => {
    if (req.method === "POST" && req.url === "/api/issues/fix") {
      let body = "";
      req.on("data", (c) => (body += c));
      req.on("end", () => {
        received = JSON.parse(body || "{}") as Record<string, unknown>;
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ ok: true, url: `https://github.com/${received.owner}/${received.repo}/issues/${received.issue_number}` }));
      });
    } else {
      res.writeHead(404);
      res.end("not found");
    }
  });
  await new Promise<void>((r) => stub.listen(port, r));
  console.log(`Otis stub (mimicking 42n-bot /api/issues/fix) listening on :${port}`);

  // Pick a validated finding — use provided ID arg or find the first validated one.
  const idArg = process.argv[2];
  let finding = idArg ? await getFinding(idArg) : null;
  if (!finding) {
    const all = await listFindings(""); // empty string = no scan filter; fall back below
    finding = all.find((f) => f.status === "validated") ?? null;
  }
  if (!finding) {
    console.error("no validated finding found (run a scan first)");
    process.exit(1);
  }
  console.log(`\nRook → Otis for finding #${finding._id}: ${finding.title}`);

  const result = await sendToOtis(finding);
  console.log("\n── Rook's sendToOtis result ──");
  console.log("ok:", result.ok);
  console.log("note:", result.note);

  console.log("\n── What Otis received at /api/issues/fix ──");
  const rec = received as unknown as Record<string, unknown>;
  const rook = rec?.rook as Record<string, unknown> | undefined;
  console.log("contract fields:", JSON.stringify({ owner: rec?.owner, repo: rec?.repo, issue_number: rec?.issue_number }));
  console.log("failing test (exploit):", (rook?.failingTest as Record<string, unknown> | undefined)?.command);
  console.log("issue title:", rook?.title);

  stub.close();
  process.exit(0);
}

main().catch((e: unknown) => {
  const msg = e instanceof Error ? e.message : String(e);
  console.error("otis-demo failed:", msg);
  process.exit(1);
});
