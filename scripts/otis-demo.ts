import "../lib/local-mode";
import http from "node:http";
import { getFinding, listFindings } from "../lib/scans";
import { sendToOtis } from "../lib/otis";

// Exercises the "Send to Otis" wire against a stub that implements 42n-bot's
// REAL intake contract (POST /api/issues/fix {owner, repo, issue_number}).
// Run with: OTIS_URL=http://127.0.0.1:4788 npx tsx scripts/otis-demo.ts [findingId]
async function main() {
  const port = Number(new URL(process.env.OTIS_URL ?? "http://127.0.0.1:4788").port || 4788);

  let received: any = null;
  const stub = http.createServer((req, res) => {
    if (req.method === "POST" && req.url === "/api/issues/fix") {
      let body = "";
      req.on("data", (c) => (body += c));
      req.on("end", () => {
        received = JSON.parse(body || "{}");
        // 42n-bot would now label the issue `bot-please` and dispatch the implementer.
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

  // Pick a validated finding.
  const id = process.argv[2] ? Number(process.argv[2]) : listFindings(1).find((f) => f.status === "validated")?.id;
  const finding = id ? getFinding(id) : null;
  if (!finding) {
    console.error("no validated finding found (run a scan first)");
    process.exit(1);
  }
  console.log(`\nRook → Otis for finding #${finding.id}: ${finding.title}`);

  const result = await sendToOtis(finding);
  console.log("\n── Rook's sendToOtis result ──");
  console.log("ok:", result.ok);
  console.log("note:", result.note);

  console.log("\n── What Otis received at /api/issues/fix ──");
  console.log("contract fields:", JSON.stringify({ owner: received?.owner, repo: received?.repo, issue_number: received?.issue_number }));
  console.log("failing test (exploit):", received?.rook?.failingTest?.command);
  console.log("issue title:", received?.rook?.title);

  stub.close();
  process.exit(0);
}

main().catch((e) => {
  console.error("otis-demo failed:", e?.message ?? e);
  process.exit(1);
});
