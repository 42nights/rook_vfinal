import { NextRequest, NextResponse } from "next/server";
import { getFinding } from "@/lib/scans";
import { sendToOtis } from "@/lib/otis";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

// "Send to Otis" (spec §7.3): hand the finding + its working exploit (as a
// failing test) to the 42n-bot implementer.
export async function POST(_req: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const finding = getFinding(Number(id));
  if (!finding) return NextResponse.json({ error: "not found" }, { status: 404 });
  if (finding.status !== "validated") {
    return NextResponse.json({ error: "only exploit-confirmed findings can be sent to Otis" }, { status: 422 });
  }
  const result = await sendToOtis(finding);
  // The full report `body` goes to Otis-the-server (via sendToOtis' own POST),
  // not back to the browser — the client only needs the contract preview.
  const clientPayload = result.payload
    ? { repo: result.payload.repo, issue_number: result.payload.issue_number, title: result.payload.title, failingTest: result.payload.failingTest }
    : null;
  return NextResponse.json({ ok: result.ok, url: result.url, note: result.note, payload: clientPayload });
}
