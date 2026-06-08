import { NextRequest, NextResponse } from "next/server";
import { getFinding } from "@/lib/scans";
import { sendToOtis } from "@/lib/otis";
import { checkApiAuth } from "@/lib/api-auth";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function POST(req: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const unauthorized = checkApiAuth(req);
  if (unauthorized) return unauthorized;

  const { id } = await params;
  const finding = await getFinding(id);
  if (!finding) return NextResponse.json({ error: "not found" }, { status: 404 });
  if (finding.status !== "validated") {
    return NextResponse.json({ error: "only exploit-confirmed findings can be sent to Otis" }, { status: 422 });
  }
  const result = await sendToOtis(finding);
  const clientPayload = result.payload
    ? { repo: result.payload.repo, issue_number: result.payload.issue_number, title: result.payload.title, failingTest: result.payload.failingTest }
    : null;
  return NextResponse.json({ ok: result.ok, url: result.url, note: result.note, payload: clientPayload });
}
