import { NextRequest, NextResponse } from "next/server";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function POST(_req: NextRequest) {
  // Scan trigger requires filesystem + subprocess — cannot run on Vercel serverless.
  // Run scans locally with `npm run scan -- <ref>` or on a GCE worker.
  return NextResponse.json(
    { error: "Scans run on the worker, not on serverless. Use `npm run scan -- <ref>` locally or trigger from the GCE VM." },
    { status: 503 },
  );
}

export async function GET(req: NextRequest) {
  const id = req.nextUrl.searchParams.get("scanId");
  if (!id) return NextResponse.json({ error: "missing scanId" }, { status: 400 });
  const { getScan } = await import("@/lib/scans");
  const { lastProgress } = await import("@/lib/progress");
  const scan = await getScan(id);
  if (!scan) return NextResponse.json({ error: "not found" }, { status: 404 });
  return NextResponse.json({ scan, last: lastProgress(id) });
}
