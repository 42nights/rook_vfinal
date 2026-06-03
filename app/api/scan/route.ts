import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const ScanBody = z.object({
  ref: z.string().min(1),
});

export async function POST(req: NextRequest) {
  let body: unknown;
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "invalid JSON" }, { status: 400 });
  }

  const parsed = ScanBody.safeParse(body);
  if (!parsed.success) {
    return NextResponse.json({ error: "ref is required" }, { status: 400 });
  }
  const { ref } = parsed.data;

  const { parseRepoRef } = await import("@/lib/git");
  const repoRef = parseRepoRef(ref);
  if (!repoRef) {
    return NextResponse.json({ error: `Could not parse repo reference: ${ref}` }, { status: 400 });
  }
  if (repoRef.local) {
    return NextResponse.json({ error: "Local path scanning is not supported from the web UI." }, { status: 400 });
  }

  const { createRepo } = await import("@/lib/repos");
  const { createScan } = await import("@/lib/scans");

  const repo = await createRepo({
    owner: repoRef.owner,
    name: repoRef.name,
    sourceUrl: repoRef.cloneUrl,
  });

  const scan = await createScan(repo._id);

  return NextResponse.json({ scanId: scan._id });
}

export async function GET(req: NextRequest) {
  const id = req.nextUrl.searchParams.get("scanId");
  if (!id) return NextResponse.json({ error: "missing scanId" }, { status: 400 });
  const { getScan, getScanLog } = await import("@/lib/scans");
  const { lastProgress } = await import("@/lib/progress");
  const scan = await getScan(id);
  if (!scan) return NextResponse.json({ error: "not found" }, { status: 404 });
  const logs = await getScanLog(id);
  return NextResponse.json({ scan, last: lastProgress(id), logs });
}
