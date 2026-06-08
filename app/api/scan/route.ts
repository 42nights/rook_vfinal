import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { checkApiAuth } from "@/lib/api-auth";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const ScanBody = z.object({
  ref: z.string().min(1),
});

export async function POST(req: NextRequest) {
  const unauthorized = checkApiAuth(req);
  if (unauthorized) return unauthorized;

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

  // Kick off the full 6-phase pipeline in-process. startScan creates the repo +
  // scan row and enqueues runScan with the repo's source URL (not the raw input,
  // which may be a partial owner/repo ref). We detach the run promise so the POST
  // returns immediately while the scan progresses; ScanProgress polls for status.
  const { startScan, TooManyError } = await import("@/lib/scan-runner");
  try {
    const { scan, done } = await startScan(repoRef.cloneUrl);
    done.catch(() => {});
    return NextResponse.json({ scanId: scan._id });
  } catch (err: unknown) {
    if (err instanceof TooManyError) {
      return NextResponse.json({ error: "Too many scans running right now. Try again in a moment." }, { status: 429 });
    }
    console.error("[scan] failed to start scan:", err instanceof Error ? err.message : err);
    return NextResponse.json({ error: "Could not start the scan. Please try again." }, { status: 500 });
  }
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
