import { NextRequest, NextResponse } from "next/server";
import { startScan } from "@/lib/scan-runner";
import { getScan } from "@/lib/scans";
import { parseRepoRef, isRefAllowedFromApi } from "@/lib/git";
import { lastProgress } from "@/lib/progress";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function POST(req: NextRequest) {
  let ref: string | undefined;
  try {
    ({ ref } = await req.json());
  } catch {
    /* ignore */
  }
  if (!ref) return NextResponse.json({ error: "Missing 'ref'." }, { status: 400 });
  const parsed = parseRepoRef(ref);
  if (!parsed) return NextResponse.json({ error: `Could not parse: ${ref}` }, { status: 400 });
  if (!isRefAllowedFromApi(parsed)) {
    return NextResponse.json(
      { error: "Local-path scanning is disabled. Use a GitHub repo (owner/repo), or set ROOK_LOCAL_ROOTS to allowlist directories." },
      { status: 403 },
    );
  }
  let started;
  try {
    started = await startScan(ref);
  } catch (e: any) {
    if (e?.name === "TooManyError") return NextResponse.json({ error: e.message }, { status: 429 });
    return NextResponse.json({ error: e?.message ?? "could not start scan" }, { status: 500 });
  }
  const { scan, repo, done } = started;
  done.catch(() => {});
  return NextResponse.json({ scanId: scan.id, repo: `${repo.owner}/${repo.name}` });
}

export async function GET(req: NextRequest) {
  const id = Number(req.nextUrl.searchParams.get("scanId"));
  const scan = getScan(id);
  if (!scan) return NextResponse.json({ error: "not found" }, { status: 404 });
  return NextResponse.json({ scan, last: lastProgress(id) });
}
