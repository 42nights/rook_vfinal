import { NextRequest, NextResponse } from "next/server";
import { getFinding } from "@/lib/scans";
import { getRepo } from "@/lib/repos";
import type { ExploitSpec } from "@/lib/sandbox/runner";
import { safeParse } from "@/lib/utils";
import { checkApiAuth } from "@/lib/api-auth";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";
export const maxDuration = 60;

declare global {
  // eslint-disable-next-line no-var
  var __rook_replay_inflight: Set<string> | undefined;
  // eslint-disable-next-line no-var
  var __rook_replay_ports: Set<number> | undefined;
}
function replayInflight(): Set<string> {
  return (globalThis.__rook_replay_inflight ??= new Set());
}
function acquireReplayPort(): number | null {
  const used = (globalThis.__rook_replay_ports ??= new Set());
  for (let p = 5600; p <= 5699; p++) {
    if (!used.has(p)) {
      used.add(p);
      return p;
    }
  }
  return null;
}
function releaseReplayPort(port: number): void {
  globalThis.__rook_replay_ports?.delete(port);
}

export async function POST(req: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const unauthorized = checkApiAuth(req);
  if (unauthorized) return unauthorized;

  const { id } = await params;
  const findingId = id;
  if (replayInflight().has(findingId)) {
    return NextResponse.json({ error: "a replay for this finding is already running" }, { status: 409 });
  }
  replayInflight().add(findingId);
  try {
    const finding = await getFinding(findingId);
    if (!finding || !finding.exploit_script) {
      return NextResponse.json({ error: "no replayable exploit" }, { status: 404 });
    }
    const repo = await getRepo(finding.repo_id);
    if (!repo) return NextResponse.json({ error: "repo not found" }, { status: 404 });

    const transcript = finding.exploit_transcript_json ? safeParse(finding.exploit_transcript_json) : null;
    if (finding.category === "secrets-in-source" || !transcript?.spec) {
      return NextResponse.json({ command: finding.exploit_script, output: transcript?.output ?? finding.vulnerable_code, live: false });
    }

    // VM-only deps (filesystem clone + subprocess target) are loaded lazily so
    // the route still imports on read-only serverless; only the live-target
    // replay path below needs them.
    const { parseRepoRef, repoDir } = await import("@/lib/git");
    const dir = repoDir(repo) ?? (parseRepoRef(repo.source_url)?.local ? repo.source_url : null);
    if (!dir) return NextResponse.json({ error: "workspace gone — re-scan to replay" }, { status: 409 });

    const port = acquireReplayPort();
    if (port === null) {
      return NextResponse.json({ error: "too many concurrent replays — try again shortly" }, { status: 429 });
    }
    try {
      const { detectFramework, startTarget } = await import("@/lib/scanner/bootstrap");
      const { runHttpExploit } = await import("@/lib/sandbox/runner");
      const fw = detectFramework(dir);
      const target = await startTarget(dir, fw, { port });
      if (!target) return NextResponse.json({ error: "could not start the target app to replay against" }, { status: 409 });
      try {
        const run = await runHttpExploit(target.url, transcript.spec as ExploitSpec, { timeoutMs: 9000 });
        return NextResponse.json({
          command: run.command,
          output: `${run.stdout}\n${run.stderr}`.trim(),
          status: run.status ?? null,
          blocked: run.blocked ?? null,
          live: true,
        });
      } finally {
        target.stop();
        target.cleanup();
      }
    } finally {
      releaseReplayPort(port);
    }
  } finally {
    replayInflight().delete(findingId);
  }
}
