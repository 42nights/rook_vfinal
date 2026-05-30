import { NextRequest, NextResponse } from "next/server";
import { getFinding } from "@/lib/scans";
import { getRepo } from "@/lib/repos";
import { parseRepoRef, repoDir } from "@/lib/git";
import { detectFramework, startTarget } from "@/lib/scanner/bootstrap";
import { runHttpExploit, type ExploitSpec } from "@/lib/sandbox/runner";
import { safeParse } from "@/lib/utils";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";
export const maxDuration = 60;

// One live replay per finding at a time — replaying starts a target subprocess,
// so concurrent replays of the same finding would spawn multiple targets.
declare global {
  // eslint-disable-next-line no-var
  var __rook_replay_inflight: Set<number> | undefined;
  // eslint-disable-next-line no-var
  var __rook_replay_ports: Set<number> | undefined;
}
function replayInflight(): Set<number> {
  return (globalThis.__rook_replay_inflight ??= new Set());
}
// Each live replay needs its own port so two different findings replaying at
// once don't both bind 4599. Scan targets occupy 4599-5598 (4599 + scanId%1000),
// so replays draw from 5600-5699.
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

// "Replay the exploit" (spec §6.3): spin the target back up and re-send the
// captured HTTP exploit live, returning the response. The demo moment.
export async function POST(_req: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const findingId = Number(id);
  // ATOMIC check-and-acquire — no await between has() and add(), so two
  // concurrent requests can't both pass and both spawn a target.
  if (replayInflight().has(findingId)) {
    return NextResponse.json({ error: "a replay for this finding is already running" }, { status: 409 });
  }
  replayInflight().add(findingId);
  try {
    const finding = getFinding(findingId);
    if (!finding || !finding.exploit_script) {
      return NextResponse.json({ error: "no replayable exploit" }, { status: 404 });
    }
    const repo = getRepo(finding.repo_id);
    if (!repo) return NextResponse.json({ error: "repo not found" }, { status: 404 });

    const transcript = finding.exploit_transcript_json ? safeParse(finding.exploit_transcript_json) : null;
    if (finding.category === "secrets-in-source" || !transcript?.spec) {
      return NextResponse.json({ command: finding.exploit_script, output: transcript?.output ?? finding.vulnerable_code, live: false });
    }

    const dir = repoDir(repo) ?? (parseRepoRef(repo.source_url)?.local ? repo.source_url : null);
    if (!dir) return NextResponse.json({ error: "workspace gone — re-scan to replay" }, { status: 409 });

    const port = acquireReplayPort();
    if (port === null) {
      return NextResponse.json({ error: "too many concurrent replays — try again shortly" }, { status: 429 });
    }
    try {
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

