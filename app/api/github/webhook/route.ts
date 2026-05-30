import { NextRequest, NextResponse } from "next/server";
import { verifySignature } from "@/lib/github/webhook";
import { githubAppConfig } from "@/lib/github/app";
import { startScan } from "@/lib/scan-runner";
import { parseRepoRef, isRefAllowedFromApi } from "@/lib/git";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

declare global {
  // eslint-disable-next-line no-var
  var __rook_seen_deliveries: Map<string, number> | undefined;
}
function alreadySeen(id: string | null): boolean {
  if (!id) return false;
  const m = (globalThis.__rook_seen_deliveries ??= new Map());
  if (m.has(id)) return true;
  m.set(id, Date.now());
  if (m.size > 1000) for (const k of [...m.keys()].slice(0, 500)) m.delete(k);
  return false;
}

// GitHub App webhook: install or push triggers a security scan (CodeRabbit-style
// "install the app, wake up to findings").
export async function POST(req: NextRequest) {
  const cfg = githubAppConfig();
  if (!cfg) return NextResponse.json({ error: "GitHub App not configured" }, { status: 501 });

  const raw = await req.text();
  if (!verifySignature(raw, req.headers.get("x-hub-signature-256"), cfg.webhookSecret)) {
    return NextResponse.json({ error: "bad signature" }, { status: 401 });
  }
  if (alreadySeen(req.headers.get("x-github-delivery"))) {
    return NextResponse.json({ ok: true, deduped: true });
  }

  const event = req.headers.get("x-github-event");
  const payload = JSON.parse(raw);
  const targets: string[] = [];
  if (event === "installation" || event === "installation_repositories") {
    const repos = payload.repositories ?? payload.repositories_added ?? [];
    for (const r of repos) targets.push(String(r.full_name));
  } else if (event === "push") {
    if (payload.repository?.full_name) targets.push(String(payload.repository.full_name));
  } else {
    return NextResponse.json({ ok: true, ignored: event });
  }

  const scanning: string[] = [];
  const deferred: string[] = [];
  for (const fn of targets) {
    const parsed = parseRepoRef(fn);
    if (!parsed || !isRefAllowedFromApi(parsed)) {
      console.warn(`[webhook] blocked disallowed ref: ${fn}`);
      deferred.push(fn);
      continue;
    }
    try {
      const started = await startScan(fn);
      started.done.catch(() => {});
      scanning.push(fn);
    } catch {
      // At capacity (or unparseable) — ack the webhook anyway so GitHub doesn't
      // retry-storm us; the user can re-trigger.
      deferred.push(fn);
    }
  }
  return NextResponse.json({ ok: true, scanning, deferred });
}
