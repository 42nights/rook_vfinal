import Link from "next/link";
import { Bug, Loader2, ShieldCheck } from "lucide-react";
import { listScans } from "@/lib/scans";
import { getRepo } from "@/lib/repos";
import { ScanInput } from "@/components/ScanInput";
import { timeAgo } from "@/lib/utils";

export const dynamic = "force-dynamic";

export default async function ScansPage() {
  const scans = await listScans();
  const repoCache = new Map<string, Awaited<ReturnType<typeof getRepo>>>();
  async function getCachedRepo(id: string) {
    if (!repoCache.has(id)) repoCache.set(id, await getRepo(id));
    return repoCache.get(id)!;
  }

  return (
    <div className="mx-auto max-w-3xl px-5 sm:px-6 py-12">
      <h1 className="font-serif text-3xl text-[var(--fg)]">Scans</h1>
      <p className="mt-1 text-[var(--fg-muted)]">Every scan Rook has run, with its verified findings.</p>

      <div className="mt-6"><ScanInput /></div>

      <div className="mt-8 space-y-2">
        {scans.length === 0 && <p className="text-sm text-[var(--fg-subtle)]">No scans yet. Point Rook at a repo above.</p>}
        {await Promise.all(scans.map(async (s) => {
          const repo = await getCachedRepo(s.repo_id);
          const active = s.status !== "done" && s.status !== "error";
          return (
            <Link
              key={s._id}
              href={`/scans/${s._id}`}
              className="flex items-center gap-3 rounded-lg border border-border bg-[var(--bg-elev)] px-4 py-3 hover:border-border-strong transition-colors"
            >
              <Bug className="h-4 w-4 text-[var(--accent)] shrink-0" />
              <div className="min-w-0 flex-1">
                <div className="font-mono text-sm text-[var(--fg)] truncate">{repo ? `${repo.owner}/${repo.name}` : `scan ${s._id}`}</div>
                <div className="text-xs text-[var(--fg-subtle)]">
                  {active ? `${s.phase ?? s.status} · ${Math.round(s.progress * 100)}%` : s.status === "error" ? s.error_message?.slice(0, 70) : `${s.verified_count} verified · ${s.false_positive_count} dropped · ${timeAgo(s.updated_at)}`}
                </div>
              </div>
              {active ? (
                <Loader2 className="h-4 w-4 animate-spin text-[var(--fg-subtle)]" />
              ) : s.status === "done" ? (
                <span className="inline-flex items-center gap-1 text-xs text-[var(--accent)]"><ShieldCheck className="h-3.5 w-3.5" /> {s.verified_count}</span>
              ) : (
                <span className="text-xs text-[var(--accent)]">error</span>
              )}
            </Link>
          );
        }))}
      </div>
    </div>
  );
}
