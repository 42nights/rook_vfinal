import Link from "next/link";
import { ShieldCheck, ArrowUpRight, Bug } from "lucide-react";
import { ScanInput } from "@/components/ScanInput";
import { listScans } from "@/lib/scans";
import { getRepo } from "@/lib/repos";
import { convex, api } from "@/lib/db/convex-client";
import { timeAgo } from "@/lib/utils";

export const dynamic = "force-dynamic";

export default async function Landing() {
  const allScans = await listScans();
  const scans = allScans.filter((s) => s.status === "done").slice(0, 5);

  const weekSince = Date.now() - 7 * 86400000;
  const weekScans = allScans.filter(
    (s) => s.status === "done" && s.created_at > weekSince,
  ).length;

  // Findings stats: query all findings across all done scans
  const allFindings = await Promise.all(
    allScans
      .filter((s) => s.status === "done")
      .map((s) =>
        convex.query(api.findings.listByScan, { scan_id: s._id }),
      ),
  ).then((arrays) => arrays.flat());

  const exploitConfirmed = allFindings.filter(
    (f) => f.status === "validated" && f.category !== "secrets-in-source",
  ).length;
  const staticProven = allFindings.filter(
    (f) => f.status === "validated" && f.category === "secrets-in-source",
  ).length;
  const verifiedTotal = exploitConfirmed + staticProven;

  const repoCache = new Map<string, Awaited<ReturnType<typeof getRepo>>>();
  async function getCachedRepo(id: string) {
    if (!repoCache.has(id)) repoCache.set(id, await getRepo(id));
    return repoCache.get(id)!;
  }

  return (
    <div className="mx-auto max-w-3xl px-5 sm:px-6 pt-16 sm:pt-24 pb-24">
      <div className="text-center animate-fade-up">
        <h1 className="font-serif text-5xl sm:text-7xl tracking-tight text-[var(--fg)]">Rook</h1>
        <p className="mt-3 font-serif text-xl sm:text-2xl text-[var(--fg-muted)]">
          Finds bugs before attackers do
        </p>
        <p className="mt-5 text-[var(--fg-muted)] max-w-xl mx-auto leading-relaxed">
          An AI red-teamer that reasons about attack paths through your code, then proves every
          finding with a working exploit. AI-driven white-box pentesting, fully local, fully
          homemade.
        </p>
      </div>

      <div className="mt-9 animate-fade-up" style={{ animationDelay: "60ms" }}>
        <ScanInput autoFocus />
      </div>

      {scans.length > 0 && (
        <section className="mt-14">
          <h2 className="text-[11px] uppercase tracking-[0.18em] text-[var(--fg-muted)] mb-3">Recent scans</h2>
          <div className="space-y-2">
            {await Promise.all(scans.map(async (s) => {
              const repo = await getCachedRepo(s.repo_id);
              return (
                <Link
                  key={s._id}
                  href={`/scans/${s._id}`}
                  className="flex items-center gap-3 rounded-lg border border-border bg-[var(--bg-elev)] px-4 py-3 hover:border-border-strong transition-colors group"
                >
                  <Bug className="h-4 w-4 text-[var(--accent)] shrink-0" />
                  <div className="min-w-0 flex-1">
                    <div className="font-mono text-sm text-[var(--fg)] truncate">{repo ? `${repo.owner}/${repo.name}` : `scan ${s._id}`}</div>
                    <div className="text-xs text-[var(--fg-subtle)]">
                      {s.verified_count} verified · {s.false_positive_count} false-positives dropped · {timeAgo(s.updated_at)}
                    </div>
                  </div>
                  <ArrowUpRight className="h-4 w-4 text-[var(--fg-subtle)] group-hover:text-[var(--accent)] transition-colors" />
                </Link>
              );
            }))}
          </div>
        </section>
      )}

      <section className="mt-12 grid grid-cols-2 gap-3">
        <div className="rounded-xl border border-border bg-[var(--bg-sunken)] px-5 py-4">
          <div className="text-3xl font-serif text-[var(--fg)]">{weekScans}</div>
          <div className="text-xs text-[var(--fg-muted)] mt-1">scans this week</div>
        </div>
        <div className="rounded-xl border border-border bg-[var(--bg-sunken)] px-5 py-4">
          <div className="text-3xl font-serif text-[var(--accent)] flex items-baseline gap-2">
            {verifiedTotal} <ShieldCheck className="h-5 w-5" />
          </div>
          <div className="text-xs text-[var(--fg-muted)] mt-1">
            verified findings ({exploitConfirmed} exploit-confirmed{staticProven > 0 ? ` · ${staticProven} static-proven` : ""})
          </div>
        </div>
      </section>

      <p className="mt-8 text-center text-xs text-[var(--fg-subtle)]">
        Every finding ships with a proof-of-concept exploit. Nothing leaves this machine.
      </p>
    </div>
  );
}
