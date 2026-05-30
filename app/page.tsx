import Link from "next/link";
import { ShieldCheck, ArrowUpRight, Bug } from "lucide-react";
import { ScanInput } from "@/components/ScanInput";
import { listScans } from "@/lib/scans";
import { getRepo } from "@/lib/repos";
import { db } from "@/lib/db";
import { timeAgo } from "@/lib/utils";

export const dynamic = "force-dynamic";

export default function Landing() {
  const scans = listScans().filter((s) => s.status === "done").slice(0, 5);
  const week = db
    .prepare("SELECT COUNT(*) AS scans FROM scans WHERE status='done' AND created_at > ?")
    .get(Date.now() - 7 * 86400000) as { scans: number };
  // Count exploit-confirmed (non-secrets) and static-proven secrets separately
  // so the displayed stat copy is accurate for each type.
  const exploitConfirmed = db
    .prepare("SELECT COUNT(*) AS n FROM findings WHERE status='validated' AND category != 'secrets-in-source'")
    .get() as { n: number };
  const staticProven = db
    .prepare("SELECT COUNT(*) AS n FROM findings WHERE status='validated' AND category = 'secrets-in-source'")
    .get() as { n: number };
  const verified = { n: exploitConfirmed.n + staticProven.n };

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
            {scans.map((s) => {
              const repo = getRepo(s.repo_id);
              return (
                <Link
                  key={s.id}
                  href={`/scans/${s.id}`}
                  className="flex items-center gap-3 rounded-lg border border-border bg-[var(--bg-elev)] px-4 py-3 hover:border-border-strong transition-colors group"
                >
                  <Bug className="h-4 w-4 text-[var(--accent)] shrink-0" />
                  <div className="min-w-0 flex-1">
                    <div className="font-mono text-sm text-[var(--fg)] truncate">{repo ? `${repo.owner}/${repo.name}` : `scan ${s.id}`}</div>
                    <div className="text-xs text-[var(--fg-subtle)]">
                      {s.verified_count} verified · {s.false_positive_count} false-positives dropped · {timeAgo(s.updated_at)}
                    </div>
                  </div>
                  <ArrowUpRight className="h-4 w-4 text-[var(--fg-subtle)] group-hover:text-[var(--accent)] transition-colors" />
                </Link>
              );
            })}
          </div>
        </section>
      )}

      <section className="mt-12 grid grid-cols-2 gap-3">
        <div className="rounded-xl border border-border bg-[var(--bg-sunken)] px-5 py-4">
          <div className="text-3xl font-serif text-[var(--fg)]">{week.scans}</div>
          <div className="text-xs text-[var(--fg-muted)] mt-1">scans this week</div>
        </div>
        <div className="rounded-xl border border-border bg-[var(--bg-sunken)] px-5 py-4">
          <div className="text-3xl font-serif text-[var(--accent)] flex items-baseline gap-2">
            {verified.n} <ShieldCheck className="h-5 w-5" />
          </div>
          <div className="text-xs text-[var(--fg-muted)] mt-1">
            verified findings ({exploitConfirmed.n} exploit-confirmed{staticProven.n > 0 ? ` · ${staticProven.n} static-proven` : ""})
          </div>
        </div>
      </section>

      <p className="mt-8 text-center text-xs text-[var(--fg-subtle)]">
        Every finding ships with a proof-of-concept exploit. Nothing leaves this machine.
      </p>
    </div>
  );
}
