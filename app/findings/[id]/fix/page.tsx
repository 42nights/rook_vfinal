import Link from "next/link";
import { notFound } from "next/navigation";
import { Wrench, ArrowUpRight, ShieldCheck } from "lucide-react";
import { getFinding, getScan } from "@/lib/scans";
import { getRepo } from "@/lib/repos";
import { buildSyntheticIssue } from "@/lib/github/synthetic-issue";
import { SendToOtis } from "@/components/SendToOtis";
import { SeverityBadge } from "@/components/SeverityBadge";

export const dynamic = "force-dynamic";

export default async function FixPage({
  params,
  searchParams,
}: {
  params: Promise<{ id: string }>;
  searchParams: Promise<{ return_to?: string }>;
}) {
  const { id } = await params;
  const { return_to } = await searchParams;
  const finding = await getFinding(id);
  if (!finding) notFound();
  const scan = await getScan(finding.scan_id);
  const repo = await getRepo(finding.repo_id);
  const prNumber = scan?.pr_number ?? null;
  const prUrl = repo && prNumber ? `https://github.com/${repo.owner}/${repo.name}/pull/${prNumber}` : null;
  const eligible = finding.status === "validated";
  const issueBody = buildSyntheticIssue(finding, prNumber);

  return (
    <article className="mx-auto max-w-3xl px-5 sm:px-6 py-10">
      <div className="flex items-center gap-2 text-sm text-[var(--fg-muted)] mb-2">
        <Link href={`/scans/${finding.scan_id}`} className="hover:text-[var(--fg)]">
          {repo ? `${repo.owner}/${repo.name}` : `scan ${finding.scan_id}`}
        </Link>
        {prUrl && (
          <>
            <span>·</span>
            <a href={prUrl} target="_blank" rel="noreferrer" className="hover:text-[var(--fg)] inline-flex items-center gap-1">
              PR #{prNumber} <ArrowUpRight className="h-3 w-3" />
            </a>
          </>
        )}
      </div>

      <div className="flex items-start justify-between gap-4">
        <h1 className="font-serif text-3xl text-[var(--fg)] leading-tight inline-flex items-center gap-2">
          <Wrench className="h-6 w-6 text-[var(--accent)] shrink-0" /> Have Otis fix this
        </h1>
        <div className="shrink-0">
          <SeverityBadge severity={finding.severity} score={finding.cvss_score} />
        </div>
      </div>

      <p className="mt-3 text-[var(--fg)]">{finding.title}</p>
      <p className="mt-1 text-sm font-mono text-[var(--fg-subtle)]">
        {finding.category}
        {finding.file_path ? ` · ${finding.file_path}:${finding.start_line}-${finding.end_line}` : ""}
      </p>

      <div className="mt-6 rounded-xl border border-border bg-[var(--bg-sunken)] p-4 text-sm text-[var(--fg-muted)] leading-relaxed">
        <p className="text-[var(--fg)] font-medium mb-2 inline-flex items-center gap-2">
          <ShieldCheck className="h-4 w-4 text-[var(--accent)]" /> What happens when you hand this off
        </p>
        Otis (the 42n-bot implementer) receives the finding as a GitHub issue with the working exploit as a failing
        test, plans a fix, implements it, and opens a fix PR — then verifies the exploit no longer succeeds before
        marking it done.{" "}
        {return_to === "github" && prUrl ? (
          <>
            When it&apos;s finished, it comments back on{" "}
            <a href={prUrl} target="_blank" rel="noreferrer" className="text-[var(--accent)] underline">
              PR #{prNumber}
            </a>{" "}
            with the fix-PR link.
          </>
        ) : null}
      </div>

      <div className="mt-6">
        {eligible ? (
          <SendToOtis findingId={finding._id} />
        ) : (
          <p className="rounded-lg border border-border bg-[var(--bg-elev)] px-4 py-3 text-sm text-[var(--fg-muted)]">
            Only exploit-confirmed (validated) findings can be handed to Otis. This finding is{" "}
            <span className="font-mono text-[var(--fg)]">{finding.status}</span>.
          </p>
        )}
      </div>

      <details className="mt-8">
        <summary className="text-xs uppercase tracking-[0.16em] text-[var(--fg-subtle)] cursor-pointer">
          Synthetic issue Otis receives
        </summary>
        <pre className="code-block mt-2 p-3 whitespace-pre-wrap text-xs text-[var(--fg)] max-h-96 overflow-y-auto">
          {issueBody}
        </pre>
      </details>
    </article>
  );
}
