import Link from "next/link";
import { notFound } from "next/navigation";
import { ChevronRight, GitCommitHorizontal } from "lucide-react";
import { getFinding, getScan } from "@/lib/scans";
import { getRepo } from "@/lib/repos";
import { SeverityBadge } from "@/components/SeverityBadge";
import { ExploitReplay } from "@/components/ExploitReplay";
import { SendToOtis } from "@/components/SendToOtis";
import { safeParse } from "@/lib/utils";

export const dynamic = "force-dynamic";

export default async function FindingPage({ params }: { params: Promise<{ id: string; n: string }> }) {
  const { id, n } = await params;
  const finding = await getFinding(n);
  const scan = await getScan(id);
  if (!finding || !scan) notFound();
  const repo = await getRepo(finding.repo_id);
  const transcript = finding.exploit_transcript_json ? safeParse(finding.exploit_transcript_json) : null;
  const history = finding.history_json ? safeParse(finding.history_json) : null;

  return (
    <article className="mx-auto max-w-3xl px-5 sm:px-6 py-10">
      <div className="flex items-center gap-2 text-sm text-[var(--fg-muted)] mb-2">
        <Link href="/scans" className="hover:text-[var(--fg)]">Scans</Link>
        <ChevronRight className="h-3.5 w-3.5" />
        <Link href={`/scans/${scan._id}`} className="hover:text-[var(--fg)]">{repo ? `${repo.owner}/${repo.name}` : `scan ${scan._id}`}</Link>
      </div>

      <div className="flex items-start justify-between gap-4">
        <h1 className="font-serif text-3xl text-[var(--fg)] leading-tight">{finding.title}</h1>
        <div className="shrink-0 text-right">
          <SeverityBadge severity={finding.severity} score={finding.cvss_score} />
        </div>
      </div>
      <p className="mt-2 text-sm font-mono text-[var(--fg-subtle)]">
        {finding.category}{finding.file_path ? ` · ${finding.file_path}:${finding.start_line}-${finding.end_line}` : ""}
      </p>

      {history && (
        <div className="mt-4 flex items-center gap-2 text-xs text-[var(--fg-muted)] rounded-lg border border-border bg-[var(--bg-sunken)] px-3 py-2">
          <GitCommitHorizontal className="h-4 w-4 text-[var(--accent)]" />
          Introduced in <code className="font-mono text-[var(--fg)]">{history.commit}</code> by {history.author} on {history.date}
        </div>
      )}

      <Block title="Summary">
        <p className="text-[var(--fg)] leading-relaxed">{finding.summary}</p>
        {finding.impact && <p className="mt-3 text-[var(--fg-muted)] leading-relaxed"><strong className="text-[var(--fg)]">Impact.</strong> {finding.impact}</p>}
      </Block>

      {finding.vulnerable_code && (
        <Block title={`Vulnerable code — ${finding.file_path}`}>
          <pre className="code-block p-3 whitespace-pre-wrap">
            {finding.vulnerable_code.split("\n").slice(0, 200).map((l, i) => (
              <div key={i}><span className="text-[var(--accent)] select-none">🔴 </span>{l}</div>
            ))}
            {finding.vulnerable_code.split("\n").length > 200 && (
              <div className="text-[var(--fg-subtle)]">… (truncated)</div>
            )}
          </pre>
        </Block>
      )}

      {finding.exploit_script && finding.status === "validated" && (
        <Block title={finding.category === "secrets-in-source" ? "Static evidence" : "Working exploit"}>
          <pre className="code-block p-3 whitespace-pre-wrap text-[var(--fg)]">{finding.exploit_script}</pre>
          {finding.category !== "secrets-in-source" && (
            <div className="mt-3">
              <ExploitReplay findingId={finding._id} exploit={finding.exploit_script} />
            </div>
          )}
        </Block>
      )}

      {transcript && (transcript.command || transcript.output) && (
        <Block title="Exploit transcript">
          <div className="code-block p-3">
            {transcript.command && <div className="text-[var(--fg-subtle)]">$ {transcript.command}</div>}
            <pre className="mt-2 whitespace-pre-wrap text-[var(--fg)] max-h-72 overflow-y-auto">{(transcript.output ?? "").slice(0, 2000)}</pre>
          </div>
          <p className="mt-2 text-sm"><strong className="text-[var(--accent)]">Confirmed:</strong> <span className="text-[var(--fg-muted)]">{transcript.evidence ?? transcript.outcome}</span></p>
        </Block>
      )}

      {finding.cvss_vector && (
        <Block title="CVSS v3.1">
          <code className="font-mono text-sm text-[var(--fg)]">{finding.cvss_vector}</code>
          <span className="ml-2 text-[var(--fg-muted)]">→ <strong className="text-[var(--fg)]">{finding.cvss_score}</strong> ({finding.severity})</span>
        </Block>
      )}

      {finding.consistency_note && (
        <Block title="Codebase consistency">
          <p className="text-[var(--fg-muted)] leading-relaxed">{finding.consistency_note}</p>
        </Block>
      )}

      {finding.recommended_fix && (
        <Block title="Recommended fix">
          <pre className="code-block p-3 whitespace-pre-wrap text-[var(--fg)]">{finding.recommended_fix}</pre>
        </Block>
      )}

      {finding.status === "validated" && (
        <Block title="Ship the fix">
          <p className="text-sm text-[var(--fg-muted)] mb-3">
            Rook found it and proved it. Hand the finding — with its working exploit as a failing test — to Otis to write the fix PR.
          </p>
          <SendToOtis findingId={finding._id} />
        </Block>
      )}

      {finding.issue_url && (
        <p className="mt-6 text-sm"><a href={finding.issue_url} className="text-[var(--accent)] underline" target="_blank" rel="noreferrer">View GitHub Issue →</a></p>
      )}
    </article>
  );
}

function Block({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="mt-7">
      <h2 className="font-serif text-lg text-[var(--fg)] mb-2 pb-1 border-b border-border">{title}</h2>
      {children}
    </section>
  );
}
