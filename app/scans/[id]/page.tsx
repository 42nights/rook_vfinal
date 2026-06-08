import Link from "next/link";
import { notFound } from "next/navigation";
import { ChevronRight, ShieldCheck, ShieldX, HelpCircle } from "lucide-react";
import { getScan, listFindings, type FindingRow as Finding } from "@/lib/scans";
import { getRepo } from "@/lib/repos";
import { ScanProgress } from "@/components/ScanProgress";
import { SeverityBadge, StatusTag } from "@/components/SeverityBadge";

export const dynamic = "force-dynamic";

export default async function ScanDetail({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const scan = await getScan(id);
  if (!scan) notFound();
  const repo = await getRepo(scan.repo_id);
  const findings = await listFindings(scan._id);
  const validated = findings.filter((f) => f.status === "validated");
  const advisories = findings.filter((f) => f.status === "advisory");
  const inconclusive = findings.filter((f) => f.status === "inconclusive");
  const dropped = findings.filter((f) => f.status === "disconfirmed");

  return (
    <div className="mx-auto max-w-3xl px-5 sm:px-6 py-10">
      <div className="flex items-center gap-2 text-sm text-[var(--fg-muted)] mb-1">
        <Link href="/scans" className="hover:text-[var(--fg)]">Scans</Link>
        <ChevronRight className="h-3.5 w-3.5" />
        <span className="font-mono text-[var(--fg)]">{repo ? `${repo.owner}/${repo.name}` : `scan ${scan._id}`}</span>
      </div>
      <h1 className="font-serif text-3xl text-[var(--fg)]">Scan #{scan._id.slice(-6)}</h1>
      {scan.framework && <p className="text-sm text-[var(--fg-subtle)] mt-1">framework: {scan.framework}{scan.target_url ? ` · target ${scan.target_url}` : ""}</p>}

      <div className="mt-6">
        <ScanProgress
          scanId={scan._id}
          initialStatus={scan.status}
          retryRef={repo && repo.owner !== "local" ? `${repo.owner}/${repo.name}` : undefined}
        />
      </div>

      {scan.status === "done" && (
        <div className="mt-6 grid grid-cols-3 gap-3">
          <Stat label="verified" value={scan.verified_count} accent />
          <Stat label="candidates" value={scan.candidate_count} />
          <Stat label="false-positives dropped" value={scan.false_positive_count} />
        </div>
      )}

      {validated.length > 0 && (
        <Section title="Verified findings" icon={<ShieldCheck className="h-4 w-4 text-[var(--accent)]" />}>
          {validated.map((f) => (
            <FindingRow key={f._id} scanId={scan._id} f={f} />
          ))}
        </Section>
      )}

      {advisories.length > 0 && (
        <Section title="Supply-chain advisories (OSV — not exploit-verified)" icon={<HelpCircle className="h-4 w-4 text-low" />}>
          {advisories.map((f) => (
            <FindingRow key={f._id} scanId={scan._id} f={f} />
          ))}
        </Section>
      )}

      {inconclusive.length > 0 && (
        <Section title="Needs human review" icon={<HelpCircle className="h-4 w-4 text-med" />}>
          {inconclusive.map((f) => (
            <FindingRow key={f._id} scanId={scan._id} f={f} />
          ))}
        </Section>
      )}

      {dropped.length > 0 && (
        <details className="mt-6">
          <summary className="text-xs uppercase tracking-[0.16em] text-[var(--fg-subtle)] cursor-pointer flex items-center gap-2">
            <ShieldX className="h-3.5 w-3.5" /> {dropped.length} disconfirmed (dropped — exploit didn&apos;t fire)
          </summary>
          <div className="mt-2 space-y-1">
            {dropped.map((f) => (
              <div key={f._id} className="text-xs font-mono text-[var(--fg-subtle)] px-3 py-1.5 rounded border border-border">
                {f.category} · {f.file_path}:{f.start_line} — {f.disconfirm_reason}
              </div>
            ))}
          </div>
        </details>
      )}

      {scan.status === "done" && validated.length === 0 && advisories.length === 0 && inconclusive.length === 0 && (
        <p className="mt-8 text-sm text-[var(--fg-muted)]">No vulnerabilities verified on this scan.</p>
      )}
    </div>
  );
}

function Stat({ label, value, accent }: { label: string; value: number; accent?: boolean }) {
  return (
    <div className="rounded-lg border border-border bg-[var(--bg-sunken)] px-4 py-3">
      <div className={`text-2xl font-serif ${accent ? "text-[var(--accent)]" : "text-[var(--fg)]"}`}>{value}</div>
      <div className="text-[11px] text-[var(--fg-muted)] mt-0.5">{label}</div>
    </div>
  );
}

function Section({ title, icon, children }: { title: string; icon: React.ReactNode; children: React.ReactNode }) {
  return (
    <section className="mt-8">
      <h2 className="text-[11px] uppercase tracking-[0.18em] text-[var(--fg-muted)] mb-3 flex items-center gap-2">{icon} {title}</h2>
      <div className="space-y-2">{children}</div>
    </section>
  );
}

function FindingRow({ scanId, f }: { scanId: string; f: Finding }) {
  return (
    <Link
      href={`/scans/${scanId}/findings/${f._id}`}
      className="flex items-center gap-3 rounded-lg border border-border bg-[var(--bg-elev)] px-4 py-3 hover:border-border-strong transition-colors group"
    >
      <SeverityBadge severity={f.severity} score={f.cvss_score} />
      <div className="min-w-0 flex-1">
        <div className="text-sm text-[var(--fg)] truncate">{f.title}</div>
        <div className="text-xs text-[var(--fg-subtle)] font-mono truncate">{f.category}{f.file_path ? ` · ${f.file_path}:${f.start_line}` : ""}</div>
      </div>
      <StatusTag status={f.status} />
      <ChevronRight className="h-4 w-4 text-[var(--fg-subtle)] group-hover:text-[var(--accent)] transition-colors" />
    </Link>
  );
}
