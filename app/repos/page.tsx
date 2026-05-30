import Link from "next/link";
import { FolderGit2, Crosshair } from "lucide-react";
import { listRepos } from "@/lib/repos";
import { listScansForRepo } from "@/lib/scans";
import { ScanInput } from "@/components/ScanInput";
import { timeAgo } from "@/lib/utils";

export const dynamic = "force-dynamic";

export default function ReposPage() {
  const repos = listRepos();
  return (
    <div className="mx-auto max-w-3xl px-5 sm:px-6 py-12">
      <h1 className="font-serif text-3xl text-[var(--fg)]">Repositories</h1>
      <p className="mt-1 text-[var(--fg-muted)]">Connect a repo, or install the GitHub App to scan on every push.</p>

      <div className="mt-6"><ScanInput /></div>

      <div className="mt-8 space-y-2">
        {repos.length === 0 && <p className="text-sm text-[var(--fg-subtle)]">No repos yet.</p>}
        {repos.map((r) => {
          const scans = listScansForRepo(r.id);
          const last = scans[0];
          return (
            <div key={r.id} className="flex items-center gap-3 rounded-lg border border-border bg-[var(--bg-elev)] px-4 py-3">
              <FolderGit2 className="h-4 w-4 text-[var(--fg-muted)] shrink-0" />
              <div className="min-w-0 flex-1">
                <div className="font-mono text-sm text-[var(--fg)] truncate">{r.owner}/{r.name}</div>
                <div className="text-xs text-[var(--fg-subtle)]">{scans.length} scan{scans.length === 1 ? "" : "s"}{last ? ` · last ${timeAgo(last.updated_at)}` : ""}</div>
              </div>
              {last && (
                <Link href={`/scans/${last.id}`} className="text-xs text-[var(--accent)] hover:underline">latest scan →</Link>
              )}
            </div>
          );
        })}
      </div>

      <div className="mt-10 rounded-xl border border-border bg-[var(--bg-sunken)] px-5 py-4">
        <h2 className="text-sm font-semibold text-[var(--fg)] flex items-center gap-2 mb-1"><Crosshair className="h-4 w-4 text-[var(--accent)]" /> Install on GitHub</h2>
        <p className="text-sm text-[var(--fg-muted)] leading-relaxed">
          Register a GitHub App (Contents: read, Issues: write) with its webhook pointed at{" "}
          <code className="font-mono text-[var(--fg)]">/api/github/webhook</code> and set{" "}
          <code className="font-mono text-[var(--fg)]">GITHUB_APP_ID</code>,{" "}
          <code className="font-mono text-[var(--fg)]">GITHUB_APP_PRIVATE_KEY_PATH</code>,{" "}
          <code className="font-mono text-[var(--fg)]">GITHUB_WEBHOOK_SECRET</code>. Installing on a repo then scans it on every push and opens triaged issues automatically.
        </p>
      </div>
    </div>
  );
}
