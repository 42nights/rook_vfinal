"use client";

import Link from "next/link";
import { useEffect } from "react";
import { useRouter, usePathname, useSearchParams } from "next/navigation";
import { Loader2, ChevronLeft } from "lucide-react";

// A freshly-created scan can 404 on a cold/direct load if the SSR query runs
// before the just-written row is readable. Rather than show the bare Next 404,
// render a branded "spinning up" state and auto-refresh a BOUNDED number of
// times so a transient miss resolves on its own — but a genuinely missing scan
// converges on a terminal "not found" instead of re-polling forever.
//
// router.refresh() remounts this client component, so the attempt count can't
// live in component state (it would reset every refresh). We carry it in a
// `?try=N` search param that survives the refresh remount.
const MAX_ATTEMPTS = 4; // ~5s total at ~1.2s intervals
const RETRY_DELAY_MS = 1200;

export default function ScanNotFound() {
  const router = useRouter();
  const pathname = usePathname();
  const searchParams = useSearchParams();

  const attempt = Number.parseInt(searchParams.get("try") ?? "0", 10) || 0;
  const exhausted = attempt >= MAX_ATTEMPTS;

  useEffect(() => {
    if (exhausted) return;
    const next = new URLSearchParams(searchParams.toString());
    next.set("try", String(attempt + 1));
    const t = setTimeout(() => {
      router.replace(`${pathname}?${next.toString()}`);
      router.refresh();
    }, RETRY_DELAY_MS);
    return () => clearTimeout(t);
  }, [exhausted, attempt, pathname, searchParams, router]);

  return (
    <div className="mx-auto max-w-3xl px-5 sm:px-6 py-16">
      <div className="rounded-xl border border-border bg-[var(--bg-elev)] p-8 flex flex-col items-center text-center gap-4">
        {exhausted ? (
          <>
            <div>
              <h1 className="font-serif text-2xl text-[var(--fg)]">Scan not found</h1>
              <p className="mt-1 text-sm text-[var(--fg-muted)]">
                This scan doesn&apos;t exist, or it was removed.
              </p>
            </div>
            <Link
              href="/scans"
              className="inline-flex items-center gap-1.5 rounded-lg border border-border px-3.5 py-1.5 text-sm text-[var(--fg-muted)] hover:text-[var(--fg)] transition-colors"
            >
              <ChevronLeft className="h-3.5 w-3.5" /> All scans
            </Link>
          </>
        ) : (
          <>
            <Loader2 className="h-6 w-6 animate-spin text-[var(--accent)]" />
            <div>
              <h1 className="font-serif text-2xl text-[var(--fg)]">Spinning up this scan…</h1>
              <p className="mt-1 text-sm text-[var(--fg-muted)]">
                If it doesn&apos;t appear in a moment, the scan may not exist.
              </p>
            </div>
            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={() => router.refresh()}
                className="inline-flex items-center gap-1.5 rounded-lg bg-[var(--accent)] text-[var(--accent-fg)] px-3.5 py-1.5 text-sm font-medium hover:opacity-90 transition-opacity"
              >
                Refresh
              </button>
              <Link
                href="/scans"
                className="inline-flex items-center gap-1.5 rounded-lg border border-border px-3.5 py-1.5 text-sm text-[var(--fg-muted)] hover:text-[var(--fg)] transition-colors"
              >
                <ChevronLeft className="h-3.5 w-3.5" /> All scans
              </Link>
            </div>
          </>
        )}
      </div>
    </div>
  );
}
