"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { Loader2, Check, AlertTriangle, ShieldCheck } from "lucide-react";
import { cn } from "@/lib/utils";

const PHASES = [
  { key: "bootstrap", label: "Bootstrap" },
  { key: "threat-model", label: "Threat model" },
  { key: "scanning", label: "Static scan" },
  { key: "exploiting", label: "Exploit synthesis" },
  { key: "reporting", label: "Report" },
  { key: "done", label: "Done" },
];
const ALIASES: Record<string, string> = { enriching: "exploiting" };

type Evt = { status: string; phase: string; progress: number; done?: boolean; error?: string };

export function ScanProgress({ scanId, initialStatus }: { scanId: string; initialStatus: string }) {
  const router = useRouter();
  const terminal = initialStatus === "done" || initialStatus === "error";
  const [evt, setEvt] = useState<Evt>(
    terminal
      ? { status: initialStatus, phase: initialStatus === "done" ? "Done" : "Error", progress: initialStatus === "done" ? 1 : 0 }
      : { status: initialStatus, phase: "Starting…", progress: 0 },
  );
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (initialStatus === "done" || initialStatus === "error") return;
    const es = new EventSource(`/api/scan/stream?scanId=${scanId}`);
    es.onmessage = (m) => {
      const e = JSON.parse(m.data) as Evt;
      setEvt(e);
      if (e.error) setError(e.error);
      if (e.done) {
        es.close();
        setTimeout(() => router.refresh(), 600);
      }
    };
    es.onerror = () => es.close();
    return () => es.close();
  }, [scanId, initialStatus, router]);

  const cur = ALIASES[evt.status] ?? evt.status;
  const activeIdx = PHASES.findIndex((p) => p.key === cur);
  const pct = Math.round((evt.progress ?? 0) * 100);

  return (
    <div className="rounded-xl border border-border bg-[var(--bg-elev)] p-5">
      {error ? (
        <div className="flex items-center gap-2 text-[var(--accent)] text-sm">
          <AlertTriangle className="h-4 w-4" /> {evt.phase}: {error}
        </div>
      ) : (
        <>
          <div className="flex items-center justify-between mb-3">
            <div className="flex items-center gap-2 text-sm text-[var(--fg)]">
              {evt.status === "done" ? <ShieldCheck className="h-4 w-4 text-[var(--accent)]" /> : <Loader2 className="h-4 w-4 animate-spin text-[var(--accent)] rook-live rounded-full" />}
              {evt.phase}
            </div>
            <span className="text-xs font-mono text-[var(--fg-muted)] tabular-nums">{pct}%</span>
          </div>
          <div className="h-1.5 rounded-full bg-[var(--bg-sunken)] overflow-hidden">
            <div className="h-full bg-[var(--accent)] transition-all duration-500 ease-out" style={{ width: `${Math.max(3, pct)}%` }} />
          </div>
          <div className="mt-4 flex flex-wrap gap-x-5 gap-y-2">
            {PHASES.map((p, i) => {
              const done = activeIdx > i || evt.status === "done";
              const active = activeIdx === i && evt.status !== "done";
              return (
                <div key={p.key} className="flex items-center gap-1.5 text-xs">
                  <span className={cn("h-4 w-4 rounded-full flex items-center justify-center shrink-0 border", done ? "bg-[var(--accent)] border-[var(--accent)] text-[var(--accent-fg)]" : active ? "border-[var(--accent)] text-[var(--accent)]" : "border-border text-[var(--fg-subtle)]")}>
                    {done ? <Check className="h-2.5 w-2.5" /> : active ? <Loader2 className="h-2.5 w-2.5 animate-spin" /> : <span className="text-[9px]">{i + 1}</span>}
                  </span>
                  <span className={cn(active || done ? "text-[var(--fg)]" : "text-[var(--fg-subtle)]")}>{p.label}</span>
                </div>
              );
            })}
          </div>
        </>
      )}
    </div>
  );
}
