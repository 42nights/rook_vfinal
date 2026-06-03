"use client";

import { useEffect, useRef, useState } from "react";
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

const TERMINAL = new Set(["done", "error"]);
const POLL_MS = 2500;

type ScanState = {
  status: string;
  phase: string | null;
  progress: number;
  error_message: string | null;
};

type LogLine = { ts: number; level: string; message: string };

export function ScanProgress({ scanId, initialStatus }: { scanId: string; initialStatus: string }) {
  const router = useRouter();
  const [state, setState] = useState<ScanState>({
    status: initialStatus,
    phase: TERMINAL.has(initialStatus) ? (initialStatus === "done" ? "Done" : "Error") : "Queued…",
    progress: initialStatus === "done" ? 1 : 0,
    error_message: null,
  });
  const [logs, setLogs] = useState<LogLine[]>([]);
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const doneRef = useRef(TERMINAL.has(initialStatus));

  useEffect(() => {
    if (doneRef.current) return;

    async function poll() {
      try {
        const res = await fetch(`/api/scan?scanId=${encodeURIComponent(scanId)}`);
        if (!res.ok) return;
        const data = (await res.json()) as {
          scan: ScanState & { phase: string | null };
          logs: LogLine[];
        };
        const { scan, logs: newLogs } = data;
        setState({
          status: scan.status,
          phase: scan.phase ?? scan.status,
          progress: scan.progress,
          error_message: scan.error_message ?? null,
        });
        if (Array.isArray(newLogs)) setLogs(newLogs);
        if (TERMINAL.has(scan.status)) {
          doneRef.current = true;
          setTimeout(() => router.refresh(), 600);
          return;
        }
      } catch {
        // network hiccup — keep polling
      }
      timerRef.current = setTimeout(poll, POLL_MS);
    }

    timerRef.current = setTimeout(poll, POLL_MS);
    return () => {
      if (timerRef.current) clearTimeout(timerRef.current);
    };
  }, [scanId, router]);

  const cur = ALIASES[state.status] ?? state.status;
  const activeIdx = PHASES.findIndex((p) => p.key === cur);
  const pct = Math.round((state.progress ?? 0) * 100);

  return (
    <div className="rounded-xl border border-border bg-[var(--bg-elev)] p-5 space-y-4">
      {state.status === "error" ? (
        <div className="flex items-center gap-2 text-[var(--accent)] text-sm">
          <AlertTriangle className="h-4 w-4" /> {state.phase}: {state.error_message ?? "Scan failed"}
        </div>
      ) : (
        <>
          <div className="flex items-center justify-between mb-3">
            <div className="flex items-center gap-2 text-sm text-[var(--fg)]">
              {state.status === "done"
                ? <ShieldCheck className="h-4 w-4 text-[var(--accent)]" />
                : <Loader2 className="h-4 w-4 animate-spin text-[var(--accent)] rook-live rounded-full" />}
              {state.phase}
            </div>
            <span className="text-xs font-mono text-[var(--fg-muted)] tabular-nums">{pct}%</span>
          </div>
          <div className="h-1.5 rounded-full bg-[var(--bg-sunken)] overflow-hidden">
            <div
              className="h-full bg-[var(--accent)] transition-all duration-500 ease-out"
              style={{ width: `${Math.max(3, pct)}%` }}
            />
          </div>
          <div className="mt-4 flex flex-wrap gap-x-5 gap-y-2">
            {PHASES.map((p, i) => {
              const done = activeIdx > i || state.status === "done";
              const active = activeIdx === i && state.status !== "done";
              return (
                <div key={p.key} className="flex items-center gap-1.5 text-xs">
                  <span
                    className={cn(
                      "h-4 w-4 rounded-full flex items-center justify-center shrink-0 border",
                      done
                        ? "bg-[var(--accent)] border-[var(--accent)] text-[var(--accent-fg)]"
                        : active
                          ? "border-[var(--accent)] text-[var(--accent)]"
                          : "border-border text-[var(--fg-subtle)]",
                    )}
                  >
                    {done
                      ? <Check className="h-2.5 w-2.5" />
                      : active
                        ? <Loader2 className="h-2.5 w-2.5 animate-spin" />
                        : <span className="text-[9px]">{i + 1}</span>}
                  </span>
                  <span className={cn(active || done ? "text-[var(--fg)]" : "text-[var(--fg-subtle)]")}>{p.label}</span>
                </div>
              );
            })}
          </div>
        </>
      )}

      {logs.length > 0 && (
        <details className="mt-2">
          <summary className="text-[10px] uppercase tracking-[0.14em] text-[var(--fg-subtle)] cursor-pointer">
            Worker log ({logs.length} lines)
          </summary>
          <div className="mt-2 max-h-48 overflow-y-auto rounded border border-border bg-[var(--bg-sunken)] p-2 font-mono text-[10px] text-[var(--fg-muted)] space-y-0.5">
            {logs.map((l, i) => (
              <div key={i} className={cn(l.level === "warn" ? "text-yellow-400" : l.level === "error" ? "text-[var(--accent)]" : "")}>
                {new Date(l.ts).toISOString().slice(11, 19)} [{l.level}] {l.message}
              </div>
            ))}
          </div>
        </details>
      )}
    </div>
  );
}
