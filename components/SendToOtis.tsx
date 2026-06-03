"use client";

import { useState } from "react";
import { Send, Loader2, ArrowRight } from "lucide-react";

export function SendToOtis({ findingId }: { findingId: string }) {
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<{ ok: boolean; url?: string; note: string; payload?: any } | null>(null);

  async function send() {
    setBusy(true);
    try {
      const res = await fetch(`/api/findings/${findingId}/otis`, { method: "POST" });
      setResult(await res.json());
    } catch {
      setResult({ ok: false, note: "network error" });
    } finally {
      setBusy(false);
    }
  }

  return (
    <div>
      <button
        onClick={send}
        disabled={busy}
        className="inline-flex items-center gap-2 rounded-lg border border-border-strong bg-[var(--bg-elev)] px-4 py-2 text-sm font-medium text-[var(--fg)] disabled:opacity-40 hover:border-[var(--accent)] transition-colors"
      >
        {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <Send className="h-4 w-4" />}
        Send to Otis <ArrowRight className="h-3.5 w-3.5 text-[var(--fg-subtle)]" />
      </button>
      {result && (
        <div className="mt-3 rounded-lg border border-border bg-[var(--bg-sunken)] p-3 text-xs">
          <p className={result.ok ? "text-[var(--accent)]" : "text-[var(--fg-muted)]"}>{result.note}</p>
          {result.url && (
            <a href={result.url} className="text-[var(--accent)] underline" target="_blank" rel="noreferrer">open Otis session →</a>
          )}
          {result.payload && (
            <div className="mt-2">
              <div className="text-[var(--fg-subtle)] mb-1">Handoff Otis receives (finding + exploit as a failing test):</div>
              <pre className="code-block p-2 whitespace-pre-wrap text-[var(--fg)] max-h-48 overflow-y-auto">{JSON.stringify(result.payload, null, 2)}</pre>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
