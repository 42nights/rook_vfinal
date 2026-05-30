"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { Crosshair, Loader2 } from "lucide-react";
import { toast } from "sonner";

export function ScanInput({ autoFocus = false }: { autoFocus?: boolean }) {
  const [value, setValue] = useState("");
  const [busy, setBusy] = useState(false);
  const router = useRouter();

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    const ref = value.trim();
    if (!ref || busy) return;
    setBusy(true);
    try {
      const res = await fetch("/api/scan", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ ref }),
      });
      const data = await res.json();
      if (!res.ok) {
        toast.error(data.error ?? "Could not start scan.");
        setBusy(false);
        return;
      }
      router.push(`/scans/${data.scanId}`);
    } catch {
      toast.error("Network error.");
      setBusy(false);
    }
  }

  return (
    <form onSubmit={submit} className="w-full">
      <div className="flex items-center gap-2 rounded-xl border border-border-strong bg-[var(--bg-elev)] px-4 py-3 focus-within:border-[var(--accent)] transition-colors">
        <Crosshair className="h-4 w-4 text-[var(--accent)] shrink-0" />
        {/* eslint-disable-next-line jsx-a11y/no-autofocus */}
        <input
          autoFocus={autoFocus}
          value={value}
          onChange={(e) => setValue(e.target.value)}
          placeholder="owner/repo  ·  a GitHub URL  ·  or a local path"
          className="flex-1 bg-transparent outline-none text-[var(--fg)] placeholder:text-[var(--fg-subtle)] text-sm sm:text-base font-mono"
          spellCheck={false}
        />
        <button
          type="submit"
          disabled={busy || !value.trim()}
          className="shrink-0 inline-flex items-center gap-1.5 rounded-lg bg-[var(--accent)] text-[var(--accent-fg)] px-4 py-2 text-sm font-medium disabled:opacity-40 hover:opacity-90 transition-opacity"
        >
          {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <Crosshair className="h-4 w-4" />}
          {busy ? "Scanning…" : "Scan for vulns"}
        </button>
      </div>
    </form>
  );
}
