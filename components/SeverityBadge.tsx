import { cn } from "@/lib/utils";

const STYLE: Record<string, string> = {
  critical: "bg-[color-mix(in_oklab,var(--crit)_18%,transparent)] text-crit border-[color-mix(in_oklab,var(--crit)_40%,transparent)]",
  high: "bg-[color-mix(in_oklab,var(--high)_16%,transparent)] text-high border-[color-mix(in_oklab,var(--high)_38%,transparent)]",
  medium: "bg-[color-mix(in_oklab,var(--med)_15%,transparent)] text-med border-[color-mix(in_oklab,var(--med)_36%,transparent)]",
  low: "bg-[color-mix(in_oklab,var(--low)_14%,transparent)] text-low border-[color-mix(in_oklab,var(--low)_34%,transparent)]",
  info: "bg-[var(--bg-sunken)] text-[var(--fg-subtle)] border-border",
};

export function SeverityBadge({ severity, score, className }: { severity: string; score?: number | null; className?: string }) {
  return (
    <span className={cn("inline-flex items-center gap-1.5 rounded-md border px-2 py-0.5 text-xs font-medium uppercase tracking-wide", STYLE[severity] ?? STYLE.info, className)}>
      {severity}
      {score != null && <span className="font-mono tabular-nums normal-case">{score}</span>}
    </span>
  );
}

const STATUS_STYLE: Record<string, string> = {
  validated: "text-[var(--accent)]",
  advisory: "text-low",
  disconfirmed: "text-[var(--fg-subtle)] line-through",
  inconclusive: "text-med",
  candidate: "text-[var(--fg-muted)]",
};

export function StatusTag({ status }: { status: string }) {
  const label =
    status === "validated" ? "✓ verified" :
    status === "advisory" ? "advisory" :
    status === "disconfirmed" ? "dropped" :
    status === "inconclusive" ? "needs review" : status;
  return <span className={cn("text-xs", STATUS_STYLE[status] ?? "text-[var(--fg-muted)]")}>{label}</span>;
}
