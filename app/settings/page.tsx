import { ShieldCheck, Cloud, Bell, Github, Box } from "lucide-react";
import { isAppConfigured } from "@/lib/github/app";
import { LOCAL_MODE } from "@/lib/constants";

export const dynamic = "force-dynamic";

export default function SettingsPage() {
  const cloud = !LOCAL_MODE;
  const appOn = isAppConfigured();
  const osv = process.env.ROOK_OSV === "true";
  const sandbox = (process.env.ROOK_SANDBOX ?? "local").toLowerCase();
  const otis = !!process.env.OTIS_URL;
  const slack = !!process.env.SLACK_WEBHOOK_URL;

  return (
    <div className="mx-auto max-w-2xl px-5 sm:px-6 py-12">
      <h1 className="font-serif text-3xl text-[var(--fg)]">Settings</h1>
      <p className="mt-1 text-[var(--fg-muted)]">Configured via environment. Rook is local-first by default.</p>

      <div className="mt-8 space-y-3">
        <Row icon={<ShieldCheck className="h-4 w-4" />} label="Model mode" value={cloud ? "Cloud (Anthropic)" : "Local"} on={!cloud} note={cloud ? "ROOK_MODE=cloud" : "ROOK_MODE=local — no outbound model calls"} />
        <Row icon={<Box className="h-4 w-4" />} label="Exploit sandbox" value={sandbox === "docker" ? "Docker" : "Local subprocess (guarded)"} on note={sandbox === "docker" ? "ROOK_SANDBOX=docker" : "ROOK_SANDBOX=local — set =docker for container isolation"} />
        <Row icon={<Cloud className="h-4 w-4" />} label="OSV supply-chain scan" value={osv ? "Enabled" : "Off"} on={osv} note="ROOK_OSV=true allows api.osv.dev for dependency vuln lookups" />
        <Row icon={<Github className="h-4 w-4" />} label="GitHub App" value={appOn ? "Configured" : "Not configured"} on={appOn} note="Install on a repo for scan-on-push + auto-issues" />
        <Row icon={<Box className="h-4 w-4" />} label="Send to Otis" value={otis ? "Wired" : "Shows handoff only"} on={otis} note="OTIS_URL — hands findings to the 42n-bot implementer" />
        <Row icon={<Bell className="h-4 w-4" />} label="Slack alerts" value={slack ? "Enabled" : "Off"} on={slack} note="SLACK_WEBHOOK_URL for finding notifications" />
      </div>
    </div>
  );
}

function Row({ icon, label, value, on, note }: { icon: React.ReactNode; label: string; value: string; on?: boolean; note?: string }) {
  return (
    <div className="rounded-lg border border-border bg-[var(--bg-elev)] px-4 py-3 flex items-start gap-3">
      <div className="text-[var(--fg-muted)] mt-0.5">{icon}</div>
      <div className="flex-1 min-w-0">
        <div className="flex items-center justify-between">
          <span className="text-sm text-[var(--fg)]">{label}</span>
          <span className={`text-xs font-medium ${on ? "text-[var(--accent)]" : "text-[var(--fg-subtle)]"}`}>{value}</span>
        </div>
        {note && <p className="text-xs text-[var(--fg-subtle)] mt-0.5 font-mono">{note}</p>}
      </div>
    </div>
  );
}
