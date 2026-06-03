"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { RookMark } from "./RookMark";
import { cn } from "@/lib/utils";
import { tenant } from "@/lib/tenant";

const NAV = [
  { href: "/", label: "Home" },
  { href: "/scans", label: "Scans" },
  { href: "/repos", label: "Repos" },
  { href: "/settings", label: "Settings" },
] as const;

export function Shell({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const isWhiteLabeled = tenant.displayName !== "Rook";
  return (
    <div className="min-h-screen flex flex-col">
      <header className="h-14 px-5 sm:px-6 flex items-center justify-between border-b border-border bg-[var(--bg)] sticky top-0 z-30">
        <Link href="/" className="flex items-center gap-3 group">
          <RookMark className="h-8 w-8" />
          <div className="leading-tight">
            <div className="font-serif text-lg text-[var(--fg)] group-hover:opacity-90 transition-opacity">{tenant.displayName}</div>
            <div className="text-[10px] uppercase tracking-[0.2em] text-[var(--fg-muted)]">AI red-teamer · 42nights</div>
          </div>
        </Link>
        <nav className="flex items-center gap-1">
          {NAV.map(({ href, label }) => {
            const active = href === "/" ? pathname === "/" : pathname.startsWith(href);
            return (
              <Link
                key={href}
                href={href}
                className={cn(
                  "px-3 py-1.5 rounded-md text-sm transition-colors",
                  active ? "text-[var(--fg)] bg-[var(--bg-elev)]" : "text-[var(--fg-muted)] hover:text-[var(--fg)] hover:bg-[var(--bg-elev)]",
                )}
              >
                {label}
              </Link>
            );
          })}
        </nav>
      </header>
      <main className="flex-1 min-w-0">{children}</main>
      {isWhiteLabeled && (
        <footer className="border-t border-border px-5 sm:px-6 py-3 text-center">
          <span className="text-[10px] uppercase tracking-[0.18em] text-[var(--fg-subtle)]">
            Built on{" "}
            <a href="https://42nights.dev" target="_blank" rel="noreferrer" className="hover:text-[var(--fg-muted)] transition-colors">
              42nights
            </a>
          </span>
        </footer>
      )}
    </div>
  );
}
