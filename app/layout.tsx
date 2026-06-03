import type { Metadata } from "next";
import { GeistSans } from "geist/font/sans";
import { GeistMono } from "geist/font/mono";
import { Newsreader } from "next/font/google";
import { Toaster } from "sonner";
import { Shell } from "@/components/Shell";
import { tenant } from "@/lib/tenant";
import "./globals.css";

const newsreader = Newsreader({ subsets: ["latin"], weight: ["400", "500", "600"], variable: "--font-serif", display: "swap" });

export const metadata: Metadata = {
  title: `${tenant.displayName} — AI red-teamer`,
  description: `${tenant.displayName} breaks your app before someone else does. Finds vulns, proves them with working exploits. Local-first.`,
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html
      lang="en"
      className={`dark ${GeistSans.variable} ${GeistMono.variable} ${newsreader.variable}`}
      style={{ "--font-display": "var(--font-geist-sans)", "--font-mono-family": "var(--font-geist-mono)" } as React.CSSProperties}
    >
      <head>
        {tenant.logoUrl && <link rel="icon" href={tenant.logoUrl} />}
        {tenant.primaryColor && (
          <style>{`.dark { --tenant-primary: ${tenant.primaryColor}; --accent: ${tenant.primaryColor}; }`}</style>
        )}
      </head>
      <body className="min-h-screen antialiased bg-[var(--bg)] text-[var(--fg)]">
        <Shell>{children}</Shell>
        <Toaster position="top-right" theme="dark" />
      </body>
    </html>
  );
}
