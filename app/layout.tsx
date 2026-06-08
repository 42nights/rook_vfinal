import type { Metadata } from "next";
import { GeistSans } from "geist/font/sans";
import { GeistMono } from "geist/font/mono";
import { Newsreader } from "next/font/google";
import { Toaster } from "sonner";
import { Shell } from "@/components/Shell";
import { tenant } from "@/lib/tenant";
import "./globals.css";

const newsreader = Newsreader({ subsets: ["latin"], weight: ["400", "500", "600"], variable: "--font-serif", display: "swap" });

const ROOK_DESC = `${tenant.displayName} breaks your app before someone else does — finds vulnerabilities and proves each one with a real working exploit.`;

export const metadata: Metadata = {
  metadataBase: new URL("https://rook-roan.vercel.app"),
  title: `${tenant.displayName} — AI red-teamer`,
  description: ROOK_DESC,
  openGraph: {
    title: `${tenant.displayName} — AI red-teamer`,
    description: ROOK_DESC,
    url: "https://rook-roan.vercel.app",
    siteName: "42nights",
    type: "website",
  },
  twitter: {
    card: "summary_large_image",
    title: `${tenant.displayName} — AI red-teamer`,
    description: ROOK_DESC,
  },
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html
      lang="en"
      className={`${GeistSans.variable} ${GeistMono.variable} ${newsreader.variable}`}
      style={{ "--font-display": "var(--font-geist-sans)", "--font-mono-family": "var(--font-geist-mono)" } as React.CSSProperties}
    >
      <head>
        {tenant.logoUrl && <link rel="icon" href={tenant.logoUrl} />}
        {tenant.primaryColor && (
          <style>{`:root, .dark { --tenant-primary: ${tenant.primaryColor}; --accent: ${tenant.primaryColor}; }`}</style>
        )}
      </head>
      <body className="min-h-screen antialiased bg-[var(--bg)] text-[var(--fg)]">
        <Shell>{children}</Shell>
        <Toaster position="top-right" theme="light" />
      </body>
    </html>
  );
}
