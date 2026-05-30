import type { Config } from "tailwindcss";

const config: Config = {
  darkMode: ["class"],
  content: ["./app/**/*.{ts,tsx}", "./components/**/*.{ts,tsx}", "./lib/**/*.{ts,tsx}"],
  theme: {
    extend: {
      fontFamily: {
        sans: ["var(--font-display)", "var(--font-geist-sans)", "ui-sans-serif", "system-ui"],
        display: ["var(--font-display)", "var(--font-geist-sans)", "ui-sans-serif", "system-ui"],
        mono: ["var(--font-mono-family)", "var(--font-geist-mono)", "ui-monospace", "SFMono-Regular"],
        serif: ["var(--font-serif)", "ui-serif", "Georgia"],
      },
      colors: {
        background: "var(--bg)",
        foreground: "var(--fg)",
        muted: { DEFAULT: "var(--bg-sunken)", foreground: "var(--fg-muted)" },
        border: "var(--border)",
        primary: { DEFAULT: "var(--accent)", foreground: "var(--accent-fg)" },
        accent: { DEFAULT: "var(--accent)", foreground: "var(--accent-fg)", soft: "var(--accent-soft)" },
        crit: { DEFAULT: "var(--crit)" },
        high: { DEFAULT: "var(--high)" },
        med: { DEFAULT: "var(--med)" },
        low: { DEFAULT: "var(--low)" },
      },
      borderRadius: { lg: "var(--radius-lg)", md: "var(--radius)", sm: "calc(var(--radius) - 2px)", xl: "var(--radius-xl)" },
      keyframes: {
        "fade-up": { "0%": { opacity: "0", transform: "translateY(8px)" }, "100%": { opacity: "1", transform: "translateY(0)" } },
      },
      animation: { "fade-up": "fade-up 0.5s cubic-bezier(0.16,1,0.3,1) both" },
    },
  },
  plugins: [require("tailwindcss-animate")],
};
export default config;
