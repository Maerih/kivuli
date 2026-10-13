import type { Config } from "tailwindcss";

// Every colour is a role backed by a CSS variable (see globals.css), so light
// and dark themes are one set of classes.
const config: Config = {
  content: ["./src/**/*.{ts,tsx}"],
  darkMode: ["selector", '[data-theme="dark"]'],
  theme: {
    extend: {
      colors: {
        page: "var(--page)",
        surface: "var(--surface)",
        raised: "var(--raised)",
        sunken: "var(--sunken)",
        line: "var(--line)",
        "line-strong": "var(--line-strong)",
        ink: "var(--ink)",
        "ink-2": "var(--ink-2)",
        muted: "var(--muted)",
        accent: "var(--accent)",
        "accent-ink": "var(--accent-ink)",
        "accent-soft": "var(--accent-soft)",
        "on-accent": "var(--on-accent)",
        critical: "var(--critical)",
        serious: "var(--serious)",
        warning: "var(--warning)",
        good: "var(--good)",
        "critical-soft": "var(--critical-soft)",
        "serious-soft": "var(--serious-soft)",
        "warning-soft": "var(--warning-soft)",
        "good-soft": "var(--good-soft)",
        mark: "var(--mark)",
      },
      fontFamily: {
        sans: ["system-ui", "-apple-system", '"Segoe UI"', "Roboto", "sans-serif"],
        mono: ["ui-monospace", "SFMono-Regular", "Menlo", "Consolas", "monospace"],
      },
      fontSize: { "2xs": ["0.6875rem", { lineHeight: "1rem" }] },
      boxShadow: { pop: "0 8px 30px rgba(0,0,0,.18), 0 0 0 1px var(--line)" },
    },
  },
  plugins: [],
};

export default config;
