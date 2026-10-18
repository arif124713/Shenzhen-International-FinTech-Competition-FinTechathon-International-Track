/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        ground: "var(--ground)",
        surface: "var(--surface)",
        "surface-sunk": "var(--surface-sunk)",
        ink: "var(--ink)",
        "ink-muted": "var(--ink-muted)",
        line: "var(--line)",
        seal: "var(--seal)",
        "seal-tint": "var(--seal-tint)",
        hold: "var(--hold)",
        "hold-tint": "var(--hold-tint)",
        deny: "var(--deny)",
        "deny-tint": "var(--deny-tint)",
        untrusted: "var(--untrusted)",
        "untrusted-tint": "var(--untrusted-tint)",
        sim: "var(--sim)",
      },
      fontFamily: {
        sans: ['"Schibsted Grotesk"', '"Hind Siliguri"', "system-ui", "sans-serif"],
        mono: ['"IBM Plex Mono"', "ui-monospace", "monospace"],
      },
      borderRadius: { panel: "10px", control: "6px", mandate: "14px" },
    },
  },
  plugins: [],
};
