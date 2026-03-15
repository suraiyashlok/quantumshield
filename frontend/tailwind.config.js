/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,jsx}"],
  theme: {
    extend: {
      colors: {
        navy: "#0a0f1e",
        "navy-light": "#111827",
        "navy-card": "#1a2235",
        quantum: "#00d4ff",
        safe: "#00ff88",
        danger: "#ff4444",
        warning: "#ffaa00",
      },
      fontFamily: {
        mono: ["JetBrains Mono", "Fira Code", "monospace"],
      },
    },
  },
  plugins: [],
}
