/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,ts,jsx,tsx}"],
  theme: {
    extend: {
      colors: {
        ink: {
          50: "#f8fafc",
          950: "#111827",
          900: "#111827",
          800: "#1f2937",
          700: "#374151",
          600: "#4b5563",
          500: "#64748b",
          400: "#9ca3af"
        },
        panel: "#ffffff",
        canvas: "#f7f8fb",
        line: "#e5e7eb",
        violet: {
          50: "#f5f3ff",
          100: "#ede9fe",
          500: "#7c3aed",
          600: "#6d28d9"
        },
        cyan: {
          50: "#ecfeff",
          500: "#06b6d4",
          600: "#0891b2"
        },
        emerald: {
          50: "#ecfdf5",
          500: "#10b981",
          600: "#059669"
        },
        amber: {
          50: "#fffbeb",
          500: "#f59e0b"
        },
        rose: {
          50: "#fff1f2",
          500: "#f43f5e"
        }
      },
      fontFamily: {
        sans: ["Inter", "Segoe UI", "system-ui", "sans-serif"],
        mono: ["JetBrains Mono", "Consolas", "monospace"]
      },
      boxShadow: {
        soft: "0 18px 45px rgba(15, 23, 42, 0.08)",
        tight: "0 8px 20px rgba(15, 23, 42, 0.06)"
      }
    },
  },
  plugins: [],
};
