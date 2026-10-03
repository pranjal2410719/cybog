/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        parchment: "#faf8f5",
        "soft-paper": "#fdfbfa",
        "warm-mist": "#d1d1cd",
        ash: "#92918b",
        graphite: "#72706b",
        ink: "#27251e",
        "deep-teal": "#016a71",
        // Keep cyborg aliases for backward compat in LiveStatusPanel / untouched helpers
        cyborg: {
          dark: "#faf8f5",
          darker: "#f0ece6",
          accent: "#016a71",
          muted: "#72706b",
          card: "#fdfbfa",
          border: "#d1d1cd",
        },
      },
      fontFamily: {
        sans: ["Inter", "ui-sans-serif", "system-ui", "-apple-system", "BlinkMacSystemFont", "Segoe UI", "Roboto", "sans-serif"],
      },
      fontSize: {
        caption: ["11px", { lineHeight: "1.43" }],
        "body-sm": ["12px", { lineHeight: "1.43" }],
        body: ["14px", { lineHeight: "1.43" }],
        "body-lg": ["16px", { lineHeight: "1.43" }],
      },
      borderRadius: {
        card: "16px",
        chip: "9999px",
        input: "12px",
        btn: "6px",
      },
      boxShadow: {
        subtle: "rgba(0,0,0,0.08) 0px 1px 2px 0px",
      },
      maxWidth: {
        page: "900px",
      },
      spacing: {
        4: "4px",
        8: "8px",
        12: "12px",
        16: "16px",
        32: "32px",
      },
    },
  },
  plugins: [],
}