/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        cyborg: {
          dark: "#0a0a0f",
          darker: "#05050a",
          accent: "#00d4aa",
          muted: "#6b7280",
          card: "#18181b",
          border: "#27272a",
        }
      }
    }
  },
  plugins: []
}