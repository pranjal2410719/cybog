import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import path from 'path'

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
  // NOTE: No Vite dev proxy. All requests go through the centralized
  // `src/api/config.ts` layer, which reads VITE_API_BASE_URL / VITE_WS_BASE_URL
  // (with localhost defaults). This keeps dev and prod behavior identical
  // and avoids a second, divergent place that knows about ports/prefixes.
  // CORS for the Vite origin (http://localhost:5173) is already enabled on
  // the backend (app/config.py CORS_ORIGINS).
  server: {
    port: 5173,
  },
  build: {
    outDir: 'dist',
    sourcemap: true,
  },
})