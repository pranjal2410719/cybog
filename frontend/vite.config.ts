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
  // Dev-only reverse proxy. Only this dev server is published through the
  // Cloudflare tunnel, so the browser sees one origin and calls the API at
  // /api/v1 same-origin: no CORS allowlist, no second public hostname. The
  // backend stays bound to 127.0.0.1 and is never exposed directly.
  //
  // This applies to `vite dev` only. The `vite build` output has no proxy, so
  // a production deploy still needs VITE_API_BASE_URL / VITE_WS_BASE_URL to
  // point at wherever the API is served from.
  server: {
    port: 5173,
    host: '0.0.0.0',
    allowedHosts: true,
    proxy: {
      '/api': { target: 'http://127.0.0.1:8000', changeOrigin: true },
      '/ws': { target: 'ws://127.0.0.1:8000', ws: true, changeOrigin: true },
    },
  },
  build: {
    outDir: 'dist',
    sourcemap: true,
  },
})
