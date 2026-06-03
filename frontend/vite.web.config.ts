import { resolve } from 'path'
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

// Standalone Vite config — serves the renderer as a plain web app.
// Use this when the Electron launcher has issues: `npm run web`
export default defineConfig({
  root: resolve('src/renderer'),
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: {
      '@renderer': resolve('src/renderer/src')
    }
  },
  server: {
    port: 5173,
    strictPort: true
  }
})
