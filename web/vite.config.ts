import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: { proxy: { '/api': 'http://localhost:8080', '/mcp': 'http://localhost:8080', '/health': 'http://localhost:8080', '/ready': 'http://localhost:8080', '/metrics': 'http://localhost:8080' } },
  build: { outDir: 'dist', sourcemap: false }
})
