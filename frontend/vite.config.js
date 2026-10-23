import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// Dev proxy lets localhost:5173 call the local FastAPI backend directly.
// In production (Vercel), the API base comes from VITE_API_BASE instead.
export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      '/api': {
        target: 'http://localhost:8001',
        changeOrigin: true,
      },
    },
  },
})
