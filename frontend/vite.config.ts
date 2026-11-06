import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

export default defineConfig({
  plugins: [react()],
  server: {
    // Lets the app use the shared styles in the repo's src/styles folder
    fs: { allow: ['..'] },
    // Sends /api/... requests to the Python API on port 8000
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:8000',
        rewrite: (path) => path.replace(/^\/api/, ''),
      },
    },
  },
})