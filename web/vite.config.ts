import { defineConfig } from 'vite'
import preact from '@preact/preset-vite'

export default defineConfig({
  plugins: [preact()],
  server: {
    port: 3069,
    proxy: {
      '/api': {
        target: 'http://localhost:8069',
        changeOrigin: true,
        cookieDomainRewrite: 'localhost',
      },
    },
  },
  build: {
    outDir: '../cmd/eighty/dist',
    emptyOutDir: true,
  },
})
