import { sveltekit } from '@sveltejs/kit/vite';
import { defineConfig } from 'vite';

const apiTarget = process.env.GNTL_API_TARGET || 'http://127.0.0.1:2026';

export default defineConfig({
  plugins: [sveltekit()],
  server: {
    proxy: {
      '/api': {
        target: apiTarget,
        changeOrigin: true,
        secure: false
      },
      '/login': {
        target: apiTarget,
        changeOrigin: true,
        secure: false
      },
      '/logout': {
        target: apiTarget,
        changeOrigin: true,
        secure: false
      }
    }
  }
});