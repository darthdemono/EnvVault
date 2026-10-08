import { defineConfig } from 'vite';

export default defineConfig({
  root: '.',
  publicDir: 'public',
  build: {
    outDir: 'dist',
    emptyOutDir: true,
  },
  server: {
    // Cargo's build output is tens of thousands of files. Watching it exhausts
    // inotify ("ENOSPC: System limit for number of file watchers reached"),
    // which kills the dev server — and with it `npm run ui-lab`.
    watch: { ignored: ['**/target/**', '**/src-tauri/target/**', '**/dist/**'] },
  },
  resolve: {
    alias: {
      '@': '/src',
    },
  },
});
