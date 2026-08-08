import { defineConfig } from 'vitest/config';

export default defineConfig({
  resolve: {
    alias: { '@': '/src' },
  },
  test: {
    environment: 'jsdom',
    include: ['tests/**/*.test.ts'],
    setupFiles: ['tests/setup.ts'],
    restoreMocks: true,
    coverage: {
      provider: 'v8',
      include: ['src/ts/**/*.ts'],
      exclude: ['src/ts/types.ts'],
      reporter: ['text', 'html'],
    },
  },
});
