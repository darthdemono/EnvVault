import { defineConfig } from '@playwright/test';

/**
 * The UI lab: the app in a real browser, at every window size it can be opened at.
 *
 * Vitest runs in jsdom, which has no layout engine — every measurement is zero
 * and no stylesheet applies — so it cannot see a clipped label or an off-panel
 * button. This config exists to cover exactly that gap, and nothing else: it does
 * not replace the unit suite, it measures what the unit suite structurally cannot.
 *
 * The app runs against `LocalVaultStore` outside Tauri (`state.ts:363`), so the
 * Vite dev server is enough — no desktop build, no unlock flow.
 */
export default defineConfig({
  testDir: './ui-lab',
  testMatch: /.*\.spec\.ts/,
  outputDir: './ui-lab/.artifacts',
  fullyParallel: true,
  reporter: [['list'], ['json', { outputFile: 'ui-lab/.artifacts/report.json' }]],
  use: {
    baseURL: 'http://127.0.0.1:5173',
    // Deterministic rendering: an animation mid-screenshot is a diff that means
    // nothing, and a caret blinking is a pixel change every 500ms.
    launchOptions: { args: ['--force-prefers-reduced-motion'] },
  },
  webServer: {
    command: 'npx vite --port 5173 --strictPort',
    url: 'http://127.0.0.1:5173',
    reuseExistingServer: true,
    timeout: 60_000,
  },
});
