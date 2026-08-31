/**
 * Layout audit: every screen, at every window size the app can be opened at.
 *
 * What this catches that 887 Vitest tests structurally cannot: jsdom has no
 * layout engine, so every measurement there is zero and no stylesheet applies.
 * A clipped label, a button pushed outside its panel, two controls stacked on
 * top of each other, a 12×12 hit target — all invisible to the unit suite and
 * obvious to anyone looking at the window.
 *
 * Findings are *measured*, not eyeballed: each one carries a selector, the
 * numbers behind it, and the viewport it appeared at. Screenshots are written
 * alongside so a person (or a model) can confirm what the numbers describe.
 */
import { test, expect, type Page } from '@playwright/test';
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { AUDIT_FN, type LayoutFinding } from './audit';
import { SEED_VAULT } from './seed';
import { VIEWPORTS } from './viewports';

const SHOTS = 'ui-lab/screenshots';
mkdirSync(SHOTS, { recursive: true });

/** Screens worth auditing, and how to reach each one. */
const SCREENS: { name: string; go: (p: Page) => Promise<void> }[] = [
  { name: 'secrets-grid', go: async () => {} },
  {
    name: 'secrets-expanded',
    go: async (p) => {
      await p.locator('.card').first().click();
      await p.waitForTimeout(120);
    },
  },
  { name: 'tools-secret-gen', go: async (p) => void (await openTool(p, 'secret-gen')) },
  { name: 'tools-health', go: async (p) => void (await openTool(p, 'health')) },
  { name: 'tools-audit', go: async (p) => void (await openTool(p, 'audit')) },
  { name: 'tools-pools', go: async (p) => void (await openTool(p, 'pools')) },
  { name: 'tools-diff', go: async (p) => void (await openTool(p, 'diff')) },
  { name: 'tools-import-export', go: async (p) => void (await openTool(p, 'import-export')) },
  { name: 'panel-remote', go: async (p) => void (await openPanel(p, 'remote')) },
  { name: 'panel-users', go: async (p) => void (await openPanel(p, 'users')) },
  {
    name: 'modal-add-entry',
    go: async (p) => {
      await p.locator('#add-btn, [data-action="add"]').first().click();
      await p.waitForTimeout(150);
    },
  },
  {
    name: 'project-config-view',
    go: async (p) => {
      await p.locator('#project-list .sidebar-item').nth(1).click();
      await p.waitForTimeout(150);
    },
  },
];

async function openPanel(page: Page, panel: string) {
  await page.locator(`#activity-bar [data-panel="${panel}"]`).click();
  await page.waitForTimeout(120);
}

async function openTool(page: Page, tool: string) {
  await openPanel(page, 'tools');
  await page.locator(`[data-tool="${tool}"]`).first().click();
  await page.waitForTimeout(150);
}

/**
 * Boot the app with the hostile seed already in place.
 *
 * `LocalVaultStore` reads `sessionStorage`, and outside Tauri `init()` skips the
 * unlock flow entirely and goes straight to `finishInit()` — so seeding before
 * the first script runs lands us on a populated grid with no login to automate.
 */
async function boot(page: Page) {
  await page.addInitScript((vault) => {
    sessionStorage.setItem('envvault', JSON.stringify(vault));
  }, SEED_VAULT);
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(String(e)));
  await page.goto('/');
  await page.waitForSelector('#card-grid', { timeout: 15_000 });
  await page.waitForTimeout(250);
  return errors;
}

const all: (LayoutFinding & { viewport: string; screen: string })[] = [];

for (const vp of VIEWPORTS) {
  test.describe(`${vp.name} (${vp.width}×${vp.height} @${vp.dpr}) — ${vp.why}`, () => {
    for (const screen of SCREENS) {
      test(screen.name, async ({ browser }) => {
        const ctx = await browser.newContext({
          viewport: { width: vp.width, height: vp.height },
          deviceScaleFactor: vp.dpr,
        });
        const page = await ctx.newPage();
        const errors = await boot(page);
        await screen.go(page);
        await page.waitForTimeout(150);

        const findings = (await page.evaluate(AUDIT_FN)) as LayoutFinding[];
        for (const f of findings) all.push({ ...f, viewport: vp.name, screen: screen.name });

        await page.screenshot({
          path: join(SHOTS, `${vp.name}__${screen.name}.png`),
          fullPage: false,
        });
        await ctx.close();

        // A script error means the screen never finished rendering, so every
        // layout measurement taken from it is meaningless. Fail loudly rather
        // than reporting a tidy audit of a half-painted page.
        expect(errors, `page errors on ${screen.name}`).toEqual([]);
      });
    }
  });
}

test.afterAll(() => {
  mkdirSync('ui-lab/.artifacts', { recursive: true });
  writeFileSync('ui-lab/.artifacts/layout-findings.json', JSON.stringify(all, null, 2));

  // Grouped so one CSS mistake reads as one line rather than as 108 findings.
  const byRule = new Map<string, Map<string, Set<string>>>();
  for (const f of all) {
    const rule = byRule.get(f.rule) ?? new Map<string, Set<string>>();
    const where = rule.get(f.selector) ?? new Set<string>();
    where.add(`${f.viewport}/${f.screen}`);
    rule.set(f.selector, where);
    byRule.set(f.rule, rule);
  }
  const lines: string[] = [`# Layout findings — ${all.length} total`, ''];
  for (const [rule, sels] of [...byRule.entries()].sort((a, b) => b[1].size - a[1].size)) {
    lines.push(`## ${rule} — ${sels.size} distinct element(s)`);
    for (const [sel, where] of [...sels.entries()].sort((a, b) => b[1].size - a[1].size)) {
      const sample = [...where].slice(0, 4).join(', ');
      lines.push(`- \`${sel}\` — ${where.size} place(s): ${sample}${where.size > 4 ? ' …' : ''}`);
    }
    lines.push('');
  }
  writeFileSync('ui-lab/.artifacts/layout-findings.md', lines.join('\n'));
});
