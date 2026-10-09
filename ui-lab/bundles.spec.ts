import { test, expect } from '@playwright/test';
import { BUNDLE_VAULT } from './seed';
import { VIEWPORTS } from './viewports';

for (const vp of VIEWPORTS) {
  test(`bundles collapse and use the full grid when expanded at ${vp.name}`, async ({
    browser,
  }) => {
    const ctx = await browser.newContext({
      viewport: { width: vp.width, height: vp.height },
      deviceScaleFactor: vp.dpr,
    });
    const page = await ctx.newPage();
    await page.addInitScript(
      ({ vault, columns }) => {
        sessionStorage.setItem('unenverse', JSON.stringify(vault));
        localStorage.setItem(
          'unenverse-settings',
          JSON.stringify({
            onboardingCompleted: true,
            groupBundles: true,
            gridColumns: columns,
          }),
        );
      },
      { vault: BUNDLE_VAULT, columns: vp.width < 1280 ? '2' : '5' },
    );
    await page.goto('/');
    const grid = page.locator('#card-grid');
    for (const [id, count] of [
      ['bundle-tmdb', 2],
      ['bundle-omni', 3],
    ] as const) {
      const bundle = grid.locator(`.bundle-card-wrap[data-bundle="${id}"]`);
      const members = bundle.locator(':scope > .pool-card-members');
      const toggle = bundle.locator('[data-action="bundle-toggle"]');
      await expect(members).toBeHidden();
      await expect(toggle).toHaveAttribute('aria-expanded', 'false');
      await toggle.click();
      await expect(members).toBeVisible();
      await expect(toggle).toHaveAttribute('aria-expanded', 'true');
      await expect(bundle).toHaveClass(/expanded/);
      const gridBox = (await grid.boundingBox())!;
      const bundleBox = (await bundle.boundingBox())!;
      expect(Math.abs(gridBox.width - bundleBox.width)).toBeLessThanOrEqual(1);
      await expect(bundle.locator('.bundle-member')).toHaveCount(count);
      for (const member of await bundle.locator('.bundle-member').all()) {
        const box = (await member.boundingBox())!;
        expect(box.width).toBeGreaterThanOrEqual(Math.min(300, bundleBox.width - 30));
        expect(box.x + box.width).toBeLessThanOrEqual(bundleBox.x + bundleBox.width + 1);
      }
      await page.screenshot({ path: test.info().outputPath(`${id}-expanded.png`) });
      await toggle.click();
      await expect(members).toBeHidden();
    }
    await ctx.close();
  });
}
