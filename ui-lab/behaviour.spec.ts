/**
 * Behaviour that only a real browser can answer.
 *
 * `layout.spec.ts` measures geometry; this file asserts the handful of
 * interactions whose outcome depends on the CSS cascade, which jsdom does not
 * implement at all. A Vitest test can prove a class was toggled — it cannot
 * prove the class won against an inline style, and that is exactly where the
 * sidebar toggle was broken.
 */
import { test, expect, type Page } from '@playwright/test';

/** Boot with a vault and a settings blob already in place, past the wizard. */
async function boot(page: Page, settings: Record<string, unknown>) {
  await page.addInitScript((s) => {
    localStorage.setItem('unenverse-settings', JSON.stringify(s));
    sessionStorage.setItem(
      'unenverse',
      JSON.stringify({ api_keys: [], user_categories: [], projects: [] }),
    );
  }, settings);
  await page.goto('/');
  await page.waitForSelector('#card-grid', { timeout: 15_000 });
  await page.waitForTimeout(250);
}

const sidebarWidth = async (page: Page) => (await page.locator('#sidebar').boundingBox())!.width;

test.describe('sidebar collapse', () => {
  test('collapses when a custom width has been persisted', async ({ page }) => {
    // The bug: `applySidebarLayout()` writes a persisted width as an *inline*
    // style, which outranks `#sidebar.collapsed { width: 0 }`. So the toggle
    // dropped the padding and left the panel at full width — and only for users
    // who had dragged the sidebar, i.e. the ones who cared about it.
    await boot(page, { onboardingCompleted: true, sidebarWidth: 300 });
    expect(await sidebarWidth(page)).toBeGreaterThan(250);

    await page.click('#sidebar-toggle');
    await page.waitForTimeout(300);
    expect(await sidebarWidth(page)).toBeLessThan(5);

    await page.click('#sidebar-toggle');
    await page.waitForTimeout(300);
    expect(await sidebarWidth(page)).toBeGreaterThan(250);
  });

  test('collapses at the stylesheet default width too', async ({ page }) => {
    await boot(page, { onboardingCompleted: true, sidebarWidth: 0 });
    await page.click('#sidebar-toggle');
    await page.waitForTimeout(300);
    expect(await sidebarWidth(page)).toBeLessThan(5);
  });
});

test.describe('boot', () => {
  test('never paints the shell before the vault state is known', async ({ page }) => {
    // `#unlock-overlay` only gets `.open` once the modules have loaded, so the
    // header, sidebar and an empty grid used to paint first and the lock screen
    // dropped over them. `html.booting` suppresses that first paint; both boot
    // terminals clear it, and so does a boot that throws.
    await page.addInitScript(() => {
      localStorage.setItem('unenverse-settings', JSON.stringify({ onboardingCompleted: true }));
    });
    await page.goto('/');
    await page.waitForSelector('#card-grid', { timeout: 15_000 });
    await page.waitForTimeout(400);
    await expect(page.locator('#header')).toBeVisible();
    expect(await page.evaluate(() => document.documentElement.classList.contains('booting'))).toBe(
      false,
    );
  });
});

test.describe('keyboard', () => {
  test('a card icon (role=button) opens the icon picker on Enter, like a button would', async ({
    page,
  }) => {
    await page.addInitScript(() => {
      localStorage.setItem('unenverse-settings', JSON.stringify({ onboardingCompleted: true }));
      sessionStorage.setItem(
        'unenverse',
        JSON.stringify({
          api_keys: [{ id: 'k1', provider: 'GitHub', api_key: 'x', secretType: 'api_key' }],
          user_categories: [],
          projects: [],
        }),
      );
    });
    await page.goto('/');
    await page.waitForSelector('.provider-icon-wrap', { timeout: 15_000 });
    const icon = page.locator('.provider-icon-wrap').first();
    await expect(icon).toHaveAttribute('aria-label', /Change icon for GitHub/);
    await icon.focus();
    await page.keyboard.press('Enter');
    await expect(page.locator('#icon-picker-overlay')).toHaveClass(/open/);
  });
});
