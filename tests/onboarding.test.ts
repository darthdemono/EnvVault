/**
 * @file Onboarding wizard — first-run walkthrough.
 *
 * The wizard's whole risk is that it becomes an obstacle: a step that cannot be
 * left, a dismissal that does not stick, or a "Skip" that silently rewrites a
 * setting the user never looked at. Every test here is one of those.
 */
import { describe, it, expect, beforeEach, vi } from 'vitest';
import { loadRealIndexHtml } from './helpers';
import { Settings, st } from '../src/ts/state';
import { showOnboarding, shouldShowOnboarding, onboardingIsOpen } from '../src/ts/onboarding';

const noop = { onAdd: () => {}, onImport: () => {} };

const card = () => document.querySelector('.onboard-card');
const nextBtn = () => document.getElementById('onboard-next') as HTMLButtonElement;
const backBtn = () => document.getElementById('onboard-back') as HTMLButtonElement;
const skipBtn = () => document.getElementById('onboard-skip') as HTMLButtonElement;
const title = () => document.getElementById('onboard-title')!.textContent ?? '';

/** Walk forward until the wizard closes, so a test can reach the last step. */
async function advanceTo(stepTitleFragment: string) {
  for (let i = 0; i < 8; i++) {
    if (title().includes(stepTitleFragment)) return;
    nextBtn().click();
    await Promise.resolve();
  }
  throw new Error(`never reached a step titled like ${stepTitleFragment}`);
}

beforeEach(async () => {
  loadRealIndexHtml();
  // Close anything a previous test left open — the module holds one overlay.
  if (onboardingIsOpen()) document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape' }));
  Settings.set('onboardingCompleted', false);
  Settings.set('autoLockMinutes', 60);
  Settings.set('lockOnHide', false);
  Settings.set('maskKeysByDefault', true);
  st.vault.api_keys = [];
});

describe('when the wizard runs', () => {
  it('is due on a fresh install and never again once dismissed', () => {
    expect(shouldShowOnboarding()).toBe(true);
    Settings.set('onboardingCompleted', true);
    expect(shouldShowOnboarding()).toBe(false);
  });

  it('does not stack a second copy of itself', async () => {
    showOnboarding(noop);
    showOnboarding(noop);
    expect(document.querySelectorAll('.onboard-card').length).toBe(1);
  });
});

describe('navigation', () => {
  it('opens on the first step with Back unavailable', async () => {
    showOnboarding(noop);
    expect(card()).toBeTruthy();
    expect(title()).toContain('Welcome');
    expect(backBtn().disabled).toBe(true);
  });

  it('moves forward and back, and the last step finishes rather than continuing', async () => {
    showOnboarding(noop);
    nextBtn().click();
    await Promise.resolve();
    expect(backBtn().disabled).toBe(false);
    const second = title();
    backBtn().click();
    expect(title()).toContain('Welcome');
    expect(second).not.toContain('Welcome');

    await advanceTo('first secret');
    expect(nextBtn().textContent).toBe('Finish');
    nextBtn().click();
    await Promise.resolve();
    expect(onboardingIsOpen()).toBe(false);
  });
});

describe('dismissal', () => {
  it('marks itself done when skipped, so it does not reappear next launch', async () => {
    showOnboarding(noop);
    skipBtn().click();
    expect(onboardingIsOpen()).toBe(false);
    expect(shouldShowOnboarding()).toBe(false);
  });

  it('closes on Escape and detaches its key handler', async () => {
    showOnboarding(noop);
    document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape' }));
    expect(onboardingIsOpen()).toBe(false);
    // A second Escape must not throw against the removed overlay — the handler
    // is document-level and outlives the nodes it was closing over.
    expect(() =>
      document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape' })),
    ).not.toThrow();
  });

  it('skipping does not silently rewrite the settings it was showing', async () => {
    // Only "Next" commits a step. A user who skips must land on exactly the
    // defaults they had, not on whatever the inputs happened to display.
    Settings.set('autoLockMinutes', 5);
    Settings.set('maskKeysByDefault', false);
    showOnboarding(noop);
    nextBtn().click(); // onto the locking step, so its inputs exist
    await Promise.resolve();
    (document.getElementById('onboard-autolock') as HTMLInputElement).value = '999';
    skipBtn().click();
    expect(Settings.get('autoLockMinutes')).toBe(5);
    expect(Settings.get('maskKeysByDefault')).toBe(false);
  });

  it('restores the header it hid', async () => {
    // #header carries a backdrop-filter, which creates a compositing layer that
    // beats z-index — every overlay in this app hides it. Failing to put it back
    // leaves the app running with no toolbar.
    const header = document.getElementById('header')!;
    showOnboarding(noop);
    expect(header.style.display).toBe('none');
    skipBtn().click();
    expect(header.style.display).not.toBe('none');
  });
});

describe('the settings each step writes', () => {
  it('records the auto-lock choice when the step is completed', async () => {
    showOnboarding(noop);
    await advanceTo('lock');
    (document.getElementById('onboard-autolock') as HTMLInputElement).value = '15';
    (document.getElementById('onboard-lockhide') as HTMLInputElement).checked = true;
    nextBtn().click();
    await Promise.resolve();
    expect(Settings.get('autoLockMinutes')).toBe(15);
    expect(Settings.get('lockOnHide')).toBe(true);
  });

  it('falls back to the default rather than NaN for a blank auto-lock field', async () => {
    // A number input hands back "" for text it refused, so "unparseable" and
    // "blank" arrive identically — and NaN minutes is a timer that never fires.
    showOnboarding(noop);
    await advanceTo('lock');
    (document.getElementById('onboard-autolock') as HTMLInputElement).value = '';
    nextBtn().click();
    await Promise.resolve();
    expect(Settings.get('autoLockMinutes')).toBe(60);
  });

  it('clamps an out-of-range auto-lock value instead of storing it', async () => {
    showOnboarding(noop);
    await advanceTo('lock');
    (document.getElementById('onboard-autolock') as HTMLInputElement).value = '99999';
    nextBtn().click();
    await Promise.resolve();
    expect(Settings.get('autoLockMinutes')).toBe(1440);
  });

  it('records the masking choice', async () => {
    showOnboarding(noop);
    await advanceTo('appear');
    (document.getElementById('onboard-mask') as HTMLInputElement).checked = false;
    nextBtn().click();
    await Promise.resolve();
    expect(Settings.get('maskKeysByDefault')).toBe(false);
  });
});

describe('the final step', () => {
  it('hands off to Add and closes, so the wizard is not in the way of the form', async () => {
    const onAdd = vi.fn();
    showOnboarding({ onAdd, onImport: () => {} });
    await advanceTo('first secret');
    (document.getElementById('onboard-add') as HTMLButtonElement).click();
    expect(onAdd).toHaveBeenCalledOnce();
    expect(onboardingIsOpen()).toBe(false);
    expect(shouldShowOnboarding()).toBe(false);
  });

  it('hands off to Import the same way', async () => {
    const onImport = vi.fn();
    showOnboarding({ onAdd: () => {}, onImport });
    await advanceTo('first secret');
    (document.getElementById('onboard-import') as HTMLButtonElement).click();
    expect(onImport).toHaveBeenCalledOnce();
    expect(onboardingIsOpen()).toBe(false);
  });

  it('says how many entries a non-empty vault already holds', async () => {
    st.vault.api_keys = [{ provider: 'A' } as any, { provider: 'B' } as any];
    showOnboarding(noop);
    await advanceTo('first secret');
    expect(document.getElementById('onboard-body')!.textContent).toContain('2 entries');
  });
});
