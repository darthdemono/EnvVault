/**
 * The Authenticator screen (Phase 22.2), and its A2 (2026-09-14) aftermath.
 *
 * The panel reverses a Phase 22 decision — the authenticator was deliberately a
 * sidebar section and not a fifth activity-bar entry. A2 then reversed *that*:
 * the sidebar section (which showed nothing on a remote vault, per A1) was
 * removed rather than fixed, because two surfaces for one feature is exactly
 * what read as the whole feature being broken. What is asserted here is that
 * the sidebar section is really gone, the panel is the only surface left, the
 * codes are still written by the ticker rather than by a render pass, and
 * advancing a counter is still an explicit action rather than a side effect of
 * looking at a card.
 */
import { describe, it, expect, beforeEach, vi } from 'vitest';
import { loadRealIndexHtml } from './helpers';
import { st, Settings } from '../src/ts/state';
import { renderAuthPanel, initAuthPanel } from '../src/ts/auth-panel';
import type { VaultEntry } from '../src/ts/types';

function entry(over: Partial<VaultEntry> = {}): VaultEntry {
  return {
    id: over.id ?? 'e1',
    provider: over.provider ?? 'GitHub',
    api_key: '',
    totp_secret: 'JBSWY3DPEHPK3PXP',
    ...over,
  } as VaultEntry;
}

function seed(entries: VaultEntry[]) {
  st.vault = { api_keys: entries, user_categories: [], projects: [] } as any;
}

beforeEach(() => {
  loadRealIndexHtml();
  Settings.set('authShowNext', false);
  seed([]);
});

describe('the panel is the only surface — the sidebar section is gone (A2)', () => {
  it('has its own activity-bar tab, panel and workspace', () => {
    // All three ids, because `switchPanel` shows them by id and a missing one is
    // a panel that silently never appears.
    expect(document.getElementById('activity-tab-auth')).toBeTruthy();
    expect(document.getElementById('auth-panel')).toBeTruthy();
    expect(document.getElementById('auth-workspace')).toBeTruthy();
  });

  it('removed the Phase 22 sidebar section', () => {
    // A2, 2026-09-14: two surfaces for one feature, and the one that showed
    // nothing on a remote vault (A1) read as the feature being broken.
    expect(document.getElementById('sidebar-section-authenticator')).toBeNull();
    expect(document.getElementById('authenticator-list')).toBeNull();
    expect(document.getElementById('totp-import-btn')).toBeNull();
    expect(document.getElementById('totp-export-btn')).toBeNull();
  });

  it('never re-adds the section key to a persisted sidebarSections list', () => {
    localStorage.setItem('envvault-sb-migrated-totp', '');
    localStorage.setItem(
      'envvault-settings',
      JSON.stringify({ sidebarSections: ['all', 'authenticator', 'prefixes'] }),
    );
    return Settings.init().then(() => {
      expect(Settings.get('sidebarSections')).not.toContain('authenticator');
    });
  });

  it('the new tab does not add a second tab stop to the tablist', () => {
    // `role="tablist"` promises arrow-key navigation and exactly one Tab stop;
    // a fifth button with tabindex="0" would cost a keyboard user an extra press
    // to get past the activity bar.
    const stops = [...document.querySelectorAll<HTMLElement>('.activity-btn')].filter(
      (b) => b.tabIndex === 0,
    );
    expect(stops).toHaveLength(1);
  });
});

describe('rendering', () => {
  it('writes a slot per seed and no code into the markup', () => {
    // Invariant: the ticker paints the digits. A render pass that baked one in
    // would leave a dead code on screen after a re-render.
    seed([entry({ id: 'a', provider: 'GitHub' }), entry({ id: 'b', provider: 'Fastmail' })]);
    renderAuthPanel();

    const cards = document.querySelectorAll('#auth-grid .auth-card');
    expect(cards).toHaveLength(2);
    for (const c of cards) {
      expect(c.querySelector('.totp-code')!.textContent).toBe('— — —');
      // Addressed by id, never by position (invariant 1).
      expect((c as HTMLElement).dataset.totpFor).toMatch(/^[ab]$/);
    }
  });

  it('skips entries with no seed', () => {
    seed([entry({ id: 'a' }), { id: 'b', provider: 'Plain', api_key: 'x' } as VaultEntry]);
    renderAuthPanel();
    expect(document.querySelectorAll('#auth-grid .auth-card')).toHaveLength(1);
  });

  it('shows the empty state only when the vault holds no seed at all', () => {
    seed([]);
    renderAuthPanel();
    expect(document.getElementById('auth-empty')!.hidden).toBe(false);

    seed([entry()]);
    renderAuthPanel();
    expect(document.getElementById('auth-empty')!.hidden).toBe(true);
  });

  it('gives a counter-based card an Advance button and no countdown ring', () => {
    seed([entry({ totp_kind: 'hotp', totp_counter: 3 })]);
    renderAuthPanel();
    const card = document.querySelector<HTMLElement>('.auth-card')!;
    expect(card.dataset.totpKind).toBe('hotp');
    expect(card.querySelector('[data-auth-advance]')).toBeTruthy();
    // A ring whose number never moves reads as a frozen UI.
    expect(card.querySelector('.totp-countdown')).toBeNull();
    expect(card.querySelector('.totp-counter')).toBeTruthy();
  });

  it('gives a time-based card a ring and no Advance button', () => {
    seed([entry()]);
    renderAuthPanel();
    const card = document.querySelector<HTMLElement>('.auth-card')!;
    expect(card.querySelector('.totp-countdown')).toBeTruthy();
    expect(card.querySelector('[data-auth-advance]')).toBeNull();
  });

  it('marks slots for the next code only when the setting is on', () => {
    seed([entry()]);
    renderAuthPanel();
    expect(document.querySelector<HTMLElement>('.auth-card')!.dataset.totpNext).toBeUndefined();

    Settings.set('authShowNext', true);
    renderAuthPanel();
    expect(document.querySelector<HTMLElement>('.auth-card')!.dataset.totpNext).toBe('1');
  });
});

describe('advancing a counter', () => {
  it('is a button, and one click moves one position', async () => {
    // Reading a code must never advance it: a counter-based code stands until it
    // is used, and walking the vault past the service breaks the factor in a way
    // that looks exactly like a wrong seed.
    const e = entry({ totp_kind: 'hotp', totp_counter: 3 });
    seed([e]);
    const save = vi.fn().mockResolvedValue(undefined);
    st.store = { save, isRemote: false } as any;
    initAuthPanel();
    renderAuthPanel();

    document.querySelector<HTMLButtonElement>('[data-auth-advance]')!.click();
    await vi.waitFor(() => expect(save).toHaveBeenCalledTimes(1));
    expect(e.totp_counter).toBe(4);
  });

  it('puts the counter back when the save fails', async () => {
    // Otherwise the screen shows a position the vault does not hold, and the
    // next code the user copies is one the service will not accept.
    const e = entry({ totp_kind: 'hotp', totp_counter: 3 });
    seed([e]);
    st.store = { save: vi.fn().mockRejectedValue(new Error('locked')), isRemote: false } as any;
    initAuthPanel();
    renderAuthPanel();

    document.querySelector<HTMLButtonElement>('[data-auth-advance]')!.click();
    await vi.waitFor(() => expect(e.totp_counter).toBe(3));
  });
});
