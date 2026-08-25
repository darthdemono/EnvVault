/**
 * The unlock screen's recent-servers picker.
 *
 * The point of this feature is that the URL and the username are a *pair* —
 * connecting to the right server under the wrong account just fails
 * authentication with no hint as to why. So the picker has to carry both, and
 * the ordering has to reflect what actually connected, not what was typed.
 */
import { describe, it, expect, beforeEach, vi } from 'vitest';
import { st, Settings, LocalVaultStore } from '../src/ts/state';
import { recentServers, showUnlockModal } from '../src/ts/lock';
import { upsertSavedRemote, markRemoteConnected } from '../src/ts/remote-panel';
import { loadRealIndexHtml, resetState } from './helpers';

vi.mock('../src/ts/utils', async (importOriginal) => {
  const real = await importOriginal<typeof import('../src/ts/utils')>();
  return { ...real, showToast: () => {} };
});

const $ = <T extends HTMLElement = HTMLElement>(id: string) => document.getElementById(id) as T;

beforeEach(() => {
  loadRealIndexHtml();
  resetState(st);
  st.store = new LocalVaultStore();
  Settings.set('remoteSaved', []);
  Settings.set('remote', { enabled: false, serverUrl: '' });
});

describe('markRemoteConnected', () => {
  it('stamps the connection time', () => {
    const cfg = upsertSavedRemote({ url: 'http://a.example', username: 'joy' });
    expect(cfg.lastConnectedAt).toBeUndefined();
    markRemoteConnected(cfg.id);
    const saved = Settings.get('remoteSaved')!.find((c) => c.id === cfg.id)!;
    expect(Date.parse(saved.lastConnectedAt!)).not.toBeNaN();
  });

  it('is a no-op for an id that is not saved', () => {
    upsertSavedRemote({ url: 'http://a.example', username: '' });
    expect(() => markRemoteConnected('nope')).not.toThrow();
    expect(Settings.get('remoteSaved')).toHaveLength(1);
  });

  it('does not stamp on save — only on a successful connection', () => {
    // Saving a server is not evidence you can get into it. If upsert stamped
    // the time, a URL typed once and never authenticated would outrank the
    // server used every day.
    upsertSavedRemote({ url: 'http://typo.example', username: '' });
    expect(Settings.get('remoteSaved')![0].lastConnectedAt).toBeUndefined();
  });
});

describe('recentServers', () => {
  it('orders most-recently-connected first', () => {
    const a = upsertSavedRemote({ url: 'http://a.example', username: '' });
    const b = upsertSavedRemote({ url: 'http://b.example', username: '' });
    const saved = Settings.get('remoteSaved')!.map((c) => ({
      ...c,
      lastConnectedAt:
        c.id === a.id ? new Date(Date.now() - 60_000).toISOString() : new Date().toISOString(),
    }));
    Settings.set('remoteSaved', saved);
    expect(recentServers().map((c) => c.id)).toEqual([b.id, a.id]);
  });

  it('sorts a never-connected server last', () => {
    // Date.parse returns NaN for a missing timestamp, and any comparison
    // involving NaN yields NaN — a comparator returning NaN leaves the array in
    // its original order, so a never-connected server stayed wherever it was
    // added rather than sinking below the one actually in use.
    const never = upsertSavedRemote({ url: 'http://never.example', username: '' });
    const used = upsertSavedRemote({ url: 'http://used.example', username: '' });
    markRemoteConnected(used.id);
    expect(recentServers().map((c) => c.id)).toEqual([used.id, never.id]);
  });

  it('does not mutate the stored list', () => {
    const a = upsertSavedRemote({ url: 'http://a.example', username: '' });
    const b = upsertSavedRemote({ url: 'http://b.example', username: '' });
    markRemoteConnected(b.id);
    recentServers();
    expect(Settings.get('remoteSaved')!.map((c) => c.id)).toEqual([a.id, b.id]);
  });

  it('returns an empty list rather than throwing when nothing is saved', () => {
    Settings.set('remoteSaved', undefined as any);
    expect(recentServers()).toEqual([]);
  });
});

describe('unlock screen server picker', () => {
  it('pre-fills the URL and username of the last server actually connected to', async () => {
    const stale = upsertSavedRemote({ url: 'http://stale.example', username: 'old' });
    const recent = upsertSavedRemote({ url: 'http://recent.example', username: 'joy' });
    markRemoteConnected(stale.id);
    // Force a distinct, later timestamp — two calls inside the same millisecond
    // would tie and make the assertion depend on sort stability.
    const saved = Settings.get('remoteSaved')!.map((c) =>
      c.id === recent.id ? { ...c, lastConnectedAt: new Date(Date.now() + 1000).toISOString() } : c,
    );
    Settings.set('remoteSaved', saved);

    await showUnlockModal(false);

    expect(($('unlock-server') as HTMLInputElement).value).toBe('http://recent.example');
    expect(($('unlock-username') as HTMLInputElement).value).toBe('joy');
  });

  it('opens the picker with an entry per saved server plus Local Vault', async () => {
    upsertSavedRemote({ url: 'http://a.example', username: '' });
    upsertSavedRemote({ url: 'http://b.example', username: '' });
    await showUnlockModal(false);

    $('unlock-server-recent').click();
    const items = document.querySelectorAll('#dropdown [data-ddid]');
    expect(items).toHaveLength(3); // Local Vault + 2 servers
    expect($('dropdown').textContent).toContain('a.example');
    expect($('dropdown').textContent).toContain('b.example');
  });

  it('picking Local Vault empties both the URL and the username', async () => {
    // Leaving a username behind while clearing the URL puts the modal in local
    // mode with a stale account still in the field — harmless on the next
    // submit, but it comes back the moment the user re-enters a server URL.
    const cfg = upsertSavedRemote({ url: 'http://a.example', username: 'joy' });
    markRemoteConnected(cfg.id);
    await showUnlockModal(false);
    expect(($('unlock-server') as HTMLInputElement).value).toBe('http://a.example');

    $('unlock-server-recent').click();
    document.querySelectorAll<HTMLElement>('#dropdown [data-ddid]')[0].click();

    expect(($('unlock-server') as HTMLInputElement).value).toBe('');
    expect(($('unlock-username') as HTMLInputElement).value).toBe('');
    expect($('unlock-title').textContent).toBe('Unlock Vault');
  });

  it('picking a server fills the URL and its paired username, and switches to remote mode', async () => {
    upsertSavedRemote({ url: 'http://a.example', username: 'joy' });
    await showUnlockModal(false);
    // Blank both fields first, or the modal's own pre-fill would satisfy the
    // assertions and the pick handler would never actually be exercised.
    ($('unlock-server') as HTMLInputElement).value = '';
    ($('unlock-username') as HTMLInputElement).value = '';

    $('unlock-server-recent').click();
    const items = document.querySelectorAll<HTMLElement>('#dropdown [data-ddid]');
    items[items.length - 1].click();

    expect(($('unlock-server') as HTMLInputElement).value).toBe('http://a.example');
    expect(($('unlock-username') as HTMLInputElement).value).toBe('joy');
    expect($('unlock-title').textContent).toBe('Connect to Remote Vault');
  });

  it('escapes a server name before putting it in the dropdown', async () => {
    // The saved list is plain JSON on disk and the name is derived from a URL
    // the user typed — invariant 4 applies here as much as to vault fields.
    Settings.set('remoteSaved', [
      {
        id: 'x',
        name: '<img src=x onerror=alert(1)>',
        url: 'http://a.example',
        username: '',
      },
    ]);
    await showUnlockModal(false);
    $('unlock-server-recent').click();
    expect($('dropdown').querySelector('img')).toBeNull();
  });

  it('says so rather than opening an empty menu when nothing is saved', async () => {
    await showUnlockModal(false);
    $('unlock-server-recent').click();
    expect($('dropdown').textContent).toContain('No servers connected yet');
  });
});

describe('unlock screen id contract', () => {
  // Same reasoning as the block in modals.test.ts: a formatter silently
  // dropping one of these elements from index.html would leave the wiring
  // querying null, and every affordance below would just do nothing.
  it('index.html still has every element the unlock screen reaches for', () => {
    [
      'unlock-server',
      'unlock-server-recent',
      'unlock-username',
      'unlock-password',
      'unlock-capslock',
      'unlock-confirm',
      'unlock-confirm-group',
      'unlock-strength',
      'unlock-strength-fill',
      'unlock-strength-label',
      'relock-password',
      'relock-capslock',
      'search-history',
      'clear-filters-btn',
      'clear-filters-count',
      's-remember-filters',
      's-clear-recent',
    ].forEach((id) => expect($(id), `#${id} missing from index.html`).toBeTruthy());
  });

  it('both password fields have a reveal button pointing at them', () => {
    ['unlock-password', 'relock-password'].forEach((id) =>
      expect(
        document.querySelector(`[data-reveal="${id}"]`),
        `no reveal button for #${id}`,
      ).toBeTruthy(),
    );
  });
});
