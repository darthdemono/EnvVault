/**
 * Locking the vault. The bar is simple: after a lock, nothing secret may remain
 * reachable — not in `st.vault`, not in a pending undo closure, not on screen.
 */
import { describe, it, expect, beforeEach, vi } from 'vitest';
import { st, LocalVaultStore } from '../src/ts/state';
import { lockVault, showRelockScreen } from '../src/ts/lock';
import { deleteKey } from '../src/ts/modals';
import { loadRealIndexHtml, makeEntry, makeProject, makeVault, resetState } from './helpers';

vi.mock('../src/ts/utils', async (importOriginal) => {
  const real = await importOriginal<typeof import('../src/ts/utils')>();
  return { ...real, showToast: () => {}, showConfirm: async () => true };
});

beforeEach(() => {
  loadRealIndexHtml();
  resetState(st);
  st.store = new LocalVaultStore();
  st.vault = makeVault({
    projects: [
      makeProject({ id: 'Universal', name: 'Universal' }),
      makeProject({ id: 'p1', name: 'Acme' }),
    ],
    user_categories: ['infra'],
    api_keys: [
      makeEntry({ id: 'a', provider: 'Alpha', api_key: 'sk-alpha-secret' }),
      makeEntry({ id: 'b', provider: 'Bravo', api_key: 'sk-bravo-secret' }),
    ],
  });
  st.vaultOpen = true;
});

describe('lockVault', () => {
  it('empties the in-memory vault', async () => {
    await lockVault('manual');
    expect(st.vault.api_keys).toEqual([]);
    expect(st.vault.user_categories).toEqual([]);
    expect(st.vault.projects.map((p) => p.id)).toEqual(['Universal']);
  });

  it('drops pending undos, which hold deleted secrets', async () => {
    // An undo closes over the entry it would restore, secret included, and the
    // Undo button stayed live after locking — so a locked vault still held
    // plaintext in memory and offered a button that put it back.
    deleteKey(new MouseEvent('click'), 0);
    expect(st.undoStack).toHaveLength(1);

    await lockVault('manual');
    expect(st.undoStack).toEqual([]);
    expect(document.getElementById('undo-bar')!.classList.contains('visible')).toBe(false);
  });

  it('leaves no trace of a deleted secret reachable through the undo stack', async () => {
    deleteKey(new MouseEvent('click'), 1);
    await lockVault('manual');
    expect(JSON.stringify(st.undoStack)).not.toContain('sk-bravo-secret');
    expect(JSON.stringify(st.vault)).not.toContain('sk-bravo-secret');
  });

  it('clears the session storage copy', async () => {
    sessionStorage.setItem(
      'envvault',
      JSON.stringify({ api_keys: [{ api_key: 'sk-alpha-secret' }] }),
    );
    await lockVault('manual');
    expect(sessionStorage.getItem('envvault')).toBeNull();
  });

  it('turns off bulk mode', async () => {
    // Bulk mode survived a lock, so the grid came back mid-selection.
    st.bulkMode = true;
    st.bulkSelected.add('a');
    await lockVault('manual');
    expect(st.bulkMode).toBe(false);
    expect(st.bulkSelected.size).toBe(0);
  });

  it('clears reveal and expand state', async () => {
    st.revealed['key-a'] = true;
    st.expanded.add('a');
    st.allExpanded = true;
    await lockVault('manual');
    expect(st.revealed).toEqual({});
    expect(st.expanded.size).toBe(0);
    expect(st.allExpanded).toBe(false);
  });

  it('clears filters and the search box', async () => {
    st.searchQ = 'alpha';
    (document.getElementById('search') as HTMLInputElement).value = 'alpha';
    st.activeTagFilter = 'prod';
    st.currentSelectedProjectIds = ['p1'];
    await lockVault('manual');
    expect(st.searchQ).toBe('');
    expect((document.getElementById('search') as HTMLInputElement).value).toBe('');
    expect(st.activeTagFilter).toBeNull();
    expect(st.currentSelectedProjectIds).toEqual(['Universal']);
  });

  it('marks the vault closed', async () => {
    await lockVault('manual');
    expect(st.vaultOpen).toBe(false);
  });

  it('reports the locked state in the header', async () => {
    await lockVault('manual');
    expect(document.getElementById('lock-status')!.textContent).toBe('Locked');
  });
});

describe('showRelockScreen', () => {
  it('explains why the vault locked', () => {
    showRelockScreen('auto');
    expect(document.getElementById('relock-reason')!.textContent).toMatch(/inactivity/i);
    showRelockScreen('visibility');
    expect(document.getElementById('relock-reason')!.textContent).toMatch(/background/i);
    showRelockScreen('switch');
    expect(document.getElementById('relock-reason')!.textContent).toMatch(/local vault/i);
  });

  it('opens with an empty password field and no stale error', () => {
    const pw = document.getElementById('relock-password') as HTMLInputElement;
    pw.value = 'left over';
    document.getElementById('relock-error')!.style.display = 'block';
    showRelockScreen('manual');
    expect(pw.value).toBe('');
    expect(document.getElementById('relock-error')!.style.display).toBe('none');
  });

  it('masks the password input', () => {
    showRelockScreen('manual');
    expect((document.getElementById('relock-password') as HTMLInputElement).type).toBe('password');
  });

  it('opens the overlay', () => {
    showRelockScreen('manual');
    expect(document.getElementById('relock-overlay')!.classList.contains('open')).toBe(true);
  });
});
