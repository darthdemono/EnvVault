/**
 * The app's half of row-level merging (Phase 30). The storage layer decides what
 * merges (`vault-core/src/storage.rs`); what is asserted here is what the app does
 * with the answer: a `+merged` version means our copy is behind and must be
 * reloaded, a conflict names the entries, and neither leaves a stale base behind.
 */
import { describe, it, expect, beforeEach, vi } from 'vitest';
import { st, persist, TauriVaultStore, VaultConflictError, conflictEntries } from '../src/ts/state';
import { loadRealIndexHtml, makeEntry, makeVault, resetState } from './helpers';

beforeEach(() => {
  loadRealIndexHtml();
  resetState(st);
});

function tauriStore(save: (cmd: string, args: any) => unknown) {
  (window as any).__TAURI__ = {
    core: { invoke: (cmd: string, args: any) => Promise.resolve(save(cmd, args)) },
  };
  return new TauriVaultStore();
}

describe('TauriVaultStore versions', () => {
  it('adopts a plain version as the next base', async () => {
    const calls: any[] = [];
    const store = tauriStore((cmd, args) => {
      calls.push({ cmd, args });
      return cmd === 'load_vault' ? { data: makeVault(), version: 'v1' } : 'v2';
    });
    await store.load();
    await store.save(makeVault());
    await store.save(makeVault());
    expect(calls[1].args.expectVersion).toBe('v1');
    expect(calls[2].args.expectVersion).toBe('v2');
    expect(store.takeMerged()).toBe(false);
  });

  it('strips the +merged marker, reports it once, and keeps the bare token', async () => {
    const calls: any[] = [];
    const store = tauriStore((cmd, args) => {
      calls.push({ cmd, args });
      return cmd === 'load_vault' ? { data: makeVault(), version: 'v1' } : 'v2+merged';
    });
    await store.load();
    await store.save(makeVault());
    expect(store.takeMerged()).toBe(true);
    expect(store.takeMerged()).toBe(false);
    await store.save(makeVault());
    expect(calls[2].args.expectVersion).toBe('v2');
  });

  it('turns a VAULT_CONFLICT naming entries into a VaultConflictError that carries them', async () => {
    const store = tauriStore(() => {
      throw new Error(
        'VAULT_CONFLICT: the vault changed since you last read it — you and another writer both changed: GitHub, Stripe',
      );
    });
    // invoke here throws synchronously inside the promise chain
    await expect(store.save(makeVault())).rejects.toMatchObject({ entries: 'GitHub, Stripe' });
  });
});

describe('conflictEntries', () => {
  it('reads the list or says there is none', () => {
    expect(conflictEntries('x both changed: A, B')).toBe('A, B');
    expect(conflictEntries('VAULT_CONFLICT: reload and retry')).toBeNull();
  });
});

describe('persist after a merged save', () => {
  it('reloads the vault so the next edit is made on top of what was merged', async () => {
    const merged = makeVault({
      api_keys: [
        makeEntry({ id: 'a', provider: 'Mine' }),
        makeEntry({ id: 'b', provider: 'Theirs' }),
      ],
    });
    let takes = 0;
    const load = vi.fn(async () => merged);
    st.store = {
      save: async () => {},
      load,
      takeMerged: () => ++takes === 1,
      isRemote: false,
      vaultId: 't',
    };
    st.vault = makeVault({ api_keys: [makeEntry({ id: 'a', provider: 'Mine' })] });
    await persist();
    expect(load).toHaveBeenCalledTimes(1);
    expect(st.vault.api_keys.map((e) => e.provider)).toEqual(['Mine', 'Theirs']);
    // A save that merged nothing does not reload.
    await persist();
    expect(load).toHaveBeenCalledTimes(1);
  });

  it('a conflict dialog names the entries both writers changed', async () => {
    const asked: string[] = [];
    vi.resetModules();
    vi.doMock('../src/ts/utils', async (orig) => ({
      ...(await orig<typeof import('../src/ts/utils')>()),
      showConfirm: async (m: string) => {
        asked.push(m);
        return false;
      },
      showToast: () => {},
    }));
    const state = await import('../src/ts/state');
    state.st.store = {
      save: async () => {
        throw new state.VaultConflictError('GitHub');
      },
      load: async () => makeVault(),
      isRemote: false,
      vaultId: 't',
    };
    state.st.vault = makeVault();
    await state.persist();
    expect(asked[0]).toContain('both changed: GitHub');
    expect(asked[0]).toContain('other entries were not in conflict');
    vi.doUnmock('../src/ts/utils');
    expect(new VaultConflictError().entries).toBeNull();
  });
});
