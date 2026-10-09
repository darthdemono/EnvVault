/**
 * Phase 30.1: persist() sends a delta when the last-synced state can be trusted
 * and the whole document when it cannot. The server and Rust halves are tested
 * where they live; this pins the client's decision.
 */
import { describe, it, expect, beforeEach } from 'vitest';
import { st, persist, forgetSynced, currentPatch, type VaultStore } from '../src/ts/state';
import type { VaultData, VaultEntry } from '../src/ts/types';

interface Sent {
  whole: VaultData[];
  patches: unknown[];
}

function stub(opts: { refuse?: boolean; fail?: boolean } = {}): VaultStore & Sent {
  const sent: Sent = { whole: [], patches: [] };
  return {
    ...sent,
    isRemote: true,
    vaultId: 'stub',
    load: () => Promise.resolve(null),
    save(d: VaultData) {
      this.whole.push(JSON.parse(JSON.stringify(d)) as VaultData);
      return Promise.resolve();
    },
    saveRows(p: unknown) {
      if (opts.refuse) return Promise.resolve(false);
      this.patches.push(p);
      return Promise.resolve(true);
    },
    lastSaveFailed: () => !!opts.fail,
  } as VaultStore & Sent;
}

const e = (id: string, extra: Partial<VaultEntry> = {}) =>
  ({ id, provider: id, api_key: 'k', ...extra }) as VaultEntry;

let store: VaultStore & Sent;
beforeEach(() => {
  forgetSynced();
  store = stub();
  st.store = store;
  st.vault = {
    api_keys: [e('a'), e('b')],
    user_categories: [],
    projects: [{ id: 'Universal', name: 'Universal', description: '' }],
  };
});

describe('persist: whole first, then deltas', () => {
  it('saves whole once, then only the changed entry', async () => {
    await persist();
    expect(store.whole).toHaveLength(1);
    st.vault.api_keys[1].api_key = 'new';
    await persist();
    expect(store.whole).toHaveLength(1);
    expect(store.patches).toEqual([{ put: [e('b', { api_key: 'new' })] }]);
  });

  it('sends adds as puts and removals as deletes', async () => {
    await persist();
    st.vault.api_keys.splice(0, 1);
    st.vault.api_keys.push(e('c'));
    await persist();
    expect(store.patches).toEqual([{ put: [e('c')], delete: ['a'] }]);
  });

  it('sends project and category changes', async () => {
    await persist();
    st.vault.projects.push({ id: 'p2', name: 'P2', description: '' });
    st.vault.user_categories = ['x'];
    expect(currentPatch()).toBeNull(); // categories array was replaced: untrusted
    await persist();
    expect(store.whole).toHaveLength(2);
    st.vault.user_categories.push('y');
    st.vault.projects[1].name = 'P2b';
    await persist();
    expect(store.patches).toEqual([
      { projects_put: [{ id: 'p2', name: 'P2b', description: '' }], categories: ['x', 'y'] },
    ]);
  });

  it('sends nothing when nothing changed', async () => {
    await persist();
    await persist();
    expect(store.whole).toHaveLength(1);
    expect(store.patches).toHaveLength(0);
  });
});

describe('persist: when a delta cannot be trusted', () => {
  it('falls back to the whole document after the entries array is replaced', async () => {
    await persist();
    st.vault.api_keys = st.vault.api_keys.filter((x) => x.id !== 'a');
    await persist();
    expect(store.whole).toHaveLength(2);
    expect(store.patches).toHaveLength(0);
  });

  it('falls back when entries were reordered', async () => {
    await persist();
    st.vault.api_keys.reverse();
    await persist();
    expect(store.whole).toHaveLength(2);
  });

  it('falls back when the store refuses deltas (a sub-user)', async () => {
    st.store = store = stub({ refuse: true });
    await persist();
    st.vault.api_keys[0].api_key = 'z';
    await persist();
    expect(store.whole).toHaveLength(2);
  });

  it('keeps the old snapshot when a save did not reach the store', async () => {
    await persist();
    st.store = store = stub({ fail: true });
    forgetSynced();
    await persist(); // whole, fails: no snapshot taken
    st.vault.api_keys[0].api_key = 'z';
    await persist();
    expect(store.whole).toHaveLength(2); // still whole, never a delta against a failed base
  });

  it('forgetSynced forces a whole save', async () => {
    await persist();
    forgetSynced();
    st.vault.api_keys[0].api_key = 'z';
    await persist();
    expect(store.whole).toHaveLength(2);
  });
});
