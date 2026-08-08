/**
 * Import paths replace `st.vault` wholesale. Every view-scoped selection that
 * pointed into the old vault has to be dropped with it — otherwise the import
 * succeeds and the user is shown an empty grid.
 */
import { describe, it, expect, beforeEach, vi } from 'vitest';
import { st, resetViewState } from '../src/ts/state';
import { handleFileSelect, parseEnvFile } from '../src/ts/import-export';
import { getFiltered } from '../src/ts/filters';
import { loadRealIndexHtml, makeEntry, makeProject, makeVault, resetState } from './helpers';

vi.mock('../src/ts/utils', async (importOriginal) => {
  const real = await importOriginal<typeof import('../src/ts/utils')>();
  return { ...real, showToast: () => {}, showConfirm: async () => true };
});

beforeEach(() => {
  loadRealIndexHtml();
  resetState(st);
});

/** Drives the real file-drop path with a JSON vault. */
async function importJson(vault: any): Promise<void> {
  const input = document.createElement('input');
  Object.defineProperty(input, 'files', {
    value: [new File([JSON.stringify(vault)], 'vault.json', { type: 'application/json' })],
  });
  handleFileSelect(input);
  // FileReader resolves on a macrotask.
  await new Promise(r => setTimeout(r, 50));
}

const INCOMING = {
  api_keys: [
    { id: 'shared-id', provider: 'NewKey', api_key: 'sk-new', price_type: 'free', categories: [], scopes: [] },
    { provider: 'Second', api_key: 'sk-2', price_type: 'free', categories: [], scopes: [] },
  ],
  projects: [{ id: 'Universal', name: 'Universal' }],
  user_categories: ['newcat'],
};

describe('resetViewState', () => {
  it('clears every selection that can outlive the data behind it', () => {
    st.filter = { type: 'category', value: 'gone' };
    st.searchQ = 'stale';
    st.currentSelectedProjectIds = ['gone-project'];
    st.currentEnvFilter = 'production';
    st.activeTagFilter = 'gone-tag';
    st.activePrefixFilter = 'GONE';
    st.expanded.add('gone-entry');
    st.allExpanded = true;
    st.revealed['key-gone-entry'] = true;

    resetViewState();

    expect(st.filter).toEqual({ type: 'all', value: '' });
    expect(st.searchQ).toBe('');
    expect(st.currentSelectedProjectIds).toEqual(['Universal']);
    expect(st.currentEnvFilter).toBe('');
    expect(st.activeTagFilter).toBeNull();
    expect(st.activePrefixFilter).toBeNull();
    expect(st.expanded.size).toBe(0);
    expect(st.allExpanded).toBe(false);
    expect(st.revealed).toEqual({});
  });

  it('clears the search box so the input matches the cleared query', () => {
    const box = document.getElementById('search') as HTMLInputElement;
    box.value = 'stale';
    document.getElementById('search-clear')!.classList.add('visible');
    resetViewState();
    expect(box.value).toBe('');
    expect(document.getElementById('search-clear')!.classList.contains('visible')).toBe(false);
  });
});

describe('importing a vault', () => {
  beforeEach(() => {
    st.vault = makeVault({
      projects: [makeProject({ id: 'Universal', name: 'Universal' }), makeProject({ id: 'old-proj', name: 'Old' })],
      user_categories: ['oldcat'],
      api_keys: [makeEntry({ id: 'shared-id', provider: 'OldKey', projectIds: ['Universal', 'old-proj'] })],
    });
  });

  it('replaces the entries', async () => {
    await importJson(INCOMING);
    expect(st.vault.api_keys.map(e => e.provider)).toEqual(['NewKey', 'Second']);
  });

  it('shows the imported entries instead of an empty grid', async () => {
    // The bug: a project selected against the previous vault survived the
    // import, matched nothing, and the freshly imported vault looked empty.
    st.currentSelectedProjectIds = ['old-proj'];
    await importJson(INCOMING);
    expect(st.currentSelectedProjectIds).toEqual(['Universal']);
    expect(getFiltered()).toHaveLength(2);
  });

  it('drops a tag filter that the new vault cannot satisfy', async () => {
    st.activeTagFilter = 'gone';
    await importJson(INCOMING);
    expect(st.activeTagFilter).toBeNull();
    expect(getFiltered()).toHaveLength(2);
  });

  it('drops a category filter from the previous vault', async () => {
    st.filter = { type: 'category', value: 'oldcat' };
    await importJson(INCOMING);
    expect(st.filter).toEqual({ type: 'all', value: '' });
    expect(getFiltered()).toHaveLength(2);
  });

  it('drops a stale search query', async () => {
    st.searchQ = 'oldkey';
    await importJson(INCOMING);
    expect(st.searchQ).toBe('');
    expect(getFiltered()).toHaveLength(2);
  });

  it('does not carry reveal state onto an imported entry that reuses an id', async () => {
    // revealed is keyed by entry id, so a colliding id would render an
    // imported secret unmasked without the user asking for it.
    st.revealed['key-shared-id'] = true;
    await importJson(INCOMING);
    expect(st.revealed).toEqual({});
  });

  it('backfills Universal onto imported entries that lack it', async () => {
    await importJson(INCOMING);
    for (const entry of st.vault.api_keys) expect(entry.projectIds).toContain('Universal');
  });

  it('defaults a missing secretType on imported entries', async () => {
    await importJson(INCOMING);
    for (const entry of st.vault.api_keys) expect(entry.secretType).toBe('api_key');
  });

  it('leaves the vault untouched when the file is not a vault', async () => {
    const input = document.createElement('input');
    Object.defineProperty(input, 'files', {
      value: [new File(['{"nope":1}'], 'bad.json', { type: 'application/json' })],
    });
    handleFileSelect(input);
    await new Promise(r => setTimeout(r, 50));
    expect(st.vault.api_keys.map(e => e.provider)).toEqual(['OldKey']);
  });
});

describe('parseEnvFile', () => {
  it('reads plain KEY=value pairs', () => {
    expect(parseEnvFile('A=1\nB=2')).toEqual([{ name: 'A', value: '1' }, { name: 'B', value: '2' }]);
  });

  it('skips comments and blank lines', () => {
    expect(parseEnvFile('# note\n\nA=1')).toEqual([{ name: 'A', value: '1' }]);
  });

  it('strips an export prefix', () => {
    expect(parseEnvFile('export A=1')).toEqual([{ name: 'A', value: '1' }]);
  });

  it('unwraps matching quotes', () => {
    expect(parseEnvFile(`A="q"\nB='s'`)).toEqual([{ name: 'A', value: 'q' }, { name: 'B', value: 's' }]);
  });

  it('keeps an = inside the value', () => {
    expect(parseEnvFile('URL=postgres://u:p@h/db?x=1')).toEqual([{ name: 'URL', value: 'postgres://u:p@h/db?x=1' }]);
  });

  it('joins backslash continuations without inserting a separator', () => {
    // Shell semantics: the backslash-newline vanishes, so the halves abut.
    expect(parseEnvFile('A=one\\\n  two')).toEqual([{ name: 'A', value: 'onetwo' }]);
  });

  it('ignores a line with no equals sign', () => {
    expect(parseEnvFile('JUST_A_NAME\nA=1')).toEqual([{ name: 'A', value: '1' }]);
  });
});
