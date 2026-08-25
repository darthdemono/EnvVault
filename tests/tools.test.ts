/**
 * Tools panel: bulk select/delete/export and the import normalizer.
 *
 * `initTools()` binds the whole panel once, so these drive the real buttons in
 * `index.html` rather than calling internals — that is also what catches a
 * handler wired to an id that no longer exists.
 */
import { describe, it, expect, beforeAll, beforeEach, vi } from 'vitest';
import { st, resetViewState } from '../src/ts/state';
import { loadRealIndexHtml, makeEntry, makeVault, resetState } from './helpers';

let confirmAnswer = true;
vi.mock('../src/ts/utils', async (importOriginal) => {
  const real = await importOriginal<typeof import('../src/ts/utils')>();
  return { ...real, showToast: () => {}, showConfirm: async () => confirmAnswer };
});

const $ = (id: string) => document.getElementById(id)!;
const bulkToggle = (idx: number) => (window as any).__envvBulkToggle?.(idx);

/**
 * `initTools()` binds every handler once, to the nodes present at that moment.
 * Re-parsing index.html per test would hand each test a fresh, unbound DOM, so
 * instead the initialised nodes are kept and re-attached — they carry their
 * listeners with them. This mirrors the app, where initTools also runs once.
 */
let boundNodes: ChildNode[] = [];

beforeAll(async () => {
  loadRealIndexHtml();
  // The tool panes are injected at runtime, not shipped in index.html, and
  // initTools queries them — same ordering the real init() relies on.
  const markup = await import('../src/ts/tools-markup');
  markup.mountToolsPanes();
  const mod = await import('../src/ts/tools');
  mod.initTools();
  boundNodes = Array.from(document.body.childNodes);
});

beforeEach(() => {
  document.body.innerHTML = '';
  for (const node of boundNodes) document.body.appendChild(node);
  resetState(st);
  resetViewState();
  confirmAnswer = true;
});

describe('bulk selection identity', () => {
  beforeEach(() => {
    st.vault = makeVault({
      api_keys: [
        makeEntry({ id: 'a', provider: 'Alpha', api_key: 'sk-a' }),
        makeEntry({ id: 'b', provider: 'Bravo', api_key: 'sk-b' }),
        makeEntry({ id: 'c', provider: 'Charlie', api_key: 'sk-c' }),
      ],
    });
    st.bulkMode = true;
    st.bulkSelected.clear();
  });

  it('records the entry id, not its array position', () => {
    bulkToggle(1);
    expect([...st.bulkSelected]).toEqual(['b']);
  });

  it('toggles a selection off', () => {
    bulkToggle(1);
    bulkToggle(1);
    expect(st.bulkSelected.size).toBe(0);
  });

  it('still points at the same entry after the array shifts', () => {
    // The bug: the selection was a set of indices, so removing an earlier entry
    // slid every higher selection onto its neighbour and bulk delete then
    // removed the wrong secrets.
    bulkToggle(2); // tick Charlie
    st.vault.api_keys.splice(0, 1); // Alpha deleted elsewhere
    const selected = st.vault.api_keys.filter((e) => e.id && st.bulkSelected.has(e.id));
    expect(selected.map((e) => e.provider)).toEqual(['Charlie']);
  });

  it('is cleared when the vault is replaced', () => {
    bulkToggle(0);
    resetViewState();
    expect(st.bulkSelected.size).toBe(0);
    expect(st.bulkMode).toBe(false);
  });

  it('ignores a toggle for an index that no longer exists', () => {
    expect(() => bulkToggle(99)).not.toThrow();
    expect(st.bulkSelected.size).toBe(0);
  });
});

describe('bulk delete', () => {
  beforeEach(() => {
    st.vault = makeVault({
      api_keys: [
        makeEntry({ id: 'a', provider: 'Alpha' }),
        makeEntry({ id: 'b', provider: 'Bravo' }),
        makeEntry({ id: 'c', provider: 'Charlie' }),
        makeEntry({ id: 'd', provider: 'Delta' }),
      ],
    });
    st.bulkMode = true;
    st.bulkSelected.clear();
  });

  async function clickDelete() {
    $('bulk-delete-btn').click();
    await new Promise((r) => setTimeout(r, 20));
  }

  it('deletes exactly the ticked entries', async () => {
    st.bulkSelected.add('b');
    st.bulkSelected.add('d');
    await clickDelete();
    expect(st.vault.api_keys.map((e) => e.provider)).toEqual(['Alpha', 'Charlie']);
  });

  it('deletes the ticked entries even after the array shifted', async () => {
    st.bulkSelected.add('c');
    st.vault.api_keys.splice(0, 1); // Alpha removed after ticking
    await clickDelete();
    expect(st.vault.api_keys.map((e) => e.provider)).toEqual(['Bravo', 'Delta']);
  });

  it('does nothing when the user cancels', async () => {
    confirmAnswer = false;
    st.bulkSelected.add('b');
    await clickDelete();
    expect(st.vault.api_keys).toHaveLength(4);
  });

  it('does nothing when the selection is empty', async () => {
    await clickDelete();
    expect(st.vault.api_keys).toHaveLength(4);
  });

  it('clears reveal state for everything it deleted', async () => {
    st.revealed['key-b'] = true;
    st.revealed['secret-b'] = true;
    st.bulkSelected.add('b');
    await clickDelete();
    expect(st.revealed).toEqual({});
  });

  it('leaves bulk mode afterwards', async () => {
    st.bulkSelected.add('b');
    await clickDelete();
    expect(st.bulkMode).toBe(false);
    expect(st.bulkSelected.size).toBe(0);
  });
});

describe('bulk export', () => {
  beforeEach(() => {
    st.vault = makeVault({
      api_keys: [
        makeEntry({ id: 'a', provider: 'Alpha Co', api_key: 'sk-a' }),
        makeEntry({ id: 'b', provider: 'Bravo', api_key: 'sk-b' }),
      ],
    });
    st.bulkMode = true;
    st.bulkSelected.clear();
    (URL as any).createObjectURL = vi.fn(() => 'blob:mock');
    (URL as any).revokeObjectURL = vi.fn();
  });

  it('asks before writing plaintext secrets to disk', async () => {
    confirmAnswer = false;
    st.bulkSelected.add('a');
    $('bulk-export-btn').click();
    await new Promise((r) => setTimeout(r, 20));
    expect((URL as any).createObjectURL).not.toHaveBeenCalled();
  });

  it('exports only the ticked entries once confirmed', async () => {
    st.bulkSelected.add('a');
    $('bulk-export-btn').click();
    await new Promise((r) => setTimeout(r, 20));
    const blob = (URL as any).createObjectURL.mock.calls[0][0] as Blob;
    const text = await blob.text();
    expect(text).toBe('ALPHA_CO=sk-a');
    expect(text).not.toContain('sk-b');
  });

  it('does not revoke the object URL before the download can start', async () => {
    st.bulkSelected.add('a');
    $('bulk-export-btn').click();
    await new Promise((r) => setTimeout(r, 20));
    // Revoking synchronously cancelled the download under WebKitGTK.
    expect((URL as any).revokeObjectURL).not.toHaveBeenCalled();
  });
});

describe('normalizeImported', () => {
  let normalizeImported: typeof import('../src/ts/tools').normalizeImported;
  let sorted: typeof import('../src/ts/filters').sorted;

  beforeAll(async () => {
    normalizeImported = (await import('../src/ts/tools')).normalizeImported;
    sorted = (await import('../src/ts/filters')).sorted;
  });

  it('rejects an object with no provider name', () => {
    // Such an entry reached sorted(), which calls provider.localeCompare and
    // threw — one malformed row in an imported file took the grid down.
    expect(normalizeImported({ api_key: 'sk-1' })).toBeNull();
    expect(normalizeImported({ provider: '   ', api_key: 'sk-1' })).toBeNull();
  });

  it('rejects non-objects', () => {
    expect(normalizeImported(null)).toBeNull();
    expect(normalizeImported('a string')).toBeNull();
    expect(normalizeImported([1, 2])).toBeNull();
  });

  it('accepts name as an alias for provider', () => {
    expect(normalizeImported({ name: 'Stripe' })!.provider).toBe('Stripe');
  });

  it('fills in the arrays the renderer assumes are present', () => {
    const e = normalizeImported({ provider: 'Stripe' })!;
    expect(e.categories).toEqual([]);
    expect(e.scopes).toEqual([]);
    expect(e.projectIds).toEqual(['Universal']);
    expect(e.secretType).toBe('api_key');
  });

  it('always includes Universal in projectIds', () => {
    expect(normalizeImported({ provider: 'S', projectIds: ['p1'] })!.projectIds).toEqual([
      'p1',
      'Universal',
    ]);
  });

  it('replaces a bogus price_type with free', () => {
    expect(normalizeImported({ provider: 'S', price_type: 'gratis' })!.price_type).toBe('free');
    expect(normalizeImported({ provider: 'S', price_type: 'paid' })!.price_type).toBe('paid');
  });

  it('coerces a non-string api_key', () => {
    expect(normalizeImported({ provider: 'S', api_key: 12345 })!.api_key).toBe('12345');
    expect(normalizeImported({ provider: 'S' })!.api_key).toBe('');
  });

  it('preserves fields it does not police', () => {
    const e = normalizeImported({ provider: 'S', api_url: 'https://x', tags: ['t'] })!;
    expect(e.api_url).toBe('https://x');
    expect(e.tags).toEqual(['t']);
  });

  it('produces entries that survive a sort', () => {
    const entries = [{ api_key: 'orphan' }, { provider: 'Zeta' }, { provider: 'Alpha' }]
      .map(normalizeImported)
      .filter((e): e is NonNullable<typeof e> => e !== null);
    expect(() => sorted(entries)).not.toThrow();
    expect(sorted(entries).map((e) => e.provider)).toEqual(['Alpha', 'Zeta']);
  });
});

describe('diff tool identity', () => {
  it('lists entries by id so a later delete cannot misdirect the diff', async () => {
    st.vault = makeVault({
      api_keys: [
        makeEntry({ id: 'a', provider: 'Alpha' }),
        makeEntry({ id: 'b', provider: 'Bravo' }),
      ],
    });
    document.querySelector<HTMLElement>('.tool-nav-btn[data-tool="diff"]')?.click();
    const values = [...$('diff-a').querySelectorAll('option')].map(
      (o) => (o as HTMLOptionElement).value,
    );
    expect(values).toContain('a');
    expect(values).toContain('b');
    expect(values).not.toContain('0');
  });
});
