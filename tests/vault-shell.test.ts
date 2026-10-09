/**
 * The app shell in `vault.ts`: sidebar filter buttons, the card context menu
 * and the global key handler. These bind once against index.html, so the suite
 * boots the real module and re-attaches the bound nodes between tests.
 */
import { describe, it, expect, beforeAll, beforeEach, vi } from 'vitest';
import { st, resetViewState, VaultConflictError } from '../src/ts/state';
import { renderGrid } from '../src/ts/render';
import { getFiltered } from '../src/ts/filters';
import { loadRealIndexHtml, makeEntry, makeVault, resetState } from './helpers';

let confirmAnswer = true;
vi.mock('../src/ts/utils', async (importOriginal) => {
  const real = await importOriginal<typeof import('../src/ts/utils')>();
  return { ...real, showToast: () => {}, showConfirm: async () => confirmAnswer };
});

const $ = (id: string) => document.getElementById(id)!;

describe('sidebar "All" filter', () => {
  beforeEach(() => {
    loadRealIndexHtml();
    resetState(st);
    st.vault = makeVault({
      api_keys: [
        makeEntry({
          id: 'a',
          provider: 'Tagged',
          tags: ['prod'],
          env_prefixes: ['VITE'],
          environment: 'production',
        } as any),
        makeEntry({ id: 'b', provider: 'Plain' }),
      ],
    });
  });

  it('clearing every sidebar narrowing shows the whole vault again', () => {
    // The prefix filter was added after this reset was written and left out of
    // it, so "All" appeared to do nothing while the grid stayed narrowed.
    st.activeTagFilter = 'prod';
    st.activePrefixFilter = 'VITE';
    st.currentEnvFilter = 'production';
    st.currentSelectedProjectIds = ['some-project'];

    // Mirror what the "All" button handler does.
    st.currentSelectedProjectIds = ['Universal'];
    st.currentEnvFilter = '';
    st.activeTagFilter = null;
    st.activePrefixFilter = null;

    expect(getFiltered()).toHaveLength(2);
  });

  it('resetViewState also clears the prefix filter', () => {
    st.activePrefixFilter = 'VITE';
    resetViewState();
    confirmAnswer = true;
    expect(st.activePrefixFilter).toBeNull();
    expect(getFiltered()).toHaveLength(2);
  });
});

describe('expand-all button label', () => {
  beforeEach(() => {
    loadRealIndexHtml();
    resetState(st);
    st.vault = makeVault({ api_keys: [makeEntry({ id: 'a' })] });
  });

  it('follows st.allExpanded on every render, not just on click', () => {
    // lock / import / vault switch all reset st.allExpanded; the label used to
    // be flipped only inside the click handler and so read "Collapse All" with
    // nothing expanded.
    st.allExpanded = true;
    renderGrid();
    expect($('expand-all-btn').textContent).toBe('Collapse All');

    st.allExpanded = false;
    renderGrid();
    expect($('expand-all-btn').textContent).toBe('Expand All');
  });

  it('reads Expand All again after the view state is reset', () => {
    st.allExpanded = true;
    renderGrid();
    resetViewState();
    renderGrid();
    expect($('expand-all-btn').textContent).toBe('Expand All');
  });
});

describe('card context menu targets', () => {
  let boundNodes: ChildNode[] = [];

  beforeAll(async () => {
    loadRealIndexHtml();
    const markup = await import('../src/ts/tools-markup');
    markup.mountToolsPanes();
    await import('../src/ts/vault'); // running init() binds the shell handlers
    await new Promise((r) => setTimeout(r, 50));
    boundNodes = Array.from(document.body.childNodes);
  });

  beforeEach(() => {
    document.body.innerHTML = '';
    for (const n of boundNodes) document.body.appendChild(n);
    resetState(st);
    resetViewState();
    confirmAnswer = true;
    st.vault = makeVault({
      api_keys: [
        makeEntry({ id: 'a', provider: 'Alpha' }),
        makeEntry({ id: 'b', provider: 'Bravo' }),
        makeEntry({ id: 'c', provider: 'Charlie' }),
      ],
    });
    renderGrid();
  });

  function openMenuOn(provider: string) {
    const card = [...document.querySelectorAll<HTMLElement>('#card-grid .card')].find((c) =>
      c.textContent?.includes(provider),
    )!;
    card.dispatchEvent(new MouseEvent('contextmenu', { bubbles: true, cancelable: true }));
  }

  function clickMenuItem(label: string) {
    const item = [...document.querySelectorAll<HTMLElement>('#dropdown .dropdown-item')].find((i) =>
      i.textContent?.includes(label),
    )!;
    expect(item, `no menu item matching "${label}"`).toBeDefined();
    item.click();
  }

  it('deletes the entry the menu was opened on', () => {
    openMenuOn('Bravo');
    clickMenuItem('Delete');
    expect(st.vault.api_keys.map((e) => e.provider)).toEqual(['Alpha', 'Charlie']);
  });

  it('still deletes the right entry after the array shifted underneath', () => {
    // The menu captured an array position at open time. An entry removed in
    // between slid every higher position down, and Delete took a neighbour.
    openMenuOn('Charlie');
    st.vault.api_keys.splice(0, 1); // Alpha removed while the menu is open
    clickMenuItem('Delete');
    expect(st.vault.api_keys.map((e) => e.provider)).toEqual(['Bravo']);
  });

  it('duplicates the entry the menu was opened on', () => {
    openMenuOn('Alpha');
    clickMenuItem('Duplicate');
    expect(st.vault.api_keys.map((e) => e.provider)).toEqual([
      'Alpha',
      'Alpha',
      'Bravo',
      'Charlie',
    ]);
  });

  it('does not delete a bundle member when its broken-template warning is declined', async () => {
    const bundle = makeEntry({ id: 'bundle', provider: 'Discord Bot', secretType: 'bundle' });
    const member = makeEntry({
      id: 'member',
      provider: 'Discord',
      bundle_id: 'bundle',
      bundle_slot: 'discord',
    });
    const composite = makeEntry({
      id: 'composite',
      provider: 'Invite',
      secretType: 'composite',
      composite_template: 'https://example.test/?id={discord.api_key}',
      bundle_id: 'bundle',
    });
    st.vault.api_keys = [bundle, member, composite];
    renderGrid();
    confirmAnswer = false;

    document.querySelector<HTMLElement>('.bundle-member [data-action="delete"]')!.click();
    await new Promise((resolve) => setTimeout(resolve, 20));

    expect(st.vault.api_keys).toContain(member);
  });

  it('bulk-selects each bundle member once, including pooled members', () => {
    const bundle = makeEntry({ id: 'bundle', provider: 'Workspace', secretType: 'bundle' });
    const first = makeEntry({
      id: 'first',
      provider: 'First',
      bundle_id: 'bundle',
      pool: 'rotation',
    });
    const second = makeEntry({
      id: 'second',
      provider: 'Second',
      bundle_id: 'bundle',
      pool: 'rotation',
    });
    st.vault.api_keys = [bundle, first, second];
    st.bulkMode = true;
    renderGrid();
    const toggle = vi.spyOn(window, '__unvBulkToggle');

    document.querySelector<HTMLElement>('[data-action="bundle-bulk-toggle"]')!.click();

    expect(toggle.mock.calls.map(([idx]) => idx)).toEqual([1, 2]);
    toggle.mockRestore();
    st.bulkMode = false;
  });

  it('reports gracefully when the entry is gone by the time the item is clicked', () => {
    openMenuOn('Bravo');
    st.vault.api_keys = st.vault.api_keys.filter((e) => e.provider !== 'Bravo');
    expect(() => clickMenuItem('Delete')).not.toThrow();
    expect(st.vault.api_keys.map((e) => e.provider)).toEqual(['Alpha', 'Charlie']);
  });

  it('dissolves parent and members with one save', async () => {
    const save = vi.fn().mockResolvedValue(undefined);
    st.store = { save, load: async () => null, isRemote: false, vaultId: 'test' };
    st.vault.api_keys = [
      makeEntry({ id: 'bundle', provider: 'Team', secretType: 'bundle' }),
      makeEntry({ id: 'one', bundle_id: 'bundle' }),
      makeEntry({ id: 'two', bundle_id: 'bundle' }),
    ];
    renderGrid();
    document.querySelector<HTMLElement>('[data-action="bundle-dissolve"]')!.click();
    await new Promise((resolve) => setTimeout(resolve, 25));
    expect(save).toHaveBeenCalledTimes(1);
    expect(st.vault.api_keys[0].secretType).toBe('env_var');
    expect(st.vault.api_keys.slice(1).every((entry) => !entry.bundle_id)).toBe(true);
  });

  it('reloads the whole bundle if dissolve loses its compare-and-swap', async () => {
    confirmAnswer = false;
    const before = makeVault({
      api_keys: [
        makeEntry({ id: 'bundle', provider: 'Team', secretType: 'bundle' }),
        makeEntry({ id: 'member', bundle_id: 'bundle' }),
      ],
    });
    st.store = {
      save: async () => {
        throw new VaultConflictError();
      },
      load: async () => before,
      isRemote: false,
      vaultId: 'test',
    };
    st.vault = makeVault({ api_keys: before.api_keys.map((entry) => ({ ...entry })) });
    renderGrid();
    document.querySelector<HTMLElement>('[data-action="bundle-dissolve"]')!.click();
    await new Promise((resolve) => setTimeout(resolve, 25));
    expect(st.vault.api_keys[0].secretType).toBe('bundle');
    expect(st.vault.api_keys[1].bundle_id).toBe('bundle');
  });
});
