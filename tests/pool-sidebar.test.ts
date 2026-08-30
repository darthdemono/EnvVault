/**
 * The Key Pools sidebar section.
 *
 * A pool is a named set of interchangeable credentials, and it now gets a
 * sidebar section beside Tags and Env Prefixes. It is a *filter*, so it inherits
 * the whole hazard list those two already carry:
 *
 *  - invariant 3 — it must be cleared when the vault is replaced, or a pool from
 *    the previous vault leaves the grid empty with the data present and invisible;
 *  - invariant 7 — a persisted pool name must be validated against the loaded
 *    vault on read, because a pool stops existing the moment its last member's
 *    `pool` field is cleared;
 *  - invariant 4 — the name is interpolated into `innerHTML` and comes from the
 *    vault, which is untrusted input.
 *
 * Membership deliberately comes from `poolsOf()` rather than a second pass over
 * the `pool` field, so this section and Tools → Key Pools cannot disagree about
 * what a pool contains.
 */
import { describe, it, expect, beforeEach } from 'vitest';
import { render, activeFilterLabels } from '../src/ts/render';
import { getFiltered } from '../src/ts/filters';
import {
  st,
  Settings,
  resetViewState,
  clearAllFilters,
  saveViewState,
  restoreViewState,
} from '../src/ts/state';
import { loadRealIndexHtml, makeEntry, makeVault, resetState } from './helpers';

const section = () => document.getElementById('sidebar-section-pools') as HTMLElement;
const list = () => document.getElementById('pool-filter-list')!;
const buttons = () => [...list().querySelectorAll<HTMLElement>('.pool-filter-btn')];

function pooledVault() {
  return makeVault({
    api_keys: [
      makeEntry({ id: '1', provider: 'OpenAI', key_id: 'a', pool: 'openai' } as any),
      makeEntry({ id: '2', provider: 'OpenAI', key_id: 'b', pool: 'openai' } as any),
      makeEntry({ id: '3', provider: 'Anthropic', pool: 'llm-fallback' } as any),
      makeEntry({ id: '4', provider: 'Standalone' } as any),
    ],
  });
}

beforeEach(() => {
  loadRealIndexHtml();
  resetState(st, pooledVault());
  Settings.set('rememberFilters', true);
  Settings.set('lastView', null);
  Settings.set('sidebarSections', [
    'all',
    'price',
    'env',
    'category',
    'project',
    'tags',
    'pools',
    'prefixes',
  ] as any);
});

describe('the sidebar section', () => {
  it('lists one row per pool, sorted, with member counts', () => {
    render();
    expect(buttons().map((b) => b.dataset.pool)).toEqual(['llm-fallback', 'openai']);
    const counts = buttons().map((b) => b.querySelector('.sidebar-count')!.textContent);
    expect(counts).toEqual(['1', '2']);
  });

  it('stays hidden when no entry declares a pool', () => {
    st.vault = makeVault({ api_keys: [makeEntry({ provider: 'Solo' })] });
    render();
    expect(section().style.display).toBe('none');
  });

  it('is hidden when the section is switched off in settings, even with pools present', () => {
    Settings.set('sidebarSections', ['all', 'project'] as any);
    render();
    expect(section().style.display).toBe('none');
  });

  it('escapes a pool name from the vault', () => {
    // Invariant 4: the vault may have come from a remote server or an imported
    // backup, and `pool` is a plain string field nobody validates on write.
    st.vault = makeVault({
      api_keys: [makeEntry({ provider: 'X', pool: '<img src=x onerror=alert(1)>' } as any)],
    });
    render();
    expect(list().querySelector('img')).toBeNull();
    expect(list().innerHTML).toContain('&lt;img');
  });

  it('does not invent a pool from a non-string field', () => {
    st.vault = makeVault({
      api_keys: [makeEntry({ provider: 'X', pool: { nope: 1 } } as any)],
    });
    render();
    expect(section().style.display).toBe('none');
    expect(list().innerHTML).not.toContain('object Object');
  });
});

describe('filtering', () => {
  it('narrows the grid to that pool only', () => {
    st.activePoolFilter = 'openai';
    expect(getFiltered().map((e) => e.id)).toEqual(['1', '2']);
  });

  it('treats a padded pool name as the same pool the sidebar shows', () => {
    // `poolsOf` trims, so a member written as "openai " groups under "openai".
    // Comparing the raw field here would list the member in the sidebar and then
    // hide it from the grid when that row is clicked.
    st.vault.api_keys.push(makeEntry({ id: '5', provider: 'OpenAI', pool: ' openai ' } as any));
    st.activePoolFilter = 'openai';
    expect(getFiltered().map((e) => e.id)).toEqual(['1', '2', '5']);
  });

  it('marks the active row and names it in the filter chips', () => {
    st.activePoolFilter = 'openai';
    render();
    const active = buttons().filter((b) => b.classList.contains('active'));
    expect(active.map((b) => b.dataset.pool)).toEqual(['openai']);
    expect(activeFilterLabels()).toContain('pool: openai');
  });
});

describe('the reference hazards a filter carries', () => {
  it('resetViewState clears it — invariant 3', () => {
    // Replacing the vault while a pool filter is set leaves getFiltered()
    // matching nothing: every secret present, none visible, under a filter the
    // user has no memory of setting.
    st.activePoolFilter = 'openai';
    resetViewState();
    expect(st.activePoolFilter).toBeNull();
  });

  it('clearAllFilters clears it — Shift+Esc must actually show everything', () => {
    st.activePoolFilter = 'openai';
    clearAllFilters();
    expect(st.activePoolFilter).toBeNull();
    expect(getFiltered()).toHaveLength(4);
  });

  it('round-trips through the persisted view', () => {
    st.activePoolFilter = 'openai';
    saveViewState();
    st.activePoolFilter = null;
    expect(restoreViewState()).toBe(true);
    expect(st.activePoolFilter).toBe('openai');
  });

  it('drops a persisted pool the loaded vault no longer has — invariant 7', () => {
    st.activePoolFilter = 'openai';
    saveViewState();
    // The pool is gone: someone cleared `pool` on both members. Nothing in the
    // session can have cleared the localStorage copy, so the validation on read
    // is the only thing standing between the user and an empty grid.
    st.vault = makeVault({ api_keys: [makeEntry({ id: '1', provider: 'OpenAI' } as any)] });
    st.activePoolFilter = null;
    restoreViewState();
    expect(st.activePoolFilter).toBeNull();
  });

  it('survives a lastView written before pools existed', () => {
    Settings.set('lastView', {
      filterType: 'all',
      filterValue: '',
      envFilter: '',
      tagFilter: null,
      prefixFilter: null,
      projectIds: ['Universal'],
    } as any);
    expect(() => restoreViewState()).not.toThrow();
    expect(st.activePoolFilter).toBeNull();
  });
});
