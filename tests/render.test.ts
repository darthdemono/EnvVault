/**
 * Card-grid rendering tests.
 *
 * The grid is built by string interpolation into `innerHTML`, so the escaping
 * assertions here are load-bearing security tests, not cosmetics: a vault entry
 * is attacker-influenced data the moment a shared/remote vault is in play.
 */
import { describe, it, expect, beforeEach } from 'vitest';
import { renderGrid, render, updateCopyAllBtn } from '../src/ts/render';
import { st, Settings } from '../src/ts/state';
import { loadRealIndexHtml, makeEntry, makeProject, makeVault, resetState } from './helpers';

const grid = () => document.getElementById('card-grid')!;
const cards = () => [...grid().querySelectorAll('.card')];

beforeEach(() => {
  loadRealIndexHtml();
  resetState(st);
  Settings.set('maskKeysByDefault', true);
  Settings.set('groupByType', false);
});

describe('renderGrid', () => {
  it('renders one card per entry', () => {
    st.vault.api_keys = [makeEntry({ provider: 'A' }), makeEntry({ provider: 'B' }), makeEntry({ provider: 'C' })];
    renderGrid();
    expect(cards()).toHaveLength(3);
  });

  it('shows an empty state instead of cards when nothing matches', () => {
    st.vault.api_keys = [];
    renderGrid();
    expect(cards()).toHaveLength(0);
    expect(grid().querySelector('.empty-state')).not.toBeNull();
  });

  it('hints at the search when the grid is empty because of a query', () => {
    st.vault.api_keys = [makeEntry({ provider: 'GitHub' })];
    st.searchQ = 'nothing-matches-this';
    renderGrid();
    expect(grid().querySelector('.empty-state')!.textContent).toMatch(/different search/i);
  });

  it('updates the result count with correct pluralisation', () => {
    st.vault.api_keys = [makeEntry()];
    renderGrid();
    expect(document.getElementById('result-count')!.textContent).toBe('1 secret');
    st.vault.api_keys.push(makeEntry());
    renderGrid();
    expect(document.getElementById('result-count')!.textContent).toBe('2 secrets');
  });

  it('replaces the previous render rather than appending to it', () => {
    st.vault.api_keys = [makeEntry(), makeEntry()];
    renderGrid();
    renderGrid();
    expect(cards()).toHaveLength(2);
  });

  it('tags each card with its index in the underlying array, not its display position', () => {
    // Sorting reorders the DOM; data-idx must still point at the real entry,
    // otherwise edit/delete act on the wrong secret.
    st.vault.api_keys = [makeEntry({ provider: 'Zeta' }), makeEntry({ provider: 'Alpha' })];
    renderGrid();
    const first = cards()[0];
    expect(first.querySelector('.card-provider')!.textContent).toContain('Alpha');
    expect(first.getAttribute('data-idx')).toBe('1');
  });

  it('groups by type with headers when the setting is on', () => {
    Settings.set('groupByType', true);
    st.vault.api_keys = [
      makeEntry({ provider: 'k', secretType: 'api_key' }),
      makeEntry({ provider: 'p', secretType: 'password' }),
    ];
    renderGrid();
    const headers = [...grid().querySelectorAll('.type-group-header')].map(h => h.textContent);
    expect(headers).toEqual(['API Keys', 'Passwords']);
    expect(cards()).toHaveLength(2);
  });

  it('honours the active tag filter', () => {
    st.vault.api_keys = [
      makeEntry({ provider: 'Tagged', tags: ['prod'] }),
      makeEntry({ provider: 'Plain' }),
    ];
    st.activeTagFilter = 'prod';
    renderGrid();
    expect(cards()).toHaveLength(1);
    expect(cards()[0].textContent).toContain('Tagged');
  });
});

describe('secret masking', () => {
  it('masks the key by default and keeps the plaintext out of the rendered text', () => {
    st.vault.api_keys = [makeEntry({ provider: 'GitHub', api_key: 'sk-live-SUPERSECRETVALUE' })];
    renderGrid();
    const kv = grid().querySelector('.key-value')!;
    expect(kv.textContent).not.toBe('sk-live-SUPERSECRETVALUE');
    expect(kv.textContent).toContain('••');
  });

  it('renders the plaintext when the entry has been explicitly revealed', () => {
    const entry = makeEntry({ id: 'e1', api_key: 'sk-live-SUPERSECRETVALUE' });
    st.vault.api_keys = [entry];
    st.revealed['key-e1'] = true;
    renderGrid();
    expect(grid().querySelector('.key-value')!.textContent).toBe('sk-live-SUPERSECRETVALUE');
  });

  it('keeps a revealed secret revealed across a re-render', () => {
    // Regression: the mask state used to be read from settings alone, so any
    // re-render silently re-masked a secret the user had just revealed.
    const entry = makeEntry({ id: 'e1', api_key: 'sk-plain' });
    st.vault.api_keys = [entry];
    st.revealed['key-e1'] = true;
    renderGrid();
    renderGrid();
    expect(grid().querySelector('.key-value')!.textContent).toBe('sk-plain');
  });

  it('carries the true secret in data-value so copy works while masked', () => {
    st.vault.api_keys = [makeEntry({ api_key: 'sk-live-VALUE' })];
    renderGrid();
    expect(grid().querySelector('.key-value')!.getAttribute('data-value')).toBe('sk-live-VALUE');
  });

  it('round-trips a secret containing an HTML entity through data-value', () => {
    // The `&`-escaping bug corrupted exactly this shape of secret on copy.
    const secret = 'p@ss&amp;w<o>rd"quoted"';
    st.vault.api_keys = [makeEntry({ api_key: secret })];
    renderGrid();
    expect(grid().querySelector('.key-value')!.getAttribute('data-value')).toBe(secret);
  });

  it('masks extra vars flagged secret and leaves the others readable', () => {
    st.vault.api_keys = [makeEntry({
      id: 'e1',
      extra_vars: [{ key: 'PUBLIC', value: 'visible', secret: false }, { key: 'PRIVATE', value: 'hidden-value', secret: true }],
    })];
    st.expanded = new Set(['e1']);
    renderGrid();
    const text = grid().textContent!;
    expect(text).toContain('visible');
    expect(text).not.toContain('hidden-value');
  });
});

describe('untrusted entry content', () => {
  it('does not execute markup in the provider name', () => {
    st.vault.api_keys = [makeEntry({ provider: '<img src=x onerror=alert(1)>' })];
    renderGrid();
    expect(grid().querySelector('img')).toBeNull();
    expect(grid().textContent).toContain('<img src=x onerror=alert(1)>');
  });

  it('does not execute markup in description, key_id or category names', () => {
    st.vault.api_keys = [makeEntry({
      id: 'e1',
      key_id: '<script>a</script>',
      description: '<iframe src=evil></iframe>',
      categories: ['<b>cat</b>'],
    })];
    st.expanded = new Set(['e1']);
    renderGrid();
    expect(grid().querySelector('script')).toBeNull();
    expect(grid().querySelector('iframe')).toBeNull();
    expect(grid().querySelector('b')).toBeNull();
  });

  it('renders an http(s) API URL as a link with rel="noopener noreferrer"', () => {
    st.vault.api_keys = [makeEntry({ id: 'e1', api_url: 'https://api.example.com' })];
    st.expanded = new Set(['e1']);
    renderGrid();
    const link = grid().querySelector<HTMLAnchorElement>('a[href="https://api.example.com"]')!;
    expect(link).not.toBeNull();
    expect(link.rel).toBe('noopener noreferrer');
    expect(link.target).toBe('_blank');
  });

  it('refuses to link a javascript: URL, rendering it as inert text', () => {
    st.vault.api_keys = [makeEntry({ id: 'e1', api_url: 'javascript:alert(document.cookie)' })];
    st.expanded = new Set(['e1']);
    renderGrid();
    expect(grid().querySelector('a[href^="javascript:"]')).toBeNull();
    expect(grid().textContent).toContain('javascript:alert(document.cookie)');
  });

  it('refuses to link a data: URL', () => {
    st.vault.api_keys = [makeEntry({ id: 'e1', callback_url: 'data:text/html,<script>alert(1)</script>' })];
    st.expanded = new Set(['e1']);
    renderGrid();
    expect(grid().querySelector('a[href^="data:"]')).toBeNull();
  });

  it('is not fooled by mixed-case or padded javascript: schemes', () => {
    st.vault.api_keys = [makeEntry({ id: 'e1', api_url: '  JaVaScRiPt:alert(1)' })];
    st.expanded = new Set(['e1']);
    renderGrid();
    expect(grid().querySelector('a')).toBeNull();
  });
});

describe('card badges', () => {
  it('shows a pin badge in the collapsed header for a pinned entry', () => {
    // The badge lives in .card-provider so it is visible without expanding.
    st.vault.api_keys = [makeEntry({ provider: 'Pinned', pinned: true })];
    renderGrid();
    expect(grid().querySelector('.card-provider .pin-badge')).not.toBeNull();
    expect(cards()[0].classList.contains('pinned')).toBe(true);
  });

  it('omits the pin badge for an unpinned entry', () => {
    st.vault.api_keys = [makeEntry({ provider: 'Plain' })];
    renderGrid();
    expect(grid().querySelector('.pin-badge')).toBeNull();
  });

  it('floats pinned entries to the top of the grid', () => {
    st.vault.api_keys = [makeEntry({ provider: 'Aaa' }), makeEntry({ provider: 'Zzz', pinned: true })];
    renderGrid();
    expect(cards()[0].textContent).toContain('Zzz');
  });

  it('marks a compromised entry', () => {
    st.vault.api_keys = [makeEntry({ compromised: true })];
    renderGrid();
    expect(grid().querySelector('.badge-compromised')).not.toBeNull();
  });

  it('flags an overdue rotation', () => {
    const longAgo = new Date(Date.now() - 400 * 86_400_000).toISOString();
    st.vault.api_keys = [makeEntry({ rotation_days: 30, last_rotated_at: longAgo })];
    renderGrid();
    expect(grid().querySelector('.badge-rotation-due')).not.toBeNull();
  });

  it('does not flag a rotation that is not yet due', () => {
    st.vault.api_keys = [makeEntry({ rotation_days: 30, last_rotated_at: new Date().toISOString() })];
    renderGrid();
    expect(grid().querySelector('.badge-rotation-due')).toBeNull();
  });

  it('shows the environment badge with its env as a data attribute', () => {
    st.vault.api_keys = [makeEntry({ environment: 'production' })];
    renderGrid();
    expect(grid().querySelector('.badge-env')!.getAttribute('data-env')).toBe('production');
  });
});

describe('tag sidebar section', () => {
  it('renders a chip per distinct tag, sorted, with counts', () => {
    st.vault.api_keys = [
      makeEntry({ tags: ['prod', 'db'] }),
      makeEntry({ tags: ['prod'] }),
    ];
    render();
    const btns = [...document.querySelectorAll<HTMLElement>('#tag-filter-list .tag-filter-btn')];
    expect(btns.map(b => b.dataset.tag)).toEqual(['db', 'prod']);
    expect(btns[1].querySelector('.sidebar-count')!.textContent).toBe('2');
  });

  it('hides the whole section when no entry carries a tag', () => {
    st.vault.api_keys = [makeEntry()];
    render();
    expect(document.getElementById('sidebar-section-tags')!.style.display).toBe('none');
  });

  it('marks the active tag chip', () => {
    st.vault.api_keys = [makeEntry({ tags: ['prod'] })];
    st.activeTagFilter = 'prod';
    render();
    expect(document.querySelector('#tag-filter-list .tag-filter-btn')!.classList.contains('active')).toBe(true);
  });

  it('escapes a tag name containing markup', () => {
    st.vault.api_keys = [makeEntry({ tags: ['<img src=x onerror=alert(1)>'] })];
    render();
    expect(document.querySelector('#tag-filter-list img')).toBeNull();
  });
});

describe('render', () => {
  it('draws the grid for a generic project selection', () => {
    st.vault = makeVault({
      projects: [makeProject({ id: 'Universal', name: 'Universal' }), makeProject({ id: 'p1', name: 'Acme', project_type: 'generic' })],
      api_keys: [makeEntry({ provider: 'A', projectIds: ['Universal', 'p1'] })],
    });
    st.currentSelectedProjectIds = ['p1'];
    render();
    expect(cards()).toHaveLength(1);
  });

  it('does not throw when the selected project no longer exists', () => {
    st.currentSelectedProjectIds = ['deleted-project'];
    st.vault.api_keys = [makeEntry()];
    expect(() => render()).not.toThrow();
  });
});

describe('updateCopyAllBtn', () => {
  it('hides the copy-all control when nothing is listed', () => {
    st.vault.api_keys = [];
    updateCopyAllBtn();
    expect(document.getElementById('copy-all-wrap')!.style.display).toBe('none');
  });

  it('shows it once there is at least one entry', () => {
    st.vault.api_keys = [makeEntry()];
    updateCopyAllBtn();
    expect(document.getElementById('copy-all-wrap')!.style.display).toBe('flex');
  });
});
