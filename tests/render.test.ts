/**
 * Card-grid rendering tests.
 *
 * The grid is built by string interpolation into `innerHTML`, so the escaping
 * assertions here are load-bearing security tests, not cosmetics: a vault entry
 * is attacker-influenced data the moment a shared/remote vault is in play.
 */
import { describe, it, expect, beforeEach } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
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

describe('card size', () => {
  // The card-size setting used to move only the grid's column width; card
  // height was whatever the content came to, so a three-line description or a
  // row of tags pushed the footer — and the copy button in it — to a different
  // offset on every card. Height and every internal dimension are now CSS
  // tokens selected by #card-grid[data-card-size], which jsdom will not compute
  // — so the tests split: the DOM contract here, the token block below.
  const sizes = ['compact', 'medium', 'large'] as const;

  it('stamps the chosen size onto the grid for CSS to select on', () => {
    st.vault.api_keys = [makeEntry()];
    sizes.forEach(size => {
      Settings.set('cardSize', size);
      renderGrid();
      expect(grid().dataset.cardSize).toBe(size);
    });
  });

  it('still sets the column width from the same setting', () => {
    st.vault.api_keys = [makeEntry()];
    Settings.set('cardSize', 'large');
    Settings.set('gridColumns', 'auto');
    renderGrid();
    expect(grid().style.gridTemplateColumns).toContain('460px');
  });

  it('wraps the provider name so it can be ellipsised apart from its badges', () => {
    // Bare text in .card-provider cannot take text-overflow, so a long name
    // widened the flex row and clipped the badges beside it instead.
    st.vault.api_keys = [makeEntry({ provider: 'A'.repeat(120) })];
    renderGrid();
    const name = cards()[0].querySelector('.card-provider-name')!;
    expect(name).not.toBeNull();
    expect(name.textContent).toBe('A'.repeat(120));
    expect(name.getAttribute('title')).toBe('A'.repeat(120));
  });

  it('leaves the project row to the stylesheet so it can be clamped by size', () => {
    // It carried an inline `display:flex` that beat any max-height rule.
    st.vault.api_keys = [makeEntry()];
    renderGrid();
    expect(cards()[0].querySelector('.card-projects')!.getAttribute('style')).toBeNull();
  });
});

describe('card-size stylesheet tokens', () => {
  // jsdom applies no stylesheet, so the sizing contract is asserted against the
  // CSS source: each size must redefine the height token, or the "resizer also
  // changes height" behaviour silently degrades to width-only.
  // process.cwd() is the vitest root; import.meta.url is not a file: URL under
  // the jsdom environment.
  const css = readFileSync(resolve(process.cwd(), 'src/css/cards.css'), 'utf8');

  it('gives every card size its own height', () => {
    const heights = [...css.matchAll(/--cs-card-h:\s*(\d+)px/g)].map(m => Number(m[1]));
    // Declared medium (the default block), then compact, then large.
    expect(heights).toHaveLength(3);
    const [medium, compact, large] = heights;
    expect(compact).toBeLessThan(medium);
    expect(medium).toBeLessThan(large);
  });

  it('defines a token block per size selector', () => {
    ['compact', 'large'].forEach(size =>
      expect(css).toContain(`#card-grid[data-card-size="${size}"]`));
  });

  it('pins the footer to a fixed height at the bottom of a collapsed card', () => {
    // Without both of these the copy-button row drifted with the content above
    // it and grew a second line whenever the dotenv key was long.
    expect(css).toMatch(/\.card-foot\s*\{[^}]*flex:\s*0 0 var\(--cs-foot-h\)/);
    expect(css).toMatch(/\.card-foot\s*\{[^}]*margin-top:\s*auto/);
  });

  it('lets the copy button shrink below its text', () => {
    // min-width defaults to auto on a flex item: the button's own text was its
    // floor, so a long key pushed the icon buttons past the card edge.
    expect(css).toMatch(/\.env-copy-btn\s*\{[^}]*min-width:\s*0/);
    expect(css).toMatch(/\.env-copy-btn\s*\{[^}]*white-space:\s*nowrap/);
  });

  it('clamps the description to a per-size line count with an ellipsis', () => {
    expect(css).toMatch(/-webkit-line-clamp:\s*var\(--cs-desc-lines\)/);
    expect([...css.matchAll(/--cs-desc-lines:\s*(\d+)/g)]).toHaveLength(3);
  });
});
