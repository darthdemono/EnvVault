import { describe, it, expect, beforeEach } from 'vitest';
import {
  getDescendantProjectIds,
  buildProjectTree,
  parseSearch,
  getFiltered,
  sorted,
} from '../src/ts/filters';
import { st } from '../src/ts/state';
import { makeEntry, makeProject, makeVault, resetState } from './helpers';

beforeEach(() => resetState(st));

describe('parseSearch', () => {
  it('splits field:value pairs out of free text', () => {
    expect(parseSearch('env:production github token')).toEqual({
      filters: { env: 'production' },
      text: 'github token',
    });
  });

  it('lowercases both keys and values', () => {
    expect(parseSearch('ENV:Production').filters).toEqual({ env: 'production' });
  });

  it('returns empty text for a query of only filters', () => {
    expect(parseSearch('cat:infra price:free').text).toBe('');
  });

  it('treats a bare word as text, not a filter', () => {
    const { filters, text } = parseSearch('stripe');
    expect(filters).toEqual({});
    expect(text).toBe('stripe');
  });

  it('treats a URL as text, not as a filter', () => {
    // Any colon-bearing token used to become a filter. `postgres://user` became
    // the filter postgres="//user", which nothing reads, and emptied the text
    // query — so searching for a connection string returned the whole vault.
    const { filters, text } = parseSearch('postgres://user@host');
    expect(filters).toEqual({});
    expect(text).toBe('postgres://user@host');
  });

  it('treats an unknown field prefix as text', () => {
    const { filters, text } = parseSearch('foo:bar');
    expect(filters).toEqual({});
    expect(text).toBe('foo:bar');
  });

  it('keeps the full value of a known filter that contains a colon', () => {
    expect(parseSearch('cat:a:b').filters).toEqual({ cat: 'a:b' });
  });

  it('still recognises the known prefixes alongside text', () => {
    const { filters, text } = parseSearch('price:free env:production https://x');
    expect(filters).toEqual({ price: 'free', env: 'production' });
    expect(text).toBe('https://x');
  });

  it('treats a leading colon as text rather than an empty field name', () => {
    expect(parseSearch(':8080').text).toBe(':8080');
  });
});

describe('getDescendantProjectIds', () => {
  it('includes the project itself and its slash-nested children', () => {
    st.vault.projects = [
      makeProject({ id: 'a', name: 'Acme' }),
      makeProject({ id: 'b', name: 'Acme/Web' }),
      makeProject({ id: 'c', name: 'Acme/Web/Edge' }),
      makeProject({ id: 'd', name: 'AcmeCorp' }),
    ];
    expect(getDescendantProjectIds('a').sort()).toEqual(['a', 'b', 'c']);
  });

  it('does not treat a name-prefix sibling as a child', () => {
    st.vault.projects = [
      makeProject({ id: 'a', name: 'Acme' }),
      makeProject({ id: 'd', name: 'AcmeCorp' }),
    ];
    expect(getDescendantProjectIds('a')).not.toContain('d');
  });

  it('resolves a virtual: parent node to its real descendants', () => {
    st.vault.projects = [
      makeProject({ id: 'b', name: 'Acme/Web' }),
      makeProject({ id: 'c', name: 'Acme/Api' }),
    ];
    expect(getDescendantProjectIds('virtual:Acme').sort()).toEqual(['b', 'c']);
  });

  it('falls back to the id itself for an unknown project', () => {
    expect(getDescendantProjectIds('nope')).toEqual(['nope']);
  });
});

describe('buildProjectTree', () => {
  it('nests children under their slash parent', () => {
    const tree = buildProjectTree([
      makeProject({ id: 'a', name: 'Acme' }),
      makeProject({ id: 'b', name: 'Acme/Web' }),
    ]);
    expect(tree).toHaveLength(1);
    expect(tree[0].name).toBe('Acme');
    expect(tree[0].children.map((c: any) => c.name)).toEqual(['Acme/Web']);
  });

  it('synthesises a virtual parent when only the child exists', () => {
    const tree = buildProjectTree([makeProject({ id: 'b', name: 'Acme/Web' })]);
    expect(tree).toHaveLength(1);
    expect(tree[0].virtual).toBe(true);
    expect(tree[0].id).toBe('virtual:Acme');
    expect(tree[0].children).toHaveLength(1);
  });

  it('sorts roots and children by name', () => {
    const tree = buildProjectTree([
      makeProject({ id: '1', name: 'Zeta' }),
      makeProject({ id: '2', name: 'Alpha' }),
      makeProject({ id: '3', name: 'Alpha/z' }),
      makeProject({ id: '4', name: 'Alpha/a' }),
    ]);
    expect(tree.map((n) => n.name)).toEqual(['Alpha', 'Zeta']);
    expect(tree[0].children.map((c: any) => c.name)).toEqual(['Alpha/a', 'Alpha/z']);
  });
});

describe('getFiltered', () => {
  it('returns everything under the Universal catch-all', () => {
    st.vault.api_keys = [makeEntry({ provider: 'A' }), makeEntry({ provider: 'B' })];
    expect(getFiltered()).toHaveLength(2);
  });

  it('does not throw when no project is selected at all', () => {
    // Regression: an empty selection used to pass undefined into
    // getDescendantProjectIds and throw, blanking the whole grid.
    st.currentSelectedProjectIds = [];
    st.vault.api_keys = [makeEntry()];
    expect(() => getFiltered()).not.toThrow();
    expect(getFiltered()).toHaveLength(1);
  });

  it('restricts to the selected project and its descendants', () => {
    st.vault.projects = [
      makeProject({ id: 'Universal', name: 'Universal' }),
      makeProject({ id: 'a', name: 'Acme' }),
      makeProject({ id: 'b', name: 'Acme/Web' }),
      makeProject({ id: 'z', name: 'Other' }),
    ];
    st.vault.api_keys = [
      makeEntry({ provider: 'root', projectIds: ['Universal', 'a'] }),
      makeEntry({ provider: 'child', projectIds: ['Universal', 'b'] }),
      makeEntry({ provider: 'other', projectIds: ['Universal', 'z'] }),
    ];
    st.currentSelectedProjectIds = ['a'];
    expect(
      getFiltered()
        .map((e) => e.provider)
        .sort(),
    ).toEqual(['child', 'root']);
  });

  it('filters by tag via the sidebar tag filter', () => {
    st.vault.api_keys = [
      makeEntry({ provider: 'tagged', tags: ['prod', 'db'] }),
      makeEntry({ provider: 'untagged' }),
    ];
    st.activeTagFilter = 'db';
    expect(getFiltered().map((e) => e.provider)).toEqual(['tagged']);
  });

  it('filters by env prefix', () => {
    st.vault.api_keys = [
      makeEntry({ provider: 'pfx', env_prefixes: ['VITE_'] } as any),
      makeEntry({ provider: 'none' }),
    ];
    st.activePrefixFilter = 'VITE_';
    expect(getFiltered().map((e) => e.provider)).toEqual(['pfx']);
  });

  it('stacks the env filter with the tag filter', () => {
    st.vault.api_keys = [
      makeEntry({ provider: 'both', environment: 'production', tags: ['db'] }),
      makeEntry({ provider: 'envonly', environment: 'production' }),
      makeEntry({ provider: 'tagonly', environment: 'staging', tags: ['db'] }),
    ];
    st.currentEnvFilter = 'production';
    st.activeTagFilter = 'db';
    expect(getFiltered().map((e) => e.provider)).toEqual(['both']);
  });

  it('matches free text case-insensitively across provider and description', () => {
    st.vault.api_keys = [
      makeEntry({ provider: 'GitHub' }),
      makeEntry({ provider: 'Stripe', api_description: 'billing GITHUB mirror' }),
      makeEntry({ provider: 'Vercel' }),
    ];
    st.searchQ = 'github';
    expect(
      getFiltered()
        .map((e) => e.provider)
        .sort(),
    ).toEqual(['GitHub', 'Stripe']);
  });

  it('supports /regex/ search syntax', () => {
    st.vault.api_keys = [
      makeEntry({ provider: 'db-prod' }),
      makeEntry({ provider: 'db-staging' }),
      makeEntry({ provider: 'cache-prod' }),
    ];
    st.searchQ = '/^db-/';
    expect(
      getFiltered()
        .map((e) => e.provider)
        .sort(),
    ).toEqual(['db-prod', 'db-staging']);
  });

  it('falls back to substring match when the regex is malformed', () => {
    st.vault.api_keys = [makeEntry({ provider: 'a(b' })];
    st.searchQ = '/a(b/';
    expect(() => getFiltered()).not.toThrow();
    expect(getFiltered()).toHaveLength(1);
  });

  it('narrows to the matching entry when searching for a URL', () => {
    // The visible symptom of the parseSearch bug: the query looked like it
    // matched everything.
    st.vault.api_keys = [
      makeEntry({ provider: 'DB', api_description: 'postgres://user@host/db' }),
      makeEntry({ provider: 'Other' }),
      makeEntry({ provider: 'Third' }),
    ];
    st.searchQ = 'postgres://user@host';
    expect(getFiltered().map((e) => e.provider)).toEqual(['DB']);
  });

  it('returns nothing when a URL search matches nothing', () => {
    st.vault.api_keys = [makeEntry({ provider: 'A' }), makeEntry({ provider: 'B' })];
    st.searchQ = 'mysql://nowhere';
    expect(getFiltered()).toHaveLength(0);
  });

  it('matches a category filter on the exact value and on slash children', () => {
    st.vault.api_keys = [
      makeEntry({ provider: 'exact', categories: ['infra'] }),
      makeEntry({ provider: 'child', categories: ['infra/db'] }),
      makeEntry({ provider: 'sibling', categories: ['infrastructure'] }),
    ];
    st.filter = { type: 'category', value: 'infra' };
    expect(
      getFiltered()
        .map((e) => e.provider)
        .sort(),
    ).toEqual(['child', 'exact']);
  });

  it('defaults a missing secretType to api_key when filtering by type', () => {
    st.vault.api_keys = [makeEntry({ provider: 'legacy' })];
    st.filter = { type: 'secret_type', value: 'api_key' };
    expect(getFiltered()).toHaveLength(1);
  });
});

describe('sorted', () => {
  it('floats pinned entries above everything else', () => {
    const out = sorted([
      makeEntry({ provider: 'Aaa' }),
      makeEntry({ provider: 'Zzz', pinned: true }),
    ]);
    expect(out.map((e) => e.provider)).toEqual(['Zzz', 'Aaa']);
  });

  it('orders by price tier then name', () => {
    st.currentSortBy = 'price';
    const out = sorted([
      makeEntry({ provider: 'p', price_type: 'paid' }),
      makeEntry({ provider: 'f2', price_type: 'free' }),
      makeEntry({ provider: 'f1', price_type: 'free' }),
      makeEntry({ provider: 'l', price_type: 'local' }),
    ]);
    expect(out.map((e) => e.provider)).toEqual(['f1', 'f2', 'l', 'p']);
  });

  it('sorts entries with no expiry last', () => {
    st.currentSortBy = 'expiry';
    const out = sorted([
      makeEntry({ provider: 'never' }),
      makeEntry({ provider: 'soon', expires_at: '2020-01-01T00:00:00Z' }),
      makeEntry({ provider: 'later', expires_at: '2030-01-01T00:00:00Z' }),
    ]);
    expect(out.map((e) => e.provider)).toEqual(['soon', 'later', 'never']);
  });

  it('does not mutate the array it is given', () => {
    const input = [makeEntry({ provider: 'Z' }), makeEntry({ provider: 'A' })];
    const copy = [...input];
    sorted(input);
    expect(input).toEqual(copy);
  });
});
