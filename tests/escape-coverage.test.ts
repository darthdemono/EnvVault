/**
 * Phase 28.1: hostile values through the renderers Phase 28 migrated but did
 * not test. Every string field of every registered secret type (and a bundle,
 * a pool and a project of every type) carries markup; the assertion is on the
 * resulting DOM, not on the string.
 */
import { describe, it, expect, beforeEach } from 'vitest';
import { renderGrid, render } from '../src/ts/render';
import { st, Settings } from '../src/ts/state';
import { registry } from '../src/ts/secret-types';
import { loadRealIndexHtml, makeEntry, makeProject, makeVault, resetState } from './helpers';
import type { VaultEntry } from '../src/ts/types';

const TAG = '<img src=x onerror=alert(1)>';
const BREAK = '" onmouseover="steal()" x="';

function clean(root: ParentNode, label: string) {
  for (const sel of ['img', 'script', 'iframe', '[onmouseover]', '[onerror]', '[onclick]']) {
    expect(root.querySelector(sel), `${label}: ${sel} became live`).toBeNull();
  }
}

function hostile(secretType: string, i: number): VaultEntry {
  const extra = [0, 1].map((n) => ({
    key: `K${n}`,
    value: n ? BREAK : TAG,
    secret: true,
    public: false,
  }));
  return makeEntry({
    id: `e${i}`,
    secretType,
    provider: i % 2 ? TAG : BREAK,
    account_name: TAG,
    key_id: BREAK,
    label: TAG,
    description: TAG,
    purpose: BREAK,
    api_key: TAG,
    api_secret: BREAK,
    api_url: 'https://x.test/"><img src=x onerror=alert(1)>',
    user_agent: TAG,
    composite_template: `https://x.test/{a}/${TAG}`,
    composite_kind: BREAK,
    totp_secret: 'JBSWY3DPEHPK3PXP',
    tags: [TAG, BREAK],
    extra_vars: extra,
  } as never);
}

beforeEach(() => {
  loadRealIndexHtml();
  resetState(st);
  Settings.set('groupByType', false);
});

describe('every registered secret type, expanded, with hostile fields', () => {
  it('renders no live element or attribute', () => {
    const types = registry().map((d) => d.id);
    st.vault = makeVault({ api_keys: types.map((t, i) => hostile(t, i)) });
    st.allExpanded = true;
    renderGrid();
    clean(document.getElementById('card-grid')!, 'grid');
    expect(document.getElementById('card-grid')!.textContent).toContain(TAG);
  });

  it('survives a bundle with hostile slots, a pool and hostile project names', () => {
    const bundle = hostile('bundle', 900);
    const m1 = { ...hostile('api_key', 901), bundle_id: 'e900', bundle_slot: 'a-b' };
    const m2 = { ...hostile('password', 902), bundle_id: 'e900', bundle_slot: 'c-d' };
    const p1 = { ...hostile('api_key', 903), pool: TAG };
    const p2 = { ...hostile('api_key', 904), pool: TAG };
    st.vault = makeVault({
      api_keys: [bundle, m1, m2, p1, p2],
      projects: [makeProject({ id: 'p', name: TAG, project_type: 'generic' } as never)],
    });
    st.allExpanded = true;
    render();
    clean(document.body, 'full render');
  });
});
