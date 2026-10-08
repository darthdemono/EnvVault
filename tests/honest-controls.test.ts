/**
 * Phase 32a: drive the control, assert what the user sees, and assert the
 * refusal is honest. Each case here was a control the efficacy probe
 * (`tests/efficacy.test.ts`) found doing nothing visible: 14 Copy buttons on the
 * generator and converter panes, bulk delete with nothing ticked, import
 * confirm with nothing staged, split-cookies on an empty field, and the session
 * preset header copy with no preset.
 */
import { describe, it, expect, beforeAll, beforeEach } from 'vitest';
import { st, resetViewState } from '../src/ts/state';
import { loadRealIndexHtml, makeEntry, makeVault, resetState } from './helpers';

let nodes: ChildNode[] = [];
const $ = (id: string) => document.getElementById(id)!;
const toast = () => $('toast');
const flush = () => new Promise((r) => setTimeout(r, 30));

beforeAll(async () => {
  loadRealIndexHtml();
  (await import('../src/ts/tools-markup')).mountToolsPanes();
  await import('../src/ts/vault');
  await new Promise((r) => setTimeout(r, 50));
  nodes = Array.from(document.body.childNodes);
});

beforeEach(() => {
  document.body.innerHTML = '';
  for (const n of nodes) document.body.appendChild(n);
  resetState(st);
  resetViewState();
  st.vault = makeVault({ api_keys: [makeEntry({ id: 'a', provider: 'Alpha' })] });
  toast().className = '';
  toast().textContent = '';
});

describe('Copy buttons on the generator and converter panes', () => {
  const pairs: [string, string][] = [
    ['sg-copy', 'sg-output'],
    ['pg-copy', 'pg-output'],
    ['uu-copy', 'uu-output'],
    ['ak-copy', 'ak-output'],
    ['hg-copy', 'hg-output'],
    ['pc-copy-cert', 'pc-cert-output'],
    ['pc-copy-key', 'pc-key-output'],
    ['sk-copy-pub', 'sk-pub-output'],
    ['sk-copy-priv', 'sk-priv-output'],
    ['st-copy', 'st-output'],
    ['b64-copy', 'b64-output'],
    ['fmt-copy', 'fmt-output'],
  ];

  for (const [btn, out] of pairs) {
    it(`${btn} says so when there is nothing to copy`, async () => {
      ($(out) as HTMLTextAreaElement).value = '';
      $(btn).click();
      await flush();
      expect(toast().textContent).toBe('Nothing to copy yet');
      expect(toast().className).toContain('err');
    });

    it(`${btn} confirms a real copy`, async () => {
      ($(out) as HTMLTextAreaElement).value = 'value-to-copy';
      $(btn).click();
      await flush();
      expect(toast().textContent).toBe('Copied ✓');
      expect(toast().className).toContain('ok');
    });
  }
});

describe('destructive and import controls with their precondition unmet', () => {
  it('bulk delete with nothing ticked explains instead of doing nothing', async () => {
    st.bulkSelected = new Set();
    $('bulk-delete-btn').click();
    await flush();
    expect(toast().textContent).toMatch(/Tick at least one secret/);
    expect(st.vault.api_keys).toHaveLength(1);
  });

  it('import confirm with nothing staged does not claim an import', async () => {
    $('import-confirm-btn').click();
    await flush();
    expect(toast().textContent).toMatch(/Nothing to import/);
    expect(toast().className).toContain('err');
  });
});

describe('chunk reordering in the config view (Phase 32.1)', () => {
  // The up/down arrows swapped with whatever chunk sat next to it in the stored
  // array. The view lists chunks grouped by type, so moving a peer "above" the
  // interface changed the stored (and exported) order and left the screen
  // identical: a button that did something real and showed nothing.
  async function wgProject(extraPeer: boolean) {
    const { render } = await import('../src/ts/render');
    const starters = await import('../src/ts/chunks/starters');
    const chunks = starters.makeWgStarterChunks();
    if (extraPeer) {
      chunks.push({ ...chunks[1], id: 'peer2', name: 'Peer 2', fields: [...chunks[1].fields] });
    }
    const project = {
      id: 'w',
      name: 'W',
      description: '',
      project_type: 'wireguard',
      chunks,
    } as never;
    st.vault = makeVault({ projects: [project], api_keys: [] });
    st.currentSelectedProjectIds = ['w'];
    render();
    return () => st.vault.projects[0].chunks!.map((c) => c.name);
  }

  it('a peer cannot be moved above the interface, and says so', async () => {
    const order = await wgProject(false);
    expect(order()).toEqual(['Interface', 'Peer']);
    (document.querySelectorAll('#card-grid [data-action="chunk-up"]')[1] as HTMLElement).click();
    await flush();
    expect(order()).toEqual(['Interface', 'Peer']);
    expect(toast().textContent).toBe('Already first of its kind');
  });

  it('a peer moves past another peer', async () => {
    const order = await wgProject(true);
    const ups = document.querySelectorAll('#card-grid [data-action="chunk-up"]');
    (ups[ups.length - 1] as HTMLElement).click();
    await flush();
    expect(order()).toEqual(['Interface', 'Peer 2', 'Peer']);
  });
});

describe('pool cards alongside a bundle (Phase 32.1)', () => {
  it('a vault holding a bundle still collapses a pool into one card', async () => {
    const { renderGrid } = await import('../src/ts/render');
    st.vault = makeVault({
      api_keys: [
        makeEntry({ id: 'bun', provider: 'Bundle', secretType: 'bundle' } as never),
        makeEntry({ id: 'm1', provider: 'Member', bundle_id: 'bun', bundle_slot: 'a' } as never),
        makeEntry({ id: 'p1', provider: 'Pooled', pool: 'pp' } as never),
        makeEntry({ id: 'p2', provider: 'Pooled', pool: 'pp', key_id: 'two' } as never),
      ],
    });
    renderGrid();
    expect(document.querySelectorAll('#card-grid [data-action="pool-card-toggle"]')).toHaveLength(
      1,
    );
  });
});

describe('icon picker apply with an empty name', () => {
  it('asks for a name instead of doing nothing', async () => {
    ($('icon-manual') as HTMLInputElement).value = '';
    $('icon-manual-apply').click();
    await flush();
    expect(toast().textContent).toBe('Type an icon name first');
  });
});

describe('controls the Phase 32.2 probe found dead or invisible', () => {
  it('Accept on the "bundle them?" banner creates the bundle', async () => {
    // The banner sits above #card-grid, outside the grid's delegated click
    // handler, so Accept and Dismiss did nothing in the real app.
    const { Settings } = await import('../src/ts/state');
    const { renderGrid } = await import('../src/ts/render');
    Settings.set('dismissedBundleSuggestions', []);
    st.vault = makeVault({
      api_keys: [
        makeEntry({ id: 't1', provider: 'Twin' }),
        makeEntry({ id: 't2', provider: 'Twin', key_id: 'b' }),
      ],
    });
    renderGrid();
    (document.querySelector('[data-action="bundle-suggest-accept"]') as HTMLElement).click();
    await flush();
    expect(st.vault.api_keys.some((e) => e.secretType === 'bundle')).toBe(true);
  });

  it('Dismiss on the banner remembers the provider', async () => {
    const { Settings } = await import('../src/ts/state');
    const { renderGrid } = await import('../src/ts/render');
    Settings.set('dismissedBundleSuggestions', []);
    st.vault = makeVault({
      api_keys: [
        makeEntry({ id: 't1', provider: 'Twin' }),
        makeEntry({ id: 't2', provider: 'Twin', key_id: 'b' }),
      ],
    });
    renderGrid();
    (document.querySelector('[data-action="bundle-suggest-dismiss"]') as HTMLElement).click();
    await flush();
    expect(Settings.get('dismissedBundleSuggestions')).toContain('twin');
  });

  it('a ${ref} badge in a config view shows the entry it points at', async () => {
    const { render } = await import('../src/ts/render');
    const project = {
      id: 'w',
      name: 'W',
      description: '',
      project_type: 'wireguard',
      chunks: [
        {
          id: 'c1',
          name: 'Peer',
          chunk_type: 'wg_peer',
          fields: [{ key: 'PublicKey', value: '${Alpha}', field_type: 'secret' }],
        },
      ],
    } as never;
    st.vault = makeVault({
      projects: [project],
      api_keys: [makeEntry({ id: 'a', provider: 'Alpha' })],
    });
    st.currentSelectedProjectIds = ['w'];
    render();
    (document.querySelector('[data-action="jump-ref"]') as HTMLElement).click();
    await flush();
    // Before: the config view stayed on screen and the entry was never visible.
    expect(document.querySelector('#card-grid [data-idx="0"]')).not.toBeNull();
    expect(st.currentSelectedProjectIds).toEqual(['Universal']);
  });

  it('a health-scan finding for a filtered-out entry still shows it', async () => {
    st.vault = makeVault({
      api_keys: [
        makeEntry({ id: 'weak', provider: 'Weak', api_key: 'x' }),
        makeEntry({ id: 'other', provider: 'Other' }),
      ],
    });
    st.searchQ = 'other';
    document.getElementById('health-scan-btn')!.click();
    await flush();
    const jumps = Array.from(
      document.querySelectorAll<HTMLElement>('#health-results [data-action="health-jump"]'),
    );
    expect(jumps.map((j) => j.dataset.id)).toContain('weak');
    jumps.find((j) => j.dataset.id === 'weak')!.click();
    await flush();
    expect(st.searchQ).toBe('');
    expect(document.querySelector('#card-grid [data-idx="0"]')).not.toBeNull();
  });
});

describe('controls bound only when their screen is shown (Phase 32.2c)', () => {
  const visible = (id: string) => $(id).style.display !== 'none';

  it('the unlock screen refuses an empty password out loud', async () => {
    const { showUnlockModal } = await import('../src/ts/lock');
    showUnlockModal(false);
    ($('unlock-password') as HTMLInputElement).value = '';
    $('unlock-submit-btn').click();
    await flush();
    expect(visible('unlock-error')).toBe(true);
    expect($('unlock-error').textContent).toMatch(/empty/i);
  });

  it('the re-lock screen refuses an empty password out loud', async () => {
    const { showRelockScreen } = await import('../src/ts/lock');
    showRelockScreen('manual');
    ($('relock-password') as HTMLInputElement).value = '';
    $('relock-submit-btn').click();
    await flush();
    expect(visible('relock-error')).toBe(true);
    expect($('relock-error').textContent).toMatch(/empty/i);
  });

  it('the card icon (role=button) answers Enter like a click', async () => {
    const { renderGrid } = await import('../src/ts/render');
    st.vault = makeVault({ api_keys: [makeEntry({ id: 'a', provider: 'Alpha' })] });
    renderGrid();
    const icon = document.querySelector<HTMLElement>('[role="button"][data-action="icon"]')!;
    expect(icon).not.toBeNull();
    icon.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', bubbles: true }));
    await flush();
    expect($('icon-picker-overlay').classList.contains('open')).toBe(true);
  });
});
