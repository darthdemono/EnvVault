/**
 * Phase 32.1: the dynamic half of the efficacy audit. `efficacy.test.ts` reaches
 * only static `button[id]`; the controls people press most are rendered into the
 * card grid with `data-action`. This seeds one entry of every registered secret
 * type (plus a pool, a TOTP seed and a bundle), expands every card, and clicks
 * each `[data-action]` once on a freshly rendered grid. A control with no visible
 * effect must be listed, with a reason, in `efficacy-cards-silent.json`.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { Settings, st, resetViewState } from '../src/ts/state';
import { renderGrid } from '../src/ts/render';
import { registry } from '../src/ts/secret-types';
import type { VaultEntry } from '../src/ts/types';
import { clearTransient, judge, probeKinds } from './probe';
import { loadRealIndexHtml, makeEntry, makeVault, resetState } from './helpers';

const allowed: Record<string, string> = JSON.parse(
  readFileSync(join(process.cwd(), 'tests', 'efficacy-cards-silent.json'), 'utf8'),
);

function seed(): VaultEntry[] {
  const out: VaultEntry[] = registry().map((t) =>
    makeEntry({
      id: `t-${t.id}`,
      provider: `P ${t.id}`,
      secretType: t.id,
      api_key: 'value-123',
      api_secret: 'secret-456',
      api_url: 'https://example.com',
      tags: ['x'],
      description: 'A long description. '.repeat(20),
      extra_vars: [{ key: 'VAR', value: 'v', secret: false }],
    } as Partial<VaultEntry>),
  );
  out.push(
    makeEntry({
      id: 'totp',
      provider: 'Has TOTP',
      totp_secret: 'JBSWY3DPEHPK3PXP',
    } as Partial<VaultEntry>),
    makeEntry({ id: 'pool1', provider: 'Pooled', pool: 'pp' } as Partial<VaultEntry>),
    makeEntry({
      id: 'pool2',
      provider: 'Pooled',
      pool: 'pp',
      key_id: 'two',
    } as Partial<VaultEntry>),
    makeEntry({ id: 'bun', provider: 'Bundle', secretType: 'bundle' } as Partial<VaultEntry>),
    makeEntry({ id: 'twin1', provider: 'Twin' } as Partial<VaultEntry>),
    makeEntry({ id: 'twin2', provider: 'Twin', key_id: 'b' } as Partial<VaultEntry>),
    makeEntry({
      id: 'mem3',
      provider: 'Member three',
      bundle_id: 'bun',
      bundle_slot: 'v3',
    } as Partial<VaultEntry>),
    makeEntry({
      id: 'mem4',
      provider: 'Member four',
      bundle_id: 'bun',
      bundle_slot: 'v4',
    } as Partial<VaultEntry>),
    makeEntry({
      id: 'mem2',
      provider: 'Member two',
      bundle_id: 'bun',
      bundle_slot: 'web',
      bundle_order: 2,
    } as Partial<VaultEntry>),
    makeEntry({
      id: 'mem',
      provider: 'Member',
      bundle_id: 'bun',
      bundle_slot: 'api',
    } as Partial<VaultEntry>),
  );
  return out;
}

function prepare(): void {
  // Dismissing the bundle suggestion persists in settings, so an earlier probe
  // would otherwise remove the banner the next one is meant to press.
  Settings.set('dismissedBundleSuggestions', []);
  resetState(st);
  resetViewState();
  st.vault = makeVault({ api_keys: seed() });
  st.allExpanded = true;
  renderGrid();
}

describe('every card control does something visible', () => {
  let nodes: ChildNode[] = [];
  const errors: string[] = [];

  beforeAll(async () => {
    loadRealIndexHtml();
    (await import('../src/ts/tools-markup')).mountToolsPanes();
    await import('../src/ts/vault');
    await new Promise((r) => setTimeout(r, 50));
    nodes = Array.from(document.body.childNodes);
    window.addEventListener('error', (e) => errors.push(String(e.message)));
    window.addEventListener('unhandledrejection', (e) => errors.push(String(e.reason)));
  });

  it('has no unexplained silent control', async () => {
    const report = await probeKinds({
      reset: () => {
        document.body.innerHTML = '';
        for (const n of nodes) document.body.appendChild(n);
        prepare();
        clearTransient();
      },
      selector: '#card-grid [data-action], #bundle-suggest [data-action]',
      errors,
    });
    if (process.env.EFFICACY_REPORT) {
      writeFileSync(process.env.EFFICACY_REPORT, JSON.stringify(report, null, 2));
    }
    expect(judge(report, allowed)).toEqual({ unexplained: [], threw: [], stale: [] });
  }, 300_000);
});
