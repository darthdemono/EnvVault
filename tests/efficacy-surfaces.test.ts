/**
 * Phase 32.2: the remaining runtime-rendered surfaces that `efficacy-cards` and
 * `efficacy-config` do not reach: the health-scan results (jump to an entry,
 * delete an empty bundle) and the Settings sidebar-layout editors (show, hide,
 * reorder). Same contract: a control kind with no visible effect must be named
 * `<surface>:<action>` in `efficacy-surfaces-silent.json` with a reason.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { RemoteVaultStore, Settings, st, resetViewState } from '../src/ts/state';
import type { VaultEntry } from '../src/ts/types';
import { clearTransient, judge, probeKinds, type KindReport } from './probe';
import { loadRealIndexHtml, makeEntry, makeVault, resetState } from './helpers';

const allowed: Record<string, string> = JSON.parse(
  readFileSync(join(process.cwd(), 'tests', 'efficacy-surfaces-silent.json'), 'utf8'),
);

describe('the remaining surfaces do something visible', () => {
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

  const fresh = () => {
    document.body.innerHTML = '';
    for (const n of nodes) document.body.appendChild(n);
    resetState(st);
    resetViewState();
  };

  const surfaces: Record<string, { selector: string; reset: () => void | Promise<void> }> = {
    health: {
      selector: '#health-results [data-action]',
      reset: () => {
        fresh();
        st.vault = makeVault({
          api_keys: [
            makeEntry({ id: 'weak', provider: 'Weak', api_key: 'x' } as Partial<VaultEntry>),
            makeEntry({
              id: 'emptybundle',
              provider: 'Empty bundle',
              secretType: 'bundle',
            } as Partial<VaultEntry>),
          ],
        });
        document.getElementById('health-scan-btn')!.click();
      },
    },
    settings: {
      selector: '#settings-overlay [data-action]',
      reset: async () => {
        fresh();
        // One section hidden, so the editor offers "+ Show" as well as the rest.
        Settings.set('sidebarSections', ['all', 'price', 'env', 'category', 'project', 'tags']);
        (await import('../src/ts/settings-panel')).openSettings();
      },
    },
    icons: {
      selector: '#icon-picker-overlay [data-action]',
      reset: async () => {
        fresh();
        (await import('../src/ts/icons')).openIconPicker();
      },
    },
    // Calendar feeds exist only against a remote store, so give it one whose
    // network calls are stubbed: the control under test is Revoke, not fetch.
    feeds: {
      selector: '#tl-feed-list [data-action]',
      reset: async () => {
        fresh();
        const remote = new RemoteVaultStore('http://localhost:1');
        remote.listCalendarFeeds = () =>
          Promise.resolve([
            { id: 'f1', name: 'Mine', kinds: ['expiry'], revoked_at: null },
          ] as never);
        remote.revokeCalendarFeed = () => Promise.resolve(true);
        st.store = remote;
        document.getElementById('tl-feeds-section')!.style.display = '';
        (await import('../src/ts/timeline')).renderTimeline();
        await new Promise((r) => setTimeout(r, 30));
      },
    },
  };

  it('has no unexplained silent control', async () => {
    const merged: KindReport = {
      targets: 0,
      kinds: 0,
      reached: [],
      silent: [],
      partial: [],
      threw: [],
    };
    for (const [name, surface] of Object.entries(surfaces)) {
      const report = await probeKinds({
        reset: surface.reset as () => void,
        selector: surface.selector,
        errors,
        afterReset: clearTransient,
      });
      merged.targets += report.targets;
      merged.kinds += report.kinds;
      merged.reached.push(...report.reached.map((k) => `${name}:${k}`));
      merged.silent.push(...report.silent.map((k) => `${name}:${k}`));
      merged.partial.push(...report.partial.map((k) => `${name}:${k}`));
      merged.threw.push(...report.threw.map((k) => `${name}:${k}`));
    }
    if (process.env.EFFICACY_REPORT) {
      writeFileSync(process.env.EFFICACY_REPORT, JSON.stringify(merged, null, 2));
    }
    expect(judge(merged, allowed)).toEqual({ unexplained: [], threw: [], stale: [] });
  }, 300_000);
});
