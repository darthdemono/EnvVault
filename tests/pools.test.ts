/**
 * The Key Pools tool pane.
 *
 * jsdom has no Tauri, so `pools.json` is unreachable here. That is deliberately
 * a tested state rather than an untested one: the pane must still render
 * membership from the vault and say the counts are unavailable, instead of
 * showing zeros that look like real usage.
 */
import { describe, it, expect, beforeAll, beforeEach } from 'vitest';
import { poolsOf, renderPoolsPane, initPoolsPane } from '../src/ts/pools';
import { st } from '../src/ts/state';
import { mountToolsPanes } from '../src/ts/tools-markup';
import { loadRealIndexHtml, makeEntry, makeVault, resetState } from './helpers';

let panes: ChildNode[] = [];

beforeAll(() => {
  loadRealIndexHtml();
  mountToolsPanes();
  panes = [...document.body.childNodes];
});

beforeEach(() => {
  document.body.innerHTML = '';
  panes.forEach((n) => document.body.appendChild(n));
  resetState(st);
});

const body = () => document.getElementById('pools-body')!;

describe('poolsOf', () => {
  it('groups entries by pool name and ignores the rest', () => {
    const vault = makeVault({
      api_keys: [
        makeEntry({ id: '1', provider: 'GitHub', key_id: 'ci-1', pool: 'github-ci' } as any),
        makeEntry({ id: '2', provider: 'GitHub', key_id: 'ci-2', pool: 'github-ci' } as any),
        makeEntry({ id: '3', provider: 'GitHub', key_id: 'personal' } as any),
        makeEntry({ id: '4', provider: 'Stripe', pool: 'stripe' } as any),
      ],
    });
    const pools = poolsOf(vault);
    expect([...pools.keys()]).toEqual(['github-ci', 'stripe']);
    expect(pools.get('github-ci')!.map((e) => e.key_id)).toEqual(['ci-1', 'ci-2']);
  });

  it('does not create a pool from a non-string field', () => {
    // Vault data is untrusted input and the declared type is erased at runtime
    // (CLAUDE.md invariant 4). Without the typeof guard this produced a pool
    // literally named "[object Object]".
    const vault = makeVault({
      api_keys: [
        makeEntry({ id: '1', provider: 'A', pool: { evil: true } } as any),
        makeEntry({ id: '2', provider: 'B', pool: 42 } as any),
        makeEntry({ id: '3', provider: 'C', pool: '   ' } as any),
      ],
    });
    expect(poolsOf(vault).size).toBe(0);
  });

  it('is empty for a vault with no entries at all', () => {
    expect(poolsOf({}).size).toBe(0);
    expect(poolsOf({ api_keys: [] }).size).toBe(0);
  });
});

describe('renderPoolsPane', () => {
  it('explains how to make one when there are no pools', async () => {
    st.vault = makeVault({ api_keys: [makeEntry({ id: '1', provider: 'GitHub' } as any)] });
    await renderPoolsPane();
    expect(body().textContent).toContain('No key pools yet');
    expect(body().querySelector('.pool-card')).toBeNull();
  });

  it('renders a card per pool with its members', async () => {
    st.vault = makeVault({
      api_keys: [
        makeEntry({ id: '1', provider: 'GitHub', key_id: 'ci-1', pool: 'github-ci' } as any),
        makeEntry({ id: '2', provider: 'GitHub', key_id: 'ci-2', pool: 'github-ci' } as any),
      ],
    });
    await renderPoolsPane();
    expect(body().querySelectorAll('.pool-card')).toHaveLength(1);
    const rows = body().querySelectorAll('.pool-table tbody tr');
    expect(rows).toHaveLength(2);
    expect(rows[0].textContent).toContain('GitHub:ci-1');
    expect(rows[1].textContent).toContain('GitHub:ci-2');
  });

  it('says counts are unavailable outside Tauri rather than showing zeros', async () => {
    // Zeros here would read as "this key has never been used", which is a
    // different and wrong claim from "this build cannot see the counter".
    st.vault = makeVault({
      api_keys: [makeEntry({ id: '1', provider: 'GitHub', pool: 'p' } as any)],
    });
    await renderPoolsPane();
    // The sentence wraps in the template, so match a fragment that cannot
    // straddle a line break.
    expect(body().textContent).toContain('available in the desktop app');
    expect(body().querySelector('.pool-uses')!.textContent!.trim()).toBe('—');
  });

  it('offers no state-changing buttons when the state file is unreachable', async () => {
    // A button that cannot do anything is worse than no button: it invites a
    // click and then fails. Same reasoning as the LAN gate refusing at the
    // write, not merely hiding the control.
    st.vault = makeVault({
      api_keys: [makeEntry({ id: '1', provider: 'GitHub', pool: 'p' } as any)],
    });
    await renderPoolsPane();
    expect(body().querySelectorAll('[data-pool-action]')).toHaveLength(0);
  });

  it('escapes a pool name and a member label', async () => {
    // Both come from vault JSON, which can arrive from a remote server or an
    // imported backup.
    st.vault = makeVault({
      api_keys: [
        makeEntry({
          id: '1',
          provider: '<img src=x onerror=alert(1)>',
          key_id: '" onmouseover="steal()" x="',
          pool: '<script>alert(1)</script>',
        } as any),
      ],
    });
    await renderPoolsPane();
    expect(body().querySelector('img'), 'injected element became live').toBeNull();
    expect(body().querySelector('script')).toBeNull();
    expect(body().querySelector('[onmouseover]'), 'injected attribute became live').toBeNull();
    expect(body().textContent).toContain('<script>alert(1)</script>');
  });

  it('re-renders cleanly instead of appending a second copy', async () => {
    st.vault = makeVault({
      api_keys: [makeEntry({ id: '1', provider: 'GitHub', pool: 'p' } as any)],
    });
    await renderPoolsPane();
    await renderPoolsPane();
    expect(body().querySelectorAll('.pool-card')).toHaveLength(1);
  });
});

describe('initPoolsPane', () => {
  it('assigns its handler rather than adding one, so repeat init cannot stack', () => {
    // The bug this project has hit at least three separate times (invariant 9):
    // `addEventListener` on a re-shown screen leaves a duplicate behind every
    // time, and the symptom is a control that fires an even number of times and
    // appears to do nothing.
    const host = body();
    initPoolsPane();
    const first = host.onclick;
    initPoolsPane();
    expect(host.onclick).not.toBeNull();
    expect(host.onclick).not.toBe(first);
    // One assignment, so exactly one handler is reachable.
    expect(typeof host.onclick).toBe('function');
  });

  it('does nothing when the pane is absent', () => {
    document.getElementById('pools-body')!.remove();
    expect(() => initPoolsPane()).not.toThrow();
  });
});
