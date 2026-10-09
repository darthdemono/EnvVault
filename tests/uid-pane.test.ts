/**
 * Tools -> Unique IDs (Phase 33.4). The routes are tested over real HTTP in
 * unv-server; this drives the pane: what a user sees for each answer.
 */
import { describe, it, expect, beforeEach, vi } from 'vitest';
import { loadRealIndexHtml, resetState } from './helpers';

vi.mock('../src/ts/utils', async (importOriginal) => {
  const real = await importOriginal<typeof import('../src/ts/utils')>();
  return { ...real, showConfirm: async () => true };
});

const $ = (id: string) => document.getElementById(id)!;
const flush = () => new Promise((r) => setTimeout(r, 20));

async function boot(answer?: { status: number; body: unknown }) {
  loadRealIndexHtml();
  // Same module instance as uid-pane's, or `instanceof RemoteVaultStore` is false.
  const { RemoteVaultStore, st } = await import('../src/ts/state');
  (await import('../src/ts/tools-markup')).mountToolsPanes();
  resetState(st);
  const calls: [string, string, unknown][] = [];
  if (answer) {
    const remote = new RemoteVaultStore('http://localhost:1');
    remote.uidRequest = async (m, p, b) => {
      calls.push([m, p, b]);
      return answer;
    };
    st.store = remote;
  }
  (await import('../src/ts/uid-pane')).initUidPane();
  return calls;
}

beforeEach(() => vi.resetModules());

describe('Unique IDs pane', () => {
  it('explains that the registry needs a server when the vault is local', async () => {
    await boot();
    $('uid-mint-btn').click();
    await flush();
    expect($('uid-status').textContent).toMatch(/Connect to a remote vault/);
  });

  it('mints with the chosen length and namespace and shows the answer', async () => {
    const calls = await boot({ status: 200, body: { value: 'abc' } });
    ($('uid-length') as HTMLInputElement).value = '16';
    ($('uid-namespace') as HTMLInputElement).value = 'ci';
    $('uid-mint-btn').click();
    await flush();
    expect(calls[0]).toEqual(['POST', '/api/uid/mint', { length: 16, namespace: 'ci' }]);
    expect($('uid-output').textContent).toContain('abc');
    expect($('uid-status').textContent).toBe('OK (200)');
  });

  it('says what a rate limit, a missing capability and a missing registry mean', async () => {
    for (const [status, re] of [
      [429, /Rate limited/],
      [403, /lacks the capability/],
      [404, /--uid-registry/],
    ] as const) {
      vi.resetModules();
      await boot({ status, body: null });
      $('uid-stats-btn').click();
      await flush();
      expect($('uid-status').textContent).toMatch(re);
    }
  });

  it('check and lookup refuse an empty box instead of sending nothing', async () => {
    const calls = await boot({ status: 200, body: {} });
    $('uid-check-btn').click();
    $('uid-lookup-btn').click();
    await flush();
    expect(calls).toHaveLength(0);
    expect($('uid-status').textContent).toMatch(/Enter a value/);
  });

  it('prune needs a date, dry-runs without deleting, and the real prune sends dry_run false', async () => {
    const calls = await boot({ status: 200, body: { count: 3 } });
    $('uid-prune-dry-btn').click();
    await flush();
    expect(calls).toHaveLength(0);
    expect($('uid-status').textContent).toMatch(/Pick a date/);
    ($('uid-prune-before') as HTMLInputElement).value = '2026-01-01';
    $('uid-prune-dry-btn').click();
    await flush();
    expect(calls[0][2]).toEqual({ before: '2026-01-01', dry_run: true });
    $('uid-prune-btn').click();
    await flush();
    expect(calls[1][2]).toEqual({ before: '2026-01-01', dry_run: false });
  });
});
