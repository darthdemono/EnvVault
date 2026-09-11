/**
 * Noticing a write from outside the window (Phase 22.2).
 *
 * The app reads the vault once at unlock and holds it in memory, so an `envv`
 * command in a terminal — or a LAN peer — changed the database underneath a
 * window that went on showing what it read at unlock, and whose next save then
 * either overwrote that work or failed with a conflict the user could not have
 * predicted.
 *
 * These pin the two halves that matter: it reloads when the stored version moves,
 * and it refuses to reload over an open editor.
 */
import { describe, it, expect, beforeEach, vi } from 'vitest';
import { loadRealIndexHtml } from './helpers';
import { st } from '../src/ts/state';
import { checkVaultVersion } from '../src/ts/vault-watch';
import type { VaultData } from '../src/ts/types';

let stored: string | null;
let loads: number;

function vault(n: number): VaultData {
  return {
    api_keys: Array.from({ length: n }, (_, i) => ({ id: `e${i}`, provider: `P${i}` })),
    user_categories: [],
    projects: [],
  } as unknown as VaultData;
}

function install(ourVersion: string | null) {
  (window as any).__TAURI__ = {
    core: {
      invoke: (cmd: string) => {
        if (cmd === 'vault_version') return Promise.resolve(stored);
        return Promise.resolve(null);
      },
    },
  };
  st.vaultOpen = true;
  st.vault = vault(1);
  st.store = {
    isRemote: false,
    lastVersion: ourVersion,
    load: async () => {
      loads++;
      (st.store as any).lastVersion = stored;
      return vault(2);
    },
  } as any;
}

beforeEach(() => {
  loadRealIndexHtml();
  loads = 0;
  stored = 'v1';
  vi.restoreAllMocks();
});

describe('checkVaultVersion', () => {
  it('does nothing while the stored version matches ours', async () => {
    install('v1');
    expect(await checkVaultVersion()).toBe(false);
    expect(loads).toBe(0);
  });

  it('reloads when something else wrote the vault', async () => {
    install('v1');
    stored = 'v2';
    expect(await checkVaultVersion()).toBe(true);
    expect(loads).toBe(1);
    expect(st.vault!.api_keys).toHaveLength(2);
  });

  it('refuses to reload over an open editor', async () => {
    // A reload replaces st.vault, and doing that under a half-typed entry throws
    // the typing away — worse than being briefly out of date. It retries on the
    // next tick instead.
    install('v1');
    stored = 'v2';
    const overlay = document.querySelector('.overlay') ?? document.createElement('div');
    overlay.classList.add('overlay', 'open');
    if (!overlay.isConnected) document.body.appendChild(overlay);

    expect(await checkVaultVersion()).toBe(false);
    expect(loads).toBe(0);

    overlay.classList.remove('open');
    expect(await checkVaultVersion()).toBe(true);
  });

  it('does nothing while the vault is locked', async () => {
    // `vault_version` answers null rather than erroring, because a locked vault
    // is the ordinary state and not a failure worth reporting once a second.
    install('v1');
    stored = null;
    expect(await checkVaultVersion()).toBe(false);
    expect(loads).toBe(0);
  });

  it('does not watch a remote vault', async () => {
    // Its writes come back through its own API, and polling one could mean a
    // request every three seconds against a server on a phone tether.
    install('v1');
    stored = 'v2';
    (st.store as any).isRemote = true;
    expect(await checkVaultVersion()).toBe(false);
    expect(loads).toBe(0);
  });

  it('never throws when the command fails', async () => {
    // It runs on a timer: a rejected promise per tick is a console nobody reads.
    install('v1');
    (window as any).__TAURI__.core.invoke = () => Promise.reject(new Error('locked'));
    await expect(checkVaultVersion()).resolves.toBe(false);
  });
});
