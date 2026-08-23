/**
 * "Open to LAN" must not be offered while a remote vault is connected.
 *
 * The card lives in `#remote-workspace` — the same panel you are looking at
 * while connected to a remote — but `lan_start` reads Rust's `VaultState` and
 * opens *this machine's* `vault.db`. Nothing locks the local vault on switching
 * to a remote (`lockVault` only calls `.lock()` on the current store), so the
 * local key is still resident and the command succeeds. Pressing the button
 * therefore published the local vault while the screen showed the remote's data.
 */
import { describe, it, expect, beforeEach, vi } from 'vitest';
import { st, LocalVaultStore, RemoteVaultStore } from '../src/ts/state';
import { lanAvailable, refreshLanPanel, startLan } from '../src/ts/lan';
import { loadRealIndexHtml, resetState } from './helpers';

const toasts: string[] = [];
vi.mock('../src/ts/utils', async (importOriginal) => {
  const real = await importOriginal<typeof import('../src/ts/utils')>();
  return { ...real, showToast: (m: string) => { toasts.push(m); }, showConfirm: async () => true };
});

const $ = <T extends HTMLElement = HTMLElement>(id: string) => document.getElementById(id) as T;

beforeEach(() => {
  loadRealIndexHtml();
  resetState(st);
  toasts.length = 0;
  st.store = new LocalVaultStore();
});

describe('lanAvailable', () => {
  it('is false outside Tauri, where the invoke bridge does not exist', () => {
    // `inTauri` is false under jsdom, so this is the baseline: the button was
    // previously rendered here too and simply did nothing when pressed.
    expect(lanAvailable()).toBe(false);
  });

  it('is false while a remote vault is connected', () => {
    st.store = new RemoteVaultStore('https://vault.example.com');
    expect(lanAvailable()).toBe(false);
  });
});

describe('LAN card rendering', () => {
  it('offers no start button while a remote vault is connected', () => {
    st.store = new RemoteVaultStore('https://vault.example.com');
    refreshLanPanel();
    expect($('lan-start-btn')).toBeNull();
  });

  it('explains why, rather than leaving an unexplained blank', () => {
    // Asserted on the remote-specific sentence, not on "this machine": the
    // normal card's help text contains that phrase too ("the master password
    // never leaves this machine"), so the looser assertion passed even with the
    // availability gate removed.
    st.store = new RemoteVaultStore('https://vault.example.com');
    refreshLanPanel();
    expect($('lan-card').textContent).toContain('Switch to the local vault');
  });

  it('drops the remote notice again after switching back to local', () => {
    st.store = new RemoteVaultStore('https://vault.example.com');
    refreshLanPanel();
    expect($('lan-card').innerHTML).not.toBe('');

    st.store = new LocalVaultStore();
    refreshLanPanel();
    // Still no button outside Tauri, but the remote-specific notice is gone.
    expect($('lan-card').textContent).not.toContain('Switch to the local vault');
  });
});

describe('startLan guard', () => {
  it('refuses to serve while a remote vault is connected', async () => {
    // Defence in depth: the card is painted once and repainted only on the
    // events we hooked, so a switch that missed a repaint would leave a live
    // button behind. Getting this wrong publishes the wrong vault.
    st.store = new RemoteVaultStore('https://vault.example.com');
    await startLan();
    expect(st.lanServerRunning).toBe(false);
    expect(toasts.join(' ')).toContain('switch to the local vault');
  });

  it('does not claim to be serving when the platform cannot serve at all', async () => {
    st.store = new LocalVaultStore();
    await startLan();
    expect(st.lanServerRunning).toBe(false);
    expect(toasts.join(' ')).toContain('desktop app');
  });
});
