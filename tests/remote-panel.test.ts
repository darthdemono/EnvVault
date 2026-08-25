/**
 * Regression tests for the two remote-vault bugs:
 *
 * 1. Connecting from the startup unlock screen never recorded the server, so it
 *    was missing from the Remote panel and the vault switcher.
 * 2. Switching back to local cleared `api_keys` and `user_categories` but left
 *    `projects`, stranding the remote's project tree in the sidebar.
 */
import { describe, it, expect, beforeEach, vi } from 'vitest';
import {
  upsertSavedRemote,
  findSavedRemote,
  switchToLocalVault,
  setRemoteFinishInitFn,
  renderRemotePanel,
} from '../src/ts/remote-panel';
import { st, Settings, RemoteVaultStore, LocalVaultStore } from '../src/ts/state';
// Importing render.ts registers the real render fn with setRenderFn, so
// triggerRender() inside switchToLocalVault paints the actual DOM.
import { render } from '../src/ts/render';
import { loadRealIndexHtml, makeEntry, makeProject, makeVault, resetState } from './helpers';

beforeEach(() => {
  loadRealIndexHtml();
  resetState(st);
  Settings.set('remoteSaved', []);
  Settings.set('remote', { enabled: false, serverUrl: '' });
  setRemoteFinishInitFn(async () => {});
});

describe('upsertSavedRemote', () => {
  it('records a server that was never added through the Add Remote form', () => {
    const cfg = upsertSavedRemote({ url: 'http://localhost:8743', username: '' });
    expect(Settings.get('remoteSaved')).toHaveLength(1);
    expect(cfg.url).toBe('http://localhost:8743');
    expect(cfg.username).toBe('');
    expect(cfg.id).toBeTruthy();
  });

  it('names an owner connection after the host', () => {
    expect(upsertSavedRemote({ url: 'https://vault.example.com', username: '' }).name).toBe(
      'vault.example.com',
    );
  });

  it('distinguishes a per-user connection in the name', () => {
    expect(upsertSavedRemote({ url: 'http://localhost:8743', username: 'alice' }).name).toBe(
      'localhost:8743 (alice)',
    );
  });

  it('does not duplicate on reconnect to the same server and user', () => {
    const first = upsertSavedRemote({ url: 'http://localhost:8743', username: 'alice' });
    const again = upsertSavedRemote({ url: 'http://localhost:8743', username: 'alice' });
    expect(Settings.get('remoteSaved')).toHaveLength(1);
    expect(again.id).toBe(first.id);
  });

  it('normalises a trailing slash so it is not treated as a different server', () => {
    const a = upsertSavedRemote({ url: 'http://localhost:8743/', username: '' });
    const b = upsertSavedRemote({ url: 'http://localhost:8743', username: '' });
    expect(a.id).toBe(b.id);
    expect(a.url).toBe('http://localhost:8743');
  });

  it('keeps two different users on one server as separate entries', () => {
    upsertSavedRemote({ url: 'http://localhost:8743', username: 'alice' });
    upsertSavedRemote({ url: 'http://localhost:8743', username: 'bob' });
    expect(Settings.get('remoteSaved')).toHaveLength(2);
  });

  it('stores the TLS fingerprint for TOFU pinning', () => {
    const cfg = upsertSavedRemote({
      url: 'https://localhost:8743',
      username: '',
      certFingerprint: 'ab:cd',
    });
    expect(cfg.certFingerprint).toBe('ab:cd');
  });

  it('warns when a known server presents a different certificate', () => {
    upsertSavedRemote({
      url: 'https://localhost:8743',
      username: '',
      certFingerprint: 'old-print',
    });
    upsertSavedRemote({
      url: 'https://localhost:8743',
      username: '',
      certFingerprint: 'new-print',
    });
    expect(document.getElementById('toast')!.textContent).toMatch(/fingerprint changed/i);
    expect(findSavedRemote('https://localhost:8743')!.certFingerprint).toBe('new-print');
  });

  it('does not warn on the first sight of a certificate', () => {
    upsertSavedRemote({
      url: 'https://localhost:8743',
      username: '',
      certFingerprint: 'first-print',
    });
    expect(document.getElementById('toast')!.textContent).not.toMatch(/fingerprint changed/i);
  });

  it('leaves the stored fingerprint alone when a reconnect reports none', () => {
    upsertSavedRemote({ url: 'https://localhost:8743', username: '', certFingerprint: 'keep-me' });
    upsertSavedRemote({ url: 'https://localhost:8743', username: '' });
    expect(findSavedRemote('https://localhost:8743')!.certFingerprint).toBe('keep-me');
  });

  it('makes the server visible in the Remote panel list', () => {
    upsertSavedRemote({ url: 'http://localhost:8743', username: '' });
    renderRemotePanel();
    const items = [...document.querySelectorAll('#remote-panel-list [data-remote-id]')];
    expect(items).toHaveLength(1);
    expect(items[0].textContent).toContain('localhost:8743');
  });
});

describe('findSavedRemote', () => {
  it('matches on url and username', () => {
    const cfg = upsertSavedRemote({ url: 'http://localhost:8743', username: 'alice' });
    expect(findSavedRemote('http://localhost:8743', 'alice')?.id).toBe(cfg.id);
  });

  it('defaults to the owner (blank username) connection', () => {
    upsertSavedRemote({ url: 'http://localhost:8743', username: 'alice' });
    expect(findSavedRemote('http://localhost:8743')).toBeUndefined();
    const owner = upsertSavedRemote({ url: 'http://localhost:8743', username: '' });
    expect(findSavedRemote('http://localhost:8743')?.id).toBe(owner.id);
  });

  it('tolerates a trailing slash', () => {
    const cfg = upsertSavedRemote({ url: 'http://localhost:8743', username: '' });
    expect(findSavedRemote('http://localhost:8743/')?.id).toBe(cfg.id);
  });

  it('returns undefined for an unknown server', () => {
    expect(findSavedRemote('http://nope:1')).toBeUndefined();
  });
});

describe('switchToLocalVault', () => {
  beforeEach(() => {
    // Simulate a live remote session holding remote data in memory.
    st.store = new RemoteVaultStore('http://localhost:8743');
    st.activeRemoteId = 'remote-1';
    st.vault = makeVault({
      api_keys: [makeEntry({ provider: 'RemoteKey' }), makeEntry({ provider: 'Another' })],
      user_categories: ['remote-cat'],
      projects: [
        makeProject({ id: 'Universal', name: 'Universal' }),
        makeProject({ id: 'rp1', name: 'Remote Project' }),
      ],
    });
    st.currentSelectedProjectIds = ['rp1'];
    Settings.set('remote', { enabled: true, serverUrl: 'http://localhost:8743' });
  });

  it('clears the remote projects, not just the entries', async () => {
    // The bug: api_keys and user_categories were emptied while projects stayed,
    // so the remote's project tree remained in the sidebar over an empty grid.
    await switchToLocalVault();
    expect(st.vault.api_keys).toEqual([]);
    expect(st.vault.user_categories).toEqual([]);
    expect(st.vault.projects.map((p) => p.id)).toEqual(['Universal']);
  });

  it('resets a project selection that pointed at a remote-only project', async () => {
    await switchToLocalVault();
    expect(st.currentSelectedProjectIds).toEqual(['Universal']);
  });

  it('clears sidebar filters carried over from the remote vault', async () => {
    st.activeTagFilter = 'prod';
    st.activePrefixFilter = 'VITE';
    await switchToLocalVault();
    expect(st.activeTagFilter).toBeNull();
    expect(st.activePrefixFilter).toBeNull();
  });

  it('drops expand and reveal state so no remote secret stays revealed', async () => {
    st.expanded.add('some-remote-entry');
    st.revealed['key-some-remote-entry'] = true;
    await switchToLocalVault();
    expect(st.expanded.size).toBe(0);
    expect(st.revealed).toEqual({});
  });

  it('swaps the store back to a local one and clears the active remote', async () => {
    await switchToLocalVault();
    expect(st.store).toBeInstanceOf(LocalVaultStore);
    expect(st.activeRemoteId).toBeNull();
  });

  it('marks the remote connection disabled in settings', async () => {
    await switchToLocalVault();
    expect(Settings.get('remote')).toEqual({ enabled: false, serverUrl: '' });
  });

  it('relabels the header', async () => {
    document.getElementById('vault-name')!.textContent = 'Production Vault';
    await switchToLocalVault();
    expect(document.getElementById('vault-name')!.textContent).toBe('Local Vault');
  });

  it('reloads the local vault through finishInit', async () => {
    const finish = vi.fn(async () => {});
    setRemoteFinishInitFn(finish);
    await switchToLocalVault();
    expect(finish).toHaveBeenCalledOnce();
  });

  it('leaves the saved remotes list intact — disconnecting is not forgetting', async () => {
    upsertSavedRemote({ url: 'http://localhost:8743', username: '' });
    await switchToLocalVault();
    expect(Settings.get('remoteSaved')).toHaveLength(1);
  });

  it('marks the vault closed so nothing treats the stale data as live', async () => {
    st.vaultOpen = true;
    await switchToLocalVault();
    expect(st.vaultOpen).toBe(false);
  });

  // The bug: clearing st.vault does nothing to the DOM, and the branch where
  // the local vault is still locked returns before finishInit — the only thing
  // that rendered. So the remote's project tree and a full config view of chunk
  // cards stayed in the document after disconnecting, and came back intact if
  // the unlock was abandoned. finishInit is a no-op here on purpose: that is
  // exactly the locked-local case.
  it('repaints the DOM itself instead of relying on finishInit', async () => {
    st.vault.projects.push(
      makeProject({
        id: 'rp2',
        name: 'Remote WG',
        project_type: 'wireguard',
        chunks: [
          {
            id: 'c1',
            chunk_type: 'wg_peer',
            name: 'PeerOne',
            fields: [{ key: 'PublicKey', value: 'abc' }],
          },
        ],
      } as any),
    );
    st.currentSelectedProjectIds = ['rp2'];
    setRemoteFinishInitFn(async () => {});
    render();
    expect(document.getElementById('project-list')!.textContent).toContain('Remote WG');
    expect(document.getElementById('card-grid')!.textContent).toContain('PeerOne');

    await switchToLocalVault();

    expect(document.getElementById('project-list')!.textContent).not.toContain('Remote WG');
    expect(document.getElementById('card-grid')!.textContent).not.toContain('PeerOne');
    expect(document.getElementById('card-grid')!.textContent).not.toContain('RemoteKey');
  });
});
