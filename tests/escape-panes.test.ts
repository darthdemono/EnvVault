/**
 * Phase 28.1: hostile values through the panes outside the card grid. Each pane
 * is fed markup in every field a vault, a remote server or a saved setting can
 * supply, and the assertion is on the resulting DOM: nothing live, text intact.
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { st, Settings, LocalVaultStore } from '../src/ts/state';
import { loadRealIndexHtml, makeEntry, makeVault, resetState } from './helpers';

const TAG = '<img src=x onerror=alert(1)>';
const BREAK = '" onmouseover="steal()" x="';

function clean(root: ParentNode, label: string) {
  for (const sel of ['img', 'script', 'iframe', '[onmouseover]', '[onerror]', '[onclick]']) {
    expect(root.querySelector(sel), `${label}: ${sel} became live`).toBeNull();
  }
}

beforeEach(() => {
  loadRealIndexHtml();
  resetState(st);
  st.store = new LocalVaultStore();
});
afterEach(() => {
  delete (window as unknown as Record<string, unknown>).__TAURI__;
});

describe('panes outside the grid', () => {
  it('the Authenticator panel', async () => {
    const { mountToolsPanes } = await import('../src/ts/tools-markup');
    mountToolsPanes();
    const { renderAuthPanel } = await import('../src/ts/auth-panel');
    st.vault = makeVault({
      api_keys: [
        makeEntry({
          id: 'a1',
          provider: TAG,
          account_name: BREAK,
          totp_secret: 'JBSWY3DPEHPK3PXP',
          totp_kind: 'hotp',
          totp_counter: 3,
        } as never),
        makeEntry({ id: 'a2', provider: BREAK, totp_secret: 'JBSWY3DPEHPK3PXP' } as never),
      ],
    });
    renderAuthPanel();
    const grid = document.getElementById('auth-grid')!;
    clean(grid, 'auth grid');
    clean(document.getElementById('auth-side-list')!, 'auth side list');
    expect(grid.textContent).toContain(TAG);
  });

  it('the saved-remotes list and detail', async () => {
    const { renderRemotePanel } = await import('../src/ts/remote-panel');
    Settings.set('remoteSaved', [
      {
        id: 'r1',
        name: TAG,
        url: `https://x.test/${BREAK}`,
        username: BREAK,
        certFingerprint: TAG,
        lastConnectedAt: TAG,
      },
    ] as never);
    st.activeRemoteId = 'r1';
    renderRemotePanel();
    clean(document.getElementById('remote-panel-list')!, 'remote list');
    clean(document.getElementById('remote-detail-host')!, 'remote detail');
    expect(document.getElementById('remote-panel-list')!.textContent).toContain(TAG);
  });

  it('the LAN card while serving', async () => {
    (window as unknown as Record<string, unknown>).__TAURI__ = {
      core: {
        invoke: () =>
          Promise.resolve({
            running: true,
            port: 1,
            url: `https://${TAG}/${BREAK}`,
            fingerprint: `${TAG}${BREAK}`,
            peers: 2,
            idle_secs: 0,
          }),
      },
    };
    const lan = await import('../src/ts/lan');
    lan.initLanPanel();
    await new Promise((r) => setTimeout(r, 30));
    const card = document.getElementById('lan-card')!;
    clean(card, 'lan card');
    await lan.stopLan(true).catch(() => undefined);
  });

  it('context menus and dropdowns with plain-text labels', async () => {
    const { showContextMenu } = await import('../src/ts/modals');
    showContextMenu(1, 1, [
      { label: TAG, fn: () => undefined },
      '---',
      { label: BREAK, fn: () => undefined },
    ]);
    const dd = document.getElementById('dropdown')!;
    clean(dd, 'context menu');
    expect(dd.textContent).toContain(TAG);
  });

  it('health-scan rows for hostile providers, accounts and projects', async () => {
    const { mountToolsPanes } = await import('../src/ts/tools-markup');
    mountToolsPanes();
    const { initTools } = await import('../src/ts/tools');
    initTools();
    st.vault = makeVault({
      api_keys: [
        makeEntry({ id: 'h1', provider: TAG, account_name: BREAK, api_key: 'abc' } as never),
        makeEntry({ id: 'h2', provider: TAG, account_name: BREAK, api_key: 'abc' } as never),
      ],
    });
    (document.getElementById('health-scan-btn') as HTMLButtonElement).click();
    const out = document.getElementById('health-results')!;
    expect(out.textContent).toContain(TAG);
    clean(out, 'health results');
  });

  it('the Unique IDs pane result line', async () => {
    const { mountToolsPanes } = await import('../src/ts/tools-markup');
    mountToolsPanes();
    const { RemoteVaultStore } = await import('../src/ts/state');
    const remote = new RemoteVaultStore('http://localhost:1');
    remote.uidRequest = () =>
      Promise.resolve({ status: 200, body: { value: TAG, namespace: BREAK, error: TAG } });
    st.store = remote;
    const { initUidPane } = await import('../src/ts/uid-pane');
    initUidPane();
    (document.getElementById('uid-mint-btn') as HTMLButtonElement).click();
    await new Promise((r) => setTimeout(r, 30));
    clean(document.getElementById('tool-uid') ?? document.body, 'uid pane');
  });

  it('the users list and a user detail, from hostile server data', async () => {
    const user = {
      id: 'u1',
      username: TAG,
      has_password: true,
      is_owner: false,
      created_at: BREAK,
      last_seen_at: BREAK,
      class_id: 'c1',
      totp_enabled: true,
    };
    const answers: Record<string, unknown> = {
      list_users: [user],
      list_user_tokens: [
        { id: 't1', user_id: 'u1', description: TAG, created_at: BREAK, expires_at: BREAK },
      ],
      get_user_permissions: { read: TAG, write: BREAK },
      list_user_classes: [
        {
          id: 'c1',
          name: TAG,
          description: BREAK,
          cap_manage_users: false,
          cap_manage_classes: false,
          cap_delete_projects: false,
          created_at: BREAK,
        },
      ],
      totp_status: { enrolled: true, enabled: true },
    };
    (window as unknown as Record<string, unknown>).__TAURI__ = {
      core: { invoke: (cmd: string) => Promise.resolve(answers[cmd] ?? null) },
    };
    const users = await import('../src/ts/users');
    await users.renderUsersPanel();
    clean(document.getElementById('users-list')!, 'users list');
    expect(document.getElementById('users-list')!.textContent).toContain(TAG);
    await users.renderUserDetail('u1');
    clean(document.getElementById('users-workspace')!, 'user detail');
    await users.renderClassesPanel();
    clean(document.getElementById('users-list')!, 'classes list');
  });

  it('the calendar feed list', async () => {
    const { RemoteVaultStore } = await import('../src/ts/state');
    const remote = new RemoteVaultStore('http://localhost:1');
    remote.listCalendarFeeds = () =>
      Promise.resolve([
        { id: BREAK, name: TAG, kinds: [TAG, BREAK], revoked_at: null },
        { id: 'r', name: BREAK, kinds: [], revoked_at: TAG },
      ]);
    st.store = remote;
    const { mountToolsPanes } = await import('../src/ts/tools-markup');
    mountToolsPanes();
    const { renderTimeline } = await import('../src/ts/timeline');
    renderTimeline();
    await new Promise((r) => setTimeout(r, 30));
    const list = document.getElementById('tl-feed-list')!;
    expect(list.textContent).toContain(TAG);
    clean(list, 'feed list');
  });

  it('the add/edit form filled from a hostile composite and a hostile web session', async () => {
    const { fillForm } = await import('../src/ts/modals');
    for (const secretType of ['composite', 'cookie', 'bundle', 'env_var']) {
      fillForm({
        secretType,
        provider: TAG,
        api_key: BREAK,
        label: BREAK,
        user_agent: TAG,
        composite_template: `https://x/{a}${TAG}`,
        composite_kind: TAG,
        extra_vars: [
          { key: TAG, value: BREAK, secret: true },
          { key: BREAK, value: TAG, public: true },
        ],
      } as never);
      const form = document.getElementById('modal-overlay')!;
      clean(form, `form (${secretType})`);
    }
  });

  it('the copy-as menu of an entry with hostile names', async () => {
    const { openCopyEnvMenu } = await import('../src/ts/modals');
    st.vault = makeVault({
      api_keys: [
        makeEntry({
          id: 'c1',
          provider: TAG,
          label: BREAK,
          key_id: TAG,
          secretType: 'cookie',
          api_key: 'a=b',
          user_agent: TAG,
          extra_vars: [{ key: TAG, value: BREAK }],
        } as never),
      ],
    });
    const btn = document.createElement('button');
    document.body.appendChild(btn);
    openCopyEnvMenu({ currentTarget: btn, target: btn, stopPropagation() {} } as never, 0);
    const dd = document.getElementById('dropdown')!;
    expect(dd.children.length).toBeGreaterThan(0);
    clean(dd, 'copy-as menu');
  });

  it('settings rows built from hostile saved settings', async () => {
    Settings.set('accentColor', BREAK as never);
    Settings.set('sidebarSections', [TAG, BREAK] as never);
    Settings.set('panelOrder', [TAG, BREAK] as never);
    Settings.set('remoteSaved', [{ id: BREAK, name: TAG, url: BREAK }] as never);
    const sp = await import('../src/ts/settings-panel');
    sp.openSettings();
    clean(document.getElementById('settings-overlay') ?? document.body, 'settings');
  });
});
