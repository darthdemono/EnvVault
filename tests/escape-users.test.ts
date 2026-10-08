/**
 * Hostile-value test for the Users/Classes panels (Phase 28): usernames, ids,
 * token descriptions and class names come from a server someone else may run.
 */
import { describe, it, expect, beforeEach } from 'vitest';
import { st } from '../src/ts/state';
import { loadRealIndexHtml, resetState } from './helpers';

const BREAKOUT = '" onmouseover="steal()" x="';
const TAG = '<img src=x onerror=alert(1)>';

beforeEach(() => {
  loadRealIndexHtml();
  resetState(st);
  (window as any).__TAURI__ = {
    core: {
      invoke: (cmd: string) => {
        switch (cmd) {
          case 'list_users':
            return Promise.resolve([
              {
                id: BREAKOUT,
                username: TAG,
                is_owner: false,
                has_password: true,
                created_at: '2024-01-01T00:00:00Z',
                last_seen_at: TAG,
                class_id: BREAKOUT,
                totp_enabled: false,
              },
            ]);
          case 'list_user_tokens':
            return Promise.resolve([
              {
                id: BREAKOUT,
                description: TAG,
                created_at: '2024-01-01T00:00:00Z',
                expires_at: TAG,
              },
            ]);
          case 'get_user_permissions':
            return Promise.resolve({ read: TAG, write: BREAKOUT });
          case 'list_user_classes':
            return Promise.resolve([
              { id: BREAKOUT, name: TAG, description: BREAKOUT, builtin: false },
            ]);
          case 'get_class_permissions':
            return Promise.resolve({ read: TAG, write: BREAKOUT });
          default:
            return Promise.resolve(null);
        }
      },
    },
  };
});

function clean(root: ParentNode) {
  for (const sel of ['img', 'script', '[onmouseover]', '[onerror]']) {
    expect(root.querySelector(sel), sel).toBeNull();
  }
}

describe('users and classes panels', () => {
  it('render hostile usernames, ids and descriptions inertly', async () => {
    const users = await import('../src/ts/users');
    await users.renderUsersPanel();
    clean(document.body);
    await users.renderUserDetail(BREAKOUT);
    clean(document.body);
    await users.renderClassesPanel();
    clean(document.body);
    expect(document.body.textContent).toContain(TAG);
  });
});
