/**
 * Users panel. Ids here are scoped to a single vault, and the panel is one of
 * the few places the app shows a credential in the clear — both are what these
 * cover.
 */
import { describe, it, expect, beforeEach, vi } from 'vitest';
import { st } from '../src/ts/state';
import { loadRealIndexHtml, resetState } from './helpers';

const invoked: { cmd: string; args: any }[] = [];
let promptCalls: { kind: 'plain' | 'password'; msg: string }[] = [];
let promptAnswer: string | null = 'new-secret';

vi.mock('../src/ts/utils', async (importOriginal) => {
  const real = await importOriginal<typeof import('../src/ts/utils')>();
  return {
    ...real,
    showToast: () => {},
    showConfirm: async () => true,
    showPrompt: async (msg: string) => {
      promptCalls.push({ kind: 'plain', msg });
      return promptAnswer;
    },
    showPasswordPrompt: async (msg: string) => {
      promptCalls.push({ kind: 'password', msg });
      return promptAnswer;
    },
  };
});

beforeEach(() => {
  loadRealIndexHtml();
  resetState(st);
  invoked.length = 0;
  promptCalls = [];
  promptAnswer = 'new-secret';
  (window as any).__TAURI__ = {
    core: {
      invoke: async (cmd: string, args: any) => {
        invoked.push({ cmd, args });
        switch (cmd) {
          case 'list_users':
            return [
              {
                id: 'u1',
                username: 'alice',
                is_owner: false,
                has_password: true,
                created_at: '2024-01-01T00:00:00Z',
                last_seen_at: null,
                class_id: null,
              },
            ];
          case 'list_user_tokens':
            return [];
          case 'get_user_permissions':
            return { read: 'project:*', write: '' };
          case 'list_user_classes':
            return [];
          default:
            return null;
        }
      },
    },
  };
});

describe('changePassword', () => {
  it('prompts with a masked field, not a plain one', async () => {
    // A new password typed into a visible input is readable over the user's
    // shoulder and gets trimmed on the way out.
    const users = await import('../src/ts/users');
    await users.renderUserDetail('u1');
    document.getElementById('change-pw-btn')!.click();
    await new Promise((r) => setTimeout(r, 20));
    expect(promptCalls.map((c) => c.kind)).toContain('password');
    expect(promptCalls.some((c) => c.kind === 'plain')).toBe(false);
  });

  it('sends the password through unchanged, spaces included', async () => {
    promptAnswer = '  pad ded  ';
    const users = await import('../src/ts/users');
    await users.renderUserDetail('u1');
    document.getElementById('change-pw-btn')!.click();
    await new Promise((r) => setTimeout(r, 20));
    const call = invoked.find((c) => c.cmd === 'set_user_password');
    expect(call!.args.password).toBe('  pad ded  ');
  });

  it('switches to token-only auth on a blank answer', async () => {
    promptAnswer = '';
    const users = await import('../src/ts/users');
    await users.renderUserDetail('u1');
    document.getElementById('change-pw-btn')!.click();
    await new Promise((r) => setTimeout(r, 20));
    expect(invoked.find((c) => c.cmd === 'set_user_password')!.args.password).toBeNull();
  });

  it('does nothing when the prompt is cancelled', async () => {
    promptAnswer = null;
    const users = await import('../src/ts/users');
    await users.renderUserDetail('u1');
    document.getElementById('change-pw-btn')!.click();
    await new Promise((r) => setTimeout(r, 20));
    expect(invoked.find((c) => c.cmd === 'set_user_password')).toBeUndefined();
  });
});

describe('resetUsersPanelState', () => {
  it('forgets the selected user', async () => {
    // User ids belong to one vault; carrying one to the next server made the
    // panel highlight and load an id from a different vault.
    const users = await import('../src/ts/users');
    st.selectedUserId = 'u-from-other-server';
    users.resetUsersPanelState();
    expect(st.selectedUserId).toBeNull();
  });

  it('clears the detail workspace', async () => {
    const users = await import('../src/ts/users');
    document.getElementById('users-workspace')!.innerHTML =
      '<div>stale detail for another vault</div>';
    users.resetUsersPanelState();
    expect(document.getElementById('users-workspace')!.innerHTML).not.toContain('stale detail');
  });
});

describe('renderUserDetail', () => {
  it('renders the user and their permission expressions', async () => {
    const users = await import('../src/ts/users');
    await users.renderUserDetail('u1');
    expect(document.getElementById('detail-username-label')!.textContent).toBe('alice');
    expect((document.getElementById('uperm-expr-read') as HTMLTextAreaElement).value).toBe(
      'project:*',
    );
  });

  it('reports a user that no longer exists instead of rendering a blank panel', async () => {
    const users = await import('../src/ts/users');
    await users.renderUserDetail('does-not-exist');
    expect(document.getElementById('users-workspace')!.textContent).toMatch(/not found/i);
  });

  it('surfaces a backend error rather than showing empty permissions', async () => {
    (window as any).__TAURI__.core.invoke = async () => {
      throw new Error('vault is locked');
    };
    const users = await import('../src/ts/users');
    await users.renderUserDetail('u1');
    expect(document.getElementById('users-workspace')!.textContent).toContain('vault is locked');
  });

  it('escapes a username containing markup', async () => {
    (window as any).__TAURI__.core.invoke = async (cmd: string) => {
      if (cmd === 'list_users')
        return [
          {
            id: 'u1',
            username: '<img src=x onerror=alert(1)>',
            is_owner: false,
            has_password: true,
            created_at: '2024-01-01T00:00:00Z',
            last_seen_at: null,
            class_id: null,
          },
        ];
      if (cmd === 'get_user_permissions') return { read: '', write: '' };
      return [];
    };
    const users = await import('../src/ts/users');
    await users.renderUserDetail('u1');
    expect(document.getElementById('users-workspace')!.querySelector('img')).toBeNull();
  });
});

describe('token overlay', () => {
  it('shows the token and dismisses on Escape', async () => {
    const users = await import('../src/ts/users');
    await users.renderUserDetail('u1');
    (window as any).__TAURI__.core.invoke = async (cmd: string) =>
      cmd === 'create_user_token' ? { token: 'envv_secret_token' } : [];
    document.getElementById('new-token-btn')!.click();
    await new Promise((r) => setTimeout(r, 20));

    const overlay = document.querySelector('.token-overlay-backdrop');
    expect(overlay).not.toBeNull();
    expect(document.getElementById('token-display')!.textContent).toBe('envv_secret_token');

    document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape' }));
    expect(document.querySelector('.token-overlay-backdrop')).toBeNull();
  });
});
