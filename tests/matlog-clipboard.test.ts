/**
 * Phase 36: the app's clipboard writes reach the materialisation log. Rust owns
 * the matching (fingerprints, never values); what is pinned here is that the
 * renderer reports every copy, with the vault, only inside the desktop app, and
 * that a failing log can never fail a copy.
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { clipboardWrite, onClipboardWrite } from '../src/ts/utils';
import { st } from '../src/ts/state';
import { resetState } from './helpers';

const calls: [string, Record<string, unknown>][] = [];
let fail = false;

beforeEach(() => {
  calls.length = 0;
  fail = false;
  resetState(st);
  st.vault = {
    api_keys: [{ id: 'a', provider: 'P', api_key: 'k' }],
    user_categories: [],
    projects: [],
  } as never;
});
afterEach(() => {
  delete (window as unknown as Record<string, unknown>).__TAURI__;
});

const bridge = () => {
  (window as unknown as Record<string, unknown>).__TAURI__ = {
    core: {
      invoke: (cmd: string, args: Record<string, unknown>) => {
        calls.push([cmd, args]);
        return fail ? Promise.reject(new Error('log broken')) : Promise.resolve(null);
      },
    },
  };
};

describe('clipboard observer', () => {
  it('hands the copied text to Rust with the vault, inside the desktop app', async () => {
    bridge();
    await clipboardWrite('sk_live_copied');
    expect(calls).toHaveLength(1);
    expect(calls[0][0]).toBe('matlog_note');
    expect(calls[0][1].text).toBe('sk_live_copied');
    expect(calls[0][1].note).toBe('clipboard');
    expect(calls[0][1].vault).toBe(st.vault);
  });

  it('does nothing in a plain browser, and nothing for a huge string', async () => {
    await clipboardWrite('x');
    bridge();
    await clipboardWrite('y'.repeat((1 << 20) + 1));
    expect(calls).toHaveLength(0);
  });

  it('a log that fails, or an observer that throws, never fails the copy', async () => {
    bridge();
    fail = true;
    await expect(clipboardWrite('z')).resolves.toBeUndefined();
    const keep = st.vault;
    onClipboardWrite(() => {
      throw new Error('observer broken');
    });
    await expect(clipboardWrite('w')).resolves.toBeUndefined();
    st.vault = keep;
  });
});
