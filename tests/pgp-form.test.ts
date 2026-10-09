/**
 * The add/edit form's "Read key" for `gpg_key` (Phase 24.5): Rust reads the key
 * (`pgp_inspect`, tested against real gpg output in vault-core); this pins what
 * the form does with the answer.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { loadRealIndexHtml, resetState } from './helpers';

vi.mock('../src/ts/utils', async (importOriginal) => {
  const real = await importOriginal<typeof import('../src/ts/utils')>();
  return { ...real, showPromptLarge: async () => '-----BEGIN PGP PUBLIC KEY BLOCK-----\n...' };
});

const $ = (id: string) => document.getElementById(id) as HTMLInputElement;
const flush = () => new Promise((r) => setTimeout(r, 30));

let answer: unknown;
const seen: [string, unknown][] = [];

beforeEach(() => {
  vi.resetModules();
  loadRealIndexHtml();
  seen.length = 0;
  answer = {
    fingerprint: 'AB'.repeat(20),
    key_id: 'AB'.repeat(8),
    user_ids: ['A <a@x>', 'B <b@x>'],
    expires_at: '2027-10-09T09:43:34Z',
  };
  (window as unknown as Record<string, unknown>).__TAURI__ = {
    core: {
      invoke: (cmd: string, args: unknown) => {
        seen.push([cmd, args]);
        return answer instanceof Error ? Promise.reject(answer) : Promise.resolve(answer);
      },
    },
  };
});
afterEach(() => {
  delete (window as unknown as Record<string, unknown>).__TAURI__;
});

async function openGpgForm() {
  const { st } = await import('../src/ts/state');
  resetState(st);
  const m = await import('../src/ts/modals');
  m.openAdd();
  const type = document.getElementById('f-secret-type') as HTMLSelectElement;
  type.value = 'gpg_key';
  type.dispatchEvent(new Event('change'));
  return m;
}

describe('gpg_key "Read key"', () => {
  it('is offered for a GPG key and no other type', async () => {
    await openGpgForm();
    expect($('f-pgp-group').style.display).toBe('flex');
    const type = document.getElementById('f-secret-type') as HTMLSelectElement;
    type.value = 'api_key';
    type.dispatchEvent(new Event('change'));
    expect($('f-pgp-group').style.display).toBe('none');
  });

  it('fills the expiry and three public variables, and pressing it again does not duplicate them', async () => {
    await openGpgForm();
    $('f-pgp-btn').click();
    await flush();
    expect(seen[0][0]).toBe('pgp_inspect');
    expect($('f-expires').value).toBe('2027-10-09T09:43:34Z');
    const keys = () =>
      [...document.querySelectorAll<HTMLInputElement>('#f-extra-vars-list .extra-var-key')].map(
        (i) => i.value,
      );
    expect(keys()).toEqual(['fingerprint', 'key_id', 'user_ids']);
    // The public flag is set: a fingerprint is for printing.
    const pub = document.querySelectorAll<HTMLInputElement>('#f-extra-vars-list .extra-var-public');
    expect([...pub].every((c) => c.checked)).toBe(true);
    $('f-pgp-btn').click();
    await flush();
    expect(keys()).toEqual(['fingerprint', 'key_id', 'user_ids']);
  });

  it('a key that does not expire clears the date, and an unreadable one changes nothing', async () => {
    await openGpgForm();
    $('f-expires').value = '2030-01-01';
    answer = {
      fingerprint: 'AB'.repeat(20),
      key_id: 'AB'.repeat(8),
      user_ids: [],
      expires_at: null,
    };
    $('f-pgp-btn').click();
    await flush();
    expect($('f-expires').value).toBe('');
    $('f-expires').value = '2031-01-01';
    answer = new Error('Not an OpenPGP packet stream');
    $('f-pgp-btn').click();
    await flush();
    expect($('f-expires').value).toBe('2031-01-01');
  });
});
