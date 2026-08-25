/**
 * Encrypted backup round trip.
 *
 * This file leaves the machine, so it is the one export whose failure modes
 * matter most: it must actually produce a file for a real-sized vault, and must
 * refuse to decrypt anything it cannot authenticate.
 */
import { describe, it, expect, beforeEach, vi } from 'vitest';
import { st, resetViewState } from '../src/ts/state';
import { exportEncryptedBackup, importEncryptedBackup } from '../src/ts/import-export';
import { loadRealIndexHtml, makeEntry, makeProject, makeVault, resetState } from './helpers';

const toasts: { msg: string; type: string }[] = [];
vi.mock('../src/ts/utils', async (importOriginal) => {
  const real = await importOriginal<typeof import('../src/ts/utils')>();
  return {
    ...real,
    showToast: (msg: string, type = '') => {
      toasts.push({ msg, type });
    },
    showConfirm: async () => true,
  };
});

/** Captures the envelope that exportEncryptedBackup would have downloaded. */
let downloaded: string | null = null;
let downloadedBlob: Blob | null = null;

/** Array.prototype.at is ES2022; this project's tsconfig targets ES2020. */
const last = <T>(arr: T[]): T => arr[arr.length - 1];

beforeEach(() => {
  loadRealIndexHtml();
  resetState(st);
  resetViewState();
  toasts.length = 0;
  downloaded = null;
  (URL as any).createObjectURL = vi.fn((blob: Blob) => {
    downloadedBlob = blob;
    return 'blob:mock';
  });
  (URL as any).revokeObjectURL = vi.fn();
});

async function exportAndCapture(password: string): Promise<string | null> {
  downloadedBlob = null;
  await exportEncryptedBackup(password);
  // Re-read through an annotated local: TS narrows the module variable to null
  // from the assignment above, not knowing the URL callback reassigned it.
  const blob = downloadedBlob as Blob | null;
  if (!blob) return null;
  downloaded = await blob.text();
  return downloaded;
}

const GOOD_PW = 'correct horse battery';

describe('password floor', () => {
  it('refuses a password shorter than the master-password minimum', async () => {
    st.vault = makeVault({ api_keys: [makeEntry()] });
    expect(await exportAndCapture('short11chr')).toBeNull();
    expect(last(toasts).msg).toMatch(/at least 12/i);
  });

  it('accepts a password at the floor', async () => {
    st.vault = makeVault({ api_keys: [makeEntry()] });
    expect(await exportAndCapture('123456789012')).not.toBeNull();
  });
});

describe('round trip', () => {
  beforeEach(() => {
    st.vault = makeVault({
      projects: [
        makeProject({ id: 'Universal', name: 'Universal' }),
        makeProject({ id: 'p1', name: 'Acme' }),
      ],
      user_categories: ['infra'],
      api_keys: [
        makeEntry({ id: 'a', provider: 'Alpha', api_key: 'sk-alpha' }),
        makeEntry({ id: 'b', provider: 'Bravo', api_key: 'sk-bravo' }),
      ],
    });
  });

  it('restores every entry', async () => {
    const env = (await exportAndCapture(GOOD_PW))!;
    st.vault = makeVault();
    await importEncryptedBackup(env, GOOD_PW);
    expect(st.vault.api_keys.map((e) => e.provider)).toEqual(['Alpha', 'Bravo']);
    expect(st.vault.api_keys[0].api_key).toBe('sk-alpha');
  });

  it('restores projects and categories', async () => {
    const env = (await exportAndCapture(GOOD_PW))!;
    st.vault = makeVault();
    await importEncryptedBackup(env, GOOD_PW);
    expect(st.vault.projects.map((p) => p.name)).toContain('Acme');
    expect(st.vault.user_categories).toEqual(['infra']);
  });

  it('does not leave the plaintext in the envelope', async () => {
    const env = (await exportAndCapture(GOOD_PW))!;
    expect(env).not.toContain('sk-alpha');
    expect(env).not.toContain('Alpha');
  });

  it('survives a vault far larger than the old spread-argument limit', async () => {
    // `String.fromCharCode(...bytes)` blew the call stack past ~100 KB, and the
    // RangeError was uncaught — the button silently did nothing for any vault
    // holding a few certificates.
    const pem = 'A'.repeat(200_000);
    st.vault = makeVault({ api_keys: [makeEntry({ provider: 'Big', api_key: pem })] });
    const env = await exportAndCapture(GOOD_PW);
    expect(env, 'export produced no file for a large vault').not.toBeNull();

    st.vault = makeVault();
    await importEncryptedBackup(env!, GOOD_PW);
    expect(st.vault.api_keys[0].api_key).toBe(pem);
  });

  it('clears view state left over from the pre-restore vault', async () => {
    const env = (await exportAndCapture(GOOD_PW))!;
    st.currentSelectedProjectIds = ['gone'];
    st.revealed['key-a'] = true;
    await importEncryptedBackup(env, GOOD_PW);
    expect(st.currentSelectedProjectIds).toEqual(['Universal']);
    expect(st.revealed).toEqual({});
  });
});

describe('rejecting bad input', () => {
  beforeEach(() => {
    st.vault = makeVault({ api_keys: [makeEntry({ provider: 'Alpha' })] });
  });

  it('rejects the wrong password without touching the vault', async () => {
    const env = (await exportAndCapture(GOOD_PW))!;
    st.vault = makeVault({ api_keys: [makeEntry({ provider: 'Existing' })] });
    await importEncryptedBackup(env, 'wrong password here');
    expect(st.vault.api_keys.map((e) => e.provider)).toEqual(['Existing']);
    expect(last(toasts).msg).toMatch(/decryption failed/i);
  });

  it('rejects a tampered ciphertext — AES-GCM authenticates', async () => {
    const env = JSON.parse((await exportAndCapture(GOOD_PW))!);
    const ct = env.ct.split('');
    ct[10] = ct[10] === 'A' ? 'B' : 'A';
    env.ct = ct.join('');
    st.vault = makeVault();
    await importEncryptedBackup(JSON.stringify(env), GOOD_PW);
    expect(st.vault.api_keys).toEqual([]);
  });

  it('rejects a file that is not a backup', async () => {
    await importEncryptedBackup('{"hello":1}', GOOD_PW);
    expect(last(toasts).msg).toMatch(/unrecognised/i);
  });

  it('rejects unparseable input', async () => {
    await importEncryptedBackup('not json at all', GOOD_PW);
    expect(last(toasts).msg).toMatch(/not a valid backup/i);
  });

  it('honours the iteration count recorded in the envelope', async () => {
    // The field was written but never read, so a backup made with a different
    // count decrypted as "wrong password".
    const env = JSON.parse((await exportAndCapture(GOOD_PW))!);
    expect(env.kdf.iters).toBeGreaterThan(0);
    env.kdf.iters = 1; // claim a count that does not match
    st.vault = makeVault();
    await importEncryptedBackup(JSON.stringify(env), GOOD_PW);
    // Deriving with the declared count now genuinely fails to decrypt, rather
    // than silently succeeding because the declared value was ignored.
    expect(st.vault.api_keys).toEqual([]);
  });
});
