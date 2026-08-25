/**
 * Trust-on-first-use for a remote server's TLS certificate.
 *
 * `remote_request` pins when handed a fingerprint and applies normal CA
 * validation when not — so reaching a self-signed server needs a fingerprint
 * that can only be obtained by reaching it. `acquireFingerprint` is the one
 * unauthenticated step that breaks that deadlock, and it must never run without
 * the user seeing what they are trusting.
 */
import { describe, it, expect, beforeEach, vi } from 'vitest';
import { st, Settings } from '../src/ts/state';
import { acquireFingerprint, upsertSavedRemote, findSavedRemote } from '../src/ts/remote-panel';
import { loadRealIndexHtml, resetState } from './helpers';

let confirmAnswer = true;
const confirmMessages: string[] = [];
const toasts: string[] = [];

vi.mock('../src/ts/utils', async (importOriginal) => {
  const real = await importOriginal<typeof import('../src/ts/utils')>();
  return {
    ...real,
    showToast: (m: string) => {
      toasts.push(m);
    },
    showConfirm: async (m: string) => {
      confirmMessages.push(m);
      return confirmAnswer;
    },
    showPasswordPrompt: async () => 'pw',
  };
});

/** Array.prototype.at is ES2022; this project's tsconfig targets ES2020. */
const last = <T>(arr: T[]): T => arr[arr.length - 1];

const FP = 'a'.repeat(64);
let probeCalls: string[] = [];
let probeResult: string | Error = FP;

beforeEach(() => {
  loadRealIndexHtml();
  resetState(st);
  Settings.set('remoteSaved', []);
  confirmAnswer = true;
  confirmMessages.length = 0;
  toasts.length = 0;
  probeCalls = [];
  probeResult = FP;
  (window as any).__TAURI__ = {
    core: {
      invoke: async (cmd: string, args: any) => {
        if (cmd === 'probe_cert_fingerprint') {
          probeCalls.push(args.url);
          if (probeResult instanceof Error) throw probeResult;
          return probeResult;
        }
        return null;
      },
    },
  };
});

describe('acquireFingerprint', () => {
  it('probes the server and returns the accepted fingerprint', async () => {
    const fp = await acquireFingerprint('https://vault.example.com');
    expect(probeCalls).toEqual(['https://vault.example.com']);
    expect(fp).toBe(FP);
  });

  it('shows the fingerprint to the user before trusting anything', async () => {
    await acquireFingerprint('https://vault.example.com');
    expect(confirmMessages).toHaveLength(1);
    // Grouped into pairs so it can actually be compared against the server.
    expect(confirmMessages[0]).toContain('AA:AA:AA');
    expect(confirmMessages[0]).toContain('vault.example.com');
  });

  it('returns null when the user declines, pinning nothing', async () => {
    confirmAnswer = false;
    expect(await acquireFingerprint('https://vault.example.com')).toBeNull();
  });

  it('reports an unreachable server instead of silently returning null', async () => {
    probeResult = new Error('connection refused');
    expect(await acquireFingerprint('https://down.example.com')).toBeNull();
    expect(last(toasts)).toMatch(/could not reach/i);
    expect(confirmMessages).toHaveLength(0);
  });

  it('does not probe a plain http server — there is no certificate to pin', async () => {
    expect(await acquireFingerprint('http://localhost:8743')).toBeNull();
    expect(probeCalls).toEqual([]);
  });

  it('does nothing outside Tauri, where the proxy does not exist', async () => {
    delete (window as any).__TAURI__;
    expect(await acquireFingerprint('https://vault.example.com')).toBeNull();
    expect(probeCalls).toEqual([]);
  });
});

describe('pin storage', () => {
  it('keeps the accepted fingerprint against the saved server', () => {
    const cfg = upsertSavedRemote({
      url: 'https://vault.example.com',
      username: '',
      certFingerprint: FP,
    });
    expect(findSavedRemote('https://vault.example.com')!.certFingerprint).toBe(FP);
    expect(cfg.certFingerprint).toBe(FP);
  });

  it('warns rather than silently re-pinning when the certificate changes', () => {
    // The old connect path overwrote the stored fingerprint on every connect,
    // so a pin held only until the first mismatch — the one moment it matters.
    upsertSavedRemote({ url: 'https://vault.example.com', username: '', certFingerprint: FP });
    const other = 'b'.repeat(64);
    upsertSavedRemote({ url: 'https://vault.example.com', username: '', certFingerprint: other });
    expect(toasts.some((t) => /fingerprint changed/i.test(t))).toBe(true);
  });
});
