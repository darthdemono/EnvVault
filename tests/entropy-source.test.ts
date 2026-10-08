/**
 * The UI generators' entropy source (Phase 33.4): the app side of
 * `--entropy-source`. The Rust mixing is tested in vault-core; this pins the
 * behaviour a user sees: bytes come from the chosen source, and an empty pool is
 * a message, never a silent fall back to the OS.
 */
import { describe, it, expect, beforeEach, vi } from 'vitest';

beforeEach(() => {
  vi.resetModules();
  delete (window as unknown as { __TAURI__?: unknown }).__TAURI__;
});

function bridge(invoke: (cmd: string, args?: unknown) => Promise<unknown>) {
  (window as unknown as { __TAURI__: unknown }).__TAURI__ = { core: { invoke } };
}

describe('entropy source for generators', () => {
  it('uses the OS source by default and needs no pool', async () => {
    const g = await import('../src/ts/generators');
    expect(g.entropySource()).toBe('os');
    expect(g.generateRandomBytes(8, 'hex')).toMatch(/^[0-9a-f]{16}$/);
  });

  it('draws from the pool of the chosen source, byte for byte', async () => {
    const invoke = vi.fn(async () => 'ab'.repeat(8192));
    bridge(invoke);
    const g = await import('../src/ts/generators');
    await g.setEntropySource('file:/dev/hwrng');
    expect(invoke).toHaveBeenCalledWith('entropy_fill', {
      source: 'file:/dev/hwrng',
      length: 8192,
    });
    expect(g.generateRandomBytes(4, 'hex')).toBe('abababab');
  });

  it('says so when the pool is empty instead of falling back to the OS', async () => {
    bridge(vi.fn(async () => Promise.reject(new Error('device missing'))));
    const g = await import('../src/ts/generators');
    await g.setEntropySource('file:/dev/hwrng').catch(() => {});
    const seen: string[] = [];
    const out = g.guardEntropy(
      () => g.generateRandomBytes(8, 'hex'),
      (m) => seen.push(m),
    );
    expect(out).toBeUndefined();
    expect(seen[0]).toMatch(/entropy source/i);
  });
});
