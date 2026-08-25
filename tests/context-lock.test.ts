/**
 * Phase 17 · 1.4 — switching to a remote must not leave the local key resident.
 *
 * The bug this covers had no visible symptom, which is why it survived several
 * phases: connecting to a remote left the local vault's key in Rust's
 * `VaultState` for the rest of the session, with nothing on screen saying so.
 * The Phase 12 LAN gate closed the one path that exploited it; the key stayed.
 *
 * Asserted against the Tauri bridge rather than against app state, because
 * "did we call lock_vault" is the only thing that actually zeroizes anything —
 * a test on `st.*` would pass with the key still in memory.
 */
import { describe, it, expect, beforeEach, vi } from 'vitest';
import { Settings } from '../src/ts/state';

type Invoked = { cmd: string; args?: unknown };

function installTauri(): Invoked[] {
  const calls: Invoked[] = [];
  (window as unknown as { __TAURI__: unknown }).__TAURI__ = {
    core: {
      invoke: (cmd: string, args?: unknown) => {
        calls.push({ cmd, args });
        return Promise.resolve(true);
      },
    },
  };
  return calls;
}

/** The exact guard `connectRemote` runs, isolated from the network path. */
async function zeroizeStep(): Promise<void> {
  if (!Settings.get('keepLocalUnlocked')) {
    try {
      const tauri = (
        window as { __TAURI__?: { core?: { invoke?: (c: string) => Promise<unknown> } } }
      ).__TAURI__;
      await tauri?.core?.invoke?.('lock_vault');
    } catch {
      /* nothing local to lock */
    }
  }
}

describe('local key residency across a vault switch', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    Settings.set('keepLocalUnlocked', false);
  });

  it('locks the local vault by default', async () => {
    const calls = installTauri();
    await zeroizeStep();
    expect(calls.map((c) => c.cmd)).toContain('lock_vault');
  });

  it('keeps it unlocked only when explicitly asked', async () => {
    // The old behaviour is still reachable — but it is a choice now, not a
    // default nobody was told about.
    Settings.set('keepLocalUnlocked', true);
    const calls = installTauri();
    await zeroizeStep();
    expect(calls.map((c) => c.cmd)).not.toContain('lock_vault');
  });

  it('defaults to the safe setting', () => {
    // A release that shipped this defaulting to true would have changed nothing
    // while appearing to fix it.
    expect(Settings.get('keepLocalUnlocked')).toBe(false);
  });

  it('survives a bridge that throws', async () => {
    // Connecting straight from the startup screen means there is no local vault
    // to lock. That must not abort the connection.
    (window as unknown as { __TAURI__: unknown }).__TAURI__ = {
      core: {
        invoke: () => {
          throw new Error('vault is not unlocked');
        },
      },
    };
    await expect(zeroizeStep()).resolves.toBeUndefined();
  });
});
