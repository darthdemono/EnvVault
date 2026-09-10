/**
 * The desktop half of a stored TOTP seed: what the app actually sends over IPC
 * and what it paints with the answer (Phase 22).
 *
 * `tests/totp.test.ts` covers the parser and the no-Tauri branch — the one that
 * prints `— — —`. Everything on the *other* side of `inTauri` was covered by
 * nothing, which mattered more than it sounds: `inTauri` is read once at module
 * scope (`state.ts`), so a suite that imports `totp.ts` normally can only ever
 * exercise the browser path. The IPC branch is where the argument names, the
 * seed normalisation, the cache and the countdown live.
 *
 * So every test here re-imports the module graph with `__TAURI__` present, via
 * `vi.resetModules()` and a dynamic import. Nothing about the real generator is
 * asserted — there is one HMAC and it is Rust's, with the RFC 6238 vectors
 * beside it in `vault-core/src/totp.rs`.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import type { VaultEntry } from '../src/ts/types';

type Invoke = (cmd: string, args?: Record<string, unknown>) => unknown;

interface TotpModule {
  liveCodeFor: (e: VaultEntry) => Promise<unknown>;
  tickTotp: () => Promise<void>;
  resetTotpCache: () => void;
  startTotpTicker: () => void;
  stopTotpTicker: () => void;
}

let calls: { cmd: string; args?: Record<string, unknown> }[] = [];

/**
 * Load `totp.ts` and `state.ts` fresh with a Tauri bridge in place.
 *
 * The reset is what makes this work: `inTauri` is a module-scope const, so the
 * bridge has to exist before the import, and a second suite in the same file
 * would otherwise reuse the first one's evaluation.
 */
async function loadWithTauri(invoke: Invoke): Promise<{ totp: TotpModule; st: any }> {
  vi.resetModules();
  (window as any).__TAURI__ = {
    core: {
      invoke: (cmd: string, args?: Record<string, unknown>) => {
        calls.push({ cmd, args });
        return Promise.resolve(invoke(cmd, args));
      },
    },
  };
  const totp = (await import('../src/ts/totp')) as unknown as TotpModule;
  const { st } = await import('../src/ts/state');
  return { totp, st };
}

function entry(over: Partial<VaultEntry> = {}): VaultEntry {
  return {
    id: 'e1',
    provider: 'GitHub',
    api_key: '',
    totp_secret: 'JBSWY3DPEHPK3PXP',
    ...over,
  } as VaultEntry;
}

/** One slot in the shape `render.ts` writes for both the card and the sidebar. */
function slotHtml(id: string): string {
  return `<div data-totp-for="${id}">
    <span class="totp-code">— — —</span>
    <span class="totp-countdown"><i class="totp-countdown-fill"></i></span>
    <span class="totp-secs"></span>
  </div>`;
}

const LIVE = {
  code: '123456',
  remaining_secs: 22,
  period: 30,
  digits: 6,
  algorithm: 'SHA1',
};

beforeEach(() => {
  calls = [];
  document.body.innerHTML = '';
});

afterEach(() => {
  delete (window as any).__TAURI__;
  vi.useRealTimers();
});

describe('liveCodeFor — what crosses the IPC boundary', () => {
  it('asks entry_totp_code by name, with the four arguments the command declares', async () => {
    const { totp } = await loadWithTauri(() => LIVE);
    await totp.liveCodeFor(entry());

    expect(calls).toHaveLength(1);
    expect(calls[0].cmd).toBe('entry_totp_code');
    // Tauri 2 matches argument keys exactly: `entry_totp_code(secret, algorithm,
    // digits, period)`. A misspelling here fails at runtime with "missing
    // required key", which is how the whole users panel broke once.
    expect(Object.keys(calls[0].args!).sort()).toEqual(['algorithm', 'digits', 'period', 'secret']);
    expect(calls[0].args).toMatchObject({ algorithm: 'SHA1', digits: 6, period: 30 });
  });

  it('normalises the seed on the way out, so one seed is one cache key and one fingerprint', async () => {
    const { totp } = await loadWithTauri(() => LIVE);
    await totp.liveCodeFor(entry({ totp_secret: 'jbsw y3dp-ehpk 3pxp==' }));
    expect(calls[0].args!.secret).toBe('JBSWY3DPEHPK3PXP');
  });

  it('sends the clamped parameters, never the stored ones', async () => {
    // A vault is untrusted input. The command clamps too (one shared reader in
    // `vault_core`), but the app must not be the thing that relies on it.
    const { totp } = await loadWithTauri(() => LIVE);
    await totp.liveCodeFor(
      entry({ totp_digits: 99, totp_period: 0, totp_algorithm: 'MD5' as any }),
    );
    expect(calls[0].args).toMatchObject({ algorithm: 'SHA1', digits: 6, period: 30 });
  });

  it('caches by seed and parameters, not by entry id', async () => {
    const { totp } = await loadWithTauri(() => LIVE);
    const a = entry({ id: 'a' });
    const b = entry({ id: 'b' }); // different entry, same seed
    await totp.liveCodeFor(a);
    await totp.liveCodeFor(b);
    expect(calls).toHaveLength(1);

    // A changed seed must never repaint the code of the one it replaced.
    await totp.liveCodeFor(entry({ id: 'a', totp_secret: 'GEZDGNBVGY3TQOJQ' }));
    expect(calls).toHaveLength(2);

    // Same seed, different parameters, is a different code.
    await totp.liveCodeFor(entry({ id: 'a', totp_digits: 8 }));
    expect(calls).toHaveLength(3);
  });

  it('does not queue a second request for a seed already in flight', async () => {
    let release!: (v: unknown) => void;
    const pending = new Promise((r) => (release = r));
    const { totp } = await loadWithTauri(() => pending);

    const first = totp.liveCodeFor(entry());
    const second = await totp.liveCodeFor(entry()); // ticks once a second; must not stack
    expect(second).toBeNull();
    expect(calls).toHaveLength(1);
    release(LIVE);
    await first;
  });

  it('returns null rather than throwing when the command fails', async () => {
    // This runs on a one-second timer. A rejected promise per card per tick is a
    // console nobody can read, and an unhandled rejection in a renderer.
    const { totp } = await loadWithTauri(() => {
      throw new Error('Vault is locked');
    });
    await expect(totp.liveCodeFor(entry())).resolves.toBeNull();
  });

  it('resetTotpCache drops what lock() must not leave in memory', async () => {
    const { totp } = await loadWithTauri(() => LIVE);
    await totp.liveCodeFor(entry());
    totp.resetTotpCache();
    await totp.liveCodeFor(entry());
    expect(calls).toHaveLength(2);
  });
});

describe('tickTotp — the desktop repaint', () => {
  it('paints the digits, the countdown and the code the copy action reads', async () => {
    const { totp, st } = await loadWithTauri(() => LIVE);
    st.vault = { api_keys: [entry()], user_categories: [], projects: [] };
    document.body.innerHTML = slotHtml('e1');

    await totp.tickTotp();

    const slot = document.querySelector<HTMLElement>('[data-totp-for]')!;
    expect(slot.querySelector('.totp-code')!.textContent).toBe('123 456');
    expect(slot.querySelector('.totp-secs')!.textContent).toBe('22');
    // Copy reads this, rather than re-deriving — re-deriving hands over the
    // *next* code when the click crosses a step boundary.
    expect(slot.dataset.totpCode).toBe('123456');
    const fill = slot.querySelector<HTMLElement>('.totp-countdown-fill')!;
    expect(fill.style.width).toBe('73.3%');
    expect(fill.classList.contains('expiring')).toBe(false);
    expect(slot.getAttribute('aria-label')).toContain('123456');
  });

  it('marks the bar expiring in the last ten seconds', async () => {
    const { totp, st } = await loadWithTauri(() => ({ ...LIVE, remaining_secs: 7 }));
    st.vault = { api_keys: [entry()], user_categories: [], projects: [] };
    document.body.innerHTML = slotHtml('e1');
    await totp.tickTotp();
    expect(document.querySelector('.totp-countdown-fill')!.classList.contains('expiring')).toBe(
      true,
    );
  });

  it('hides a slot whose entry was deleted instead of painting its neighbour', async () => {
    // Invariant 1: the ticker holds no references between ticks, so a slot left
    // over from the previous render resolves to nothing rather than to whatever
    // took that position.
    const { totp, st } = await loadWithTauri(() => LIVE);
    st.vault = { api_keys: [entry({ id: 'other' })], user_categories: [], projects: [] };
    document.body.innerHTML = slotHtml('e1');
    await totp.tickTotp();
    expect(document.querySelector<HTMLElement>('[data-totp-for]')!.hidden).toBe(true);
    expect(calls).toHaveLength(0);
  });

  it('leaves the previous digits alone when a tick gets no answer', async () => {
    const { totp, st } = await loadWithTauri(() => {
      throw new Error('Vault is locked');
    });
    st.vault = { api_keys: [entry()], user_categories: [], projects: [] };
    document.body.innerHTML = slotHtml('e1');
    await totp.tickTotp();
    // Not blanked to zeros or to a stale code from another entry.
    expect(document.querySelector('.totp-code')!.textContent).toBe('— — —');
  });

  it('the ticker is idempotent by assignment and stops cleanly', async () => {
    // Invariant 9: calling it twice leaves one interval, not two racing ones.
    vi.useFakeTimers();
    const { totp, st } = await loadWithTauri(() => LIVE);
    st.vault = { api_keys: [entry()], user_categories: [], projects: [] };
    document.body.innerHTML = slotHtml('e1');

    totp.startTotpTicker();
    totp.startTotpTicker();
    expect(vi.getTimerCount()).toBe(1);
    totp.stopTotpTicker();
    expect(vi.getTimerCount()).toBe(0);
  });
});
