/**
 * Stored third-party TOTP seeds — the TypeScript half (Phase 22).
 *
 * The parse/URI cases live in `tests/fixtures/parity/totp-seeds.json`, and
 * `envv-cli/tests/totp.rs` asserts `vault_core::totp` against the identical
 * file. Reviewing two parsers for agreement does not work; the fixture is what
 * turns a divergence into a test failure instead of a URI that means one thing
 * in the app and another in the CLI.
 *
 * There is no code-generation test here on purpose: this half does not generate
 * codes. `vault-core/src/totp.rs` owns the one HMAC in the project and carries
 * the RFC 6238 vectors; the app asks it over IPC.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  parseTotpSeed,
  buildOtpauthUri,
  normalizeB32,
  totpParamsOf,
  totpRemainingSecs,
  totpStoredOf,
  hasTotp,
  groupCode,
  tickTotp,
  resetTotpCache,
  TOTP_DEFAULTS,
  type TotpStored,
} from '../src/ts/totp';
import { refreshTotpStatus } from '../src/ts/modals';
import { st } from '../src/ts/state';
import { loadRealIndexHtml } from './helpers';
import type { VaultEntry } from '../src/ts/types';

const HERE = dirname(fileURLToPath(import.meta.url));
const TABLE = JSON.parse(
  readFileSync(join(HERE, 'fixtures', 'parity', 'totp-seeds.json'), 'utf8'),
) as {
  parse: {
    in: string;
    out: Omit<TotpStored, never> | null;
  }[];
  uri: {
    stored: {
      secret: string;
      algorithm: string;
      digits: number;
      period: number;
      kind?: string;
      counter?: number;
    };
    issuer_fallback: string;
    account_fallback: string;
    out: string;
  }[];
  params: {
    entry: Record<string, unknown>;
    out: { algorithm: string; digits: number; period: number; kind: string; counter: number };
  }[];
};

describe('parseTotpSeed — golden table', () => {
  for (const c of TABLE.parse) {
    it(`${JSON.stringify(c.in)} -> ${c.out ? c.out.secret : 'refused'}`, () => {
      if (c.out === null) {
        expect(() => parseTotpSeed(c.in)).toThrow();
        return;
      }
      expect(parseTotpSeed(c.in)).toEqual(c.out);
    });
  }
});

describe('buildOtpauthUri — golden table', () => {
  for (const c of TABLE.uri) {
    it(`${c.stored.secret} as ${c.issuer_fallback || '(no issuer)'}`, () => {
      const stored: TotpStored = {
        secret: c.stored.secret,
        kind: (c.stored.kind ?? 'totp') as TotpStored['kind'],
        algorithm: c.stored.algorithm as TotpStored['algorithm'],
        digits: c.stored.digits,
        period: c.stored.period,
        counter: c.stored.counter ?? 0,
        issuer: null,
        account: null,
      };
      expect(buildOtpauthUri(stored, c.issuer_fallback, c.account_fallback)).toBe(c.out);
    });
  }

  it('every URI it writes parses back to the same seed', () => {
    // The exported URI is what a user scans into a replacement phone. One that
    // does not read back is a lockout discovered at the worst possible moment.
    for (const c of TABLE.uri) {
      const back = parseTotpSeed(c.out);
      expect(back.secret).toBe(c.stored.secret);
      expect(back.algorithm).toBe(c.stored.algorithm);
      expect(back.digits).toBe(c.stored.digits);
      expect(back.period).toBe(c.stored.period);
    }
  });
});

describe('normalizeB32', () => {
  it('collapses every spelling of one seed to one string', () => {
    // Two entries holding the same seed typed differently must be
    // byte-identical, or their fingerprints disagree and a duplicate is
    // invisible to `unv totp ls` and to the health scan.
    const spellings = [
      'JBSWY3DPEHPK3PXP',
      'jbswy3dpehpk3pxp',
      'JBSW Y3DP EHPK 3PXP',
      'JBSW-Y3DP-EHPK-3PXP',
    ];
    for (const s of spellings) expect(normalizeB32(s)).toBe('JBSWY3DPEHPK3PXP');
  });
});

describe('totpParamsOf — golden table', () => {
  // The third parity table. These four fields were read three different ways in
  // Rust alone — `unv totp code` clamped, `unv totp ls` did not, and
  // `entry_totp_code` did neither — so an entry could list as a 99-digit
  // credential, hand over six digits, and return an error to the app instead of
  // a code. `vault_core::totp::Params::from_fields` is now the single reader and
  // `envv-cli/tests/totp.rs` asserts it against this identical file.
  for (const c of TABLE.params) {
    it(`${JSON.stringify(c.entry)} -> ${c.out.algorithm}/${c.out.digits}/${c.out.period}`, () => {
      const got = totpParamsOf(c.entry as unknown as VaultEntry);
      expect(got.algorithm).toBe(c.out.algorithm);
      expect(got.digits).toBe(c.out.digits);
      expect(got.period).toBe(c.out.period);
      expect(got.kind).toBe(c.out.kind);
      expect(got.counter).toBe(c.out.counter);
    });
  }
});

describe('totpParamsOf — a vault is untrusted input', () => {
  // Invariant 4: these fields arrive from an imported backup or a remote server
  // as readily as from the form, and the TypeScript unions are erased at
  // runtime. A period of 0 reaching the divider is a crash in a card renderer.
  const cases: [Partial<VaultEntry>, string][] = [
    [{}, 'nothing set'],
    [{ totp_period: 0 }, 'a period of zero'],
    [{ totp_period: -30 } as Partial<VaultEntry>, 'a negative period'],
    [{ totp_period: 999999 }, 'a period past the cap'],
    [{ totp_digits: 5 }, 'fewer digits than RFC 4226 allows'],
    [{ totp_digits: 11 }, 'more digits than 31 bits can express'],
    [{ totp_digits: 'six' } as unknown as Partial<VaultEntry>, 'a digit count that is text'],
    [{ totp_algorithm: 'WHIRLPOOL' } as unknown as Partial<VaultEntry>, 'an unknown algorithm'],
    [{ totp_algorithm: null }, 'an explicit null'],
  ];
  for (const [patch, label] of cases) {
    it(`falls back to the defaults for ${label}`, () => {
      expect(totpParamsOf(patch as VaultEntry)).toEqual({ ...TOTP_DEFAULTS });
    });
  }

  it('keeps parameters that are in range', () => {
    expect(
      totpParamsOf({ totp_algorithm: 'SHA512', totp_digits: 8, totp_period: 60 } as VaultEntry),
    ).toEqual({ kind: 'totp', algorithm: 'SHA512', digits: 8, period: 60, counter: 0 });
  });

  it('sha-256 with a dash is read, because real URIs contain it', () => {
    expect(totpParamsOf({ totp_algorithm: 'sha-256' } as unknown as VaultEntry).algorithm).toBe(
      'SHA256',
    );
  });
});

describe('totpRemainingSecs', () => {
  it('counts down a full period and never reaches zero', () => {
    // A countdown reading 0 for one second in every period gets reported as a
    // bug; at a step boundary the *new* code has a full period ahead of it.
    expect(totpRemainingSecs(30, 0)).toBe(30);
    expect(totpRemainingSecs(30, 1)).toBe(29);
    expect(totpRemainingSecs(30, 29)).toBe(1);
    expect(totpRemainingSecs(30, 30)).toBe(30);
    expect(totpRemainingSecs(60, 119)).toBe(1);
  });

  it('survives a period of zero rather than dividing by it', () => {
    expect(totpRemainingSecs(0, 12345)).toBe(1);
    expect(totpRemainingSecs(NaN, 12345)).toBe(1);
  });
});

describe('hasTotp / totpStoredOf / groupCode', () => {
  it('whitespace is not a seed', () => {
    expect(hasTotp({ totp_secret: null })).toBe(false);
    expect(hasTotp({ totp_secret: '   ' })).toBe(false);
    expect(hasTotp({ totp_secret: 'JBSWY3DPEHPK3PXP' })).toBe(true);
  });

  it('normalises the stored seed on read, not only on write', () => {
    // Vaults written by an older build, or by hand, carry the grouped spelling.
    expect(totpStoredOf({ totp_secret: 'jbsw y3dp' } as VaultEntry).secret).toBe('JBSWY3DP');
  });

  it('splits a code the way an authenticator displays it', () => {
    expect(groupCode('123456')).toBe('123 456');
    expect(groupCode('12345678')).toBe('1234 5678');
    expect(groupCode('1234567')).toBe('1234 567');
  });
});

describe('tickTotp — the repaint pass', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
    resetTotpCache();
    st.vault = {
      api_keys: [
        {
          id: 'e1',
          provider: 'GitHub',
          api_key: 'k',
          totp_secret: 'JBSWY3DPEHPK3PXP',
          price_type: 'free',
          categories: [],
          projectIds: ['Universal'],
          scopes: [],
        },
        {
          id: 'e2',
          provider: 'NoSeed',
          api_key: 'k',
          price_type: 'free',
          categories: [],
          projectIds: ['Universal'],
          scopes: [],
        },
      ],
      user_categories: [],
      projects: [],
    } as never;
  });
  afterEach(() => {
    vi.unstubAllGlobals();
    document.body.innerHTML = '';
  });

  function slot(id: string): HTMLElement {
    document.body.insertAdjacentHTML(
      'beforeend',
      `<div data-totp-for="${id}"><span class="totp-code"></span>
       <span class="totp-secs"></span><i class="totp-countdown-fill"></i></div>`,
    );
    return document.querySelector<HTMLElement>(`[data-totp-for="${id}"]`)!;
  }

  it('hides a slot whose entry has no seed, and one whose entry is gone', async () => {
    // Invariant 1: the slot names an entry id, and the entry it names can be
    // deleted between renders. Looking it up each tick is what keeps a stale
    // slot from painting the neighbour's code.
    const none = slot('e2');
    const missing = slot('e404');
    await tickTotp();
    expect(none.hidden).toBe(true);
    expect(missing.hidden).toBe(true);
  });

  it('says so rather than showing a code when there is no Rust to ask', async () => {
    // jsdom is not Tauri, which is the same position `npm run dev` is in. Six
    // digits from somewhere else would be worse than an obvious placeholder.
    const s = slot('e1');
    await tickTotp();
    expect(s.hidden).toBe(false);
    expect(s.querySelector('.totp-code')!.textContent).toBe('— — —');
    expect(s.title).toContain('desktop app');
    // Nothing for the copy action to grab, so it cannot copy a placeholder.
    expect(s.dataset.totpCode).toBe('');
  });

  it('does nothing at all when no slot is on screen', async () => {
    // The ticker runs once a second for the life of an unlocked vault; the
    // common case is a grid with no TOTP entry visible at all.
    await expect(tickTotp()).resolves.toBeUndefined();
  });
});

describe('the add/edit form carries the kind and the counter', () => {
  beforeEach(() => {
    loadRealIndexHtml();
  });

  it('a pasted counter-based URI fills the kind and the counter, and shows both', () => {
    // The counter is the half that has to survive a paste: a counter-based seed
    // read back at zero is a second factor that fails until the account is
    // resynced, and that failure looks exactly like a wrong seed.
    const input = document.getElementById('f-totp') as HTMLInputElement;
    input.value = 'otpauth://hotp/Acme:me?secret=JBSWY3DPEHPK3PXP&counter=7';
    refreshTotpStatus();

    expect(input.value).toBe('JBSWY3DPEHPK3PXP');
    expect((document.getElementById('f-totp-kind') as HTMLSelectElement).value).toBe('hotp');
    expect((document.getElementById('f-totp-counter') as HTMLInputElement).value).toBe('7');
    expect(document.getElementById('f-totp-counter-wrap')!.hidden).toBe(false);
    expect(document.getElementById('f-totp-status')!.textContent).toContain('#7');
  });

  it('hides the counter for a time-based seed', () => {
    const input = document.getElementById('f-totp') as HTMLInputElement;
    input.value = 'JBSWY3DPEHPK3PXP';
    refreshTotpStatus();
    expect(document.getElementById('f-totp-counter-wrap')!.hidden).toBe(true);
    expect(document.getElementById('f-totp-status')!.textContent).toContain('every 30s');
  });

  it('hides the parameter boxes for Steam, which fixes its own shape', () => {
    // Showing three boxes that change nothing invites the user to set them and
    // then wonder why Steam rejects the codes.
    const input = document.getElementById('f-totp') as HTMLInputElement;
    input.value = 'otpauth://steam/Steam:me?secret=JBSWY3DPEHPK3PXP';
    refreshTotpStatus();
    expect((document.getElementById('f-totp-kind') as HTMLSelectElement).value).toBe('steam');
    expect(document.getElementById('f-totp-params')!.hidden).toBe(true);
    expect(document.getElementById('f-totp-status')!.textContent).toContain('5 characters');
  });
});
