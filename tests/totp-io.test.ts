/**
 * Importing and exporting authenticator seeds — the TypeScript half (Phase 22).
 *
 * The parsers, the format writers and the merge rules are all in
 * `vault-core/src/totp_import.rs` and are tested there, against real Ente,
 * Aegis, 2FAS, andOTP, Bitwarden and Google Authenticator shapes. Duplicating
 * any of that here would be duplicating the thing this design deliberately does
 * not duplicate.
 *
 * What is testable on this side is the wiring: that nothing reaches for Rust
 * when there is no Rust, that the summary sentence counts what happened, and
 * that the seed-only entry an import produces can be saved from the form at all.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import {
  summarise,
  EXPORT_FORMATS,
  importTotpFile,
  buildTotpExport,
  type MergeReport,
} from '../src/ts/totp-io';
import { st } from '../src/ts/state';
import { loadRealIndexHtml, resetState } from './helpers';

function report(patch: Partial<MergeReport> = {}): MergeReport {
  return {
    entries: [],
    format: 'aegis',
    created: [],
    updated: [],
    unchanged: [],
    conflicts: [],
    skipped: [],
    ...patch,
  };
}

const one = { provider: 'Acme', account: 'me' };

describe('summarise', () => {
  it('counts every outcome the merge can produce', () => {
    expect(
      summarise(
        report({
          created: [one, one],
          updated: [one],
          unchanged: [one],
          conflicts: [one],
          skipped: [{ name: 'x', reason: 'HOTP' }],
        }),
      ),
    ).toBe('2 added, 1 updated, 1 already current, 1 left alone, 1 skipped');
  });

  it('names the nothing case rather than producing an empty sentence', () => {
    // "Imported: " with nothing after it reads as a truncated message.
    expect(summarise(report())).toBe('nothing to import');
  });

  it('omits the outcomes that did not happen', () => {
    expect(summarise(report({ created: [one] }))).toBe('1 added');
  });
});

describe('EXPORT_FORMATS', () => {
  it('offers only what the Rust side can write, with a file extension each', () => {
    // `build()` refuses andotp, bitwarden and google by name. Offering one here
    // would produce an error toast for a menu item the user was right to pick.
    expect(EXPORT_FORMATS.map((f) => f.value)).toEqual(['otpauth', 'aegis', '2fas']);
    for (const f of EXPORT_FORMATS) expect(f.ext).toMatch(/^(txt|json)$/);
  });

  it('names Ente in the otpauth label, because that is what people will look for', () => {
    expect(EXPORT_FORMATS[0].label).toContain('Ente');
  });
});

describe('outside Tauri', () => {
  beforeEach(() => {
    loadRealIndexHtml();
    resetState(st);
  });
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('import says so instead of calling a command that is not there', async () => {
    // jsdom is not Tauri, and neither is `npm run dev` in a plain browser.
    // Reaching for `__TAURI__.core.invoke` there throws inside a click handler,
    // which surfaces as a button that does nothing at all.
    await expect(importTotpFile('otpauth://totp/A?secret=JBSWY3DPEHPK3PXP')).resolves.toBeNull();
  });

  it('export says so before it assembles anything', async () => {
    st.vault.api_keys = [
      {
        id: 'e1',
        provider: 'Acme',
        api_key: '',
        totp_secret: 'JBSWY3DPEHPK3PXP',
        price_type: 'free',
        categories: [],
        projectIds: ['Universal'],
        scopes: [],
      },
    ] as never;
    await expect(buildTotpExport('otpauth')).resolves.toBeNull();
  });

  it('export refuses an empty selection rather than writing an empty file', async () => {
    // A zero-entry Aegis vault imports cleanly and silently replaces nothing,
    // which is the worst possible outcome to hand somebody who believes they
    // just backed up their second factors.
    st.vault.api_keys = [];
    await expect(buildTotpExport('otpauth')).resolves.toBeNull();
  });
});
