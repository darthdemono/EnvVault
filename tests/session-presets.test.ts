/**
 * Web session provider presets (Phase 24.5). The SAPISIDHASH vector is
 * computed independently (`printf '%s' "1000000000 testsapisid
 * https://example.com" | sha1sum`) rather than by running this module against
 * itself — CLAUDE.md's own rule that two implementations agreeing proves
 * nothing about two identical mistakes, applied here even though there is
 * only one implementation, because the alternative is trusting the arithmetic
 * with nothing to check it against.
 */
import { describe, it, expect } from 'vitest';
import {
  presets,
  findPreset,
  missingRequiredCookies,
  deriveHeaders,
} from '../src/ts/session-presets';
import type { VaultEntry } from '../src/ts/types';

function entryWithCookies(pairs: Record<string, string>, api_url?: string): VaultEntry {
  return {
    provider: 'X',
    api_key: '',
    price_type: 'free',
    secretType: 'cookie',
    categories: [],
    projectIds: ['Universal'],
    scopes: [],
    api_url,
    extra_vars: Object.entries(pairs).map(([key, value]) => ({ key, value, secret: true })),
  } as VaultEntry;
}

describe('session presets registry', () => {
  it('lists at least the eight sourced presets', () => {
    const ids = presets().map((p) => p.id);
    for (const id of [
      'x-twitter',
      'instagram',
      'linkedin',
      'youtube-google',
      'spotify',
      'slack-browser',
      'nextauth',
      'cloudflare-clearance',
    ]) {
      expect(ids).toContain(id);
    }
  });

  it('findPreset resolves a known id and not an unknown one', () => {
    expect(findPreset('x-twitter')?.label).toBe('X / Twitter');
    expect(findPreset('not-a-real-preset')).toBeUndefined();
  });
});

describe('missingRequiredCookies', () => {
  it('names every required cookie the jar does not have', () => {
    const preset = findPreset('x-twitter')!;
    const entry = entryWithCookies({ auth_token: 'abc' });
    expect(missingRequiredCookies(entry, preset)).toEqual(['ct0']);
  });

  it('is empty once every required cookie is present', () => {
    const preset = findPreset('x-twitter')!;
    const entry = entryWithCookies({ auth_token: 'abc', ct0: 'def' });
    expect(missingRequiredCookies(entry, preset)).toEqual([]);
  });
});

describe('deriveHeaders', () => {
  it('emits a static header verbatim', async () => {
    const preset = findPreset('instagram')!;
    const entry = entryWithCookies({ csrftoken: 'tok', sessionid: 's', ds_user_id: '1' });
    const headers = await deriveHeaders(entry, preset);
    expect(headers).toContainEqual({ name: 'X-IG-App-ID', value: '936619743392459' });
  });

  it('copies a cookie value into a header, stripping quotes when asked', async () => {
    const preset = findPreset('linkedin')!;
    const entry = entryWithCookies({ li_at: 'a', JSESSIONID: '"ajax:12345"' });
    const headers = await deriveHeaders(entry, preset);
    expect(headers).toContainEqual({ name: 'csrf-token', value: 'ajax:12345' });
  });

  it('omits a cookie-sourced header when the cookie is missing', async () => {
    const preset = findPreset('linkedin')!;
    const entry = entryWithCookies({ li_at: 'a' });
    const headers = await deriveHeaders(entry, preset);
    expect(headers.find((h) => h.name === 'csrf-token')).toBeUndefined();
  });

  it('derives SAPISIDHASH matching an independently computed SHA-1', async () => {
    const preset = findPreset('youtube-google')!;
    const entry = entryWithCookies({ SAPISID: 'testsapisid' });
    // 1_000_000_000_000 ms → ts = 1000000000. Vector computed with:
    //   printf '%s' "1000000000 testsapisid https://example.com" | sha1sum
    const headers = await deriveHeaders(entry, preset, 'https://example.com', 1_000_000_000_000);
    expect(headers).toContainEqual({
      name: 'Authorization',
      value: 'SAPISIDHASH 1000000000_983ab06cdeb0cbeae14d3de966fa4266bee4e5d1',
    });
  });

  it('omits SAPISIDHASH when there is no SAPISID cookie or no origin', async () => {
    const preset = findPreset('youtube-google')!;
    const noSapisid = entryWithCookies({});
    expect((await deriveHeaders(noSapisid, preset, 'https://example.com')).length).toBe(0);

    const noOrigin = entryWithCookies({ SAPISID: 'x' });
    expect((await deriveHeaders(noOrigin, preset)).length).toBe(0);
  });

  it('falls back to the entry api_url when no explicit origin is given', async () => {
    const preset = findPreset('youtube-google')!;
    const entry = entryWithCookies({ SAPISID: 'testsapisid' }, 'https://example.com');
    const headers = await deriveHeaders(entry, preset, undefined, 1_000_000_000_000);
    expect(headers).toContainEqual({
      name: 'Authorization',
      value: 'SAPISIDHASH 1000000000_983ab06cdeb0cbeae14d3de966fa4266bee4e5d1',
    });
  });
});
