/**
 * Phase 23, steps 4–7 — the behaviour changes that are not covered by a parity
 * fixture because they live on one side only.
 *
 * The fixtures in `tests/fixtures/parity/` pin the *formats* (names, quoting,
 * profiles, auth schemes, cookies) from both implementations. What is left is
 * the app's own rules: which entries are allowed to have no primary value, which
 * names collide, and what a file-shaped credential emits.
 */
import { describe, it, expect, beforeEach } from 'vitest';
import { st, resetViewState } from '../src/ts/state';
import {
  entryHasPayload,
  primaryIsOptional,
  findNameCollisions,
  namesGeneratedBy,
  disambiguateNames,
  Exporter,
} from '../src/ts/state';
import { isFileShaped, fileContentsOf, fileEnvLine } from '../src/ts/file-cred';
import {
  cookiesOf,
  cookiesToExtraVars,
  parseAnyCookies,
  toPlaywrightStorageState,
} from '../src/ts/cookies';
import { timeUntil } from '../src/ts/ui-qol';
import type { VaultEntry } from '../src/ts/types';

function entry(p: Partial<VaultEntry>): VaultEntry {
  return {
    provider: 'X',
    api_key: '',
    price_type: 'free',
    secretType: 'api_key',
    categories: [],
    projectIds: ['Universal'],
    scopes: [],
    ...p,
  } as VaultEntry;
}

beforeEach(() => {
  st.vault = { api_keys: [], user_categories: [], projects: [] };
  resetViewState();
});

describe('step 4 — an entry may legitimately have no primary value', () => {
  it('lets an env_var entry carry its payload entirely in named variables', () => {
    const e = entry({
      provider: 'Aws',
      secretType: 'env_var',
      extra_vars: [{ key: 'ACCESS_KEY_ID', value: 'AKIA…' }],
    });
    expect(primaryIsOptional(e)).toBe(true);
    expect(entryHasPayload(e)).toBe(true);
  });

  it('lets an authenticator-only entry exist — what an Ente import produces', () => {
    expect(primaryIsOptional(entry({ totp_secret: 'JBSWY3DPEHPK3PXP' }))).toBe(true);
  });

  it('still requires one for an ordinary api_key entry', () => {
    expect(primaryIsOptional(entry({ secretType: 'api_key' }))).toBe(false);
  });

  it('refuses an env_var entry that holds nothing at all', () => {
    const e = entry({ secretType: 'env_var' });
    expect(primaryIsOptional(e)).toBe(false);
    expect(entryHasPayload(e)).toBe(false);
  });

  it('omits the primary line rather than writing NAME= for an empty value', () => {
    // `NAME=` means "set to the empty string" in a file about to be loaded,
    // which is a different claim from saying nothing about it.
    const text = Exporter.dotenv([
      entry({
        provider: 'Aws',
        secretType: 'env_var',
        extra_vars: [{ key: 'REGION', value: 'eu-west-1' }],
      }),
    ]);
    expect(text).not.toMatch(/^AWS=/m);
    expect(text).toContain('AWS_REGION=eu-west-1');
  });
});

describe('step 5 — cookies', () => {
  it('reads a jar out of the primary value when it has not been split', () => {
    const e = entry({ secretType: 'cookie', api_key: 'sp_dc=A; sp_key=B' });
    expect(cookiesOf(e).map((c) => c.name)).toEqual(['sp_dc', 'sp_key']);
  });

  it('prefers the split form, which is the one carrying the attributes', () => {
    const e = entry({
      secretType: 'cookie',
      api_key: 'ignored=yes',
      extra_vars: [{ key: 'sid', value: 'abc', attrs: { domain: '.x.com', path: '/' } }],
    });
    const jar = cookiesOf(e);
    expect(jar).toHaveLength(1);
    expect(jar[0].domain).toBe('.x.com');
  });

  it('marks every split cookie secret — none of them is ever the public half', () => {
    const rows = cookiesToExtraVars(parseAnyCookies('a=1; b=2'));
    expect(rows.every((r) => r.secret)).toBe(true);
    expect(rows.some((r) => r.public)).toBe(false);
  });

  it('writes cookie and localStorage state in Playwright format', () => {
    const state = JSON.parse(
      toPlaywrightStorageState(
        entry({
          secretType: 'cookie',
          api_url: 'https://app.example.test/path',
          extra_vars: [{ key: 'sid', value: 'secret', attrs: { path: '/', secure: true } }],
          storage_tokens: [
            { origin: 'https://app.example.test/path', storage: 'local', key: 'token', value: 'x' },
          ],
        }),
      ),
    );
    expect(state.cookies[0]).toMatchObject({
      name: 'sid',
      value: 'secret',
      domain: 'app.example.test',
      path: '/',
      secure: true,
    });
    expect(state.origins).toEqual([
      { origin: 'https://app.example.test', localStorage: [{ name: 'token', value: 'x' }] },
    ]);
  });

  it('refuses Playwright export that would silently omit sessionStorage', () => {
    expect(() =>
      toPlaywrightStorageState(
        entry({
          storage_tokens: [{ origin: 'https://x.test', storage: 'session', key: 'k', value: 'v' }],
        }),
      ),
    ).toThrow(/cannot represent sessionStorage/);
  });
});

describe('step 5 — E7, expiry below a day', () => {
  it('counts in minutes for a session that dies within the hour', () => {
    const soon = new Date(Date.now() + 38 * 60_000).toISOString();
    expect(timeUntil(soon)).toMatch(/^expires in 3[78] min$/);
  });

  it('counts in hours below a day — "expires today" meant nothing for these', () => {
    const later = new Date(Date.now() + 5 * 3600_000).toISOString();
    expect(timeUntil(later)).toBe('expires in 5h');
  });

  it('treats a bare date as the end of that day, not midnight', () => {
    // Otherwise every long-lived credential expires a day early.
    const today = new Date().toISOString().slice(0, 10);
    expect(timeUntil(today)).toMatch(/^expires in/);
  });

  it('says nothing at all for an unparseable stamp, rather than "NaN days"', () => {
    expect(timeUntil('whenever')).toBe('');
  });
});

describe('step 6 — E2, name collisions', () => {
  it('finds a collision inside one entry', () => {
    // `primary_role: id` plus a var keyed ID generates SPOTIFY_ID twice, and
    // every .env parser takes the last line.
    const e = entry({
      provider: 'Spotify',
      primary_role: 'id',
      api_key: 'a',
      extra_vars: [{ key: 'ID', value: 'b' }],
    });
    const clashes = findNameCollisions([e]);
    expect(clashes).toHaveLength(1);
    expect(clashes[0].name).toBe('SPOTIFY_ID');
  });

  it('finds a collision across a key pool, which is several entries for one provider', () => {
    const pool = [
      entry({ provider: 'GitHub', api_key: 'a', pool: 'ci' }),
      entry({ provider: 'GitHub', api_key: 'b', pool: 'ci' }),
    ];
    expect(findNameCollisions(pool)).toHaveLength(1);
  });

  it('compares case-insensitively, because Windows environment variables are', () => {
    const a = entry({ provider: 'Api', api_key: '1' });
    const b = entry({ provider: 'API', api_key: '2' });
    expect(findNameCollisions([a, b], { case: 'preserve' })).toHaveLength(1);
  });

  it('appends rather than dropping, and the first occurrence keeps its name', () => {
    const e = entry({
      provider: 'Spotify',
      primary_role: 'id',
      api_key: 'a',
      extra_vars: [{ key: 'ID', value: 'b' }],
    });
    expect(disambiguateNames(namesGeneratedBy(e))).toEqual(['SPOTIFY_ID', 'SPOTIFY_ID_2']);
  });
});

describe('step 7 — E17, file-shaped credentials', () => {
  it('recognises a stored file', () => {
    expect(isFileShaped(entry({ blob_data: '{"type":"service_account"}' }))).toBe(true);
    expect(isFileShaped(entry({ api_key: 'plain' }))).toBe(false);
  });

  it('guesses the extension from the content, never from a name', () => {
    expect(fileContentsOf(entry({ blob_data: '{"a":1}' }))?.ext).toBe('json');
    expect(fileContentsOf(entry({ blob_data: '-----BEGIN PRIVATE KEY-----' }))?.ext).toBe('pem');
    expect(fileContentsOf(entry({ certificate_data: 'x' }))?.ext).toBe('pem');
  });

  it('emits the path and never the bytes', () => {
    const e = entry({ provider: 'Gcp', blob_data: '{"k":1}', mount_path: '/etc/gcp/sa.json' });
    expect(fileEnvLine(e, 'GOOGLE_APPLICATION_CREDENTIALS')).toBe(
      'GOOGLE_APPLICATION_CREDENTIALS=/etc/gcp/sa.json',
    );
  });

  it('emits nothing until the user has said where the file goes', () => {
    // The honest answer to "what variable does this set" is nothing — emitting
    // the contents instead is the mistake this whole item exists to stop.
    expect(fileEnvLine(entry({ blob_data: '{"k":1}' }), 'X')).toBeNull();
  });
});
