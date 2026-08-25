/**
 * `chunks/env-link.ts` — matching plain `KEY=value` env fields against vault
 * entries so they can become `${ref}` placeholders.
 *
 * At 0% coverage until Phase 18, and it is not a trivial module: a five-tier
 * scoring function decides which entry an env var refers to. A wrong match here
 * rewrites a working `.env` to point at the wrong secret, and the deploy that
 * follows fails somewhere else entirely.
 *
 * The tests are written against the *ranking*, not just the happy path —
 * confidence ordering is the whole design, so each tier is pinned against the
 * tier below it.
 */
import { describe, it, expect, beforeEach } from 'vitest';
import { buildEnvLinkMatches } from '../src/ts/chunks/env-link';
import { st } from '../src/ts/state';
import type { SecretChunk, VaultEntry } from '../src/ts/types';

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

function chunk(fields: { key: string; value: string }[]): SecretChunk {
  return {
    id: 'c1',
    chunk_type: 'env_file',
    name: '.env',
    fields: fields.map((f) => ({ ...f, field_type: 'var' })),
  } as SecretChunk;
}

beforeEach(() => {
  st.vault = { api_keys: [], user_categories: [], projects: [] };
});

describe('exact-name matching', () => {
  it('matches an env key to an entry of the same name', () => {
    st.vault.api_keys = [entry({ provider: 'STRIPE', api_key: 'sk_live_x' })];
    const [m] = buildEnvLinkMatches(chunk([{ key: 'STRIPE', value: 'sk_live_x' }]));
    expect(m.match?.ref).toBe('STRIPE/key');
    expect(m.match?.confidence).toBe(100);
  });

  it('does not let array order decide between two entries of the same name', () => {
    // Regression test. Both `AWS` and `AWS_PROD` matched `AWS=` at 100, and the
    // tie was broken by whichever came first in `api_keys` — so adding an
    // unrelated entry could silently repoint an env var at a different secret.
    // The keyless entry is the exact match; the one with a key_id is named
    // `AWS_PROD` and is therefore a weaker claim on the bare name.
    st.vault.api_keys = [
      entry({ provider: 'AWS', key_id: 'PROD', api_key: 'a' }),
      entry({ provider: 'AWS', api_key: 'b' }),
    ];
    const [m] = buildEnvLinkMatches(chunk([{ key: 'AWS', value: 'zzz' }]));
    expect(m.match?.confidence).toBe(100);
    expect(m.match?.entry.key_id).toBeUndefined();

    // …and the result must not depend on the order they appear in.
    st.vault.api_keys.reverse();
    const [m2] = buildEnvLinkMatches(chunk([{ key: 'AWS', value: 'zzz' }]));
    expect(m2.match?.entry.key_id).toBeUndefined();
  });

  it('still prefers the keyed entry when the key names it', () => {
    st.vault.api_keys = [
      entry({ provider: 'AWS', api_key: 'b' }),
      entry({ provider: 'AWS', key_id: 'PROD', api_key: 'a' }),
    ];
    const [m] = buildEnvLinkMatches(chunk([{ key: 'AWS_PROD', value: 'zzz' }]));
    expect(m.match?.entry.key_id).toBe('PROD');
  });

  it('surfaces a password entry as ${name/password}, not ${name/key}', () => {
    // Both resolve to api_key. The label is what a human reads in the config,
    // and "key" on a password entry reads as the wrong secret.
    st.vault.api_keys = [entry({ provider: 'DB', secretType: 'password', api_key: 'hunter2' })];
    const [m] = buildEnvLinkMatches(chunk([{ key: 'DB', value: 'hunter2' }]));
    expect(m.match?.ref).toBe('DB/password');
  });
});

describe('prefix-aware matching', () => {
  it('strips a declared env_prefix and matches the remainder', () => {
    st.vault.api_keys = [
      entry({ provider: 'LASTFM', env_prefixes: ['APP_'], api_key: 'k' }),
    ];
    const [m] = buildEnvLinkMatches(chunk([{ key: 'APP_LASTFM_APIKEY', value: 'k' }]));
    expect(m.match?.confidence).toBe(92);
    expect(m.match?.ref).toBe('LASTFM/APIKEY');
  });

  it('prefers a named extra_var over the provider suffix', () => {
    st.vault.api_keys = [
      entry({
        provider: 'SVC',
        env_prefixes: ['APP_'],
        extra_vars: [{ key: 'JWT_SECRET', value: 'jwt' }],
        api_key: 'k',
      }),
    ];
    const [m] = buildEnvLinkMatches(chunk([{ key: 'APP_JWT_SECRET', value: 'jwt' }]));
    expect(m.match?.ref).toBe('SVC/JWT_SECRET');
  });

  it('tolerates a prefix written without its trailing underscore', () => {
    st.vault.api_keys = [entry({ provider: 'API', env_prefixes: ['APP'], api_key: 'k' })];
    const [m] = buildEnvLinkMatches(chunk([{ key: 'APP_API', value: 'k' }]));
    expect(m.match?.confidence).toBe(92);
  });
});

describe('value matching, when the name says nothing', () => {
  it('matches on an identical secret value', () => {
    st.vault.api_keys = [entry({ provider: 'Mailgun', api_key: 'key-abcdef123456' })];
    const [m] = buildEnvLinkMatches(chunk([{ key: 'SMTP_TOKEN', value: 'key-abcdef123456' }]));
    expect(m.match?.ref).toBe('Mailgun/key');
    expect(m.match?.confidence).toBe(88);
  });

  it('will not match a short value', () => {
    // A 5-character value collides by accident. Linking on it would point an
    // env var at an unrelated secret, which is worse than leaving it plain.
    st.vault.api_keys = [entry({ provider: 'Thing', api_key: 'admin' })];
    const [m] = buildEnvLinkMatches(chunk([{ key: 'SOMETHING', value: 'admin' }]));
    expect(m.match).toBeUndefined();
  });

  it('ranks fields: api_key beats api_secret beats username', () => {
    st.vault.api_keys = [
      entry({ provider: 'A', api_key: 'shared-value-here' }),
      entry({ provider: 'B', api_secret: 'shared-value-here' }),
      entry({ provider: 'C', username: 'shared-value-here' }),
    ];
    const [m] = buildEnvLinkMatches(chunk([{ key: 'ANYTHING', value: 'shared-value-here' }]));
    expect(m.match?.entry.provider).toBe('A');
  });
});

describe('suffix matching, the weakest tier', () => {
  it('strips leading segments to find the provider', () => {
    st.vault.api_keys = [entry({ provider: 'GITHUB', api_key: 'g' })];
    const [m] = buildEnvLinkMatches(chunk([{ key: 'CI_RUNNER_GITHUB', value: 'unrelated' }]));
    expect(m.match?.confidence).toBe(75);
  });

  it('scores a case-insensitive suffix lowest of all', () => {
    st.vault.api_keys = [entry({ provider: 'GitHub', api_key: 'g' })];
    const [m] = buildEnvLinkMatches(chunk([{ key: 'CI_GITHUB', value: 'unrelated' }]));
    expect(m.match?.confidence).toBe(63);
  });

  it('matches provider_keyid as a suffix, below a bare provider suffix', () => {
    st.vault.api_keys = [entry({ provider: 'AWS', key_id: 'PROD', api_key: 'a' })];
    const [m] = buildEnvLinkMatches(chunk([{ key: 'CI_AWS_PROD', value: 'unrelated' }]));
    expect(m.match?.confidence).toBe(70);
    expect(m.match?.entry.key_id).toBe('PROD');
  });

  it('drops anything below the confidence floor', () => {
    st.vault.api_keys = [entry({ provider: 'Totally Unrelated', api_key: 'x' })];
    const [m] = buildEnvLinkMatches(chunk([{ key: 'DATABASE_URL', value: 'postgres://x' }]));
    expect(m.match).toBeUndefined();
  });
});

describe('already-linked fields and creation suggestions', () => {
  it('reports an existing ${ref} instead of re-matching it', () => {
    st.vault.api_keys = [entry({ provider: 'STRIPE', api_key: 'sk' })];
    const [m] = buildEnvLinkMatches(chunk([{ key: 'STRIPE', value: '${STRIPE/key}' }]));
    expect(m.alreadyLinked).toBe(true);
    expect(m.existingRef).toBe('STRIPE/key');
    expect(m.match).toBeUndefined();
  });

  it('suggests a new entry when nothing matches', () => {
    const [m] = buildEnvLinkMatches(chunk([{ key: 'SENTRY_DSN', value: 'https://x@sentry.io/1' }]));
    expect(m.suggestCreate).toEqual({
      provider: 'SENTRY',
      keyId: 'DSN',
      secretType: 'connection_string',
    });
  });

  it('types a suggestion from the key suffix', () => {
    expect(
      buildEnvLinkMatches(chunk([{ key: 'ADMIN_PASSWORD', value: 'p' }]))[0].suggestCreate
        ?.secretType,
    ).toBe('password');
    expect(
      buildEnvLinkMatches(chunk([{ key: 'SVC_API_KEY', value: 'k' }]))[0].suggestCreate?.secretType,
    ).toBe('api_key');
  });

  it('suggests nothing for an empty value', () => {
    // An unset variable is a placeholder the author has not filled in yet.
    // Offering to create a vault entry for it would store an empty secret.
    const [m] = buildEnvLinkMatches(chunk([{ key: 'TODO_LATER', value: '' }]));
    expect(m.suggestCreate).toBeUndefined();
    expect(m.match).toBeUndefined();
  });

  it('skips fields with no key at all', () => {
    expect(buildEnvLinkMatches(chunk([{ key: '', value: 'orphan' }]))).toHaveLength(0);
  });
});
