/**
 * The secret-type registry (Phase 24.5). Not a twin pair — there is exactly
 * one `secret-types.json`, read here and by `vault_core::secret_types` — so
 * this is a schema test, not a parity fixture: what could disagree is the
 * *reader*, not the data.
 */
import { describe, it, expect } from 'vitest';
import {
  registry,
  findSecretType,
  secretTypeLabel,
  secretTypesByGroup,
  maskWholeFor,
} from '../src/ts/secret-types';

const EXISTING_TEN = [
  'api_key',
  'password',
  'certificate',
  'env_var',
  'connection_string',
  'ssh_key',
  'file_blob',
  'cookie',
  'composite',
  'bundle',
];

const NEW_SIXTEEN = [
  'oauth_client',
  'signing_key',
  'registry_token',
  'database',
  'recovery_codes',
  'gpg_key',
  'age_key',
  'local_service',
  'tracker',
  'usenet_server',
  'wifi',
  'license_key',
  'crypto_wallet',
  'passkey',
  'secure_note',
  'identity_document',
];

describe('secret-types registry', () => {
  it('has exactly the ten existing plus sixteen new types', () => {
    const ids = registry().map((t) => t.id);
    for (const id of [...EXISTING_TEN, ...NEW_SIXTEEN]) {
      expect(ids).toContain(id);
    }
    expect(ids.length).toBe(EXISTING_TEN.length + NEW_SIXTEEN.length);
  });

  it('every id is unique', () => {
    const ids = registry().map((t) => t.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it('findSecretType resolves a known type and not an unknown one', () => {
    expect(findSecretType('cookie')?.label).toBe('Web Session');
    expect(findSecretType('from_the_future')).toBeUndefined();
  });

  it('secretTypeLabel falls back to the raw id for an unknown type', () => {
    expect(secretTypeLabel('wifi')).toBe('Wi-Fi');
    expect(secretTypeLabel('from_the_future')).toBe('from_the_future');
  });

  it('groups every type under one of the four groups', () => {
    const byGroup = secretTypesByGroup();
    const total = [...byGroup.values()].reduce((n, list) => n + list.length, 0);
    expect(total).toBe(registry().length);
    expect(byGroup.has('core')).toBe(true);
    expect(byGroup.has('dev_infra')).toBe(true);
  });

  it('mask_whole matches the cookie/web-session rule (E5) and is false by default', () => {
    expect(maskWholeFor('cookie')).toBe(true);
    expect(maskWholeFor('api_key')).toBe(false);
    expect(maskWholeFor(undefined)).toBe(false);
    expect(maskWholeFor('from_the_future')).toBe(false);
  });
});
