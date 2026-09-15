/**
 * Phase 24.5's form-side behaviour for the sixteen new types: the primary
 * value is optional for all of them (none has a `primary` in the registry),
 * and picking one in the add/edit form suggests named-variable rows for its
 * per-type field table rather than leaving `extra_vars` empty with no hint.
 */
import { describe, it, expect, beforeEach } from 'vitest';
import { st, primaryIsOptional, entryHasPayload } from '../src/ts/state';
import { suggestExtraVarsForType, dynamicSecretFields } from '../src/ts/modals';
import { loadRealIndexHtml, resetState } from './helpers';
import type { SecretType, VaultEntry } from '../src/ts/types';

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

const NEW_SIXTEEN: SecretType[] = [
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

describe('primaryIsOptional — Phase 24.5 types', () => {
  it('is optional for every one of the sixteen new types, primary or not', () => {
    for (const t of NEW_SIXTEEN) {
      expect(primaryIsOptional(entry({ secretType: t }))).toBe(true);
    }
  });

  it('entryHasPayload still requires something — the type alone is not payload', () => {
    expect(entryHasPayload(entry({ secretType: 'wifi' }))).toBe(false);
    expect(
      entryHasPayload(
        entry({ secretType: 'wifi', extra_vars: [{ key: 'security', value: 'wpa2' }] }),
      ),
    ).toBe(true);
    expect(entryHasPayload(entry({ secretType: 'wifi', api_key: 'passphrase' }))).toBe(true);
  });
});

describe('suggestExtraVarsForType', () => {
  beforeEach(() => {
    loadRealIndexHtml();
    resetState(st);
  });

  it('adds named-variable rows for a type with a field table', () => {
    const select = document.getElementById('f-secret-type') as HTMLSelectElement;
    select.value = 'wifi';
    dynamicSecretFields();
    suggestExtraVarsForType('wifi');
    const keys = [
      ...document.querySelectorAll<HTMLInputElement>('#f-extra-vars-list .extra-var-key'),
    ].map((i) => i.value);
    expect(keys).toContain('security');
    expect(keys).toContain('hidden');
  });

  it('never overwrites rows already present', () => {
    const select = document.getElementById('f-secret-type') as HTMLSelectElement;
    select.value = 'wifi';
    dynamicSecretFields();
    suggestExtraVarsForType('wifi');
    const before = document.querySelectorAll('#f-extra-vars-list .extra-var-row').length;
    suggestExtraVarsForType('wifi');
    const after = document.querySelectorAll('#f-extra-vars-list .extra-var-row').length;
    expect(after).toBe(before);
  });

  it('does nothing for a type with no suggested fields (secure_note)', () => {
    suggestExtraVarsForType('secure_note');
    expect(document.querySelectorAll('#f-extra-vars-list .extra-var-row').length).toBe(0);
  });

  it('marks realistically-secret suggested fields to start masked', () => {
    suggestExtraVarsForType('oauth_client');
    const secretRow = [
      ...document.querySelectorAll<HTMLElement>('#f-extra-vars-list .extra-var-row'),
    ].find((r) => r.querySelector<HTMLInputElement>('.extra-var-key')?.value === 'client_secret');
    expect(secretRow?.querySelector<HTMLInputElement>('.extra-var-secret')?.checked).toBe(true);
  });
});
