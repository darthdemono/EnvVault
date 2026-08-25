/**
 * Entry-level operations and the chunk references that point at them.
 *
 * Shared theme: anything that identifies an entry by its *position* in
 * `api_keys`, or by its *provider name*, breaks the moment that position or
 * name changes. These pin the identity-keyed behaviour in place.
 */
import { describe, it, expect, beforeEach, vi } from 'vitest';
import { st, entryId } from '../src/ts/state';
import {
  deleteKey,
  duplicateKey,
  saveModal,
  fillForm,
  populateProjectSelect,
  buildCatChips,
} from '../src/ts/modals';
import { renameProviderRefs } from '../src/ts/chunk-ops';
import { loadRealIndexHtml, makeEntry, makeProject, makeVault, resetState } from './helpers';

vi.mock('../src/ts/utils', async (importOriginal) => {
  const real = await importOriginal<typeof import('../src/ts/utils')>();
  return { ...real, showToast: () => {}, showConfirm: async () => true };
});

const evt = () => new MouseEvent('click');

beforeEach(() => {
  loadRealIndexHtml();
  resetState(st);
});

describe('deleteKey undo', () => {
  beforeEach(() => {
    st.vault.api_keys = [
      makeEntry({ id: 'a', provider: 'Alpha' }),
      makeEntry({ id: 'b', provider: 'Bravo' }),
      makeEntry({ id: 'c', provider: 'Charlie' }),
      makeEntry({ id: 'd', provider: 'Delta' }),
    ];
  });

  it('restores the entry to its original slot', () => {
    deleteKey(evt(), 1);
    expect(st.vault.api_keys.map((e) => e.id)).toEqual(['a', 'c', 'd']);
    st.undoStack[0].fn();
    expect(st.vault.api_keys.map((e) => e.id)).toEqual(['a', 'b', 'c', 'd']);
  });

  it('still restores to the right slot after a second delete shifted the array', () => {
    // The bug: undo replayed a captured index, so a delete in between put the
    // restored entry back in the wrong place.
    deleteKey(evt(), 2); // remove Charlie -> a, b, d
    const undoCharlie = st.undoStack[0].fn;
    deleteKey(evt(), 0); // remove Alpha   -> b, d
    undoCharlie();
    expect(st.vault.api_keys.map((e) => e.id)).toEqual(['b', 'c', 'd']);
  });

  it('appends when the entry that followed is itself gone', () => {
    deleteKey(evt(), 2); // remove Charlie, anchored on Delta
    const undoCharlie = st.undoStack[0].fn;
    deleteKey(evt(), 2); // remove Delta
    undoCharlie();
    expect(st.vault.api_keys.map((e) => e.id)).toEqual(['a', 'b', 'c']);
  });

  it('restores a deleted last entry to the end', () => {
    deleteKey(evt(), 3);
    st.undoStack[0].fn();
    expect(st.vault.api_keys.map((e) => e.id)).toEqual(['a', 'b', 'c', 'd']);
  });

  it('clears the reveal state of the deleted entry', () => {
    st.revealed['key-b'] = true;
    st.revealed['secret-b'] = true;
    st.expanded.add('b');
    deleteKey(evt(), 1);
    expect(st.revealed).toEqual({});
    expect(st.expanded.has('b')).toBe(false);
  });
});

describe('duplicateKey', () => {
  it('gives the copy a fresh identity', () => {
    st.vault.api_keys = [makeEntry({ id: 'a', provider: 'Alpha' })];
    duplicateKey(evt(), 0);
    expect(st.vault.api_keys).toHaveLength(2);
    expect(st.vault.api_keys[1].id).not.toBe('a');
    expect(st.vault.api_keys[1].id).toBeTruthy();
  });

  it("does not inherit the source entry's rotation history", () => {
    // version_history holds *previous secret values*. Copying it handed the new
    // entry a log of another entry's secrets, visible in its history panel.
    st.vault.api_keys = [
      makeEntry({
        id: 'a',
        provider: 'Alpha',
        version_history: [{ value: 'old-secret-value', saved_at: '2020-01-01T00:00:00Z' }],
        last_rotated_at: '2020-01-01',
      }),
    ];
    duplicateKey(evt(), 0);
    const copy = st.vault.api_keys[1];
    expect(copy.version_history).toBeUndefined();
    expect(copy.last_rotated_at).toBeUndefined();
    expect(JSON.stringify(copy)).not.toContain('old-secret-value');
  });

  it('keeps the secret and the compromised flag, which do describe the copy', () => {
    st.vault.api_keys = [makeEntry({ id: 'a', api_key: 'sk-shared', compromised: true })];
    duplicateKey(evt(), 0);
    expect(st.vault.api_keys[1].api_key).toBe('sk-shared');
    expect(st.vault.api_keys[1].compromised).toBe(true);
  });

  it('inserts the copy directly after the source', () => {
    st.vault.api_keys = [makeEntry({ id: 'a' }), makeEntry({ id: 'b' })];
    duplicateKey(evt(), 0);
    expect(st.vault.api_keys.map((e) => e.id)[1]).not.toBe('b');
    expect(st.vault.api_keys).toHaveLength(3);
  });
});

describe('renameProviderRefs', () => {
  function vaultWithRefs() {
    return makeVault({
      projects: [
        makeProject({
          id: 'p1',
          name: 'Infra',
          chunks: [
            {
              id: 'c1',
              name: 'web',
              chunk_type: 'generic',
              fields: [
                { key: 'bare', value: '${Stripe}', field_type: 'text' },
                { key: 'withField', value: '${Stripe/api_url}', field_type: 'text' },
                { key: 'other', value: '${Twilio/api_key}', field_type: 'text' },
                { key: 'chunkRef', value: '${chunk:web/bare}', field_type: 'text' },
                { key: 'literal', value: 'not-a-ref', field_type: 'text' },
              ],
            },
          ],
        } as any),
      ],
    });
  }

  beforeEach(() => {
    st.vault = vaultWithRefs();
  });

  const fields = () => st.vault.projects[0].chunks![0].fields as any[];
  const byKey = (k: string) => fields().find((f) => f.key === k).value;

  it('rewrites both the bare and the field-suffixed reference', () => {
    const n = renameProviderRefs('Stripe', null, 'StripeLive', null);
    expect(n).toBe(2);
    expect(byKey('bare')).toBe('${StripeLive}');
    expect(byKey('withField')).toBe('${StripeLive/api_url}');
  });

  it('leaves references to other providers alone', () => {
    renameProviderRefs('Stripe', null, 'StripeLive', null);
    expect(byKey('other')).toBe('${Twilio/api_key}');
  });

  it('never touches a ${chunk:…} reference', () => {
    renameProviderRefs('Stripe', null, 'StripeLive', null);
    expect(byKey('chunkRef')).toBe('${chunk:web/bare}');
  });

  it('leaves plain values alone', () => {
    renameProviderRefs('Stripe', null, 'StripeLive', null);
    expect(byKey('literal')).toBe('not-a-ref');
  });

  it('rewrites the compound PROVIDER_KEYID spelling', () => {
    st.vault.projects[0].chunks![0].fields = [
      { key: 'a', value: '${Stripe_v2/api_key}', field_type: 'text' },
    ] as any;
    renameProviderRefs('Stripe', 'v2', 'Adyen', 'v3');
    expect(byKey('a')).toBe('${Adyen_v3/api_key}');
  });

  it('adds a key_id to the reference when one is introduced by the rename', () => {
    renameProviderRefs('Stripe', null, 'Stripe', 'live');
    expect(byKey('withField')).toBe('${Stripe_live/api_url}');
  });

  it('reports zero when nothing referenced the entry', () => {
    expect(renameProviderRefs('Nobody', null, 'Someone', null)).toBe(0);
  });

  it('survives a project with no chunks', () => {
    st.vault.projects.push(makeProject({ id: 'p2', name: 'Empty' }));
    expect(() => renameProviderRefs('Stripe', null, 'X', null)).not.toThrow();
  });
});

describe('saveModal provider rename', () => {
  beforeEach(() => {
    st.vault = makeVault({
      projects: [
        makeProject({ id: 'Universal', name: 'Universal' }),
        makeProject({
          id: 'p1',
          name: 'Infra',
          chunks: [
            {
              id: 'c1',
              name: 'web',
              chunk_type: 'generic',
              fields: [{ key: 'k', value: '${Stripe/api_key}', field_type: 'text' }],
            },
          ],
        } as any),
      ],
      api_keys: [makeEntry({ id: 'a', provider: 'Stripe', api_key: 'sk-1' })],
    });
    populateProjectSelect();
    buildCatChips([]);
  });

  const refValue = () => (st.vault.projects[1].chunks![0].fields as any[])[0].value;

  it('carries chunk references through a rename', () => {
    // Without the cascade the reference silently went stale — the field just
    // started rendering unresolved, with nothing pointing at the cause.
    fillForm(st.vault.api_keys[0]);
    (document.getElementById('f-provider') as HTMLInputElement).value = 'StripeLive';
    (document.getElementById('edit-index') as HTMLInputElement).value = '0';
    saveModal();
    expect(st.vault.api_keys[0].provider).toBe('StripeLive');
    expect(refValue()).toBe('${StripeLive/api_key}');
  });

  it('leaves references untouched when the provider did not change', () => {
    fillForm(st.vault.api_keys[0]);
    (document.getElementById('f-key') as HTMLInputElement).value = 'sk-rotated';
    (document.getElementById('edit-index') as HTMLInputElement).value = '0';
    saveModal();
    expect(refValue()).toBe('${Stripe/api_key}');
  });

  it('preserves the entry id across an edit', () => {
    fillForm(st.vault.api_keys[0]);
    (document.getElementById('f-provider') as HTMLInputElement).value = 'Renamed';
    (document.getElementById('edit-index') as HTMLInputElement).value = '0';
    saveModal();
    expect(st.vault.api_keys[0].id).toBe('a');
  });
});
