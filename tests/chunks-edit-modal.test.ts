/**
 * `chunks/edit-modal.ts` — the add/rename/retype/delete editor for a chunk's
 * fields.
 *
 * At 0% coverage until Phase 18. It is worth testing for one specific reason:
 * every field row is addressed by `data-idx`, and the delete handler splices the
 * array. That is invariant 1's exact shape — an index captured at render time
 * and used after the array can have changed — so the tests below hammer delete
 * ordering rather than the happy path.
 */
import { describe, it, expect, beforeEach } from 'vitest';
import { loadRealIndexHtml } from './helpers';
import {
  openChunkEditModal,
  closeChunkEditModal,
  renderChunkEditFields,
  readChunkEditFields,
  saveChunkEdit,
} from '../src/ts/chunks/edit-modal';
import { st } from '../src/ts/state';
import type { Project, SecretChunk, ChunkField } from '../src/ts/types';

function fields(...pairs: [string, string, string?][]): ChunkField[] {
  return pairs.map(([key, value, t]) => ({
    key,
    value,
    field_type: (t ?? 'var') as ChunkField['field_type'],
    secret: t === 'secret',
  }));
}

function project(chunk: SecretChunk): Project {
  return { id: 'p1', name: 'Proj', project_type: 'docker', chunks: [chunk] } as Project;
}

function chunkOf(f: ChunkField[]): SecretChunk {
  return { id: 'c1', chunk_type: 'env_file', name: '.env', fields: f } as SecretChunk;
}

beforeEach(() => {
  loadRealIndexHtml();
  st.vault = { api_keys: [], user_categories: [], projects: [] };
});

describe('opening and closing', () => {
  it('fills every field the form reaches for', () => {
    // Id contract: these are the ids `openChunkEditModal` writes into. A
    // formatter dropping one of them from index.html is a failure mode this
    // project has actually shipped (Phase 3, #new-category-form).
    const c = chunkOf(fields(['A', '1']));
    c.notes = 'a note';
    c.disabled = true;
    openChunkEditModal(project(c), c);

    expect((document.getElementById('chunk-edit-name') as HTMLInputElement).value).toBe('.env');
    expect((document.getElementById('chunk-edit-notes') as HTMLInputElement).value).toBe('a note');
    expect((document.getElementById('chunk-edit-disabled') as HTMLInputElement).checked).toBe(true);
    expect((document.getElementById('chunk-edit-project-id') as HTMLInputElement).value).toBe('p1');
    expect((document.getElementById('chunk-edit-chunk-id') as HTMLInputElement).value).toBe('c1');
    expect(document.getElementById('chunk-edit-overlay')!.classList.contains('open')).toBe(true);
  });

  it('shows an absent note as empty rather than "undefined"', () => {
    const c = chunkOf(fields(['A', '1']));
    openChunkEditModal(project(c), c);
    expect((document.getElementById('chunk-edit-notes') as HTMLInputElement).value).toBe('');
  });

  it('closes', () => {
    const c = chunkOf(fields(['A', '1']));
    openChunkEditModal(project(c), c);
    closeChunkEditModal();
    expect(document.getElementById('chunk-edit-overlay')!.classList.contains('open')).toBe(false);
  });
});

describe('render / read round trip', () => {
  it('reads back exactly what it rendered', () => {
    const f = fields(
      ['HOST', 'db.internal'],
      ['PASS', 'hunter2', 'secret'],
      ['PORT', '5432', 'port'],
    );
    renderChunkEditFields(f);
    expect(readChunkEditFields()).toEqual(f);
  });

  it('derives `secret` from the type rather than storing it twice', () => {
    renderChunkEditFields(fields(['K', 'v', 'secret']));
    expect(readChunkEditFields()[0].secret).toBe(true);
    renderChunkEditFields(fields(['K', 'v', 'var']));
    expect(readChunkEditFields()[0].secret).toBe(false);
  });

  it('trims the key but never the value', () => {
    // Leading whitespace in a key is a typo; in a value it can be significant —
    // a PEM block or an indented YAML fragment.
    renderChunkEditFields([
      { key: '  K  ', value: '  spaced  ', field_type: 'var', secret: false },
    ]);
    const [f] = readChunkEditFields();
    expect(f.key).toBe('K');
    expect(f.value).toBe('  spaced  ');
  });

  it('preserves a description the UI never shows', () => {
    // Descriptions come from starter templates and have no input of their own.
    // Reading fields back must not silently drop them.
    renderChunkEditFields([
      { key: 'K', value: 'v', field_type: 'var', secret: false, description: 'env' },
    ]);
    expect(readChunkEditFields()[0].description).toBe('env');
  });

  it('escapes a value containing quotes and markup', () => {
    // Chunk fields are vault data, and vault data is untrusted input.
    renderChunkEditFields(fields(['K', '"><img src=x onerror=alert(1)>']));
    expect(document.querySelectorAll('#chunk-edit-fields img')).toHaveLength(0);
    expect(readChunkEditFields()[0].value).toBe('"><img src=x onerror=alert(1)>');
  });

  it('renders every field type as a selectable option', () => {
    // The <select> is hand-written HTML with one branch per type. A type missing
    // from it silently becomes the first option on the next save, retyping a
    // field the user never touched.
    const types = [
      'var',
      'env_var',
      'secret',
      'list',
      'multiline',
      'port',
      'user_id',
      'subnet',
      'ip',
      'endpoint',
      'volume_mount',
      'cert',
    ] as const;
    renderChunkEditFields(
      types.map((t) => ({ key: t, value: 'v', field_type: t, secret: t === 'secret' })),
    );
    expect(readChunkEditFields().map((f) => f.field_type)).toEqual([...types]);
  });

  it('replaces rather than appends on re-render', () => {
    renderChunkEditFields(fields(['A', '1'], ['B', '2']));
    renderChunkEditFields(fields(['C', '3']));
    expect(readChunkEditFields().map((f) => f.key)).toEqual(['C']);
  });
});

describe('deleting a field — the index-reuse trap', () => {
  it('removes the row that was clicked, not its neighbour', () => {
    renderChunkEditFields(fields(['A', '1'], ['B', '2'], ['C', '3']));
    const btns = document.querySelectorAll<HTMLButtonElement>('.chunk-field-delete');
    btns[1].click();
    expect(readChunkEditFields().map((f) => f.key)).toEqual(['A', 'C']);
  });

  it('stays correct across successive deletes', () => {
    // The handler re-renders after each delete, so `data-idx` is rebuilt every
    // time. If it did not, the second click would target a stale position and
    // remove the wrong field — the bug that destroyed the wrong secrets in bulk
    // delete during Phase 11.
    renderChunkEditFields(fields(['A', '1'], ['B', '2'], ['C', '3'], ['D', '4']));
    document.querySelectorAll<HTMLButtonElement>('.chunk-field-delete')[0].click();
    document.querySelectorAll<HTMLButtonElement>('.chunk-field-delete')[0].click();
    expect(readChunkEditFields().map((f) => f.key)).toEqual(['C', 'D']);
  });

  it('keeps edits made before the delete', () => {
    // The handler reads the live DOM rather than the array it was rendered
    // from, so typing then deleting must not revert the typing.
    renderChunkEditFields(fields(['A', '1'], ['B', '2']));
    const keyInput = document.querySelector<HTMLInputElement>('.chunk-field-key-input')!;
    keyInput.value = 'RENAMED';
    document.querySelectorAll<HTMLButtonElement>('.chunk-field-delete')[1].click();
    expect(readChunkEditFields().map((f) => f.key)).toEqual(['RENAMED']);
  });

  it('can empty the list', () => {
    renderChunkEditFields(fields(['ONLY', '1']));
    document.querySelector<HTMLButtonElement>('.chunk-field-delete')!.click();
    expect(readChunkEditFields()).toEqual([]);
  });
});

describe('saving', () => {
  it('writes name, notes, disabled and fields back onto the chunk', () => {
    const c = chunkOf(fields(['A', '1']));
    const p = project(c);
    st.vault.projects = [p];
    openChunkEditModal(p, c);

    (document.getElementById('chunk-edit-name') as HTMLInputElement).value = 'renamed.env';
    (document.getElementById('chunk-edit-notes') as HTMLInputElement).value = 'why';
    (document.getElementById('chunk-edit-disabled') as HTMLInputElement).checked = true;
    document.querySelector<HTMLInputElement>('.chunk-field-val-input')!.value = 'changed';
    saveChunkEdit();

    expect(c.name).toBe('renamed.env');
    expect(c.notes).toBe('why');
    expect(c.disabled).toBe(true);
    expect(c.fields[0].value).toBe('changed');
    expect(document.getElementById('chunk-edit-overlay')!.classList.contains('open')).toBe(false);
  });

  it('refuses an empty name and leaves the modal open', () => {
    const c = chunkOf(fields(['A', '1']));
    const p = project(c);
    st.vault.projects = [p];
    openChunkEditModal(p, c);
    (document.getElementById('chunk-edit-name') as HTMLInputElement).value = '   ';
    saveChunkEdit();

    expect(c.name).toBe('.env');
    expect(document.getElementById('chunk-edit-overlay')!.classList.contains('open')).toBe(true);
  });

  it('stores an emptied note as undefined, not an empty string', () => {
    // `notes: ''` and no note render differently downstream; the exporters test
    // for absence.
    const c = chunkOf(fields(['A', '1']));
    c.notes = 'had one';
    const p = project(c);
    st.vault.projects = [p];
    openChunkEditModal(p, c);
    (document.getElementById('chunk-edit-notes') as HTMLInputElement).value = '';
    saveChunkEdit();
    expect(c.notes).toBeUndefined();
    expect(c.disabled).toBeUndefined();
  });

  it('does nothing when the chunk has vanished under it', () => {
    // The modal holds ids, and the vault can be replaced while it is open —
    // invariant 3. Saving must not resurrect a deleted chunk or throw.
    const c = chunkOf(fields(['A', '1']));
    const p = project(c);
    st.vault.projects = [p];
    openChunkEditModal(p, c);
    p.chunks = [];
    expect(() => saveChunkEdit()).not.toThrow();
  });

  it('does nothing when the project has vanished under it', () => {
    const c = chunkOf(fields(['A', '1']));
    st.vault.projects = [project(c)];
    openChunkEditModal(project(c), c);
    st.vault.projects = [];
    expect(() => saveChunkEdit()).not.toThrow();
  });
});
