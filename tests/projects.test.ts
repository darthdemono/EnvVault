/**
 * Project and category CRUD.
 *
 * The recurring defect in this area: sub-projects and sub-categories are just
 * names sharing a `parent/` prefix, so an operation on the parent has to carry
 * the whole sub-tree — and when an id changes, every entry referencing it has
 * to follow. Missing either half loses data silently.
 */
import { describe, it, expect, beforeEach, vi } from 'vitest';
import { st } from '../src/ts/state';
import { deleteProject, renameProject, deleteCategory, renameCategory } from '../src/ts/projects';
import { buildProjectTree, getFiltered } from '../src/ts/filters';
import { loadRealIndexHtml, makeEntry, makeProject, makeVault, resetState } from './helpers';

let promptAnswer = 'renamed';
let confirmAnswer = true;

vi.mock('../src/ts/utils', async (importOriginal) => {
  const real = await importOriginal<typeof import('../src/ts/utils')>();
  return {
    ...real,
    showConfirm: async () => confirmAnswer,
    showPrompt: async () => promptAnswer,
    showToast: () => {},
  };
});

beforeEach(() => {
  loadRealIndexHtml();
  resetState(st);
  promptAnswer = 'renamed';
  confirmAnswer = true;
});

function nestedVault() {
  return makeVault({
    projects: [
      makeProject({ id: 'Universal', name: 'Universal' }),
      makeProject({ id: 'acme', name: 'Acme' }),
      makeProject({ id: 'acme-web', name: 'Acme/Web' }),
      makeProject({ id: 'acme-web-edge', name: 'Acme/Web/Edge' }),
    ],
    api_keys: [
      makeEntry({ provider: 'ParentKey', projectIds: ['Universal', 'acme'] }),
      makeEntry({ provider: 'WebKey',    projectIds: ['Universal', 'acme-web'] }),
      makeEntry({ provider: 'EdgeKey',   projectIds: ['Universal', 'acme-web-edge'] }),
    ],
  });
}

describe('deleteProject', () => {
  beforeEach(() => { st.vault = nestedVault(); });

  it('keeps entries attached to sub-projects that survive the delete', async () => {
    // The bug: promoting a child changed its id, the prune pass then saw every
    // entry's reference as dangling and stripped it, so deleting a parent
    // silently emptied all of its surviving sub-projects.
    await deleteProject('acme');
    const web = st.vault.projects.find(p => p.name === 'Web')!;
    expect(web).toBeDefined();
    const webKey = st.vault.api_keys.find(e => e.provider === 'WebKey')!;
    expect(webKey.projectIds).toContain(web.id);
  });

  it('leaves the promoted sub-project reachable from the sidebar', async () => {
    await deleteProject('acme');
    const web = st.vault.projects.find(p => p.name === 'Web')!;
    st.currentSelectedProjectIds = [web.id];
    expect(getFiltered().map(e => e.provider).sort()).toEqual(['EdgeKey', 'WebKey']);
  });

  it('follows the selection when the selected project is a promoted child', async () => {
    st.currentSelectedProjectIds = ['acme-web'];
    await deleteProject('acme');
    const web = st.vault.projects.find(p => p.name === 'Web')!;
    expect(st.currentSelectedProjectIds).toEqual([web.id]);
    expect(getFiltered().length).toBeGreaterThan(0);
  });

  it('falls back to Universal when the deleted project itself was selected', async () => {
    st.currentSelectedProjectIds = ['acme'];
    await deleteProject('acme');
    expect(st.currentSelectedProjectIds).toEqual(['Universal']);
  });

  it('drops entries of the deleted project back to Universal', async () => {
    await deleteProject('acme');
    const parentKey = st.vault.api_keys.find(e => e.provider === 'ParentKey')!;
    expect(parentKey.projectIds).toEqual(['Universal']);
  });

  it('promotes the whole chain, keeping grandchildren nested under their parent', async () => {
    await deleteProject('acme');
    const names = st.vault.projects.map(p => p.name).sort();
    expect(names).toEqual(['Universal', 'Web', 'Web/Edge']);
  });

  it('leaves every entry carrying Universal', async () => {
    await deleteProject('acme');
    for (const entry of st.vault.api_keys) {
      expect(entry.projectIds).toContain('Universal');
    }
  });

  it('refuses to delete the Universal catch-all', async () => {
    await deleteProject('Universal');
    expect(st.vault.projects.find(p => p.id === 'Universal')).toBeDefined();
  });

  it('does nothing when the user cancels', async () => {
    confirmAnswer = false;
    await deleteProject('acme');
    expect(st.vault.projects.map(p => p.id)).toContain('acme');
  });

  it('does not collide a promoted child with an existing top-level project', async () => {
    st.vault.projects.push(makeProject({ id: 'web', name: 'Web' }));
    await deleteProject('acme');
    const ids = st.vault.projects.map(p => p.id);
    expect(new Set(ids).size).toBe(ids.length);
  });
});

describe('renameProject', () => {
  beforeEach(() => { st.vault = nestedVault(); });

  it('renames sub-projects along with their parent', async () => {
    // Renaming only the parent left "Acme/Web" orphaned, and buildProjectTree
    // then invented a phantom virtual "Acme" for a project that was gone.
    promptAnswer = 'Corp';
    await renameProject('acme');
    expect(st.vault.projects.map(p => p.name).sort())
      .toEqual(['Corp', 'Corp/Web', 'Corp/Web/Edge', 'Universal']);
  });

  it('leaves no phantom parent in the sidebar tree', async () => {
    promptAnswer = 'Corp';
    await renameProject('acme');
    const tree = buildProjectTree(st.vault.projects);
    expect(tree.some((n: any) => n.virtual)).toBe(false);
    expect(tree.map((n: any) => n.name).sort()).toEqual(['Corp', 'Universal']);
  });

  it('repoints entries at the new sub-project ids', async () => {
    promptAnswer = 'Corp';
    await renameProject('acme');
    const web = st.vault.projects.find(p => p.name === 'Corp/Web')!;
    const webKey = st.vault.api_keys.find(e => e.provider === 'WebKey')!;
    expect(webKey.projectIds).toContain(web.id);
    st.currentSelectedProjectIds = [web.id];
    expect(getFiltered().map(e => e.provider).sort()).toEqual(['EdgeKey', 'WebKey']);
  });

  it('follows the selection when a renamed child was selected', async () => {
    st.currentSelectedProjectIds = ['acme-web'];
    promptAnswer = 'Corp';
    await renameProject('acme');
    const web = st.vault.projects.find(p => p.name === 'Corp/Web')!;
    expect(st.currentSelectedProjectIds).toEqual([web.id]);
  });

  it('follows the selection when the renamed project itself was selected', async () => {
    st.currentSelectedProjectIds = ['acme'];
    promptAnswer = 'Corp';
    await renameProject('acme');
    expect(st.currentSelectedProjectIds).toEqual([st.vault.projects.find(p => p.name === 'Corp')!.id]);
  });

  it('refuses a name that collides with an existing project', async () => {
    st.vault.projects.push(makeProject({ id: 'corp', name: 'Corp' }));
    promptAnswer = 'Corp';
    await renameProject('acme');
    expect(st.vault.projects.find(p => p.id === 'acme')!.name).toBe('Acme');
  });

  it('does nothing when the prompt is cancelled or unchanged', async () => {
    promptAnswer = 'Acme';
    await renameProject('acme');
    expect(st.vault.projects.find(p => p.id === 'acme')).toBeDefined();
  });
});

describe('deleteCategory', () => {
  beforeEach(() => {
    st.vault = makeVault({
      user_categories: ['infra', 'infra/db', 'infra/net', 'infrastructure', 'billing'],
      api_keys: [
        makeEntry({ provider: 'A', categories: ['infra'] }),
        makeEntry({ provider: 'B', categories: ['infra/db', 'billing'] }),
        makeEntry({ provider: 'C', categories: ['infrastructure'] }),
      ],
    });
  });

  it('deletes the sub-categories with their parent', async () => {
    // Leaving "infra/db" behind made it unreachable — the sidebar filters by
    // prefix from a parent that no longer existed — while it stayed stamped on
    // every entry.
    await deleteCategory('infra');
    expect(st.vault.user_categories.sort()).toEqual(['billing', 'infrastructure']);
  });

  it('strips the whole sub-tree from entries', async () => {
    await deleteCategory('infra');
    expect(st.vault.api_keys.find(e => e.provider === 'A')!.categories).toEqual([]);
    expect(st.vault.api_keys.find(e => e.provider === 'B')!.categories).toEqual(['billing']);
  });

  it('does not touch a category that merely shares a name prefix', async () => {
    await deleteCategory('infra');
    expect(st.vault.user_categories).toContain('infrastructure');
    expect(st.vault.api_keys.find(e => e.provider === 'C')!.categories).toEqual(['infrastructure']);
  });

  it('clears a filter pointing anywhere inside the deleted sub-tree', async () => {
    st.filter = { type: 'category', value: 'infra/db' };
    await deleteCategory('infra');
    expect(st.filter).toEqual({ type: 'all', value: '' });
  });

  it('does nothing when the user cancels', async () => {
    confirmAnswer = false;
    await deleteCategory('infra');
    expect(st.vault.user_categories).toContain('infra');
  });
});

describe('renameCategory', () => {
  beforeEach(() => {
    st.vault = makeVault({
      user_categories: ['infra', 'infra/db', 'infrastructure'],
      api_keys: [
        makeEntry({ provider: 'A', categories: ['infra'] }),
        makeEntry({ provider: 'B', categories: ['infra/db'] }),
        makeEntry({ provider: 'C', categories: ['infrastructure'] }),
      ],
    });
  });

  it('renames sub-categories along with their parent', async () => {
    promptAnswer = 'core';
    await renameCategory('infra');
    expect(st.vault.user_categories.sort()).toEqual(['core', 'core/db', 'infrastructure']);
  });

  it('repoints entries in the sub-tree', async () => {
    promptAnswer = 'core';
    await renameCategory('infra');
    expect(st.vault.api_keys.find(e => e.provider === 'B')!.categories).toEqual(['core/db']);
  });

  it('leaves a name-prefix sibling alone', async () => {
    promptAnswer = 'core';
    await renameCategory('infra');
    expect(st.vault.api_keys.find(e => e.provider === 'C')!.categories).toEqual(['infrastructure']);
  });

  it('follows a filter pointing at a renamed sub-category', async () => {
    st.filter = { type: 'category', value: 'infra/db' };
    promptAnswer = 'core';
    await renameCategory('infra');
    expect(st.filter).toEqual({ type: 'category', value: 'core/db' });
    expect(getFiltered().map(e => e.provider)).toEqual(['B']);
  });

  it('refuses a name that already exists', async () => {
    promptAnswer = 'infrastructure';
    await renameCategory('infra');
    expect(st.vault.user_categories).toContain('infra');
  });
});
