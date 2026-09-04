/**
 * @file
 * Project and category CRUD operations.
 */

import type { Project, ProjectType } from './types';
import { isExperimentalProjectType } from './types';
import { st, triggerRender, persist, Settings } from './state';
import { showToast, showConfirm, showPrompt } from './utils';
import {
  makeWgStarterChunks,
  makeDockerStarterChunks,
  makeNginxStarterChunks,
  makeK8sStarterChunks,
  makeSshStarterChunks,
  makeTraefikStarterChunks,
  makeApacheStarterChunks,
  makeHaproxyStarterChunks,
  makeAnsibleStarterChunks,
  makePostgresStarterChunks,
} from './chunk-ops';

// ── Filter setter ─────────────────────────────────────────────────────────

export function doSetFilter(type: string, value: string) {
  st.filter =
    st.filter.type === type && st.filter.value === value
      ? { type: 'all', value: '' }
      : { type, value };
  triggerRender();
}

// ── Category operations ───────────────────────────────────────────────────

export async function deleteCategory(name: string) {
  // Categories nest by slash the same way projects do, and the sidebar filter
  // matches on that prefix. Deleting only the exact name left "infra/db" behind
  // with no "infra" above it — unreachable from the sidebar but still stamped
  // on every entry that carried it.
  const prefix = name + '/';
  const doomed = (c: string) => c === name || c.startsWith(prefix);
  const subCount = st.vault.user_categories.filter((c) => c.startsWith(prefix)).length;

  let msg = `Delete category "${name}"?`;
  if (subCount)
    msg += ` ${subCount} sub-categor${subCount === 1 ? 'y' : 'ies'} will be deleted too.`;
  if (!(await showConfirm(msg))) return;

  st.vault.user_categories = st.vault.user_categories.filter((c) => !doomed(c));
  st.vault.api_keys.forEach((k) => {
    if (k.categories) k.categories = k.categories.filter((c) => !doomed(c));
  });
  if (st.filter.type === 'category' && doomed(st.filter.value))
    st.filter = { type: 'all', value: '' };
  persist();
  triggerRender();
}

export async function renameCategory(name: string) {
  const next = (await showPrompt('Rename category:', name))?.trim();
  if (!next || next === name) return;
  if (st.vault.user_categories.includes(next)) {
    showToast(`Category "${next}" already exists`, 'err');
    return;
  }

  // Carry the sub-tree along, as deleteCategory now does.
  const prefix = name + '/';
  const remap = (c: string) =>
    c === name ? next : c.startsWith(prefix) ? next + c.slice(name.length) : c;

  st.vault.user_categories = st.vault.user_categories.map(remap);
  st.vault.api_keys.forEach((k) => {
    if (k.categories) k.categories = k.categories.map(remap);
  });
  if (
    st.filter.type === 'category' &&
    (st.filter.value === name || st.filter.value.startsWith(prefix))
  ) {
    st.filter = { type: 'category', value: remap(st.filter.value) };
  }
  persist();
  triggerRender();
}

// ── Project operations ────────────────────────────────────────────────────

/** Project name → id. Kept in one place so rename and delete agree on the shape. */
export function slugifyProjectName(name: string): string {
  return name
    .toLowerCase()
    .replace(/[^a-z0-9/]+/g, '-')
    .replace(/^-|-$/g, '');
}

/**
 * Whether this project's id was chosen by hand rather than derived from its name.
 *
 * Derived rather than stored: a project whose id is not what `slugifyProjectName`
 * would produce for its current name must have been given one deliberately. That
 * keeps custom slugs working for vaults written before they existed, and means
 * there is no flag that can disagree with the data it describes.
 */
export function hasCustomSlug(project: Project): boolean {
  return project.id !== slugifyProjectName(project.name);
}

/** Characters a project id may contain. Mirrors what `slugifyProjectName` emits. */
const SLUG_RE = /^[a-z0-9]+(?:[-/][a-z0-9]+)*$/;

/**
 * Validate a hand-written slug, returning an error message or `null`.
 *
 * A project id ends up in `entry.projectIds`, in RBAC scope values and in
 * exported filenames, so the shape has to stay predictable — an id with a space
 * or an uppercase letter would round-trip through `slugifyProjectName` into a
 * *different* id the next time anything derived one.
 */
export function validateSlug(raw: string, existing: Project[], selfId?: string): string | null {
  const slug = raw.trim();
  if (!slug) return 'Slug cannot be empty';
  if (slug.length > 64) return 'Slug must be 64 characters or fewer';
  if (slug.toLowerCase() === 'universal') return '"Universal" is reserved';
  if (!SLUG_RE.test(slug)) {
    return 'Slug may use lowercase letters, digits, - and / (no leading, trailing or repeated separators)';
  }
  if (existing.some((p) => p.id === slug && p.id !== selfId))
    return `Slug "${slug}" is already taken`;
  return null;
}

export async function renameProject(id: string) {
  const project = st.vault.projects.find((p) => p.id === id);
  if (!project) return;
  const newName = (await showPrompt(`Rename "${project.name}" to:`, project.name))?.trim();
  if (!newName || newName === project.name) return;
  // A hand-chosen slug survives a rename. The id is what every entry, every
  // permission rule and every `${…}` scope points at, so re-deriving it from a
  // new display name would silently retarget all of them — which is exactly why
  // someone pinned it in the first place.
  const newId = hasCustomSlug(project) ? project.id : slugifyProjectName(newName);
  if (newId !== id && st.vault.projects.find((p) => p.id === newId)) {
    showToast('Project already exists', 'err');
    return;
  }

  const oldName = project.name;
  // Sub-projects are just names sharing a `parent/` prefix, so renaming the
  // parent has to carry them along. It used to rename only the parent, leaving
  // "Acme/Web" behind after "Acme" became "Corp" — buildProjectTree then
  // synthesised a phantom "Acme" node for a project that no longer existed.
  const children = st.vault.projects.filter(
    (p) => p !== project && p.name.startsWith(oldName + '/'),
  );

  const idRemap = new Map<string, string>();
  if (newId !== id) idRemap.set(id, newId);
  project.id = newId;
  project.name = newName;

  for (const child of children) {
    const childName = newName + child.name.slice(oldName.length);
    // Same rule per child: a sub-project with its own pinned slug keeps it.
    if (hasCustomSlug(child)) {
      child.name = childName;
      continue;
    }
    const base = slugifyProjectName(childName);
    let fid = base;
    let n = 1;
    while (st.vault.projects.find((p) => p !== child && p.id === fid)) fid = `${base}-${n++}`;
    if (child.id !== fid) idRemap.set(child.id, fid);
    child.id = fid;
    child.name = childName;
  }

  if (idRemap.size) {
    st.vault.api_keys.forEach((k) => {
      if (k.projectIds) k.projectIds = k.projectIds.map((pid) => idRemap.get(pid) ?? pid);
    });
    const selected = st.currentSelectedProjectIds[0];
    if (selected && idRemap.has(selected)) st.currentSelectedProjectIds = [idRemap.get(selected)!];
  }

  persist();
  triggerRender();
  showToast(`Renamed to "${newName}"`, 'ok');
}

export async function deleteProject(id: string) {
  if (id === 'Universal') return;
  const project = st.vault.projects.find((p) => p.id === id);
  if (!project) return;
  const children = st.vault.projects.filter(
    (p) => p !== project && p.name.startsWith(project.name + '/'),
  );
  let msg = `Delete project "${project.name}"?`;
  if (children.length)
    msg += ` ${children.length} sub-project${children.length === 1 ? '' : 's'} will be promoted to top level.`;
  if (!(await showConfirm(msg))) return;

  st.vault.api_keys.forEach((k) => {
    if (k.projectIds?.includes(id)) k.projectIds = k.projectIds.filter((pid) => pid !== id);
  });
  st.vault.projects = st.vault.projects.filter((p) => p.id !== id);

  // Promoting a sub-project changes its id, so every entry that referenced the
  // old id has to follow it. Without this remap the next prune pass saw those
  // ids as dangling and stripped them: deleting a parent silently emptied every
  // surviving sub-project, and the entries fell back to Universal.
  const idRemap = new Map<string, string>();
  for (const child of children) {
    const newName = child.name.slice(project.name.length + 1);
    // A promoted sub-project with a pinned slug keeps it — promotion changes
    // where it sits in the tree, not what points at it.
    if (hasCustomSlug(child)) {
      child.name = newName;
      continue;
    }
    const newId = slugifyProjectName(newName);
    let fid = newId;
    let n = 1;
    while (st.vault.projects.find((p) => p !== child && p.id === fid)) fid = `${newId}-${n++}`;
    if (child.id !== fid) idRemap.set(child.id, fid);
    child.id = fid;
    child.name = newName;
  }
  if (idRemap.size) {
    st.vault.api_keys.forEach((k) => {
      if (k.projectIds) k.projectIds = k.projectIds.map((pid) => idRemap.get(pid) ?? pid);
    });
  }

  st.vault.api_keys.forEach((k) => {
    k.projectIds = (k.projectIds ?? []).filter(
      (pid) => pid === 'Universal' || st.vault.projects.some((p) => p.id === pid),
    );
    if (!k.projectIds.includes('Universal')) k.projectIds.push('Universal');
  });

  const selected = st.currentSelectedProjectIds[0];
  if (selected === id) st.currentSelectedProjectIds = ['Universal'];
  // The selection can also be a promoted child, whose id just changed. Leaving
  // it stale pointed the sidebar at a project that no longer existed, and the
  // grid rendered empty.
  else if (selected && idRemap.has(selected))
    st.currentSelectedProjectIds = [idRemap.get(selected)!];

  persist();
  triggerRender();
  showToast(`Project "${project.name}" deleted`, 'ok');
}

// ── Project create modal ──────────────────────────────────────────────────

let _projectCreateType: ProjectType = 'generic';

/**
 * Shows or hides the untested project types in the create picker.
 *
 * Applied on every open rather than once at boot: the setting can be toggled
 * while the app is running, and the picker lives in static markup that nothing
 * else repaints.
 */
export function applyExperimentalTypeVisibility(): void {
  const show = !!Settings.get('experimentalProjectTypes');
  document.querySelectorAll<HTMLButtonElement>('.project-type-btn').forEach((btn) => {
    const type = btn.dataset.ptype as ProjectType | undefined;
    if (!isExperimentalProjectType(type)) return;
    btn.style.display = show ? '' : 'none';
    btn.classList.toggle('experimental', show);
  });
}

export function openProjectCreateModal() {
  _projectCreateType = 'generic';
  const overlay = document.getElementById('project-create-overlay')!;
  const nameEl = document.getElementById('project-create-name') as HTMLInputElement;
  const descEl = document.getElementById('project-create-desc') as HTMLInputElement;
  const slugEl = document.getElementById('project-create-slug') as HTMLInputElement | null;
  nameEl.value = '';
  descEl.value = '';
  if (slugEl) {
    slugEl.value = '';
    // Show what an empty slug field will produce, so the id is never a surprise.
    // Assigned, not added: this modal is opened repeatedly and addEventListener
    // would stack a handler per open (invariant 9).
    slugEl.placeholder = 'derived from the name';
    nameEl.oninput = () => {
      slugEl.placeholder = slugifyProjectName(nameEl.value.trim()) || 'derived from the name';
    };
  }
  applyExperimentalTypeVisibility();
  document.querySelectorAll<HTMLButtonElement>('.project-type-btn').forEach((btn) => {
    const on = btn.dataset.ptype === 'generic';
    btn.classList.toggle('active', on);
    btn.setAttribute('role', 'radio');
    btn.setAttribute('aria-checked', String(on));
  });
  overlay.classList.add('open');
  setTimeout(() => nameEl.focus(), 60);
}

export function closeProjectCreateModal() {
  document.getElementById('project-create-overlay')!.classList.remove('open');
}

export function openCategoryCreateModal() {
  const overlay = document.getElementById('category-create-overlay')!;
  const nameEl = document.getElementById('category-create-name') as HTMLInputElement;
  nameEl.value = '';
  overlay.classList.add('open');
  setTimeout(() => nameEl.focus(), 60);
}

export function closeCategoryCreateModal() {
  document.getElementById('category-create-overlay')!.classList.remove('open');
}

export function saveCategoryCreate() {
  const nameEl = document.getElementById('category-create-name') as HTMLInputElement;
  const name = nameEl.value.trim().toLowerCase();
  if (!name) {
    showToast('Name is required', 'err');
    return;
  }
  if (st.vault.user_categories.includes(name)) {
    showToast('Category already exists', 'err');
    return;
  }
  st.vault.user_categories.push(name);
  persist();
  closeCategoryCreateModal();
  triggerRender();
  showToast(`Created "${name}"`, 'ok');
}

export function saveProjectCreate() {
  const nameEl = document.getElementById('project-create-name') as HTMLInputElement;
  const descEl = document.getElementById('project-create-desc') as HTMLInputElement;
  const slugEl = document.getElementById('project-create-slug') as HTMLInputElement | null;
  const trimmed = nameEl.value.trim();
  if (!trimmed) {
    showToast('Name is required', 'err');
    return;
  }

  const customSlug = slugEl?.value.trim() ?? '';
  if (customSlug) {
    const problem = validateSlug(customSlug, st.vault.projects);
    if (problem) {
      showToast(problem, 'err', 4000);
      return;
    }
  }
  // One place decides the id, and it is the same rule the CLI applies.
  const leafId = customSlug || slugifyProjectName(trimmed);
  if (!leafId) {
    showToast('Name produces an empty slug — set one explicitly', 'err', 4000);
    return;
  }
  if (st.vault.projects.find((p) => p.id === leafId)) {
    showToast('Project already exists', 'err');
    return;
  }

  const newProject: Project = {
    id: leafId,
    name: trimmed,
    description: descEl.value.trim() || undefined,
    project_type: _projectCreateType !== 'generic' ? _projectCreateType : undefined,
  };

  if (_projectCreateType === 'wireguard') {
    newProject.chunks = makeWgStarterChunks();
  } else if (_projectCreateType === 'docker') {
    newProject.chunks = makeDockerStarterChunks();
  } else if (_projectCreateType === 'nginx') {
    newProject.chunks = makeNginxStarterChunks();
  } else if (_projectCreateType === 'kubernetes') {
    newProject.chunks = makeK8sStarterChunks();
  } else if (_projectCreateType === 'ssh_config') {
    newProject.chunks = makeSshStarterChunks();
  } else if (_projectCreateType === 'traefik') {
    newProject.chunks = makeTraefikStarterChunks();
  } else if (_projectCreateType === 'apache') {
    newProject.chunks = makeApacheStarterChunks();
  } else if (_projectCreateType === 'haproxy') {
    newProject.chunks = makeHaproxyStarterChunks();
  } else if (_projectCreateType === 'ansible') {
    newProject.chunks = makeAnsibleStarterChunks();
  } else if (_projectCreateType === 'postgres') {
    newProject.chunks = makePostgresStarterChunks();
  }

  const nameParts = trimmed.split('/');
  for (let i = 1; i < nameParts.length; i++) {
    const ancestorName = nameParts.slice(0, i).join('/');
    const ancestorId = ancestorName
      .toLowerCase()
      .replace(/[^a-z0-9/]+/g, '-')
      .replace(/^-|-$/g, '');
    if (!st.vault.projects.find((p) => p.id === ancestorId)) {
      st.vault.projects.push({ id: ancestorId, name: ancestorName });
    }
  }
  st.vault.projects.push(newProject);
  persist();
  closeProjectCreateModal();
  triggerRender();
  showToast(`Created "${trimmed}"`, 'ok');
}

export function setProjectCreateType(type: ProjectType) {
  // `display:none` on the button is a paint-time gate, and the picker is static
  // markup driven by a delegated click handler — so a stale DOM, a keyboard
  // activation, or the setting being switched off with the modal already open
  // could still land here with a gated type. Creating a project is what writes
  // `project_type` into the vault, so refuse at the write, not just the paint.
  if (isExperimentalProjectType(type) && !Settings.get('experimentalProjectTypes')) {
    _projectCreateType = 'generic';
    applyExperimentalTypeVisibility();
    return;
  }
  _projectCreateType = type;
}
