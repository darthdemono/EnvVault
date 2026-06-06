/**
 * @file Project and category CRUD operations.
 */

import type { Project, ProjectType } from './types';
import { st, triggerRender } from './state';
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
  st.filter = (st.filter.type === type && st.filter.value === value) ? { type: 'all', value: '' } : { type, value };
  triggerRender();
}

// ── Category operations ───────────────────────────────────────────────────

export async function deleteCategory(name: string) {
  if (!await showConfirm(`Delete category "${name}"?`)) return;
  st.vault.user_categories = st.vault.user_categories.filter(c => c !== name);
  st.vault.api_keys.forEach(k => { if (k.categories) k.categories = k.categories.filter(c => c !== name); });
  if (st.filter.type === 'category' && st.filter.value === name) st.filter = { type: 'all', value: '' };
  st.store.save(st.vault);
  triggerRender();
}

export async function renameCategory(name: string) {
  const next = (await showPrompt('Rename category:', name))?.trim();
  if (!next || next === name) return;
  if (st.vault.user_categories.includes(next)) { showToast(`Category "${next}" already exists`, 'err'); return; }
  st.vault.user_categories = st.vault.user_categories.map(c => c === name ? next : c);
  st.vault.api_keys.forEach(k => { if (k.categories) k.categories = k.categories.map(c => c === name ? next : c); });
  if (st.filter.type === 'category' && st.filter.value === name) st.filter = { type: 'category', value: next };
  st.store.save(st.vault);
  triggerRender();
}

// ── Project operations ────────────────────────────────────────────────────

export async function renameProject(id: string) {
  const project = st.vault.projects.find(p => p.id === id);
  if (!project) return;
  const newName = (await showPrompt(`Rename "${project.name}" to:`, project.name))?.trim();
  if (!newName || newName === project.name) return;
  const newId = newName.toLowerCase().replace(/[^a-z0-9/]+/g, '-').replace(/^-|-$/g, '');
  if (newId !== id && st.vault.projects.find(p => p.id === newId)) { showToast('Project already exists', 'err'); return; }
  project.id = newId;
  project.name = newName;
  st.vault.api_keys.forEach(k => {
    if (k.projectIds?.includes(id)) k.projectIds = k.projectIds.map(pid => pid === id ? newId : pid);
  });
  if (st.currentSelectedProjectIds[0] === id) st.currentSelectedProjectIds = [newId];
  st.store.save(st.vault);
  triggerRender();
  showToast(`Renamed to "${newName}"`, 'ok');
}

export async function deleteProject(id: string) {
  if (id === 'Universal') return;
  const project = st.vault.projects.find(p => p.id === id);
  if (!project) return;
  const children = st.vault.projects.filter(p => p.name.startsWith(project.name + '/'));
  let msg = `Delete project "${project.name}"?`;
  if (children.length) msg += ` ${children.length} sub-project${children.length === 1 ? '' : 's'} will be promoted to top level.`;
  if (!await showConfirm(msg)) return;
  st.vault.api_keys.forEach(k => {
    if (k.projectIds?.includes(id)) {
      k.projectIds = k.projectIds.filter(pid => pid !== id);
      if (!k.projectIds.length) k.projectIds = ['Universal'];
    }
  });
  st.vault.projects = st.vault.projects.filter(p => p.id !== id);
  for (const child of children) {
    const newName = child.name.slice(project.name.length + 1);
    const newId = newName.toLowerCase().replace(/[^a-z0-9/]+/g, '-').replace(/^-|-$/g, '');
    let fid = newId; let n = 1;
    while (st.vault.projects.find(p => p.id === fid)) fid = `${newId}-${n++}`;
    child.id = fid; child.name = newName;
  }
  st.vault.api_keys.forEach(k => {
    if (k.projectIds) {
      k.projectIds = k.projectIds.filter(pid => st.vault.projects.some(p => p.id === pid));
      if (!k.projectIds.length) k.projectIds = ['Universal'];
    }
  });
  if (st.currentSelectedProjectIds[0] === id) st.currentSelectedProjectIds = ['Universal'];
  st.store.save(st.vault);
  triggerRender();
  showToast(`Project "${project.name}" deleted`, 'ok');
}

// ── Project create modal ──────────────────────────────────────────────────

let _projectCreateType: ProjectType = 'generic';

export function openProjectCreateModal() {
  _projectCreateType = 'generic';
  const overlay = document.getElementById('project-create-overlay')!;
  const nameEl = document.getElementById('project-create-name') as HTMLInputElement;
  const descEl = document.getElementById('project-create-desc') as HTMLInputElement;
  nameEl.value = '';
  descEl.value = '';
  document.querySelectorAll<HTMLButtonElement>('.project-type-btn').forEach(btn => {
    btn.classList.toggle('active', btn.dataset.ptype === 'generic');
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
  if (!name) { showToast('Name is required', 'err'); return; }
  if (st.vault.user_categories.includes(name)) { showToast('Category already exists', 'err'); return; }
  st.vault.user_categories.push(name);
  st.store.save(st.vault);
  closeCategoryCreateModal();
  triggerRender();
  showToast(`Created "${name}"`, 'ok');
}

export function saveProjectCreate() {
  const nameEl = document.getElementById('project-create-name') as HTMLInputElement;
  const descEl = document.getElementById('project-create-desc') as HTMLInputElement;
  const trimmed = nameEl.value.trim();
  if (!trimmed) { showToast('Name is required', 'err'); return; }
  const leafId = trimmed.toLowerCase().replace(/[^a-z0-9/]+/g, '-').replace(/^-|-$/g, '');
  if (st.vault.projects.find(p => p.id === leafId)) { showToast('Project already exists', 'err'); return; }

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
    const ancestorId = ancestorName.toLowerCase().replace(/[^a-z0-9/]+/g, '-').replace(/^-|-$/g, '');
    if (!st.vault.projects.find(p => p.id === ancestorId)) {
      st.vault.projects.push({ id: ancestorId, name: ancestorName });
    }
  }
  st.vault.projects.push(newProject);
  st.store.save(st.vault);
  closeProjectCreateModal();
  triggerRender();
  showToast(`Created "${trimmed}"`, 'ok');
}

export function setProjectCreateType(type: ProjectType) {
  _projectCreateType = type;
}
