/**
 * @file Chunk edit modal — add, rename, retype and reorder the fields of a
 *       single config chunk.
 */

import type { Project, SecretChunk, ChunkField, ChunkFieldType } from '../types';
import { st, triggerRender, persist } from '../state';
import { esc, escAttr, showToast, delSVG } from '../utils';
// ── Chunk edit modal ───────────────────────────────────────────────────────

export function openChunkEditModal(project: Project, chunk: SecretChunk) {
  const overlay = document.getElementById('chunk-edit-overlay')!;
  (document.getElementById('chunk-edit-name') as HTMLInputElement).value = chunk.name;
  (document.getElementById('chunk-edit-notes') as HTMLInputElement).value = chunk.notes || '';
  (document.getElementById('chunk-edit-disabled') as HTMLInputElement).checked = !!chunk.disabled;
  (document.getElementById('chunk-edit-project-id') as HTMLInputElement).value = project.id;
  (document.getElementById('chunk-edit-chunk-id') as HTMLInputElement).value = chunk.id;
  renderChunkEditFields(chunk.fields);
  overlay.classList.add('open');
}

export function closeChunkEditModal() {
  document.getElementById('chunk-edit-overlay')!.classList.remove('open');
}

export function renderChunkEditFields(fields: ChunkField[]) {
  const container = document.getElementById('chunk-edit-fields')!;
  container.innerHTML = '';
  fields.forEach((field, i) => {
    const row = document.createElement('div');
    row.className = 'chunk-edit-row';
    row.dataset.idx = String(i);
    if (field.description) row.dataset.description = field.description;
    row.innerHTML = `
      <input class="form-input mono chunk-field-key-input" placeholder="Key" value="${escAttr(field.key)}" style="flex:0 0 140px">
      <input class="form-input mono chunk-field-val-input" placeholder="Value or \${REF}" value="${escAttr(field.value)}" style="flex:1">
      <select class="form-input chunk-field-type-select" style="flex:0 0 110px">
        <option value="var"${field.field_type === 'var' ? ' selected' : ''}>var</option>
        <option value="env_var"${field.field_type === 'env_var' ? ' selected' : ''}>env_var</option>
        <option value="secret"${field.field_type === 'secret' ? ' selected' : ''}>secret</option>
        <option value="list"${field.field_type === 'list' ? ' selected' : ''}>list</option>
        <option value="multiline"${field.field_type === 'multiline' ? ' selected' : ''}>multiline</option>
        <option value="port"${field.field_type === 'port' ? ' selected' : ''}>port</option>
        <option value="user_id"${field.field_type === 'user_id' ? ' selected' : ''}>user_id</option>
        <option value="subnet"${field.field_type === 'subnet' ? ' selected' : ''}>subnet</option>
        <option value="ip"${field.field_type === 'ip' ? ' selected' : ''}>ip</option>
        <option value="endpoint"${field.field_type === 'endpoint' ? ' selected' : ''}>endpoint</option>
        <option value="volume_mount"${field.field_type === 'volume_mount' ? ' selected' : ''}>volume_mount</option>
        <option value="cert"${field.field_type === 'cert' ? ' selected' : ''}>cert</option>
      </select>
      <button class="icon-btn sm danger chunk-field-delete" data-idx="${i}" title="Remove field">${delSVG}</button>
    `;
    container.appendChild(row);
  });

  container.querySelectorAll<HTMLButtonElement>('.chunk-field-delete').forEach(btn => {
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      const idx = parseInt(btn.dataset.idx!);
      const currentFields = readChunkEditFields();
      currentFields.splice(idx, 1);
      renderChunkEditFields(currentFields);
    });
  });
}

export function readChunkEditFields(): ChunkField[] {
  const rows = document.querySelectorAll<HTMLElement>('#chunk-edit-fields .chunk-edit-row');
  return Array.from(rows).map(row => {
    const ft = (row.querySelector('.chunk-field-type-select') as HTMLSelectElement).value as ChunkFieldType;
    const field: ChunkField = {
      key:        (row.querySelector('.chunk-field-key-input') as HTMLInputElement).value.trim(),
      value:      (row.querySelector('.chunk-field-val-input') as HTMLInputElement).value,
      field_type: ft,
      secret:     ft === 'secret',
    };
    if (row.dataset.description) field.description = row.dataset.description;
    return field;
  });
}

export function saveChunkEdit() {
  const projId = (document.getElementById('chunk-edit-project-id') as HTMLInputElement).value;
  const chunkId = (document.getElementById('chunk-edit-chunk-id') as HTMLInputElement).value;
  const name = (document.getElementById('chunk-edit-name') as HTMLInputElement).value.trim();
  if (!name) { showToast('Chunk name is required', 'err'); return; }
  const project = st.vault.projects.find(p => p.id === projId);
  if (!project || !project.chunks) return;
  const chunk = project.chunks.find(c => c.id === chunkId);
  if (!chunk) return;
  chunk.name = name;
  chunk.notes = (document.getElementById('chunk-edit-notes') as HTMLInputElement).value.trim() || undefined;
  chunk.disabled = (document.getElementById('chunk-edit-disabled') as HTMLInputElement).checked || undefined;
  chunk.fields = readChunkEditFields();
  persist();
  closeChunkEditModal();
  triggerRender();
  showToast('Chunk saved', 'ok');
}

