/**
 * @file API Vault — application bootstrap.
 * All logic lives in the dedicated modules under src/.
 * This file wires everything together and registers event listeners.
 */

import { st, Settings, TauriVaultStore, LocalVaultStore, inTauri, setRenderFn, triggerRender, switchPanel, switchTool } from './state';
import { initIconPicker, openIconPicker, iconHTML } from './icons';
import {
  showToast, showConfirm, clipboardWrite,
} from './utils';
import { getFiltered, sorted } from './filters';
import {
  CustomSelect, DropdownItem, TYPE_CONFIG,
  showDropdown, showContextMenu,
  applySchemaTooltips, buildCatChips, dynamicSecretFields,
  openModal, openAdd, openEdit, closeModal, saveModal, duplicateKey, deleteKey, pushUndo,
  injectIntoForm, quickGenerate,
  toggleCard, toggleReveal, copyField, doCopyEnv, onIconWrapClick, openIconPickerFor,
} from './modals';
import {
  doSetFilter,
  openProjectCreateModal, closeProjectCreateModal, saveProjectCreate, setProjectCreateType,
  openCategoryCreateModal, closeCategoryCreateModal, saveCategoryCreate,
  deleteCategory, renameCategory, renameProject, deleteProject,
} from './projects';
import {
  copyAll, exportAs, handleFileSelect,
  openEnvImportModal, closeEnvImportModal, confirmEnvImport,
} from './import-export';
import { openSettings, saveSettings, closeSettings } from './settings-panel';
import { lockVault, resetLock, showUnlockModal, setFinishInitFn } from './lock';
import { initTools } from './tools';
import {
  render, renderGrid, updateCopyAllBtn, renderProjectTree,
} from './render';
import {
  openChunkEditModal, closeChunkEditModal, saveChunkEdit,
  renderChunkEditFields, readChunkEditFields,
} from './chunk-ops';
import type { ProjectType } from './types';

// Wire the global render callback so all modules can call triggerRender()
setRenderFn(render);
setFinishInitFn(finishInit);

/* ================================ BOOTSTRAP ================================ */

let searchDebounceTimer: ReturnType<typeof setTimeout>;

function debouncedSearch() {
  clearTimeout(searchDebounceTimer);
  searchDebounceTimer = setTimeout(() => { renderGrid(); updateCopyAllBtn(); }, 150);
}

async function finishInit() {
  try {
    const r = await fetch('./schema.json');
    if (r.ok) st.schema = await r.json();
  } catch {}

  try {
    const data = await st.store.load();
    if (data) {
      st.vault.api_keys        = data.api_keys;
      st.vault.user_categories = data.user_categories || [];
      st.vault.projects        = data.projects || [{ id: 'Universal', name: 'Universal', description: '' }];

      if (!st.vault.projects.find(p => p.id === 'Universal')) {
        st.vault.projects.unshift({ id: 'Universal', name: 'Universal', description: '' });
      }

      let needsSave = false;
      for (const key of st.vault.api_keys) {
        if (!key.projectIds)                          { key.projectIds = ['Universal']; needsSave = true; }
        else if (!key.projectIds.includes('Universal')){ key.projectIds.push('Universal'); needsSave = true; }
        if (!key.secretType)                          { key.secretType = 'api_key';   needsSave = true; }
      }
      if (needsSave) await st.store.save(st.vault);

      document.getElementById('load-banner')!.style.display = 'none';
      showToast(`Loaded ${st.vault.api_keys.length} keys`, 'ok', 1800);
    } else {
      document.getElementById('load-banner')!.style.display = 'flex';
    }
  } catch { document.getElementById('load-banner')!.style.display = 'flex'; }

  render();
  resetLock();
  initTools();
}

async function init() {
  await Settings.init();
  initIconPicker();

  // Wrap form selects as custom dropdowns (WebKitGTK compositing workaround)
  ['f-secret-type', 'f-price', 'f-env'].forEach(id => {
    const el = document.getElementById(id) as HTMLSelectElement | null;
    if (el) st.formCustomSelects.set(id, new CustomSelect(el));
  });

  st.store = inTauri ? new TauriVaultStore() : new LocalVaultStore();

  // File picker (dynamic input — WebKitGTK ghost widget workaround)
  const openFilePicker = (accept: string) => {
    const inp = document.createElement('input');
    inp.type = 'file'; inp.accept = accept;
    document.body.appendChild(inp);
    let done = false;
    const cleanup = () => { if (done) return; done = true; if (document.body.contains(inp)) document.body.removeChild(inp); };
    inp.addEventListener('change', function () { handleFileSelect(this); this.value = ''; cleanup(); }, { once: true });
    inp.addEventListener('cancel', cleanup, { once: true });
    inp.click();
    setTimeout(() => window.addEventListener('focus', cleanup, { once: true }), 300);
  };

  document.getElementById('load-banner-browse-btn')?.addEventListener('click', () => openFilePicker('.json,.env,text/plain'));

  // Sidebar — filter buttons
  document.getElementById('sidebar')!.addEventListener('click', (e) => {
    const btn = (e.target as HTMLElement).closest<HTMLButtonElement>('.sidebar-item');
    if (!btn) return;
    const filterType  = btn.dataset.filterType;
    const filterValue = btn.dataset.filterValue;
    if (filterType && filterValue !== undefined) {
      if (filterType === 'all') st.currentSelectedProjectIds = ['Universal'];
      doSetFilter(filterType, filterValue);
    }
  });

  // Categories section: rename/delete tags
  document.getElementById('project-tree')!.addEventListener('click', (e) => {
    const target = e.target as HTMLElement;
    const renameBtn = target.closest<HTMLElement>('.rename-cat');
    if (renameBtn?.dataset.category) { renameCategory(renameBtn.dataset.category); return; }
    const deleteBtn = target.closest<HTMLElement>('.delete-cat');
    if (deleteBtn?.dataset.category) { deleteCategory(deleteBtn.dataset.category); return; }
  });

  // Projects section: selection, rename, delete
  document.getElementById('category-list')!.addEventListener('click', (e) => {
    const target = e.target as HTMLElement;
    const projBtn = target.closest<HTMLButtonElement>('[data-project-id]');
    if (projBtn?.dataset.projectId) {
      const id = projBtn.dataset.projectId!;
      st.currentSelectedProjectIds = (st.currentSelectedProjectIds[0] === id) ? ['Universal'] : [id];
      render(); return;
    }
    const renameBtn = target.closest<HTMLElement>('.rename-proj');
    if (renameBtn?.dataset.project) { renameProject(renameBtn.dataset.project); return; }
    const deleteBtn = target.closest<HTMLElement>('.delete-proj');
    if (deleteBtn?.dataset.project) { deleteProject(deleteBtn.dataset.project); return; }
  });

  // Search
  const searchEl      = document.getElementById('search') as HTMLInputElement;
  const searchClearBtn = document.getElementById('search-clear')!;
  searchEl.addEventListener('input', (e) => {
    st.searchQ = (e.target as HTMLInputElement).value;
    st.searchQ ? searchClearBtn.classList.add('visible') : searchClearBtn.classList.remove('visible');
    debouncedSearch();
  });
  searchClearBtn.addEventListener('click', () => {
    st.searchQ = '';
    searchEl.value = '';
    searchClearBtn.classList.remove('visible');
    renderGrid(); updateCopyAllBtn();
  });

  // Sort dropdown
  document.getElementById('sort-btn')?.addEventListener('click', (e) => {
    const opts = [
      { value: 'provider', label: 'A – Z' },
      { value: 'price',    label: 'Price Type' },
      { value: 'category', label: 'Category' },
      { value: 'expiry',   label: 'Expiry' },
    ];
    showDropdown(e.currentTarget as HTMLElement, opts.map(opt => ({
      label: (opt.value === st.currentSortBy ? '✓ ' : '    ') + opt.label,
      active: opt.value === st.currentSortBy,
      fn: () => {
        st.currentSortBy = opt.value;
        const labelEl = document.getElementById('sort-label-text');
        if (labelEl) labelEl.textContent = opt.label;
        renderGrid();
      },
    })));
  });

  // Expand all
  document.getElementById('expand-all-btn')!.addEventListener('click', function () {
    st.allExpanded = !st.allExpanded;
    this.textContent = st.allExpanded ? 'Collapse All' : 'Expand All';
    if (st.allExpanded) st.vault.api_keys.forEach((_, i) => st.expanded.add(i));
    else st.expanded.clear();
    renderGrid();
  });

  // Sidebar toggle + add button
  document.getElementById('sidebar-toggle')!.addEventListener('click', () => document.getElementById('sidebar')?.classList.toggle('collapsed'));
  document.getElementById('add-btn')!.addEventListener('click', openAdd);

  // Entry modal buttons
  document.getElementById('modal-close')!.addEventListener('click', closeModal);
  document.getElementById('modal-cancel')!.addEventListener('click', closeModal);
  document.getElementById('modal-save')!.addEventListener('click', saveModal);
  document.getElementById('modal-duplicate')!.addEventListener('click', () => {
    const idx = parseInt((document.getElementById('edit-index') as HTMLInputElement).value);
    if (idx >= 0) duplicateKey(new Event('click'), idx);
    closeModal();
  });

  // Icon picker (inside entry modal)
  document.getElementById('f-icon-pick')!.addEventListener('click', () =>
    openIconPicker(document.getElementById('f-icon') as HTMLInputElement, document.getElementById('f-icon-preview') as HTMLElement)
  );
  document.getElementById('f-icon')!.addEventListener('input', (e) => {
    const prev = document.getElementById('f-icon-preview')!;
    prev.innerHTML = (e.target as HTMLInputElement).value ? iconHTML('', (e.target as HTMLInputElement).value) : '';
  });

  // Settings panel
  document.getElementById('settings-btn')!.addEventListener('click', openSettings);
  document.getElementById('settings-close')!.addEventListener('click', () => { saveSettings(); closeSettings(); });
  document.getElementById('settings-overlay')!.addEventListener('click', (e) => { if (e.target === e.currentTarget) { saveSettings(); closeSettings(); } });
  document.getElementById('settings-export-btn')!.addEventListener('click', () => {
    const url = URL.createObjectURL(new Blob([JSON.stringify(Settings.getAll(), null, 2)], { type: 'application/json' }));
    const a = Object.assign(document.createElement('a'), { href: url, download: 'settings.json' });
    document.body.appendChild(a); a.click(); document.body.removeChild(a);
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  });

  // Segmented controls (card size, grid columns, activity bar)
  document.querySelectorAll('.seg-control').forEach(ctrl => ctrl.addEventListener('click', (e) => {
    const btn = (e.target as HTMLElement).closest('button[data-val]') as HTMLButtonElement | null;
    if (!btn) return;
    ctrl.querySelectorAll('button').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    const key = ctrl.id === 's-card-size' ? 'cardSize'
      : ctrl.id === 's-grid-cols' ? 'gridColumns'
      : ctrl.id === 's-activity-bar-position' ? 'activityBarPosition'
      : 'activityBarStyle';
    Settings.set(key as any, btn.dataset.val as any);
    Settings._apply(); render();
  }));

  // Accent color
  document.getElementById('s-accent')!.addEventListener('input', (e) => {
    const v = (e.target as HTMLInputElement).value;
    document.getElementById('s-accent-val')!.textContent = v;
    Settings.set('accentColor', v); Settings._apply();
  });
  document.getElementById('s-accent-reset')!.addEventListener('click', () => {
    const def = '#7364c9';
    (document.getElementById('s-accent') as HTMLInputElement).value = def;
    document.getElementById('s-accent-val')!.textContent = def;
    Settings.set('accentColor', def); Settings._apply();
  });

  // Copy-All
  document.getElementById('copy-all-arrow')!.addEventListener('click', (e) => showDropdown(e.currentTarget as HTMLElement, [
    { label: 'Copy .env',  fn: () => copyAll('dotenv') },
    { label: 'Copy YAML',  fn: () => copyAll('yaml') },
    { label: 'Copy JSON',  fn: () => copyAll('json') },
  ]));
  document.getElementById('copy-all-btn')!.addEventListener('click', () => copyAll(Settings.get('defaultExportFormat')));

  // Env import modal
  document.getElementById('env-import-close')?.addEventListener('click', closeEnvImportModal);
  document.getElementById('env-import-cancel')?.addEventListener('click', closeEnvImportModal);
  document.getElementById('env-import-confirm')?.addEventListener('click', confirmEnvImport);
  document.getElementById('env-import-select-all')?.addEventListener('click', () =>
    document.querySelectorAll<HTMLInputElement>('.env-import-check').forEach(cb => cb.checked = true));
  document.getElementById('env-import-select-none')?.addEventListener('click', () =>
    document.querySelectorAll<HTMLInputElement>('.env-import-check').forEach(cb => cb.checked = false));
  document.getElementById('env-import-overlay')?.addEventListener('click', (e) => { if (e.target === e.currentTarget) closeEnvImportModal(); });

  // Data import/export
  document.getElementById('settings-import-btn')?.addEventListener('click', () => openFilePicker('.json,.env,text/plain'));
  document.getElementById('settings-export-dotenv')?.addEventListener('click', () => exportAs('dotenv'));
  document.getElementById('settings-export-yaml')?.addEventListener('click', () => exportAs('yaml'));
  document.getElementById('settings-export-json')?.addEventListener('click', () => exportAs('json'));

  // Category create modal
  document.getElementById('new-category-root-btn')?.addEventListener('click', openCategoryCreateModal);
  document.getElementById('category-create-close')?.addEventListener('click', closeCategoryCreateModal);
  document.getElementById('category-create-cancel')?.addEventListener('click', closeCategoryCreateModal);
  document.getElementById('category-create-save')?.addEventListener('click', saveCategoryCreate);
  document.getElementById('category-create-overlay')?.addEventListener('click', (e) => { if (e.target === e.currentTarget) closeCategoryCreateModal(); });
  document.getElementById('category-create-name')?.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') saveCategoryCreate();
    if (e.key === 'Escape') closeCategoryCreateModal();
  });

  // Project create modal
  document.getElementById('new-category-btn')!.addEventListener('click', openProjectCreateModal);
  document.getElementById('project-create-close')?.addEventListener('click', closeProjectCreateModal);
  document.getElementById('project-create-cancel')?.addEventListener('click', closeProjectCreateModal);
  document.getElementById('project-create-save')?.addEventListener('click', saveProjectCreate);
  document.getElementById('project-create-overlay')?.addEventListener('click', (e) => { if (e.target === e.currentTarget) closeProjectCreateModal(); });
  document.getElementById('project-create-name')?.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') saveProjectCreate();
    if (e.key === 'Escape') closeProjectCreateModal();
  });
  document.querySelectorAll<HTMLButtonElement>('.project-type-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll<HTMLButtonElement>('.project-type-btn').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      setProjectCreateType((btn.dataset.ptype || 'generic') as ProjectType);
    });
  });

  // Chunk edit modal
  document.getElementById('chunk-edit-close')?.addEventListener('click', closeChunkEditModal);
  document.getElementById('chunk-edit-cancel')?.addEventListener('click', closeChunkEditModal);
  document.getElementById('chunk-edit-save')?.addEventListener('click', saveChunkEdit);
  document.getElementById('chunk-edit-overlay')?.addEventListener('click', (e) => { if (e.target === e.currentTarget) closeChunkEditModal(); });
  document.getElementById('chunk-edit-add-field')?.addEventListener('click', () => {
    const current = readChunkEditFields();
    current.push({ key: '', value: '', field_type: 'var' });
    renderChunkEditFields(current);
  });

  // Lock
  document.getElementById('lock-btn')!.addEventListener('click', async () => { if (await showConfirm('Lock vault?')) lockVault(); });

  // Undo bar
  document.getElementById('undo-btn')!.addEventListener('click', () => {
    const last = st.undoStack.pop();
    if (last) { last.fn(); document.getElementById('undo-bar')!.classList.remove('visible'); }
  });

  // Keyboard shortcuts overlay
  const shortcutsEl = document.getElementById('shortcuts-overlay')!;
  document.getElementById('shortcuts-btn')!.addEventListener('click', () => shortcutsEl.classList.add('open'));
  document.getElementById('shortcuts-close')!.addEventListener('click', () => shortcutsEl.classList.remove('open'));
  shortcutsEl.addEventListener('click', (e) => { if (e.target === e.currentTarget) shortcutsEl.classList.remove('open'); });

  // Global keyboard shortcuts
  document.addEventListener('keydown', (e) => {
    const inInput = ['INPUT', 'SELECT', 'TEXTAREA'].includes((document.activeElement as HTMLElement)?.tagName);
    if ((e.ctrlKey || e.metaKey) && e.key === 'k') { e.preventDefault(); (document.getElementById('search') as HTMLInputElement).focus(); (document.getElementById('search') as HTMLInputElement).select(); return; }
    if ((e.ctrlKey || e.metaKey) && e.key === 'n') { e.preventDefault(); openAdd(); return; }
    if (!inInput && e.key === 's') openSettings();
    if (!inInput && e.key === 'b') document.getElementById('sidebar-toggle')!.click();
    if (!inInput && e.key === '?') shortcutsEl.classList.add('open');
    if (e.key === 'Escape') {
      shortcutsEl.classList.remove('open');
      closeSettings(); closeModal();
      if (st.searchQ) { st.searchQ = ''; (document.getElementById('search') as HTMLInputElement).value = ''; renderGrid(); }
    }
  });

  // Card grid — delegated click
  document.getElementById('card-grid')!.addEventListener('click', (e) => {
    const el = (e.target as HTMLElement).closest('[data-action]') as HTMLElement | null;
    if (!el) return;
    const action = el.dataset.action!;
    const idx    = el.dataset.idx !== undefined ? parseInt(el.dataset.idx!) : -1;
    const value  = el.dataset.value ?? '';
    const field  = el.dataset.field ?? '';
    if (action === 'copy-env' && el.classList.contains('card-head') && (e.target as HTMLElement).closest('[data-action]') !== el) return;
    e.stopPropagation();
    switch (action) {
      case 'toggle':      toggleCard(e, idx); break;
      case 'reveal':      toggleReveal(e, field, idx, value); break;
      case 'copy-field':  copyField(e, value, el); break;
      case 'copy-env':    doCopyEnv(e, idx); break;
      case 'duplicate':   duplicateKey(e, idx); break;
      case 'edit':        openEdit(e, idx); break;
      case 'delete':      deleteKey(e, idx); break;
      case 'icon':        onIconWrapClick(e, idx); break;
      case 'toggle-desc': el.classList.toggle('open'); (el.nextElementSibling as HTMLElement)?.classList.toggle('open'); break;
    }
  });

  // Card grid — double-click to edit
  document.getElementById('card-grid')!.addEventListener('dblclick', (e) => {
    const card = (e.target as HTMLElement).closest<HTMLElement>('[data-idx]');
    if (!card) return;
    const idx = parseInt(card.dataset.idx!);
    if (!isNaN(idx)) openEdit(e as MouseEvent, idx);
  });

  // Card grid — right-click context menu
  document.getElementById('card-grid')!.addEventListener('contextmenu', (e) => {
    const card = (e.target as HTMLElement).closest<HTMLElement>('[data-idx]');
    if (!card) return;
    e.preventDefault();
    const idx = parseInt(card.dataset.idx!);
    if (isNaN(idx)) return;
    const entry = st.vault.api_keys[idx];
    if (!entry) return;
    const _keyLabel = TYPE_CONFIG[entry.secretType || 'api_key']?.keyLabel || 'Key';
    const _items: Array<DropdownItem | '---'> = [
      { label: 'Copy Provider',         fn: () => clipboardWrite(entry.provider).then(() => showToast('Copied ✓', 'ok', 1500)) },
      { label: `Copy ${_keyLabel}`,     fn: () => copyField(e as MouseEvent, entry.api_key, card) },
    ];
    if (entry.api_secret) _items.push({ label: 'Copy Secret', fn: () => copyField(e as MouseEvent, entry.api_secret!, card) });
    _items.push(
      { label: 'Copy .env line', fn: () => doCopyEnv(e as MouseEvent, idx) },
      '---',
      { label: 'Edit',      fn: () => openEdit(e as MouseEvent, idx) },
      { label: 'Duplicate', fn: () => duplicateKey(e as MouseEvent, idx) },
      '---',
      { label: 'Delete',    fn: () => deleteKey(e as MouseEvent, idx) },
    );
    showContextMenu(e.clientX, e.clientY, _items);
  });

  // Misc
  document.getElementById('vault-switcher')!.addEventListener('click', () => showToast('Multi-vault support coming in v2', '', 3000));
  document.getElementById('f-secret-type')?.addEventListener('change', dynamicSecretFields);
  document.getElementById('f-key-generate')?.addEventListener('click', () => quickGenerate());

  // ── Tauri unlock flow ──
  if (inTauri) {
    (st.store as TauriVaultStore).vaultFilePath().then(p => {
      const el = document.getElementById('lock-status');
      if (el && p) el.title = `Vault file: ${p}`;
    });
    document.getElementById('vault-name')!.textContent = 'Local Vault';
    const exists = await (st.store as TauriVaultStore).exists();
    await showUnlockModal(!exists);
    return;
  }

  // Web path
  await finishInit();
}

init();
