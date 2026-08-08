/**
 * @file EnvVault — application bootstrap.
 * All logic lives in the dedicated modules under src/.
 * This file wires everything together and registers event listeners.
 */

import { st, Settings, TauriVaultStore, LocalVaultStore, RemoteVaultStore, inTauri, setRenderFn, triggerRender, switchPanel, switchTool, persist, entryId, ensureEntryIds, applyUsersPanelVisibility, applySidebarLayout, restoreViewState, clearAllFilters, SIDEBAR_MIN_W, SIDEBAR_MAX_W } from './state';
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
  markAsRotated,
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
  exportK8sSecret, exportTfvars, exportEncryptedBackup, importEncryptedBackup,
} from './import-export';
import { openSettings, saveSettings, closeSettings, cancelSettings } from './settings-panel';
import { lockVault, resetLock, showUnlockModal, setFinishInitFn } from './lock';
import { initTools } from './tools';
import { mountToolsPanes } from './tools-markup';
import { initUsersPanel, renderUsersPanel } from './users';
import { initRemotePanel, setRemoteFinishInitFn, renderRemotePanel, switchToLocalVault } from './remote-panel';
import { initLanPanel } from './lan';
import {
  render, renderGrid, updateCopyAllBtn, renderProjectTree,
  openEnvLinkModal, closeEnvLinkModal, applyEnvLink,
} from './render';
import {
  openChunkEditModal, closeChunkEditModal, saveChunkEdit,
  renderChunkEditFields, readChunkEditFields,
} from './chunk-ops';
import { wireSearchHistory, closeSearchHistory, wireCloseGuard } from './ui-qol';
import type { ProjectType } from './types';

// Wire the global render callback so all modules can call triggerRender()
setRenderFn(render);
setFinishInitFn(finishInit);

/* ================================ BOOTSTRAP ================================ */

/** Grid sort modes. Module-level so the persisted value can be validated against it. */
const SORT_OPTIONS = [
  { value: 'provider', label: 'A – Z' },
  { value: 'price',    label: 'Price Type' },
  { value: 'category', label: 'Category' },
  { value: 'expiry',   label: 'Expiry' },
];

/**
 * Applies the persisted sort mode and syncs the toolbar label to it.
 *
 * The stored value is checked against SORT_OPTIONS rather than trusted: an
 * unrecognised mode falls through every branch of `sorted()` and leaves the
 * grid in insertion order while the button claims otherwise.
 */
function restoreSort(): void {
  const saved = Settings.get('lastSortBy');
  const opt = SORT_OPTIONS.find(o => o.value === saved);
  if (!opt) return;
  st.currentSortBy = opt.value;
  const labelEl = document.getElementById('sort-label-text');
  if (labelEl) labelEl.textContent = opt.label;
}

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
      const remoteEmpty = !data.api_keys?.length;
      const localHasData = st.vault.api_keys.length > 0;

      // Remote vault empty but in-memory vault has data: offer to push before overwriting.
      if (remoteEmpty && localHasData && st.store.isRemote) {
        const push = await showConfirm(
          `Remote vault is empty — push your ${st.vault.api_keys.length} local entries to it?`
        );
        if (push) {
          await persist();
          showToast(`Pushed ${st.vault.api_keys.length} entries to remote ✓`, 'ok', 2500);
          // Keep existing st.vault — do not overwrite with empty remote data.
        } else {
          st.vault.api_keys        = [];
          st.vault.user_categories = [];
          st.vault.projects        = [{ id: 'Universal', name: 'Universal', description: '' }];
        }
      } else {
        // `|| []` on all three: a vault blob written by an older build (or an
        // edited backup) can be missing a key entirely, and an undefined
        // api_keys threw on the very next line that iterates it.
        st.vault.api_keys        = data.api_keys || [];
        st.vault.user_categories = data.user_categories || [];
        st.vault.projects        = data.projects || [{ id: 'Universal', name: 'Universal', description: '' }];
      }

      if (!st.vault.projects.find(p => p.id === 'Universal')) {
        st.vault.projects.unshift({ id: 'Universal', name: 'Universal', description: '' });
      }

      let needsSave = false;
      for (const key of st.vault.api_keys) {
        if (!key.projectIds)                          { key.projectIds = ['Universal']; needsSave = true; }
        else if (!key.projectIds.includes('Universal')){ key.projectIds.push('Universal'); needsSave = true; }
        if (!key.secretType)                          { key.secretType = 'api_key';   needsSave = true; }
        // The 'chunk' secret type has been removed — it could never be saved
        // through the UI anyway (its key field was hidden but still required).
        // Its content lived in extra_vars, which the normal card renders too, so
        // relabelling loses nothing.
        if ((key.secretType as string) === 'chunk')   { key.secretType = 'env_var';   needsSave = true; }
      }
      // Backfill stable ids for vaults written before the field existed, and
      // repair any duplicates. Runs once; afterwards every entry carries an id.
      if (ensureEntryIds(st.vault.api_keys)) needsSave = true;
      if (needsSave) await persist();

      document.getElementById('load-banner')!.style.display = 'none';
      st.vaultOpen = true;
      showToast(`Loaded ${st.vault.api_keys.length} keys`, 'ok', 1800);
    } else {
      document.getElementById('load-banner')!.style.display = 'flex';
    }
  } catch { document.getElementById('load-banner')!.style.display = 'flex'; }

  // Restore the last grid view *before* the first render, so the app paints once
  // in its final state instead of flashing the unfiltered grid. restoreViewState
  // drops any id the loaded vault does not have — see its doc comment.
  restoreViewState();

  render();
  resetLock();
  initTools();
  initUsersPanel();
  applyUsersPanelVisibility();
  initRemotePanel();
  initLanPanel();
  setRemoteFinishInitFn(finishInit);
}

async function init() {
  // Must run before anything queries the tools DOM: the tool panes live in
  // tools-markup.ts and are injected here, not present in index.html.
  mountToolsPanes();

  await Settings.init();
  applySidebarLayout();
  restoreSort();
  initIconPicker();
  wireSearchHistory((q) => {
    // Store the query exactly as typed — parseSearch() lowercases what it needs
    // to, and pre-lowercasing here would both diverge from the input handler and
    // display a mangled query in the active-filter tooltip.
    const el = document.getElementById('search') as HTMLInputElement;
    el.value = q;
    st.searchQ = q;
    document.getElementById('search-clear')?.classList.add('visible');
    renderGrid(); updateCopyAllBtn();
  });
  wireCloseGuard();

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
    // Tag filter button
    if (btn.classList.contains('tag-filter-btn')) {
      const tag = btn.dataset.tag ?? '';
      st.activeTagFilter = (st.activeTagFilter === tag) ? null : tag;
      triggerRender();
      return;
    }
    // Env-prefix filter button
    if (btn.classList.contains('prefix-filter-btn')) {
      const pfx = btn.dataset.prefix ?? '';
      st.activePrefixFilter = (st.activePrefixFilter === pfx) ? null : pfx;
      triggerRender();
      return;
    }
    const filterType  = btn.dataset.filterType;
    const filterValue = btn.dataset.filterValue;
    if (filterType && filterValue !== undefined) {
      if (filterType === 'env') {
        st.currentEnvFilter = (st.currentEnvFilter === filterValue) ? '' : filterValue;
        triggerRender();
      } else {
        if (filterType === 'all') {
          st.currentSelectedProjectIds = ['Universal'];
          st.currentEnvFilter = '';
          st.activeTagFilter = null;
          // The prefix filter was added after this reset was written and never
          // added to it, so "All" left the grid narrowed with nothing in the
          // sidebar looking active to explain why.
          st.activePrefixFilter = null;
        }
        doSetFilter(filterType, filterValue);
      }
    }
  });

  // Categories section: rename/delete tags
  document.getElementById('category-tree')!.addEventListener('click', (e) => {
    const target = e.target as HTMLElement;
    const renameBtn = target.closest<HTMLElement>('.rename-cat');
    if (renameBtn?.dataset.category) { renameCategory(renameBtn.dataset.category); return; }
    const deleteBtn = target.closest<HTMLElement>('.delete-cat');
    if (deleteBtn?.dataset.category) { deleteCategory(deleteBtn.dataset.category); return; }
  });

  // Projects section: selection, rename, delete
  document.getElementById('project-list')!.addEventListener('click', (e) => {
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
    const opts = SORT_OPTIONS;
    showDropdown(e.currentTarget as HTMLElement, opts.map(opt => ({
      label: (opt.value === st.currentSortBy ? '✓ ' : '    ') + opt.label,
      active: opt.value === st.currentSortBy,
      fn: () => {
        st.currentSortBy = opt.value;
        Settings.set('lastSortBy', opt.value);
        const labelEl = document.getElementById('sort-label-text');
        if (labelEl) labelEl.textContent = opt.label;
        renderGrid();
      },
    })));
  });

  // Expand all
  document.getElementById('expand-all-btn')!.addEventListener('click', () => {
    st.allExpanded = !st.allExpanded;
    if (st.allExpanded) st.vault.api_keys.forEach(k => st.expanded.add(entryId(k)));
    else st.expanded.clear();
    renderGrid();   // renderGrid syncs the button label from st.allExpanded
  });

  // Sidebar toggle + add button. The collapsed state is persisted: it is a
  // layout preference, and resetting it on every launch made Ctrl-B feel like
  // it had not been remembered.
  document.getElementById('sidebar-toggle')!.addEventListener('click', () => {
    const sb = document.getElementById('sidebar');
    if (!sb) return;
    sb.classList.toggle('collapsed');
    Settings.set('sidebarCollapsed', sb.classList.contains('collapsed'));
  });
  document.getElementById('add-btn')!.addEventListener('click', openAdd);

  // Sidebar resize handle
  {
    const resizer = document.getElementById('sidebar-resizer');
    const sidebar = document.getElementById('sidebar');
    if (resizer && sidebar) {
      let _startX = 0, _startW = 0;
      resizer.addEventListener('mousedown', (e) => {
        _startX = e.clientX;
        _startW = sidebar.getBoundingClientRect().width;
        resizer.classList.add('dragging');
        let _w = _startW;
        const onMove = (ev: MouseEvent) => {
          _w = Math.max(SIDEBAR_MIN_W, Math.min(SIDEBAR_MAX_W, _startW + ev.clientX - _startX));
          sidebar.style.width = _w + 'px';
        };
        const onUp = () => {
          resizer.classList.remove('dragging');
          document.removeEventListener('mousemove', onMove);
          document.removeEventListener('mouseup', onUp);
          // Persist on mouseup, not on every mousemove: writing localStorage on
          // each pixel of the drag serialises the whole settings blob ~60×/sec.
          Settings.set('sidebarWidth', Math.round(_w));
        };
        document.addEventListener('mousemove', onMove);
        document.addEventListener('mouseup', onUp);
        e.preventDefault();
      });

      // Double-click the handle to go back to the stylesheet default — the only
      // way out once a persisted width has been dragged to an awkward size.
      resizer.addEventListener('dblclick', () => {
        Settings.set('sidebarWidth', 0);
        sidebar.style.width = '';
        showToast('Sidebar width reset', 'ok', 1500);
      });
    }
  }

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

  // ENV link modal
  document.getElementById('env-link-close')?.addEventListener('click', closeEnvLinkModal);
  document.getElementById('env-link-cancel')?.addEventListener('click', closeEnvLinkModal);
  document.getElementById('env-link-apply')?.addEventListener('click', applyEnvLink);
  document.getElementById('env-link-overlay')?.addEventListener('click', (e) => { if (e.target === e.currentTarget) closeEnvLinkModal(); });

  // Data import/export
  document.getElementById('settings-import-btn')?.addEventListener('click', () => openFilePicker('.json,.env,.yaml,.yml,text/plain'));
  document.getElementById('settings-export-dotenv')?.addEventListener('click', () => exportAs('dotenv'));
  document.getElementById('settings-export-yaml')?.addEventListener('click', () => exportAs('yaml'));
  document.getElementById('settings-export-json')?.addEventListener('click', () => exportAs('json'));
  document.getElementById('settings-export-k8s')?.addEventListener('click', () => exportK8sSecret());
  document.getElementById('settings-export-tfvars')?.addEventListener('click', () => exportTfvars());
  document.getElementById('settings-export-encrypted')?.addEventListener('click', () => {
    const pw = (document.getElementById('settings-backup-pw') as HTMLInputElement).value;
    exportEncryptedBackup(pw);
  });
  document.getElementById('settings-import-encrypted')?.addEventListener('click', () => {
    const pw = (document.getElementById('settings-backup-pw') as HTMLInputElement).value;
    if (!pw) { showToast('Enter the backup password first', 'err'); return; }
    const inp = document.createElement('input');
    inp.type = 'file'; inp.accept = '.vaultbak,.json,text/plain';
    inp.onchange = () => {
      const f = inp.files?.[0];
      if (!f) { inp.remove(); return; }
      const reader = new FileReader();
      reader.onload = e => { importEncryptedBackup(String(e.target?.result ?? ''), pw); inp.remove(); };
      reader.readAsText(f);
    };
    document.body.appendChild(inp);
    inp.click();
  });

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
  document.getElementById('new-project-btn')!.addEventListener('click', openProjectCreateModal);
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

  // Clear every active filter
  document.getElementById('clear-filters-btn')?.addEventListener('click', () => {
    clearAllFilters();
    closeSearchHistory();
    triggerRender();
  });

  // Lock
  document.getElementById('lock-btn')!.addEventListener('click', async () => { if (await showConfirm('Lock vault?')) lockVault(); });

  // Undo bar
  document.getElementById('undo-btn')!.addEventListener('click', () => {
    const last = st.undoStack.pop();
    if (last) {
      clearTimeout(last.t);
      last.fn();
      if (!st.undoStack.length) document.getElementById('undo-bar')!.classList.remove('visible');
    }
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
    // Shift+Esc: drop every filter at once. Plain Escape only clears the search
    // box, which is not enough now that a category/project/tag selection can be
    // restored from a previous session.
    if (e.key === 'Escape' && e.shiftKey) {
      e.preventDefault();
      clearAllFilters();
      triggerRender();
      showToast('Filters cleared', 'ok', 1500);
      return;
    }
    if (e.key === 'Escape') {
      shortcutsEl.classList.remove('open');
      // Escape used to just hide the panel: theme and accent apply live, so the
      // preview stayed on screen while never being committed — neither saved
      // nor reverted. Escape is a cancel, same as the Cancel button.
      if (document.getElementById('settings-overlay')?.classList.contains('open')) cancelSettings();
      // Only close the entry modal if it is actually open: closeModal() also
      // discards the saved form draft, so a stray Escape used to throw away a
      // draft left by a previous session before it could be restored.
      if (document.getElementById('modal-overlay')?.classList.contains('open')) closeModal();
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
    if ((window as any).__envvIsBulkMode?.() && action !== 'bulk-toggle') {
      const card = el.closest<HTMLElement>('[data-idx]');
      if (card) { (window as any).__envvBulkToggle?.(parseInt(card.dataset.idx!)); return; }
    }
    e.stopPropagation();
    switch (action) {
      case 'toggle':      toggleCard(e, idx); break;
      case 'reveal':      toggleReveal(e, field, idx, value); break;
      case 'copy-field':  copyField(e, value, el); break;
      case 'copy-env':    doCopyEnv(e, idx); break;
      case 'rotate':      markAsRotated(idx); break;
      case 'pin': {
        const entry = st.vault.api_keys[idx];
        if (entry) {
          entry.pinned = entry.pinned ? undefined : true;
          persist();
          triggerRender();
          showToast(entry.pinned ? 'Pinned ✓' : 'Unpinned', 'ok', 1500);
        }
        break;
      }
      case 'bulk-toggle': (window as any).__envvBulkToggle?.(idx); break;
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
    // Use a plain string label — showContextMenu renders via innerHTML so user data must be escaped.
    const _safeProvider = entry.provider.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    const _items: Array<DropdownItem | '---'> = [
      { label: `Copy Provider: ${_safeProvider}`, fn: () => clipboardWrite(entry.provider).then(() => showToast('Copied ✓', 'ok', 1500)) },
      { label: `Copy ${_keyLabel}`,               fn: () => copyField(e as MouseEvent, entry.api_key, card) },
    ];
    if (entry.api_secret) _items.push({ label: 'Copy Secret', fn: () => copyField(e as MouseEvent, entry.api_secret!, card) });
    // Resolve the position again when the item is actually clicked. The menu
    // captures `idx` at open time, and anything that splices api_keys in
    // between (an undo restoring an entry, a peer's edit reloading the vault)
    // would otherwise point these at the wrong secret.
    const liveIdx = () => st.vault.api_keys.indexOf(entry);
    const onEntry = (fn: (i: number) => void) => () => {
      const i = liveIdx();
      if (i < 0) { showToast('That secret no longer exists', 'err'); return; }
      fn(i);
    };
    _items.push(
      { label: 'Copy .env line', fn: onEntry(i => doCopyEnv(e as MouseEvent, i)) },
      '---',
      { label: 'Edit',      fn: onEntry(i => openEdit(e as MouseEvent, i)) },
      { label: 'Duplicate', fn: onEntry(i => duplicateKey(e as MouseEvent, i)) },
      '---',
      { label: 'Delete',    fn: onEntry(i => deleteKey(e as MouseEvent, i)) },
    );
    showContextMenu(e.clientX, e.clientY, _items);
  });

  // Misc
  document.getElementById('vault-switcher')!.addEventListener('click', (e) => {
    const isRemote = st.store instanceof RemoteVaultStore;
    const saved = Settings.get('remoteSaved') ?? [];
    const items: any[] = [
      {
        label: isRemote ? '  Local Vault' : '⬤ Local Vault',
        active: !isRemote,
        // Shared with the Remote panel's Disconnect button — it also clears
        // st.vault.projects (which this used to leave behind) and prompts for
        // the master password when the local vault is still locked.
        fn: () => { if (isRemote) void switchToLocalVault(); },
      },
      '---',
    ];
    saved.forEach(cfg => {
      const connected = st.activeRemoteId === cfg.id;
      items.push({
        label: `${connected ? '⬤' : '  '} ${cfg.name}`,
        active: connected,
        fn: () => {
          if (!connected) {
            switchPanel('remote');
            st.activeRemoteId = cfg.id;
            // Static import — remote-panel is already in this module's graph, so a
            // dynamic import here only produced a Vite chunking warning.
            renderRemotePanel();
          }
        },
      });
    });
    items.push('---');
    items.push({ label: '+ Add Remote Vault', active: false, fn: () => switchPanel('remote') });
    items.push({ label: 'Remote settings…', active: false, fn: () => openSettings() });
    showDropdown(e.currentTarget as HTMLElement, items);
  });
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
