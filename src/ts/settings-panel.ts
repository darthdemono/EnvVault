/**
 * @file Settings panel: themes, sidebar order, panel order, remote config, open/save/close.
 */

import type { AppSettings } from './types';
import { Settings, triggerRender, applySidebarOrder, applyActivityBar, applyUsersPanelVisibility } from './state';
import { showToast } from './utils';

// ── Theme definitions ──────────────────────────────────────────────────────

const THEMES = [
  { id: 'dark',       label: 'Dark',       bg: '#0e0e0e', accent: '#7364c9' },
  { id: 'midnight',   label: 'Midnight',   bg: '#09090f', accent: '#5b8dd9' },
  { id: 'dracula',    label: 'Dracula',    bg: '#282a36', accent: '#bd93f9' },
  { id: 'nord',       label: 'Nord',       bg: '#2e3440', accent: '#88c0d0' },
  { id: 'catppuccin', label: 'Catppuccin', bg: '#1e1e2e', accent: '#cba6f7' },
  { id: 'light',      label: 'Light',      bg: '#f0f0f6', accent: '#6355b5' },
  { id: 'system',     label: 'System',     bg: 'linear-gradient(135deg, #0e0e0e 50%, #f0f0f6 50%)', accent: '#7364c9' },
];

export function buildThemeSwatches() {
  const wrap = document.getElementById('theme-swatches')!;
  if (!wrap) return;
  wrap.innerHTML = '';
  THEMES.forEach(t => {
    const sw = document.createElement('div');
    sw.className = `theme-swatch${Settings.get('theme') === t.id ? ' active' : ''}`;
    sw.title = t.label;
    sw.style.cssText = `background:${t.bg};box-shadow:inset 0 0 0 4px ${t.accent}55;font-size:9px;display:flex;align-items:center;justify-content:center;color:${t.accent}`;
    sw.addEventListener('click', () => {
      Settings.set('theme', t.id);
      Settings._apply();
      buildThemeSwatches();
    });
    wrap.appendChild(sw);
  });
}

// ── Sidebar order editor ──────────────────────────────────────────────────

const SIDEBAR_SECTION_DEFS = [
  { key: 'all',      label: 'All Secrets' },
  { key: 'price',    label: 'Price Types' },
  { key: 'env',      label: 'Environment' },
  { key: 'category', label: 'Categories' },
  { key: 'project',  label: 'Projects' },
  { key: 'tags',     label: 'Tags' },
  { key: 'prefixes', label: 'Env Prefixes' },
];
const DEFAULT_SIDEBAR_SECTIONS = ['all', 'price', 'env', 'category', 'project', 'tags', 'prefixes'];

export function buildSidebarOrderEditor() {
  const container = document.getElementById('s-sidebar-sections');
  if (!container) return;
  const sections = [...(Settings.get('sidebarSections') || DEFAULT_SIDEBAR_SECTIONS)] as string[];
  container.innerHTML = '';

  sections.forEach((sKey, i) => {
    const def = SIDEBAR_SECTION_DEFS.find(d => d.key === sKey);
    if (!def) return;
    const row = document.createElement('div');
    row.className = 'sidebar-order-row';
    row.dataset.key = sKey;
    // 'all' is locked visible; everything else is draggable + hideable.
    if (sKey !== 'all') row.draggable = true;
    const isFirst = i === 0, isLast = i === sections.length - 1;
    row.innerHTML = `
      <span class="sidebar-order-grip" title="Drag to reorder">⠿</span>
      <span class="sidebar-order-label">${def.label}</span>
      <div class="sidebar-order-btns">
        <button class="btn-xs" data-action="up" ${isFirst ? 'disabled' : ''}>▲</button>
        <button class="btn-xs" data-action="down" ${isLast ? 'disabled' : ''}>▼</button>
        <button class="btn-xs" data-action="${sKey === 'all' ? 'locked' : 'remove'}" ${sKey === 'all' ? 'disabled' : ''} title="${sKey === 'all' ? 'Always visible' : 'Hide'}">✕</button>
      </div>`;
    container.appendChild(row);
  });

  SIDEBAR_SECTION_DEFS.filter(d => !sections.includes(d.key)).forEach(def => {
    const row = document.createElement('div');
    row.className = 'sidebar-order-row sidebar-order-hidden';
    row.dataset.key = def.key;
    row.innerHTML = `<span class="sidebar-order-label sidebar-order-dim">${def.label}</span><button class="btn-xs" data-action="add">+ Show</button>`;
    container.appendChild(row);
  });

  const commit = (secs: string[]) => {
    Settings.set('sidebarSections', secs as any);
    applySidebarOrder();
    triggerRender();          // recompute data-gated tags/prefixes visibility
    buildSidebarOrderEditor();
  };

  container.onclick = (e) => {
    const btn = (e.target as HTMLElement).closest<HTMLElement>('[data-action]');
    if (!btn) return;
    const action = btn.dataset.action!;
    const rowEl  = btn.closest<HTMLElement>('[data-key]')!;
    const key    = rowEl.dataset.key!;
    const secs   = [...(Settings.get('sidebarSections') || DEFAULT_SIDEBAR_SECTIONS)] as string[];
    const idx    = secs.indexOf(key);
    if (action === 'up'        && idx > 0)             { [secs[idx-1], secs[idx]] = [secs[idx], secs[idx-1]]; }
    else if (action === 'down' && idx < secs.length-1) { [secs[idx], secs[idx+1]] = [secs[idx+1], secs[idx]]; }
    else if (action === 'remove' && key !== 'all')     { secs.splice(idx, 1); }
    else if (action === 'add')                         { secs.push(key); }
    else return;
    commit(secs);
  };

  // ── Drag-and-drop reorder (VSCodium-style) ──
  let dragKey: string | null = null;
  container.ondragstart = (e) => {
    const row = (e.target as HTMLElement).closest<HTMLElement>('.sidebar-order-row[draggable="true"]');
    if (!row) return;
    dragKey = row.dataset.key!;
    row.classList.add('dragging');
    e.dataTransfer!.effectAllowed = 'move';
  };
  container.ondragend = () => {
    container.querySelectorAll('.sidebar-order-row').forEach(r => r.classList.remove('dragging', 'drag-over'));
    dragKey = null;
  };
  container.ondragover = (e) => {
    e.preventDefault();
    const over = (e.target as HTMLElement).closest<HTMLElement>('.sidebar-order-row');
    container.querySelectorAll('.drag-over').forEach(r => r.classList.remove('drag-over'));
    // Can't drop onto the locked 'all' row or the hidden pool.
    if (over && over.dataset.key !== 'all' && !over.classList.contains('sidebar-order-hidden')) {
      over.classList.add('drag-over');
    }
  };
  container.ondrop = (e) => {
    e.preventDefault();
    const over = (e.target as HTMLElement).closest<HTMLElement>('.sidebar-order-row');
    if (!dragKey || !over) return;
    const targetKey = over.dataset.key!;
    if (targetKey === dragKey || targetKey === 'all' || over.classList.contains('sidebar-order-hidden')) return;
    const secs = [...(Settings.get('sidebarSections') || DEFAULT_SIDEBAR_SECTIONS)] as string[];
    const from = secs.indexOf(dragKey);
    let to = secs.indexOf(targetKey);
    if (from < 0 || to < 0) return;
    secs.splice(from, 1);
    to = secs.indexOf(targetKey);            // recompute after removal
    secs.splice(to, 0, dragKey);             // insert before the drop target
    commit(secs);
  };
}

// ── Panel order editor ────────────────────────────────────────────────────

export function buildPanelOrderEditor() {
  const container = document.getElementById('s-panel-order');
  if (!container) return;

  const ALL_PANELS = [
    { key: 'secrets', label: 'Secrets',      removable: false },
    { key: 'tools',   label: 'Tools',         removable: true  },
    { key: 'remote',  label: 'Remote Vaults', removable: true  },
    { key: 'users',   label: 'Users (RBAC)',  removable: true  },
  ];

  const order = [...(Settings.get('panelOrder') || ALL_PANELS.map(p => p.key))];
  container.innerHTML = '';

  order.forEach((pKey, i) => {
    const def = ALL_PANELS.find(p => p.key === pKey);
    if (!def) return;
    const row = document.createElement('div');
    row.className = 'sidebar-order-row';
    row.dataset.key = pKey;
    const isFirst = i === 0, isLast = i === order.length - 1;
    row.innerHTML = `
      <span class="sidebar-order-label">${def.label}</span>
      <div class="sidebar-order-btns">
        <button class="btn-xs" data-action="up" ${isFirst ? 'disabled' : ''}>▲</button>
        <button class="btn-xs" data-action="down" ${isLast ? 'disabled' : ''}>▼</button>
        <button class="btn-xs" data-action="${def.removable ? 'remove' : 'locked'}" ${def.removable ? '' : 'disabled'} title="${def.removable ? 'Hide' : 'Cannot hide'}">✕</button>
      </div>`;
    container.appendChild(row);
  });

  ALL_PANELS.filter(p => !order.includes(p.key)).forEach(def => {
    const row = document.createElement('div');
    row.className = 'sidebar-order-row sidebar-order-hidden';
    row.dataset.key = def.key;
    row.innerHTML = `<span class="sidebar-order-label sidebar-order-dim">${def.label}</span><button class="btn-xs" data-action="add">+ Show</button>`;
    container.appendChild(row);
  });

  container.onclick = (e) => {
    const btn = (e.target as HTMLElement).closest<HTMLElement>('[data-action]');
    if (!btn) return;
    const action = btn.dataset.action!;
    const rowEl  = btn.closest<HTMLElement>('[data-key]')!;
    const key    = rowEl.dataset.key!;
    const ord    = [...(Settings.get('panelOrder') || ALL_PANELS.map(p => p.key))];
    const idx    = ord.indexOf(key);
    if (action === 'up'     && idx > 0)              { [ord[idx-1], ord[idx]] = [ord[idx], ord[idx-1]]; }
    else if (action === 'down' && idx < ord.length-1) { [ord[idx], ord[idx+1]] = [ord[idx+1], ord[idx]]; }
    else if (action === 'remove')                     { ord.splice(idx, 1); }
    else if (action === 'add')                        { ord.push(key); }
    Settings.set('panelOrder', ord);
    applyPanelOrder();
    buildPanelOrderEditor();
  };
}

export function applyPanelOrder() {
  const order = Settings.get('panelOrder') || ['secrets', 'tools', 'remote', 'users'];
  document.querySelectorAll<HTMLButtonElement>('.activity-btn[data-panel]').forEach(btn => {
    const panel = btn.dataset.panel!;
    const idx   = order.indexOf(panel);
    if (idx >= 0) {
      btn.style.display = '';
      btn.style.order   = String(idx);
    } else {
      btn.style.display = 'none';
    }
  });
  // Must run last: the loop above unconditionally re-shows every ordered panel,
  // which would undo the Users gate.
  applyUsersPanelVisibility();
}

// ── Settings tabs ─────────────────────────────────────────────────────────

function initSettingsTabs() {
  const tabs  = document.querySelectorAll<HTMLButtonElement>('.settings-tab');
  const panes = document.querySelectorAll<HTMLElement>('.settings-tab-pane');
  tabs.forEach(tab => {
    tab.addEventListener('click', () => {
      tabs.forEach(t => t.classList.remove('active'));
      panes.forEach(p => p.classList.remove('active'));
      tab.classList.add('active');
      const pane = document.querySelector<HTMLElement>(`.settings-tab-pane[data-spane="${tab.dataset.stab}"]`);
      if (pane) pane.classList.add('active');
    });
  });
}

// ── Remote vault section ──────────────────────────────────────────────────
//
// The legacy "Quick Connect" single-server form used to live here. It carried a
// nasty bug: `saveSettings()` unconditionally called an `applyRemoteConfig()`
// that reassigned `st.store` from the state of its (unchecked) enable toggle.
// So opening Settings while connected to a remote vault and closing it — which
// saves — silently tore down the live connection and dropped you back to the
// local vault, with no warning and no obvious cause.
//
// The Remote panel supersedes it entirely: named connections, per-server
// credentials, TLS fingerprint pinning. Settings now only links to it, and
// nothing in the settings save path touches `st.store`.

// ── Open / save / close ───────────────────────────────────────────────────

let _tabsInited = false;
/**
 * Settings as they were when the panel opened.
 *
 * Theme and accent apply live (you need to see them to choose them), which
 * previously made "Cancel" a lie — the preview had already been committed.
 * Cancel now restores this snapshot.
 */
let _settingsSnapshot: AppSettings | null = null;

export function openSettings() {
  const s = Settings.getAll();
  _settingsSnapshot = { ...s };

  if (!_tabsInited) { initSettingsTabs(); _tabsInited = true; }

  buildThemeSwatches();
  buildSidebarOrderEditor();
  buildPanelOrderEditor();

  (document.getElementById('s-accent')          as HTMLInputElement).value   = s.accentColor;
  document.getElementById('s-accent-val')!.textContent                       = s.accentColor;
  (document.getElementById('s-autolock')         as HTMLInputElement).value   = String(s.autoLockMinutes);
  (document.getElementById('s-lock-on-hide')     as HTMLInputElement).checked = s.lockOnHide;
  (document.getElementById('s-mask')             as HTMLInputElement).checked = s.maskKeysByDefault;
  (document.getElementById('s-expiry-warn')      as HTMLInputElement).checked = s.showExpiryWarning;
  (document.getElementById('s-expiry-days')      as HTMLInputElement).value   = String(s.expiryWarningDays);
  (document.getElementById('s-default-account')  as HTMLInputElement).value   = s.defaultAccount || '';
  (document.getElementById('s-export-format')    as HTMLSelectElement).value  = s.defaultExportFormat;
  (document.getElementById('s-env-copy-field')   as HTMLSelectElement).value  = s.envCopyField || 'api_key';
  (document.getElementById('s-custom-css')       as HTMLTextAreaElement).value = s.customCss || '';
  (document.getElementById('s-group-by-type')    as HTMLInputElement).checked = s.groupByType;
  (document.getElementById('s-remember-filters') as HTMLInputElement).checked = s.rememberFilters !== false;
  (document.getElementById('s-experimental-ptypes') as HTMLInputElement).checked = !!s.experimentalProjectTypes;

  // Assignment, not addEventListener: the settings pane is opened repeatedly and
  // `{ once: true }` only detaches after a click, so every open that did not
  // click left another handler attached and they all fired together later.
  const clearRecent = document.getElementById('s-clear-recent');
  if (clearRecent) (clearRecent as HTMLElement).onclick = () => {
    Settings.set('recentSearches', []);
    showToast('Search history cleared', 'ok', 1500);
  };

  ['s-card-size', 's-grid-cols', 's-activity-bar-position', 's-activity-bar-style'].forEach(id => {
    const key = id === 's-card-size' ? 'cardSize'
      : id === 's-grid-cols' ? 'gridColumns'
      : id === 's-activity-bar-position' ? 'activityBarPosition'
      : 'activityBarStyle';
    document.querySelectorAll<HTMLButtonElement>(`#${id} button`).forEach(
      btn => btn.classList.toggle('active', btn.dataset.val === String(Settings.get(key as keyof AppSettings))));
  });

  // accent reset
  const resetBtn = document.getElementById('s-accent-reset');
  if (resetBtn) resetBtn.onclick = () => {
    (document.getElementById('s-accent') as HTMLInputElement).value = '#7364c9';
    document.getElementById('s-accent-val')!.textContent = '#7364c9';
  };
  // accent live preview
  const accentInput = document.getElementById('s-accent') as HTMLInputElement | null;
  if (accentInput) accentInput.oninput = () => {
    document.getElementById('s-accent-val')!.textContent = accentInput.value;
  };

  // seg-control buttons
  document.querySelectorAll<HTMLElement>('.seg-control').forEach(ctrl => {
    ctrl.querySelectorAll<HTMLButtonElement>('button').forEach(btn => {
      btn.onclick = () => {
        ctrl.querySelectorAll('button').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
      };
    });
  });

  document.getElementById('settings-overlay')!.classList.add('open');

  // footer buttons
  const saveBtn   = document.getElementById('settings-save');
  const cancelBtn = document.getElementById('settings-cancel');
  if (saveBtn)   saveBtn.onclick   = () => { saveSettings(); closeSettings(); };
  if (cancelBtn) cancelBtn.onclick = cancelSettings;
}

/** Discard edits made since the panel opened, including live previews. */
export function cancelSettings() {
  if (_settingsSnapshot) {
    Settings.setAll(_settingsSnapshot);
    Settings._apply();
    applyActivityBar();
    applyPanelOrder();
    triggerRender();
  }
  closeSettings();
}

export function saveSettings() {
  const getSegVal = (id: string) => document.querySelector<HTMLButtonElement>(`#${id} button.active`)?.dataset.val;

  // `parseInt(...) || 0` turned anything unreadable into 0, and 0 means
  // auto-lock OFF. The field is <input type="number">, so the browser discards
  // letters and hands back "" — meaning a typo silently switched off the
  // vault's inactivity lock. Off is spelled `0` here (the label says so), so an
  // empty box is a mistake: keep what was set. Range comes from min/max on the
  // input, which nothing enforced on save.
  const AUTOLOCK_MAX = 480;
  const autoLockRaw = (document.getElementById('s-autolock') as HTMLInputElement).value.trim();
  const autoLockParsed = parseInt(autoLockRaw, 10);
  const prevAutoLock = Settings.get('autoLockMinutes');
  const autoLockMinutes = Number.isFinite(autoLockParsed)
    ? Math.min(Math.max(autoLockParsed, 0), AUTOLOCK_MAX)
    : prevAutoLock;
  if (autoLockMinutes !== autoLockParsed) {
    showToast(
      Number.isFinite(autoLockParsed)
        ? `Auto-lock must be 0–${AUTOLOCK_MAX} min — using ${autoLockMinutes}`
        : `Auto-lock interval left blank — keeping ${autoLockMinutes} min (enter 0 for never)`,
      'err', 4000,
    );
  }

  Settings.setAll({
    accentColor:         (document.getElementById('s-accent')         as HTMLInputElement).value,
    autoLockMinutes,
    lockOnHide:          (document.getElementById('s-lock-on-hide')  as HTMLInputElement).checked,
    maskKeysByDefault:   (document.getElementById('s-mask')           as HTMLInputElement).checked,
    showExpiryWarning:   (document.getElementById('s-expiry-warn')    as HTMLInputElement).checked,
    expiryWarningDays:   parseInt((document.getElementById('s-expiry-days') as HTMLInputElement).value) || 30,
    defaultAccount:      (document.getElementById('s-default-account') as HTMLInputElement).value.trim(),
    defaultExportFormat: (document.getElementById('s-export-format')  as HTMLSelectElement).value as AppSettings['defaultExportFormat'],
    envCopyField:        (document.getElementById('s-env-copy-field') as HTMLSelectElement).value as AppSettings['envCopyField'],
    customCss:           (document.getElementById('s-custom-css')     as HTMLTextAreaElement).value,
    groupByType:         (document.getElementById('s-group-by-type')  as HTMLInputElement).checked,
    rememberFilters:     (document.getElementById('s-remember-filters') as HTMLInputElement).checked,
    experimentalProjectTypes: (document.getElementById('s-experimental-ptypes') as HTMLInputElement).checked,
    activityBarPosition: (getSegVal('s-activity-bar-position') || 'left') as 'left' | 'right',
    activityBarStyle:    (getSegVal('s-activity-bar-style')    || 'icon') as 'icon' | 'icon-label',
  });
  // Switching the preference off must also drop what was already stored —
  // otherwise the last view stays on disk and comes back the moment the user
  // turns the setting on again, which reads as the toggle not having worked.
  if (!Settings.get('rememberFilters')) Settings.set('lastView', null);
  Settings._apply();
  applyActivityBar();
  applyPanelOrder();
  triggerRender();
  // Re-arm the auto-lock timer so a changed interval takes effect immediately
  // instead of on the next unlock.
  import('./lock').then(m => m.resetLock()).catch(() => {});
  _settingsSnapshot = Settings.getAll();
  showToast('Settings saved', 'ok', 1500);
}

export function closeSettings() {
  document.getElementById('settings-overlay')!.classList.remove('open');
}
