/**
 * @file Settings panel: themes, sidebar order editor, open/save/close.
 */

import type { AppSettings } from './types';
import { Settings, triggerRender, applyGridSettings, applySidebarOrder, applyActivityBar } from './state';

// ── Theme definitions ──────────────────────────────────────────────────────

const THEMES = [
  { id: 'dark', label: 'Dark', bg: '#0e0e0e', accent: '#7364c9' },
  { id: 'midnight', label: 'Midnight', bg: '#09090f', accent: '#5b8dd9' },
  { id: 'dracula', label: 'Dracula', bg: '#282a36', accent: '#bd93f9' },
  { id: 'nord', label: 'Nord', bg: '#2e3440', accent: '#88c0d0' },
  { id: 'catppuccin', label: 'Catppuccin', bg: '#1e1e2e', accent: '#cba6f7' },
  { id: 'light', label: 'Light', bg: '#f0f0f6', accent: '#6355b5' },
];

// ── Theme swatches ────────────────────────────────────────────────────────

export function buildThemeSwatches() {
  const wrap = document.getElementById('theme-swatches')!;
  wrap.innerHTML = '';
  THEMES.forEach(t => {
    const sw = document.createElement('div');
    sw.className = `theme-swatch${Settings.get('theme') === t.id ? ' active' : ''}`;
    sw.title = t.label;
    sw.style.cssText = `background:${t.bg};box-shadow:inset 0 0 0 4px ${t.accent}55`;
    sw.addEventListener('click', () => { Settings.set('theme', t.id); Settings._apply(); buildThemeSwatches(); });
    wrap.appendChild(sw);
  });
}

// ── Sidebar order editor ──────────────────────────────────────────────────

export function buildSidebarOrderEditor() {
  const container = document.getElementById('s-sidebar-sections');
  if (!container) return;
  const sections = [...(Settings.get('sidebarSections') || ['all', 'price', 'category', 'project'])];
  const allDefs = [
    { key: 'all', label: 'All Secrets' },
    { key: 'price', label: 'Price Types' },
    { key: 'category', label: 'Categories' },
    { key: 'project', label: 'Projects' },
  ];
  container.innerHTML = '';
  sections.forEach((sKey, i) => {
    const def = allDefs.find(d => d.key === sKey);
    if (!def) return;
    const row = document.createElement('div');
    row.className = 'sidebar-order-row';
    row.dataset.key = sKey;
    const isFirst = i === 0;
    const isLast = i === sections.length - 1;
    row.innerHTML = `<span class="sidebar-order-label">${def.label}</span><div class="sidebar-order-btns"><button class="btn-xs" data-action="up" ${isFirst ? 'disabled' : ''}>▲</button><button class="btn-xs" data-action="down" ${isLast ? 'disabled' : ''}>▼</button><button class="btn-xs" data-action="${sKey === 'all' ? 'locked' : 'remove'}" ${sKey === 'all' ? 'disabled' : ''} title="${sKey === 'all' ? 'Always visible' : 'Hide'}">✕</button></div>`;
    container.appendChild(row);
  });
  allDefs.filter(d => !sections.includes(d.key as any)).forEach(def => {
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
    const rowEl = btn.closest<HTMLElement>('[data-key]')!;
    const key = rowEl.dataset.key!;
    const secs = [...(Settings.get('sidebarSections') || ['all', 'price', 'category', 'project'])];
    const idx = secs.indexOf(key as any);
    if (action === 'up' && idx > 0) { [secs[idx - 1], secs[idx]] = [secs[idx], secs[idx - 1]]; }
    else if (action === 'down' && idx < secs.length - 1) { [secs[idx], secs[idx + 1]] = [secs[idx + 1], secs[idx]]; }
    else if (action === 'remove' && key !== 'all') { secs.splice(idx, 1); }
    else if (action === 'add') { secs.push(key as any); }
    Settings.set('sidebarSections', secs as any);
    applySidebarOrder();
    buildSidebarOrderEditor();
  };
}

// ── Open / save / close settings ─────────────────────────────────────────

export function openSettings() {
  const s = Settings.getAll();
  buildThemeSwatches();
  buildSidebarOrderEditor();
  (document.getElementById('s-accent') as HTMLInputElement).value = s.accentColor;
  document.getElementById('s-accent-val')!.textContent = s.accentColor;
  (document.getElementById('s-autolock') as HTMLInputElement).value = String(s.autoLockMinutes);
  (document.getElementById('s-mask') as HTMLInputElement).checked = s.maskKeysByDefault;
  (document.getElementById('s-expiry-warn') as HTMLInputElement).checked = s.showExpiryWarning;
  (document.getElementById('s-expiry-days') as HTMLInputElement).value = String(s.expiryWarningDays);
  (document.getElementById('s-default-account') as HTMLInputElement).value = s.defaultAccount || '';
  (document.getElementById('s-export-format') as HTMLSelectElement).value = s.defaultExportFormat;
  (document.getElementById('s-custom-css') as HTMLTextAreaElement).value = s.customCss || '';
  (document.getElementById('s-group-by-type') as HTMLInputElement).checked = s.groupByType;
  ['s-card-size', 's-grid-cols', 's-activity-bar-position', 's-activity-bar-style'].forEach(id => {
    const key = id === 's-card-size' ? 'cardSize'
      : id === 's-grid-cols' ? 'gridColumns'
      : id === 's-activity-bar-position' ? 'activityBarPosition'
      : 'activityBarStyle';
    document.querySelectorAll<HTMLButtonElement>(`#${id} button`).forEach(btn => btn.classList.toggle('active', btn.dataset.val === String(Settings.get(key as keyof AppSettings))));
  });
  document.getElementById('settings-overlay')!.classList.add('open');
}

export function saveSettings() {
  const getSegVal = (id: string) => document.querySelector<HTMLButtonElement>(`#${id} button.active`)?.dataset.val;
  Settings.setAll({
    accentColor: (document.getElementById('s-accent') as HTMLInputElement).value,
    autoLockMinutes: parseInt((document.getElementById('s-autolock') as HTMLInputElement).value) || 20,
    maskKeysByDefault: (document.getElementById('s-mask') as HTMLInputElement).checked,
    showExpiryWarning: (document.getElementById('s-expiry-warn') as HTMLInputElement).checked,
    expiryWarningDays: parseInt((document.getElementById('s-expiry-days') as HTMLInputElement).value) || 30,
    defaultAccount: (document.getElementById('s-default-account') as HTMLInputElement).value.trim(),
    defaultExportFormat: (document.getElementById('s-export-format') as HTMLSelectElement).value as AppSettings['defaultExportFormat'],
    customCss: (document.getElementById('s-custom-css') as HTMLTextAreaElement).value,
    groupByType: (document.getElementById('s-group-by-type') as HTMLInputElement).checked,
    activityBarPosition: (getSegVal('s-activity-bar-position') || 'left') as 'left' | 'right',
    activityBarStyle: (getSegVal('s-activity-bar-style') || 'icon') as 'icon' | 'icon-label',
  });
  Settings._apply();
  applyActivityBar();
  triggerRender();
}

export function closeSettings() { document.getElementById('settings-overlay')!.classList.remove('open'); }
