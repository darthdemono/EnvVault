import type { AppSettings, VaultEntry } from './types';
import {
  Settings,
  triggerRender,
  applySidebarOrder,
  applyActivityBar,
  applyUsersPanelVisibility,
  type EnvNameCase,
} from './state';
import { saveFile, showConfirm, showPasswordPrompt, showToast } from './utils';
import { buildCopyText, type CopyProfile, type MetadataStyle } from './copy-profile';
import { html, setHtml } from './html';
import { inTauri, invokeTauri } from './tauri';

// ── Theme definitions ──────────────────────────────────────────────────────

const THEMES = [
  { id: 'dark', label: 'Dark', bg: '#0e0e0e', accent: '#7364c9' },
  { id: 'midnight', label: 'Midnight', bg: '#09090f', accent: '#5b8dd9' },
  { id: 'dracula', label: 'Dracula', bg: '#282a36', accent: '#bd93f9' },
  { id: 'nord', label: 'Nord', bg: '#2e3440', accent: '#88c0d0' },
  { id: 'catppuccin', label: 'Catppuccin', bg: '#1e1e2e', accent: '#cba6f7' },
  { id: 'light', label: 'Light', bg: '#f0f0f6', accent: '#6355b5' },
  {
    id: 'system',
    label: 'System',
    bg: 'linear-gradient(135deg, #0e0e0e 50%, #f0f0f6 50%)',
    accent: '#7364c9',
  },
];

export function buildThemeSwatches() {
  const wrap = document.getElementById('theme-swatches')!;
  if (!wrap) return;
  setHtml(wrap, '');
  THEMES.forEach((t) => {
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

type SidebarSection = AppSettings['sidebarSections'][number];

const SIDEBAR_SECTION_DEFS: { key: SidebarSection; label: string }[] = [
  { key: 'all', label: 'All Secrets' },
  { key: 'price', label: 'Price Types' },
  { key: 'env', label: 'Environment' },
  { key: 'category', label: 'Categories' },
  { key: 'project', label: 'Projects' },
  { key: 'tags', label: 'Tags' },
  { key: 'pools', label: 'Key Pools' },
  { key: 'prefixes', label: 'Env Prefixes' },
];
// `authenticator` removed here in A2 (2026-09-14) — see state.ts's migration note.
const DEFAULT_SIDEBAR_SECTIONS: AppSettings['sidebarSections'] = [
  'all',
  'price',
  'env',
  'category',
  'project',
  'tags',
  'pools',
  'prefixes',
];

export function buildSidebarOrderEditor() {
  const container = document.getElementById('s-sidebar-sections');
  if (!container) return;
  const sections = [...(Settings.get('sidebarSections') || DEFAULT_SIDEBAR_SECTIONS)];
  setHtml(container, '');

  sections.forEach((sKey, i) => {
    const def = SIDEBAR_SECTION_DEFS.find((d) => d.key === sKey);
    if (!def) return;
    const row = document.createElement('div');
    row.className = 'sidebar-order-row';
    row.dataset.key = sKey;
    // 'all' is locked visible; everything else is draggable + hideable.
    if (sKey !== 'all') row.draggable = true;
    const isFirst = i === 0,
      isLast = i === sections.length - 1;
    setHtml(
      row,
      html` <span class="sidebar-order-grip" title="Drag to reorder">⠿</span>
        <span class="sidebar-order-label">${def.label}</span>
        <div class="sidebar-order-btns">
          <button class="btn-xs" data-action="up" ${isFirst ? 'disabled' : ''}>▲</button>
          <button class="btn-xs" data-action="down" ${isLast ? 'disabled' : ''}>▼</button>
          <button
            class="btn-xs"
            data-action="${sKey === 'all' ? 'locked' : 'remove'}"
            ${sKey === 'all' ? 'disabled' : ''}
            title="${sKey === 'all' ? 'Always visible' : 'Hide'}"
          >
            ✕
          </button>
        </div>`,
    );
    container.appendChild(row);
  });

  SIDEBAR_SECTION_DEFS.filter((d) => !sections.includes(d.key)).forEach((def) => {
    const row = document.createElement('div');
    row.className = 'sidebar-order-row sidebar-order-hidden';
    row.dataset.key = def.key;
    setHtml(
      row,
      html`<span class="sidebar-order-label sidebar-order-dim">${def.label}</span
        ><button class="btn-xs" data-action="add">+ Show</button>`,
    );
    container.appendChild(row);
  });

  const commit = (secs: AppSettings['sidebarSections']) => {
    Settings.set('sidebarSections', secs);
    applySidebarOrder();
    triggerRender(); // recompute data-gated tags/prefixes visibility
    buildSidebarOrderEditor();
  };

  container.onclick = (e) => {
    const btn = (e.target as HTMLElement).closest<HTMLElement>('[data-action]');
    if (!btn) return;
    const action = btn.dataset.action!;
    const rowEl = btn.closest<HTMLElement>('[data-key]')!;
    const key = rowEl.dataset.key! as SidebarSection;
    const secs = [...(Settings.get('sidebarSections') || DEFAULT_SIDEBAR_SECTIONS)];
    const idx = secs.indexOf(key);
    if (action === 'up' && idx > 0) {
      [secs[idx - 1], secs[idx]] = [secs[idx], secs[idx - 1]];
    } else if (action === 'down' && idx < secs.length - 1) {
      [secs[idx], secs[idx + 1]] = [secs[idx + 1], secs[idx]];
    } else if (action === 'remove' && key !== 'all') {
      secs.splice(idx, 1);
    } else if (action === 'add') {
      secs.push(key);
    } else return;
    commit(secs);
  };

  // ── Drag-and-drop reorder (VSCodium-style) ──
  let dragKey: SidebarSection | null = null;
  container.ondragstart = (e) => {
    const row = (e.target as HTMLElement).closest<HTMLElement>(
      '.sidebar-order-row[draggable="true"]',
    );
    if (!row) return;
    dragKey = row.dataset.key! as SidebarSection;
    row.classList.add('dragging');
    // WebKitGTK refuses to start an HTML drag without a payload.  Chromium
    // accepts the old effectAllowed-only version, which made this look wired
    // everywhere except the shipped desktop app.
    e.dataTransfer?.setData('text/plain', dragKey);
    if (e.dataTransfer) e.dataTransfer.effectAllowed = 'move';
  };
  container.ondragend = () => {
    container
      .querySelectorAll('.sidebar-order-row')
      .forEach((r) => r.classList.remove('dragging', 'drag-over'));
    dragKey = null;
  };
  container.ondragover = (e) => {
    e.preventDefault();
    const over = (e.target as HTMLElement).closest<HTMLElement>('.sidebar-order-row');
    container.querySelectorAll('.drag-over').forEach((r) => r.classList.remove('drag-over'));
    // Can't drop onto the locked 'all' row or the hidden pool.
    if (over && over.dataset.key !== 'all' && !over.classList.contains('sidebar-order-hidden')) {
      over.classList.add('drag-over');
    }
  };
  container.ondrop = (e) => {
    e.preventDefault();
    const over = (e.target as HTMLElement).closest<HTMLElement>('.sidebar-order-row');
    if (!dragKey || !over) return;
    const targetKey = over.dataset.key! as SidebarSection;
    if (
      targetKey === dragKey ||
      targetKey === 'all' ||
      over.classList.contains('sidebar-order-hidden')
    )
      return;
    const secs = [...(Settings.get('sidebarSections') || DEFAULT_SIDEBAR_SECTIONS)];
    const from = secs.indexOf(dragKey);
    let to = secs.indexOf(targetKey);
    if (from < 0 || to < 0) return;
    secs.splice(from, 1);
    to = secs.indexOf(targetKey); // recompute after removal
    secs.splice(to, 0, dragKey); // insert before the drop target
    commit(secs);
  };
  container.onkeydown = (e) => {
    if (!e.altKey || (e.key !== 'ArrowUp' && e.key !== 'ArrowDown')) return;
    const row = (e.target as HTMLElement).closest<HTMLElement>('.sidebar-order-row[data-key]');
    const key = row?.dataset.key as SidebarSection | undefined;
    if (!key || key === 'all' || row?.classList.contains('sidebar-order-hidden')) return;
    const secs = [...(Settings.get('sidebarSections') || DEFAULT_SIDEBAR_SECTIONS)];
    const from = secs.indexOf(key);
    const to = from + (e.key === 'ArrowUp' ? -1 : 1);
    if (from < 1 || to < 1 || to >= secs.length) return;
    e.preventDefault();
    [secs[from], secs[to]] = [secs[to], secs[from]];
    commit(secs);
  };
}

// ── Panel order editor ────────────────────────────────────────────────────

export function buildPanelOrderEditor() {
  const container = document.getElementById('s-panel-order');
  if (!container) return;

  const ALL_PANELS = [
    { key: 'secrets', label: 'Secrets', removable: false },
    { key: 'tools', label: 'Tools', removable: true },
    { key: 'remote', label: 'Remote Vaults', removable: true },
    { key: 'users', label: 'Users (RBAC)', removable: true },
    { key: 'auth', label: 'Authenticator (2FA)', removable: true },
  ];

  const order = [...(Settings.get('panelOrder') || ALL_PANELS.map((p) => p.key))];
  setHtml(container, '');

  order.forEach((pKey, i) => {
    const def = ALL_PANELS.find((p) => p.key === pKey);
    if (!def) return;
    const row = document.createElement('div');
    row.className = 'sidebar-order-row';
    row.dataset.key = pKey;
    const isFirst = i === 0,
      isLast = i === order.length - 1;
    setHtml(
      row,
      html` <span class="sidebar-order-label">${def.label}</span>
        <div class="sidebar-order-btns">
          <button class="btn-xs" data-action="up" ${isFirst ? 'disabled' : ''}>▲</button>
          <button class="btn-xs" data-action="down" ${isLast ? 'disabled' : ''}>▼</button>
          <button
            class="btn-xs"
            data-action="${def.removable ? 'remove' : 'locked'}"
            ${def.removable ? '' : 'disabled'}
            title="${def.removable ? 'Hide' : 'Cannot hide'}"
          >
            ✕
          </button>
        </div>`,
    );
    container.appendChild(row);
  });

  ALL_PANELS.filter((p) => !order.includes(p.key)).forEach((def) => {
    const row = document.createElement('div');
    row.className = 'sidebar-order-row sidebar-order-hidden';
    row.dataset.key = def.key;
    setHtml(
      row,
      html`<span class="sidebar-order-label sidebar-order-dim">${def.label}</span
        ><button class="btn-xs" data-action="add">+ Show</button>`,
    );
    container.appendChild(row);
  });

  container.onclick = (e) => {
    const btn = (e.target as HTMLElement).closest<HTMLElement>('[data-action]');
    if (!btn) return;
    const action = btn.dataset.action!;
    const rowEl = btn.closest<HTMLElement>('[data-key]')!;
    const key = rowEl.dataset.key!;
    const ord = [...(Settings.get('panelOrder') || ALL_PANELS.map((p) => p.key))];
    const idx = ord.indexOf(key);
    if (action === 'up' && idx > 0) {
      [ord[idx - 1], ord[idx]] = [ord[idx], ord[idx - 1]];
    } else if (action === 'down' && idx < ord.length - 1) {
      [ord[idx], ord[idx + 1]] = [ord[idx + 1], ord[idx]];
    } else if (action === 'remove') {
      ord.splice(idx, 1);
    } else if (action === 'add') {
      ord.push(key);
    }
    Settings.set('panelOrder', ord);
    applyPanelOrder();
    buildPanelOrderEditor();
  };
}

// ── Provider catalogue (Phase 31.1) ────────────────────────────────────────
// `unv catalogue show` / `update`. The signature check, rollback refusal and
// cache are all Rust (`vault_core::catalogue`); this row only asks. Like the TOTP
// code, it cannot work in a plain browser, and says so rather than pretending.

type CatalogueStatus = {
  source: 'catalogue' | 'bundled';
  generated_at?: string;
  providers?: number;
};

function describeCatalogue(c: CatalogueStatus): string {
  return c.source === 'catalogue'
    ? `Using the downloaded catalogue from ${c.generated_at ?? '?'} (${c.providers ?? 0} providers).`
    : 'Using the issuer list built into this app. Update to fetch newer signed entries.';
}

function wireCatalogueRow(): void {
  const status = document.getElementById('s-catalogue-status');
  const btn = document.getElementById('s-catalogue-update') as HTMLButtonElement | null;
  if (!status || !btn) return;
  if (!inTauri) {
    status.textContent = 'Available in the desktop app. In a terminal: unv catalogue update.';
    btn.disabled = true;
    return;
  }
  btn.disabled = false;
  invokeTauri<CatalogueStatus>('catalogue_status')
    .then((c) => (status.textContent = describeCatalogue(c)))
    .catch((e: unknown) => (status.textContent = `Cannot read the catalogue: ${String(e)}`));
  // Assignment, not addEventListener: this pane is opened repeatedly (invariant 9).
  btn.onclick = () => {
    btn.disabled = true;
    status.textContent = 'Fetching…';
    invokeTauri<{ generated_at: string; providers: number }>('catalogue_update', {})
      .then((r) => {
        status.textContent = describeCatalogue({ source: 'catalogue', ...r });
        showToast('Catalogue updated', 'ok', 1500);
      })
      .catch((e: unknown) => {
        // The Rust side names the reason: bad signature, rollback, unreachable.
        status.textContent = `Not updated: ${String(e)}`;
        showToast('Catalogue not updated', 'err', 2500);
      })
      .finally(() => (btn.disabled = false));
  };
}

// ── Full-fidelity archive (Phase 33.3) ──────────────────────────────────────
// `unv backup archive` / `restore-archive`. The cryptography and the checks are
// Rust (`unv_cli::backup`); this only collects a password and a file.

function pickTextFile(): Promise<string | null> {
  return new Promise((resolve) => {
    // Created and removed per use: a static file input is a ghost widget in
    // WebKitGTK (AGENTS.md, Phase 3).
    const inp = document.createElement('input');
    inp.type = 'file';
    inp.style.display = 'none';
    document.body.appendChild(inp);
    const done = (v: string | null) => {
      inp.remove();
      resolve(v);
    };
    inp.onchange = () => {
      const f = inp.files?.[0];
      if (!f) return done(null);
      f.text().then(done, () => done(null));
    };
    inp.click();
  });
}

function wireArchiveRows(): void {
  const make = document.getElementById('s-archive-btn') as HTMLButtonElement | null;
  const restore = document.getElementById('s-archive-restore-btn') as HTMLButtonElement | null;
  if (!make || !restore) return;
  if (!inTauri) {
    for (const b of [make, restore]) {
      b.disabled = true;
      b.title = 'Available in the desktop app. In a terminal: unv backup archive.';
    }
    return;
  }
  make.onclick = () => {
    void (async () => {
      const pw = await showPasswordPrompt(
        'Archive password (12+ characters). Keep it somewhere the archive is not.',
      );
      if (!pw) return;
      try {
        const text = await invokeTauri<string>('backup_archive_build', { password: pw });
        const r = await saveFile(text, 'unenverse.vaultarc', 'application/json');
        if (r.ok) showToast(`Archive written${r.path ? `: ${r.path}` : ''}`, 'ok', 3500);
        else showToast(`Could not write the archive: ${r.error}`, 'err', 4000);
      } catch (e) {
        showToast(`Archive failed: ${e instanceof Error ? e.message : String(e)}`, 'err', 4000);
      }
    })();
  };
  restore.onclick = () => {
    void (async () => {
      const text = await pickTextFile();
      if (text === null) return;
      const pw = await showPasswordPrompt('Password this archive was made with');
      if (!pw) return;
      const ok = await showConfirm(
        "Replace this machine's vault with the archive? The current vault is overwritten and cannot be recovered from here.",
      );
      if (!ok) return;
      try {
        await invokeTauri('backup_archive_restore', { text, password: pw });
        showToast("Restored. Reloading; unlock with the archive's master password.", 'ok', 3000);
        setTimeout(() => window.location.reload(), 800);
      } catch (e) {
        showToast(`Restore failed: ${e instanceof Error ? e.message : String(e)}`, 'err', 5000);
      }
    })();
  };
}

// ── Entropy source (Phase 33.4) ────────────────────────────────────────────
// Options come from `entropy_sources` rather than a list here, so the dropdown
// can never offer a source the backend would refuse. Applied on Save.

async function wireEntropyRow(current: string): Promise<void> {
  const sel = document.getElementById('s-entropy-source') as HTMLSelectElement | null;
  if (!sel) return;
  if (!inTauri) {
    sel.disabled = true;
    sel.title =
      'Hardware entropy sources are available in the desktop app. In a terminal: --entropy-source.';
    return;
  }
  try {
    const sources =
      await invokeTauri<{ id: string; ready: boolean; detail: string }[]>('entropy_sources');
    sel.replaceChildren(
      ...sources.map((src) => {
        const o = document.createElement('option');
        o.value = src.id;
        o.textContent = src.id === 'os' ? 'Operating system' : src.id;
        if (!src.ready) {
          o.disabled = true;
          o.textContent += ` (unavailable: ${src.detail})`;
        }
        return o;
      }),
    );
    sel.value = current;
  } catch (e) {
    sel.title = `Cannot list entropy sources: ${String(e)}`;
  }
}

// ── The Copy section's worked example ──────────────────────────────────────

/**
 * A worked example that re-renders as the four copy options change.
 *
 * These are interacting switches — profile, metadata style, case, prefix — and
 * a list of four labels with no preview is how a settings panel becomes
 * unreadable. The example uses a fixed invented entry rather than one of the
 * user's: the panel must show the same thing on an empty vault, and a real
 * credential's name in a settings screenshot is a small leak for no gain.
 */
const COPY_PREVIEW_ENTRY = {
  provider: 'Spotify',
  label: 'game',
  version: '2',
  primary_role: 'id',
  api_key: 'djjsdjdj',
  api_secret: 'shhh',
  env_prefixes: ['ND'],
  environment: 'production',
  expires_at: '2026-12-01',
  rate_limit_count: 100,
  rate_limit_period: 'minute',
  scopes: ['playlist-read'],
  tags: ['music'],
  projectIds: ['Universal', 'jukebox'],
  rotation_days: 90,
} as unknown as VaultEntry;

function renderCopyPreview(): void {
  const out = document.getElementById('s-copy-preview');
  if (!out) return;
  const val = (id: string) =>
    (document.getElementById(id) as HTMLSelectElement | null)?.value ?? '';
  out.textContent = buildCopyText(COPY_PREVIEW_ENTRY, {
    profile: (val('s-copy-profile') || 'basic') as CopyProfile,
    metadataStyle: (val('s-metadata-style') || 'comment') as MetadataStyle,
    case: (val('s-env-copy-case') || 'upper') as EnvNameCase,
    includePrefix: !!(document.getElementById('s-env-include-prefix') as HTMLInputElement | null)
      ?.checked,
  });
}

let _copyPreviewBound = false;

/** Assignment-guarded (invariant 9): `openSettings` runs on every open. */
function wireCopyPreview(): void {
  if (_copyPreviewBound) return;
  _copyPreviewBound = true;
  for (const id of [
    's-copy-profile',
    's-metadata-style',
    's-env-copy-case',
    's-env-include-prefix',
  ]) {
    document.getElementById(id)?.addEventListener('change', renderCopyPreview);
  }
}

export function applyPanelOrder() {
  const order = Settings.get('panelOrder') || ['secrets', 'tools', 'remote', 'users', 'auth'];
  document.querySelectorAll<HTMLButtonElement>('.activity-btn[data-panel]').forEach((btn) => {
    const panel = btn.dataset.panel!;
    const idx = order.indexOf(panel);
    if (idx >= 0) {
      btn.style.display = '';
      btn.style.order = String(idx);
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
  const tabs = document.querySelectorAll<HTMLButtonElement>('.settings-tab');
  const panes = document.querySelectorAll<HTMLElement>('.settings-tab-pane');
  tabs.forEach((tab) => {
    tab.addEventListener('click', () => {
      tabs.forEach((t) => t.classList.remove('active'));
      panes.forEach((p) => p.classList.remove('active'));
      tab.classList.add('active');
      const pane = document.querySelector<HTMLElement>(
        `.settings-tab-pane[data-spane="${tab.dataset.stab}"]`,
      );
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

  if (!_tabsInited) {
    initSettingsTabs();
    _tabsInited = true;
  }

  buildThemeSwatches();
  buildSidebarOrderEditor();
  buildPanelOrderEditor();

  (document.getElementById('s-accent') as HTMLInputElement).value = s.accentColor;
  document.getElementById('s-accent-val')!.textContent = s.accentColor;
  (document.getElementById('s-autolock') as HTMLInputElement).value = String(s.autoLockMinutes);
  (document.getElementById('s-lock-on-hide') as HTMLInputElement).checked = s.lockOnHide;
  (document.getElementById('s-mask') as HTMLInputElement).checked = s.maskKeysByDefault;
  (document.getElementById('s-expiry-warn') as HTMLInputElement).checked = s.showExpiryWarning;
  (document.getElementById('s-expiry-days') as HTMLInputElement).value = String(
    s.expiryWarningDays,
  );
  (document.getElementById('s-default-account') as HTMLInputElement).value = s.defaultAccount || '';
  (document.getElementById('s-export-format') as HTMLSelectElement).value = s.defaultExportFormat;
  (document.getElementById('s-env-copy-field') as HTMLSelectElement).value =
    s.envCopyField || 'api_key';
  (document.getElementById('s-copy-profile') as HTMLSelectElement).value = s.copyProfile || 'basic';
  (document.getElementById('s-metadata-style') as HTMLSelectElement).value =
    s.metadataStyle || 'comment';
  (document.getElementById('s-env-copy-case') as HTMLSelectElement).value =
    s.envCopyCase || 'upper';
  (document.getElementById('s-env-include-prefix') as HTMLInputElement).checked =
    !!s.envIncludePrefix;
  wireCopyPreview();
  renderCopyPreview();
  (document.getElementById('s-custom-css') as HTMLTextAreaElement).value = s.customCss || '';
  (document.getElementById('s-group-by-type') as HTMLInputElement).checked = s.groupByType;
  (document.getElementById('s-remember-filters') as HTMLInputElement).checked =
    s.rememberFilters !== false;
  (document.getElementById('s-experimental-ptypes') as HTMLInputElement).checked =
    !!s.experimentalProjectTypes;
  (document.getElementById('s-keep-local-unlocked') as HTMLInputElement).checked =
    !!s.keepLocalUnlocked;

  // Assignment, not addEventListener: the settings pane is opened repeatedly and
  // `{ once: true }` only detaches after a click, so every open that did not
  // click left another handler attached and they all fired together later.
  const clearRecent = document.getElementById('s-clear-recent');
  if (clearRecent)
    (clearRecent as HTMLElement).onclick = () => {
      Settings.set('recentSearches', []);
      showToast('Search history cleared', 'ok', 1500);
    };

  wireCatalogueRow();
  wireArchiveRows();
  void wireEntropyRow(s.entropySource || 'os');

  const runOnboarding = document.getElementById('s-run-onboarding');
  if (runOnboarding)
    (runOnboarding as HTMLElement).onclick = async () => {
      // Closing Settings first: the wizard edits two of the settings this panel
      // is showing, and leaving the panel open behind it would display stale
      // values that overwrite the wizard's on the next Save.
      closeSettings();
      const { showOnboarding } = await import('./onboarding');
      const { openAdd } = await import('./modals');
      showOnboarding({
        onAdd: () => openAdd(),
        // Re-running the wizard from Settings has no file picker to hand it —
        // that closure lives in `init()`. Pointing at the load banner's browse
        // button is the same action by a different route.
        onImport: () => document.getElementById('load-banner-browse-btn')?.click(),
      });
    };

  ['s-card-size', 's-grid-cols', 's-activity-bar-position', 's-activity-bar-style'].forEach(
    (id) => {
      const key =
        id === 's-card-size'
          ? 'cardSize'
          : id === 's-grid-cols'
            ? 'gridColumns'
            : id === 's-activity-bar-position'
              ? 'activityBarPosition'
              : 'activityBarStyle';
      const current = Settings.get(key as keyof AppSettings);
      const currentValue =
        typeof current === 'string' || typeof current === 'number' ? String(current) : '';
      document
        .querySelectorAll<HTMLButtonElement>(`#${id} button`)
        .forEach((btn) => btn.classList.toggle('active', btn.dataset.val === currentValue));
    },
  );

  // accent reset
  const resetBtn = document.getElementById('s-accent-reset');
  if (resetBtn)
    resetBtn.onclick = () => {
      (document.getElementById('s-accent') as HTMLInputElement).value = '#7364c9';
      document.getElementById('s-accent-val')!.textContent = '#7364c9';
    };
  // accent live preview
  const accentInput = document.getElementById('s-accent') as HTMLInputElement | null;
  if (accentInput)
    accentInput.oninput = () => {
      document.getElementById('s-accent-val')!.textContent = accentInput.value;
    };

  // seg-control buttons
  document.querySelectorAll<HTMLElement>('.seg-control').forEach((ctrl) => {
    ctrl.querySelectorAll<HTMLButtonElement>('button').forEach((btn) => {
      btn.onclick = () => {
        ctrl.querySelectorAll('button').forEach((b) => b.classList.remove('active'));
        btn.classList.add('active');
      };
    });
  });

  document.getElementById('settings-overlay')!.classList.add('open');

  // footer buttons
  const saveBtn = document.getElementById('settings-save');
  const cancelBtn = document.getElementById('settings-cancel');
  if (saveBtn)
    saveBtn.onclick = () => {
      saveSettings();
      closeSettings();
    };
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
  const getSegVal = (id: string) =>
    document.querySelector<HTMLButtonElement>(`#${id} button.active`)?.dataset.val;

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
      'err',
      4000,
    );
  }

  Settings.setAll({
    accentColor: (document.getElementById('s-accent') as HTMLInputElement).value,
    autoLockMinutes,
    lockOnHide: (document.getElementById('s-lock-on-hide') as HTMLInputElement).checked,
    maskKeysByDefault: (document.getElementById('s-mask') as HTMLInputElement).checked,
    showExpiryWarning: (document.getElementById('s-expiry-warn') as HTMLInputElement).checked,
    expiryWarningDays:
      parseInt((document.getElementById('s-expiry-days') as HTMLInputElement).value) || 30,
    defaultAccount: (document.getElementById('s-default-account') as HTMLInputElement).value.trim(),
    defaultExportFormat: (document.getElementById('s-export-format') as HTMLSelectElement)
      .value as AppSettings['defaultExportFormat'],
    envCopyField: (document.getElementById('s-env-copy-field') as HTMLSelectElement)
      .value as AppSettings['envCopyField'],
    copyProfile: (document.getElementById('s-copy-profile') as HTMLSelectElement)
      .value as AppSettings['copyProfile'],
    metadataStyle: (document.getElementById('s-metadata-style') as HTMLSelectElement)
      .value as AppSettings['metadataStyle'],
    envCopyCase: (document.getElementById('s-env-copy-case') as HTMLSelectElement)
      .value as AppSettings['envCopyCase'],
    envIncludePrefix: (document.getElementById('s-env-include-prefix') as HTMLInputElement).checked,
    customCss: (document.getElementById('s-custom-css') as HTMLTextAreaElement).value,
    groupByType: (document.getElementById('s-group-by-type') as HTMLInputElement).checked,
    rememberFilters: (document.getElementById('s-remember-filters') as HTMLInputElement).checked,
    experimentalProjectTypes: (document.getElementById('s-experimental-ptypes') as HTMLInputElement)
      .checked,
    keepLocalUnlocked: (document.getElementById('s-keep-local-unlocked') as HTMLInputElement)
      .checked,
    entropySource: (document.getElementById('s-entropy-source') as HTMLSelectElement).value || 'os',
    activityBarPosition: (getSegVal('s-activity-bar-position') || 'left') as 'left' | 'right',
    activityBarStyle: (getSegVal('s-activity-bar-style') || 'icon') as 'icon' | 'icon-label',
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
  import('./lock').then((m) => m.resetLock()).catch(() => {});
  _settingsSnapshot = Settings.getAll();
  showToast('Settings saved', 'ok', 1500);
}

export function closeSettings() {
  document.getElementById('settings-overlay')!.classList.remove('open');
}
