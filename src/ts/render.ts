/**
 * @file Render: sidebar, project tree, card grid, config view, copy-all button.
 */

import type { VaultEntry, SecretType, Project, ProjectType, SecretChunk, ChunkFieldType } from './types';
import { st, Settings, setRenderFn, applyGridSettings, dotenvKey } from './state';
import { getFiltered, sorted, buildProjectTree, getDescendantProjectIds } from './filters';
import { iconHTML } from './icons';
import { esc, escAttr, maskKey, showToast, showConfirm, showPrompt, showPromptLarge, clipboardWrite, eyeSVG, copySVG, editSVG, delSVG, dupSVG } from './utils';
import { TYPE_CONFIG, showDropdown, markAsRotated } from './modals';
import {
  renderChunkCard,
  renderDockerServicesCard,
  getProjectTypeLabel,
  makeConfigViewHeaderBtns,
  exportWireGuard,
  exportDockerCompose,
  exportServicesSection,
  exportNginx,
  exportK8s,
  exportSshConfig,
  exportTraefik,
  exportApache,
  exportHaproxy,
  exportAnsible,
  exportPostgres,
  parseWgConf,
  parseDockerCompose,
  parseSshConfig,
  parseNginxConf,
  parseApacheConf,
  parseHaproxyConf,
  pickFileText,
  openChunkEditModal,
  resolveFieldRef,
  chunkToString,
} from './chunk-ops';
import { parseEnvFile } from './import-export';

// ── Project tree renderers ─────────────────────────────────────────────────

export function renderProjectTree() {
  const container = document.getElementById('project-tree');
  if (!container) return;
  container.innerHTML = '';
  renderUserCatTree(container, st.vault.user_categories || [], st.vault.api_keys);
}

function renderProjectList(container: HTMLElement, projects: Project[], all: VaultEntry[]) {
  const tree = buildProjectTree(projects.filter(p => p.id !== 'Universal'));
  function renderNode(node: any, depth: number) {
    const nodeId: string = node.virtual ? 'virtual:' + node.name : node.id;
    const descendantIds = getDescendantProjectIds(nodeId);
    const count = all.filter(k =>
      k.projectIds && descendantIds.some(pid => k.projectIds!.includes(pid))
    ).length;
    const displayName = node.name.split('/').pop()!;
    const isActive = st.currentSelectedProjectIds[0] === nodeId;
    const _ptLabels: Record<string, string> = { wireguard: 'WG', docker: 'DC', nginx: 'Nginx', kubernetes: 'K8s', ssh_config: 'SSH', traefik: 'TF' };
    const ptBadge = !node.virtual && node.project_type && node.project_type !== 'generic'
      ? ` <span class="badge badge-ptype">${_ptLabels[node.project_type] ?? node.project_type}</span>`
      : '';
    const row = document.createElement('div');
    row.className = 'sidebar-cat-row';
    row.style.paddingLeft = `${depth * 14}px`;
    if (node.virtual) {
      row.innerHTML = `
        <button class="sidebar-item${isActive ? ' active' : ''}" data-project-id="${escAttr(nodeId)}" style="color:var(--text3)">
          <span class="sidebar-label" style="font-weight:600;font-size:10.5px;text-transform:uppercase;letter-spacing:.06em">${esc(displayName)}</span>
          <span class="sidebar-count">${count}</span>
        </button>`;
    } else {
      row.innerHTML = `
        <button class="sidebar-item${isActive ? ' active' : ''}" data-project-id="${escAttr(nodeId)}">
          <span class="sidebar-label">${esc(displayName)}${ptBadge}</span>
          <span class="sidebar-count">${count}</span>
        </button>
        <button class="sidebar-cat-del rename-proj" data-project="${escAttr(node.id)}" title="Rename">✎</button>
        <button class="sidebar-cat-del delete-proj" data-project="${escAttr(node.id)}" title="Delete">✕</button>`;
    }
    container.appendChild(row);
    for (const child of node.children) renderNode(child, depth + 1);
  }
  for (const node of tree) renderNode(node, 0);
}

// ── Sidebar ────────────────────────────────────────────────────────────────

function renderSidebar() {
  const all = st.vault.api_keys;
  document.getElementById('count-all')!.textContent = String(all.length);
  document.getElementById('count-free')!.textContent = String(all.filter(k => k.price_type === 'free').length);
  document.getElementById('count-local')!.textContent = String(all.filter(k => k.price_type === 'local').length);
  document.getElementById('count-paid')!.textContent = String(all.filter(k => k.price_type === 'paid').length);
  document.getElementById('count-conditional')!.textContent = String(all.filter(k => k.price_type === 'conditional').length);
  const stTypes: SecretType[] = ['api_key', 'password', 'env_var', 'connection_string', 'ssh_key', 'certificate', 'file_blob'];
  stTypes.forEach(stType => {
    const el = document.getElementById(`count-st-${stType}`);
    if (el) el.textContent = String(all.filter(k => (k.secretType || 'api_key') === stType).length);
  });

  // Environment counts
  const envValues = ['production', 'staging', 'development', 'testing'] as const;
  envValues.forEach(env => {
    const el = document.getElementById(`count-env-${env}`);
    if (el) el.textContent = String(all.filter(k => k.environment === env).length);
  });

  // Update active state for both st.filter items and env filter items
  document.querySelectorAll<HTMLButtonElement>('.sidebar-item[data-filter-type]').forEach(btn => {
    const t = btn.dataset.filterType;
    const v = btn.dataset.filterValue ?? '';
    if (t === 'env') {
      btn.classList.toggle('active', st.currentEnvFilter === v && v !== '');
    } else {
      btn.classList.toggle('active', (t === 'all' && st.filter.type === 'all' && !st.currentEnvFilter) || (t === st.filter.type && v === st.filter.value));
    }
  });

  const catList = document.getElementById('category-list')!;
  catList.innerHTML = '';
  renderProjectList(catList, st.vault.projects || [], all);

  renderTagSection(all);
}

function renderTagSection(all: VaultEntry[]) {
  const container = document.getElementById('tag-filter-list');
  if (!container) return;

  // Collect unique tags with counts
  const tagMap = new Map<string, number>();
  for (const k of all) {
    for (const t of (k.tags ?? [])) {
      tagMap.set(t, (tagMap.get(t) ?? 0) + 1);
    }
  }

  const section = document.getElementById('sidebar-section-tags');
  if (section) section.style.display = tagMap.size > 0 ? '' : 'none';

  container.innerHTML = [...tagMap.entries()]
    .sort((a, b) => a[0].localeCompare(b[0]))
    .map(([tag, count]) => {
      const active = st.activeTagFilter === tag;
      const style = tagColor(tag);
      return `<div class="sidebar-cat-row">
        <button class="sidebar-item tag-filter-btn${active ? ' active' : ''}" data-tag="${escAttr(tag)}">
          <span class="tag-chip-sidebar" style="${style}">${esc(tag)}</span>
          <span class="sidebar-count">${count}</span>
        </button>
      </div>`;
    }).join('');
}

function renderUserCatTree(container: HTMLElement, cats: string[], all: VaultEntry[]) {
  type CatNode = { name: string; real: boolean; children: CatNode[] };
  const byName = new Map<string, CatNode>();
  for (const cat of cats) {
    byName.set(cat, { name: cat, real: true, children: [] });
  }
  for (const cat of cats) {
    const parts = cat.split('/');
    for (let i = 1; i < parts.length; i++) {
      const ancestorName = parts.slice(0, i).join('/');
      if (!byName.has(ancestorName)) {
        byName.set(ancestorName, { name: ancestorName, real: false, children: [] });
      }
    }
  }
  const roots: CatNode[] = [];
  for (const [name, node] of byName) {
    const parts = name.split('/');
    if (parts.length === 1) { roots.push(node); }
    else { byName.get(parts.slice(0, -1).join('/'))?.children.push(node); }
  }
  for (const [, node] of byName) node.children.sort((a, b) => a.name.localeCompare(b.name));
  roots.sort((a, b) => a.name.localeCompare(b.name));

  function renderCatNode(node: CatNode, depth: number) {
    const pfx = node.name + '/';
    const count = all.filter(k => (k.categories || []).some(c => c === node.name || c.startsWith(pfx))).length;
    const displayName = node.name.split('/').pop()!;
    const isActive = st.filter.type === 'category' && st.filter.value === node.name;
    const indent = depth * 14;
    const row = document.createElement('div');
    row.className = 'sidebar-cat-row';
    row.style.paddingLeft = `${indent}px`;
    if (!node.real) {
      row.innerHTML = `
        <button class="sidebar-item${isActive ? ' active' : ''}" data-filter-type="category" data-filter-value="${escAttr(node.name)}" style="color:var(--text3)">
          <span class="sidebar-label" style="font-weight:600;font-size:10.5px;text-transform:uppercase;letter-spacing:.06em">${esc(displayName)}</span>
          <span class="sidebar-count">${count}</span>
        </button>`;
    } else {
      row.innerHTML = `
        <button class="sidebar-item${isActive ? ' active' : ''}" data-filter-type="category" data-filter-value="${escAttr(node.name)}">
          <span class="sidebar-label">${esc(displayName)}</span>
          <span class="sidebar-count">${count}</span>
        </button>
        <button class="sidebar-cat-del rename-cat" data-category="${escAttr(node.name)}" title="Rename">✎</button>
        <button class="sidebar-cat-del delete-cat" data-category="${escAttr(node.name)}" title="Delete">✕</button>`;
    }
    container.appendChild(row);
    for (const child of node.children) renderCatNode(child, depth + 1);
  }
  for (const root of roots) renderCatNode(root, 0);
}

// ── Grid ───────────────────────────────────────────────────────────────────

export function renderGrid() {
  const items = sorted(getFiltered());
  const grid = document.getElementById('card-grid')!;
  document.getElementById('result-count')!.textContent = `${items.length} secret${items.length !== 1 ? 's' : ''}`;
  applyGridSettings();
  if (!items.length) {
    grid.innerHTML = `<div class="empty-state"><svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg><p>No secrets found</p><small>${st.searchQ ? 'Try a different search' : 'Add a secret or import a backup'}</small></div>`;
    return;
  }
  grid.innerHTML = '';
  if (Settings.get('groupByType')) {
    const GROUP_ORDER: SecretType[] = ['api_key', 'password', 'env_var', 'connection_string', 'ssh_key', 'certificate', 'file_blob'];
    const GROUP_LABELS: Record<string, string> = { api_key: 'API Keys', password: 'Passwords', env_var: 'Env Variables', connection_string: 'Connections', ssh_key: 'SSH Keys', certificate: 'Certificates', file_blob: 'File Blobs' };
    const groups = new Map<SecretType, VaultEntry[]>();
    items.forEach(entry => {
      const stType = (entry.secretType || 'api_key') as SecretType;
      if (!groups.has(stType)) groups.set(stType, []);
      groups.get(stType)!.push(entry);
    });
    let animIdx = 0;
    GROUP_ORDER.forEach(stType => {
      const groupItems = groups.get(stType);
      if (!groupItems?.length) return;
      const hdr = document.createElement('div');
      hdr.className = 'type-group-header';
      hdr.textContent = GROUP_LABELS[stType] || stType;
      grid.appendChild(hdr);
      groupItems.forEach(entry => grid.appendChild(buildCard(entry, st.vault.api_keys.indexOf(entry), animIdx++)));
    });
  } else {
    items.forEach((entry, i) => grid.appendChild(buildCard(entry, st.vault.api_keys.indexOf(entry), i)));
  }
}

function buildCard(entry: VaultEntry, idx: number, animIdx: number): HTMLElement {
  const isExp = st.allExpanded || st.expanded.has(idx);
  const pt = entry.price_type || 'free';
  const expiry = expiryBadge(entry);
  const envBadge = entry.environment ? `<span class="badge badge-env" data-env="${entry.environment}">${entry.environment}</span>` : '';
  const keyIdBadge = entry.key_id ? `<span class="badge badge-keyid">${esc(entry.key_id)}</span>` : '';
  const typeBadge = entry.secretType && entry.secretType !== 'api_key' ? `<span class="badge badge-keyid">${entry.secretType}</span>` : '';
  const hasMask = Settings.get('maskKeysByDefault');
  const envFmt = Settings.get('defaultExportFormat');
  const envLabel = envFmt === 'yaml' ? 'YAML' : '.env';

  const card = document.createElement('div');
  const expiryBorderCls = getExpiryBorderClass(entry);
  const pinnedCls = entry.pinned ? ' pinned' : '';
  card.className = `card${isExp ? ' expanded' : ''}${expiryBorderCls}${pinnedCls}`;
  card.style.animationDelay = `${Math.min(animIdx * 20, 180)}ms`;
  card.dataset.idx = String(idx);

  // Only http/https URLs are rendered as links — blocks javascript: and data: URIs.
  const safeUrl = (raw: string | null | undefined): string => {
    if (!raw) return '';
    const trimmed = raw.trim();
    if (/^https?:\/\//i.test(trimmed)) return `<a href="${esc(trimmed)}" target="_blank" rel="noopener noreferrer">${esc(trimmed)}</a>`;
    return esc(trimmed); // render as plain text if not http/https
  };

  const metaRows: Array<[string, string]> = [];
  if (entry.version) metaRows.push(['Version', esc(entry.version)]);
  if (entry.rate_limit) metaRows.push(['Rate Limit', esc(entry.rate_limit)]);
  if (entry.expires_at) metaRows.push(['Expires', esc(entry.expires_at)]);
  if (entry.api_url) metaRows.push(['API URL', safeUrl(entry.api_url)]);
  if (entry.callback_url) metaRows.push(['Callback', safeUrl(entry.callback_url)]);
  if (entry.details) metaRows.push(['Details', esc(entry.details)]);

  const projectBadges = entry.projectIds?.filter(pid => pid !== 'Universal').map(pid => {
    const proj = st.vault.projects.find(p => p.id === pid);
    if (!proj) return '';
    const leaf = proj.name.includes('/') ? proj.name.split('/').pop()! : proj.name;
    return `<span class="badge badge-keyid" style="background:var(--accent-dim)" title="${escAttr(proj.name)}">${esc(leaf)}</span>`;
  }).join('') || '';

  card.innerHTML = `
    <div class="bulk-checkbox" data-action="bulk-toggle" data-idx="${idx}"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><polyline points="20 6 9 20 4 15"/></svg></div>
    <div class="card-head" data-action="copy-env" data-idx="${idx}">
      <div class="provider-icon-wrap" data-action="icon" data-idx="${idx}">
        ${iconHTML(entry.provider, entry.custom_icon)}
      </div>
      <div class="card-meta">
        <div class="card-provider">
          ${esc(entry.provider)}
          ${entry.pinned ? `<span class="pin-badge" title="Pinned"><svg width="9" height="9" viewBox="0 0 24 24" fill="currentColor" stroke="none"><path d="M5 17h14v-1.76a2 2 0 0 0-1.11-1.79l-1.78-.9A2 2 0 0 1 15 10.76V6h1a2 2 0 0 0 0-4H8a2 2 0 0 0 0 4h1v4.76a2 2 0 0 1-1.11 1.79l-1.78.9A2 2 0 0 0 5 15.24Z"/></svg></span>` : ''}
          <span class="badge badge-price" data-price="${pt}">${pt}</span>
          ${envBadge}${keyIdBadge}${typeBadge}${expiry}
        </div>
        <div class="card-account">${esc(entry.account_name || entry.username || entry.email || '')}</div>
        <div class="card-projects" style="margin-top: 4px; display: flex; gap: 4px; flex-wrap: wrap;">${projectBadges}</div>
      </div>
      <button class="card-chevron" data-action="toggle" data-idx="${idx}"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="6 9 12 15 18 9"/></svg></button>
    </div>
    ${entry.api_description ? `<div class="card-apidesc">${esc(entry.api_description)}</div>` : ''}
    <div class="card-body">
      <div class="key-section">
        <div class="key-row">
          <div class="key-label">${(TYPE_CONFIG[entry.secretType || 'api_key']?.keyLabel || 'API Key').toUpperCase()}</div>
          <div class="key-value${hasMask ? '' : ' revealed'}" id="kv-key-${idx}" data-action="copy-field" data-value="${escAttr(entry.api_key)}">${hasMask ? maskKey(entry.api_key) : esc(entry.api_key)}</div>
          <div class="key-actions">
            <button class="icon-btn sm${hasMask ? '' : ' active'}" id="reveal-key-${idx}" data-action="reveal" data-field="key" data-idx="${idx}" data-value="${escAttr(entry.api_key)}">${eyeSVG}</button>
            <button class="icon-btn sm" data-action="copy-field" data-value="${escAttr(entry.api_key)}">${copySVG}</button>
          </div>
        </div>
        ${entry.api_secret ? `<div class="key-row"><div class="key-label">SECRET</div><div class="key-value${hasMask ? '' : ' revealed'}" id="kv-secret-${idx}" data-action="copy-field" data-value="${escAttr(entry.api_secret)}">${hasMask ? maskKey(entry.api_secret) : esc(entry.api_secret)}</div><div class="key-actions"><button class="icon-btn sm${hasMask ? '' : ' active'}" id="reveal-secret-${idx}" data-action="reveal" data-field="secret" data-idx="${idx}" data-value="${escAttr(entry.api_secret)}">${eyeSVG}</button><button class="icon-btn sm" data-action="copy-field" data-value="${escAttr(entry.api_secret)}">${copySVG}</button></div></div>` : ''}
        ${entry.username ? `<div class="key-row"><div class="key-label">USERNAME</div><div class="key-value" data-action="copy-field" data-value="${escAttr(entry.username)}">${esc(entry.username)}</div><button class="icon-btn sm" data-action="copy-field" data-value="${escAttr(entry.username)}">${copySVG}</button></div>` : ''}
        ${entry.email ? `<div class="key-row"><div class="key-label">EMAIL</div><div class="key-value" data-action="copy-field" data-value="${escAttr(entry.email)}">${esc(entry.email)}</div><button class="icon-btn sm" data-action="copy-field" data-value="${escAttr(entry.email)}">${copySVG}</button></div>` : ''}
      </div>
      ${entry.scopes?.length ? `<div class="scopes-row">${entry.scopes.map(s => `<span class="scope-pill">${esc(s)}</span>`).join('')}</div>` : ''}
      ${entry.description ? `<div class="desc-section"><button class="desc-toggle" data-action="toggle-desc"><svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="9 18 15 12 9 6"/></svg>General Description</button><div class="desc-content">${esc(entry.description)}</div></div>` : ''}
      ${metaRows.length ? `<div class="meta-section">${metaRows.map(([k, v]) => `<div class="meta-row"><span class="meta-key">${k}</span><span class="meta-val">${v}</span></div>`).join('')}</div>` : ''}
      ${entry.categories?.length ? `<div class="cat-pills">${entry.categories.map(c => `<span class="cat-pill">${esc(c)}</span>`).join('')}</div>` : ''}
      ${entry.last_rotated_at ? `<div class="meta-section"><div class="meta-row"><span class="meta-key">Last Rotated</span><span class="meta-val" style="color:var(--text2)">${esc(entry.last_rotated_at)}</span> ${rotationAgeBadge(entry)}</div></div>` : ''}
    </div>
    ${entry.tags?.length ? `<div class="card-tags">${entry.tags.map(t => `<span class="tag-chip-card" style="${tagColor(t)}">${esc(t)}</span>`).join('')}</div>` : ''}
    <div class="card-foot">
      <button class="env-copy-btn" id="env-btn-${idx}" data-action="copy-env" data-idx="${idx}">${copySVG}<span class="env-format-badge">${envLabel}</span><span id="env-label-${idx}">${dotenvKey(entry)}</span></button>
      <button class="icon-btn sm" data-action="rotate" data-idx="${idx}" title="Mark as rotated" style="font-size:11px;gap:3px;">↺</button>
      <button class="icon-btn sm${entry.pinned ? ' pin-btn active' : ' pin-btn'}" data-action="pin" data-idx="${idx}" title="${entry.pinned ? 'Unpin' : 'Pin to top'}"><svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="12" y1="17" x2="12" y2="22"/><path d="M5 17h14v-1.76a2 2 0 0 0-1.11-1.79l-1.78-.9A2 2 0 0 1 15 10.76V6h1a2 2 0 0 0 0-4H8a2 2 0 0 0 0 4h1v4.76a2 2 0 0 1-1.11 1.79l-1.78.9A2 2 0 0 0 5 15.24Z"/></svg></button>
      <button class="icon-btn sm" data-action="duplicate" data-idx="${idx}" title="Duplicate">${dupSVG}</button>
      <button class="icon-btn sm" data-action="edit" data-idx="${idx}" title="Edit">${editSVG}</button>
      <button class="icon-btn sm danger" data-action="delete" data-idx="${idx}" title="Delete">${delSVG}</button>
    </div>`;
  return card;
}

function getExpiryBorderClass(entry: VaultEntry): string {
  if (!entry.expires_at) return '';
  const days = Math.round((new Date(entry.expires_at).getTime() - Date.now()) / 86400000);
  if (days < 0) return ' expiry-urgent';
  if (days <= 7)  return ' expiry-urgent';
  if (days <= 30) return ' expiry-warn';
  return ' expiry-safe';
}

function rotationAgeBadge(entry: VaultEntry): string {
  if (!entry.last_rotated_at) return '';
  const days = Math.round((Date.now() - new Date(entry.last_rotated_at).getTime()) / 86400000);
  const cls = days < 30 ? ' fresh' : '';
  const label = days === 0 ? 'today' : days === 1 ? '1d ago' : `${days}d ago`;
  return `<span class="rotation-age-badge${cls}">${label}</span>`;
}

const TAG_COLORS = [
  'background:rgba(115,100,201,.18);color:#a699e8',
  'background:rgba(79,201,126,.15);color:#4fc97e',
  'background:rgba(201,100,100,.15);color:#e07070',
  'background:rgba(88,180,220,.15);color:#58b4dc',
  'background:rgba(201,166,74,.15);color:#c9a64a',
  'background:rgba(180,88,220,.15);color:#b458dc',
];
function tagColor(tag: string): string {
  let h = 0;
  for (let i = 0; i < tag.length; i++) h = (h * 31 + tag.charCodeAt(i)) >>> 0;
  return TAG_COLORS[h % TAG_COLORS.length];
}

function expiryBadge(entry: VaultEntry): string {
  if (!Settings.get('showExpiryWarning') || !entry.expires_at) return '';
  const exp = new Date(entry.expires_at);
  const now = new Date();
  exp.setHours(23, 59, 59);
  const days = Math.round((exp.getTime() - now.getTime()) / 86400000);
  if (days < 0) return `<span class="badge badge-expiry-expired" title="${entry.expires_at}">Expired ${Math.abs(days)}d ago</span>`;
  if (days <= Settings.get('expiryWarningDays')) return `<span class="badge badge-expiry-warn" title="${entry.expires_at}">Expires in ${days}d</span>`;
  return '';
}

// ── Config view ────────────────────────────────────────────────────────────

function renderConfigView(project: Project) {
  const grid = document.getElementById('card-grid')!;
  document.getElementById('result-count')!.textContent = `${project.project_type} config`;
  applyGridSettings();
  grid.style.gridTemplateColumns = '1fr';

  const typeLabel = getProjectTypeLabel(project.project_type!);

  const wrapper = document.createElement('div');
  wrapper.className = 'config-view';

  const header = document.createElement('div');
  header.className = 'config-view-header';
  header.innerHTML = `
    <div class="config-view-header-meta">
      <span class="config-view-title">${esc(project.name)}</span>
      <span class="config-type-badge">${esc(typeLabel)}</span>
      ${project.description ? `<span style="font-size:11px;color:var(--text3)">${esc(project.description)}</span>` : ''}
    </div>
    <div class="config-view-header-btns">
      <button class="btn btn-ghost btn-sm" data-action="import-env-chunk" data-project-id="${escAttr(project.id)}">Import .env</button>
      ${makeConfigViewHeaderBtns(project)}
    </div>
  `;
  wrapper.appendChild(header);

  const chunks = project.chunks || [];
  const typeChunks = chunks.filter(c => c.chunk_type !== 'env_file');
  const envChunks  = chunks.filter(c => c.chunk_type === 'env_file');

  const makeCol = (label: string, items: SecretChunk[]) => {
    const col = document.createElement('div');
    col.className = 'chunks-col';
    const hdr = document.createElement('div');
    hdr.className = 'chunks-col-label';
    hdr.textContent = label;
    col.appendChild(hdr);
    for (const chunk of items) col.appendChild(renderChunkCard(chunk, project));
    return col;
  };

  if (project.project_type === 'wireguard') {
    const ifaceChunks = chunks.filter(c => c.chunk_type === 'wg_interface');
    const peerChunks  = chunks.filter(c => c.chunk_type === 'wg_peer');
    const otherChunks = chunks.filter(c => c.chunk_type !== 'wg_interface' && c.chunk_type !== 'wg_peer');
    if (ifaceChunks.length > 0 && peerChunks.length > 0) {
      const twoCol = document.createElement('div');
      twoCol.className = 'chunks-two-col';
      twoCol.appendChild(makeCol('Interface', ifaceChunks));
      twoCol.appendChild(makeCol('Peers', peerChunks));
      wrapper.appendChild(twoCol);
      if (otherChunks.length) {
        const extra = document.createElement('div');
        extra.className = 'chunks-grid';
        for (const chunk of otherChunks) extra.appendChild(renderChunkCard(chunk, project));
        wrapper.appendChild(extra);
      }
    } else {
      const chunksGrid = document.createElement('div');
      chunksGrid.className = 'chunks-grid';
      for (const chunk of chunks) chunksGrid.appendChild(renderChunkCard(chunk, project));
      wrapper.appendChild(chunksGrid);
    }
  } else if (project.project_type === 'nginx') {
    const nginxChunks = chunks.filter(c => c.chunk_type !== 'nginx_key' && c.chunk_type !== 'env_file');
    const keyChunks   = chunks.filter(c => c.chunk_type === 'nginx_key');
    const nginxEnvChunks = chunks.filter(c => c.chunk_type === 'env_file');
    if (keyChunks.length > 0 || nginxEnvChunks.length > 0) {
      const twoCol = document.createElement('div');
      twoCol.className = 'chunks-two-col';
      const leftGrid = document.createElement('div');
      leftGrid.className = 'chunks-grid nginx-grid';
      for (const chunk of nginxChunks) leftGrid.appendChild(renderChunkCard(chunk, project));
      twoCol.appendChild(leftGrid);
      const rightCol = document.createElement('div');
      rightCol.className = 'chunks-col';
      if (keyChunks.length) {
        const hdr = document.createElement('div');
        hdr.className = 'chunks-col-label';
        hdr.textContent = 'Key Files';
        rightCol.appendChild(hdr);
        for (const chunk of keyChunks) rightCol.appendChild(renderChunkCard(chunk, project));
      }
      if (nginxEnvChunks.length) {
        const hdr2 = document.createElement('div');
        hdr2.className = 'chunks-col-label';
        hdr2.textContent = 'Environment Files';
        rightCol.appendChild(hdr2);
        for (const chunk of nginxEnvChunks) rightCol.appendChild(renderChunkCard(chunk, project));
      }
      twoCol.appendChild(rightCol);
      wrapper.appendChild(twoCol);
    } else {
      const chunksGrid = document.createElement('div');
      chunksGrid.className = 'chunks-grid nginx-grid';
      for (const chunk of chunks) chunksGrid.appendChild(renderChunkCard(chunk, project));
      wrapper.appendChild(chunksGrid);
    }
  } else if (project.project_type === 'docker') {
    const netChunks = chunks.filter(c => c.chunk_type === 'docker_network');
    const volChunks = chunks.filter(c => c.chunk_type === 'docker_volume');
    const efChunks  = chunks.filter(c => c.chunk_type === 'env_file');

    const twoCol = document.createElement('div');
    twoCol.className = 'chunks-two-col chunks-two-col-docker';

    const leftCol = document.createElement('div');
    leftCol.className = 'chunks-col';
    leftCol.appendChild(renderDockerServicesCard(project));
    twoCol.appendChild(leftCol);

    const rightCol = document.createElement('div');
    rightCol.className = 'chunks-col';

    if (efChunks.length) {
      const hdr = document.createElement('div');
      hdr.className = 'chunks-col-label'; hdr.textContent = 'Environment Files';
      rightCol.appendChild(hdr);
      for (const chunk of efChunks) rightCol.appendChild(renderChunkCard(chunk, project));
    }
    if (netChunks.length) {
      const hdr = document.createElement('div');
      hdr.className = 'chunks-col-label'; hdr.textContent = 'Networks';
      rightCol.appendChild(hdr);
      for (const chunk of netChunks) rightCol.appendChild(renderChunkCard(chunk, project));
    }
    if (volChunks.length) {
      const hdr = document.createElement('div');
      hdr.className = 'chunks-col-label'; hdr.textContent = 'Volumes';
      rightCol.appendChild(hdr);
      for (const chunk of volChunks) rightCol.appendChild(renderChunkCard(chunk, project));
    }
    if (!efChunks.length && !netChunks.length && !volChunks.length) {
      const empty = document.createElement('div');
      empty.style.cssText = 'color:var(--text3);font-size:11px;padding:12px;text-align:center';
      empty.textContent = 'Add networks, volumes, or env files via header buttons.';
      rightCol.appendChild(empty);
    }

    twoCol.appendChild(rightCol);
    wrapper.appendChild(twoCol);
  } else if (typeChunks.length > 0 && envChunks.length > 0) {
    // Two-column layout: project-type chunks left, env_file chunks right.
    const twoCol = document.createElement('div');
    twoCol.className = 'chunks-two-col';
    twoCol.appendChild(makeCol(getProjectTypeLabel(project.project_type!), typeChunks));
    twoCol.appendChild(makeCol('Environment Files', envChunks));
    wrapper.appendChild(twoCol);
  } else {
    const chunksGrid = document.createElement('div');
    chunksGrid.className = 'chunks-grid';
    for (const chunk of chunks) chunksGrid.appendChild(renderChunkCard(chunk, project));
    wrapper.appendChild(chunksGrid);
  }

  if (!chunks.length && project.project_type !== 'docker') {
    const _emptyMsgs: Partial<Record<ProjectType, string>> = {
      wireguard:  'No sections yet — import a wg0.conf or click "+ Add Peer".',
      docker:     'No services yet — import a docker-compose.yml or click "+ Add Service".',
      nginx:      'No blocks yet — use "+ Server", "+ Upstream" or "+ Location".',
      kubernetes: 'No resources yet — use "+ Deploy", "+ Service", "+ ConfigMap", etc.',
      ssh_config: 'No hosts yet — import a ~/.ssh/config or click "+ Add Host".',
      traefik:    'No routes yet — use "+ Router", "+ Service" or "+ Middleware".',
    };
    const empty = document.createElement('div');
    empty.style.cssText = 'color:var(--text3);font-size:12px;padding:20px 0;text-align:center';
    empty.textContent = _emptyMsgs[project.project_type!] || 'No chunks yet. Use the buttons above to add sections.';
    wrapper.appendChild(empty);
  }

  grid.innerHTML = '';
  grid.appendChild(wrapper);

  wrapper.addEventListener('click', async (e) => {
    const el = (e.target as HTMLElement).closest<HTMLElement>('[data-action]');
    if (!el) return;
    const action = el.dataset.action!;
    const projId = el.dataset.projectId!;
    const chunkId = el.dataset.chunkId;

    if (action === 'chunk-copy') {
      clipboardWrite(el.dataset.value || '').then(() => showToast('Copied ✓', 'ok', 1500));
      return;
    }

    const proj = st.vault.projects.find(p => p.id === projId);
    if (!proj) return;

    if (action === 'edit-chunk') {
      const chunk = proj.chunks?.find(c => c.id === chunkId);
      if (chunk) openChunkEditModal(proj, chunk);
      return;
    }

    if (action === 'copy-chunk-full') {
      const chunk = proj.chunks?.find(c => c.id === chunkId);
      if (chunk) {
        clipboardWrite(chunkToString(chunk)).then(() => showToast('Copied ✓', 'ok', 1500));
      }
      return;
    }

    if (action === 'copy-chunk-raw') {
      const chunk = proj.chunks?.find(c => c.id === chunkId);
      if (chunk) {
        const envF = chunk.fields.filter(f => f.description === 'env' || chunk.chunk_type === 'env_file');
        clipboardWrite(envF.map(f => `${f.key}=${f.value}`).join('\n')).then(() => showToast('Copied ✓', 'ok', 1500));
      }
      return;
    }

    if (action === 'copy-chunk-env') {
      const chunk = proj.chunks?.find(c => c.id === chunkId);
      if (chunk) {
        const envF = chunk.fields.filter(f => f.description === 'env');
        const text = envF.map(f => `${f.key}=${resolveFieldRef(f.value, true).resolved ?? f.value}`).join('\n');
        clipboardWrite(text).then(() => showToast('Copied .env ✓', 'ok', 1500));
      }
      return;
    }

    if (action === 'delete-chunk') {
      if (!await showConfirm(`Delete chunk "${proj.chunks?.find(c => c.id === chunkId)?.name}"?`)) return;
      proj.chunks = (proj.chunks || []).filter(c => c.id !== chunkId);
      st.store.save(st.vault);
      render();
      return;
    }

    if (action === 'chunk-up' || action === 'chunk-down') {
      const _cks = proj.chunks || [];
      const _ci = _cks.findIndex(c => c.id === chunkId);
      if (_ci < 0) return;
      if (action === 'chunk-up' && _ci > 0) [_cks[_ci - 1], _cks[_ci]] = [_cks[_ci], _cks[_ci - 1]];
      if (action === 'chunk-down' && _ci < _cks.length - 1) [_cks[_ci], _cks[_ci + 1]] = [_cks[_ci + 1], _cks[_ci]];
      proj.chunks = _cks;
      st.store.save(st.vault); render(); return;
    }

    if (action === 'dup-chunk') {
      const _src = proj.chunks?.find(c => c.id === chunkId);
      if (!_src) return;
      const _dup = { ..._src, id: crypto.randomUUID(), name: _src.name + ' (copy)', fields: _src.fields.map(f => ({ ...f })) };
      if (!proj.chunks) proj.chunks = [];
      const _ci2 = proj.chunks.findIndex(c => c.id === chunkId);
      proj.chunks.splice(_ci2 + 1, 0, _dup);
      st.store.save(st.vault); render();
      showToast(`Duplicated "${_src.name}"`, 'ok'); return;
    }

    if (action === 'add-wg-peer') {
      const newPeer = {
        id: crypto.randomUUID(),
        name: `Peer ${((proj.chunks || []).filter(c => c.chunk_type === 'wg_peer').length + 1)}`,
        chunk_type: 'wg_peer' as const,
        fields: [
          { key: 'PublicKey',           value: '', field_type: 'var' as const },
          { key: 'AllowedIPs',          value: '', field_type: 'var' as const },
          { key: 'Endpoint',            value: '', field_type: 'var' as const },
          { key: 'PersistentKeepalive', value: '', field_type: 'var' as const },
          { key: 'PresharedKey',        value: '', field_type: 'secret' as const, secret: true },
        ],
      };
      if (!proj.chunks) proj.chunks = [];
      proj.chunks.push(newPeer);
      st.store.save(st.vault);
      render();
      return;
    }

    if (action === 'add-docker-service') {
      const n = ((proj.chunks || []).filter(c => c.chunk_type === 'docker_service').length + 1);
      if (!proj.chunks) proj.chunks = [];
      proj.chunks.push({ id: crypto.randomUUID(), name: `service-${n}`, chunk_type: 'docker_service', fields: [] });
      st.store.save(st.vault); render(); return;
    }

    if (action === 'add-docker-network') {
      const name = await showPrompt('Network name:', 'my-network');
      if (!name) return;
      if (!proj.chunks) proj.chunks = [];
      const nc = proj.chunks.find(c => c.chunk_type === 'docker_network');
      if (nc) {
        nc.fields.push({ key: name, value: '', field_type: 'var' });
      } else {
        proj.chunks.push({ id: crypto.randomUUID(), name: 'networks', chunk_type: 'docker_network', fields: [{ key: name, value: '', field_type: 'var' }] });
      }
      st.store.save(st.vault); render(); return;
    }

    if (action === 'add-docker-volume') {
      const name = await showPrompt('Volume name:', 'my-volume');
      if (!name) return;
      if (!proj.chunks) proj.chunks = [];
      const vc = proj.chunks.find(c => c.chunk_type === 'docker_volume');
      if (vc) {
        vc.fields.push({ key: name, value: '', field_type: 'var' });
      } else {
        proj.chunks.push({ id: crypto.randomUUID(), name: 'volumes', chunk_type: 'docker_volume', fields: [{ key: name, value: '', field_type: 'var' }] });
      }
      st.store.save(st.vault); render(); return;
    }

    if (action === 'export-wg') {
      const conf = exportWireGuard(proj);
      showDropdown(el, [
        { label: 'Copy wg0.conf', fn: () => clipboardWrite(conf).then(() => showToast('Copied ✓', 'ok')) },
        { label: 'Download wg0.conf', fn: () => {
          const blob = new Blob([conf], { type: 'text/plain' });
          const url = URL.createObjectURL(blob);
          const a = Object.assign(document.createElement('a'), { href: url, download: `${proj.name}.conf` });
          document.body.appendChild(a); a.click(); document.body.removeChild(a);
          setTimeout(() => URL.revokeObjectURL(url), 1000);
          showToast('Downloaded', 'ok');
        }},
      ]);
      return;
    }

    if (action === 'export-docker') {
      const { yaml, envFile } = exportDockerCompose(proj);
      showDropdown(el, [
        { label: 'Copy YAML', fn: () => clipboardWrite(yaml).then(() => showToast('Copied YAML ✓', 'ok')) },
        { label: 'Copy .env', fn: () => clipboardWrite(envFile).then(() => showToast('Copied .env ✓', 'ok')) },
        { label: 'Download YAML', fn: () => {
          const blob = new Blob([yaml], { type: 'text/plain' });
          const url = URL.createObjectURL(blob);
          const a = Object.assign(document.createElement('a'), { href: url, download: 'docker-compose.yml' });
          document.body.appendChild(a); a.click(); document.body.removeChild(a);
          setTimeout(() => URL.revokeObjectURL(url), 1000);
        }},
        { label: 'Download .env', fn: () => {
          const blob = new Blob([envFile], { type: 'text/plain' });
          const url = URL.createObjectURL(blob);
          const a = Object.assign(document.createElement('a'), { href: url, download: `${proj.name}.env` });
          document.body.appendChild(a); a.click(); document.body.removeChild(a);
          setTimeout(() => URL.revokeObjectURL(url), 1000);
        }},
      ]);
      return;
    }

    if (action === 'export-docker-services') {
      const yaml = exportServicesSection(proj);
      if (yaml) clipboardWrite(yaml).then(() => showToast('Services YAML copied ✓', 'ok', 1800));
      else showToast('No services to copy', '', 1500);
      return;
    }

    if (action === 'import-wg') {
      const doImportWg = async (text: string) => {
        const parsed = parseWgConf(text);
        if (!parsed.length) { showToast('No WireGuard sections found', 'err'); return; }
        if (proj.chunks?.length && !await showConfirm(`Replace ${proj.chunks.length} existing chunk(s) with ${parsed.length} imported sections?`)) return;
        proj.chunks = parsed;
        st.store.save(st.vault); render();
        showToast(`Imported ${parsed.length} sections ✓`, 'ok');
      };
      showDropdown(el, [
        { label: 'Import from file', fn: () => pickFileText('text/plain,.conf', (text) => doImportWg(text)) },
        { label: 'Paste wg0.conf text…', fn: async () => {
          const text = await showPromptLarge('Paste wg0.conf contents:', '');
          if (text) doImportWg(text);
        }},
      ]);
      return;
    }

    if (action === 'import-docker') {
      const doImportDocker = async (text: string) => {
        const parsed = parseDockerCompose(text);
        if (!parsed.length) { showToast('No services/networks/volumes found', 'err'); return; }
        if (proj.chunks?.length && !await showConfirm(`Replace ${proj.chunks.length} existing chunk(s) with ${parsed.length} imported chunks?`)) return;
        proj.chunks = parsed;
        st.store.save(st.vault); render();
        showToast(`Imported ${parsed.length} chunks ✓`, 'ok');
      };
      showDropdown(el, [
        { label: 'Import from file', fn: () => pickFileText('text/plain,text/yaml,.yaml,.yml', (text) => doImportDocker(text)) },
        { label: 'Paste YAML…', fn: async () => {
          const text = await showPromptLarge('Paste docker-compose.yml contents:', '');
          if (text) doImportDocker(text);
        }},
      ]);
      return;
    }

    if (action === 'import-ssh') {
      pickFileText('', async (text) => {
        const parsed = parseSshConfig(text);
        if (!parsed.length) { showToast('No Host blocks found in file', 'err'); return; }
        if (proj.chunks?.length && !await showConfirm(`Replace ${proj.chunks.length} existing chunk(s) with ${parsed.length} imported host blocks?`)) return;
        proj.chunks = parsed;
        st.store.save(st.vault); render();
        showToast(`Imported ${parsed.length} host blocks ✓`, 'ok');
      });
      return;
    }

    if (action === 'import-nginx') {
      const doImportNginx = async (text: string, merge: boolean) => {
        const parsed = parseNginxConf(text);
        if (!parsed.length) { showToast('No server/upstream blocks found', 'err'); return; }
        if (!merge) {
          if (proj.chunks?.length && !await showConfirm(`Replace ${proj.chunks.length} existing chunk(s) with ${parsed.length} imported chunks?`)) return;
          proj.chunks = parsed;
        } else {
          if (!proj.chunks) proj.chunks = [];
          proj.chunks.push(...parsed);
        }
        st.store.save(st.vault); render();
        // Surface any SSL cert domains found so user can add them to vault
        const certDomains = new Set<string>();
        for (const chunk of parsed) {
          for (const field of chunk.fields) {
            if (field.field_type === 'cert') {
              const m = field.value.match(/\/live\/([^/]+)\//);
              if (m) certDomains.add(m[1]);
            }
          }
        }
        const certNote = certDomains.size > 0
          ? ` — SSL cert domains: ${[...certDomains].join(', ')} (add certificate vault entries to auto-link)`
          : '';
        showToast(`Imported ${parsed.length} chunks ✓${certNote}`, 'ok');
      };
      const hasExisting = (proj.chunks?.length ?? 0) > 0;
      showDropdown(el, [
        { label: 'Import from file', fn: () => pickFileText('text/plain,.conf,.nginx', (text) => doImportNginx(text, false)) },
        { label: 'Paste nginx config…', fn: async () => {
          const text = await showPromptLarge('Paste nginx site config:', '');
          if (text) doImportNginx(text, false);
        }},
        ...(hasExisting ? [{ label: 'Append to existing', fn: () => pickFileText('text/plain,.conf,.nginx', (text) => doImportNginx(text, true)) }] : []),
      ]);
      return;
    }

    if (action === 'export-env-chunk') {
      const chunk = proj.chunks?.find(c => c.id === chunkId);
      if (!chunk) return;
      const dotenv = chunk.fields.filter(f => f.key && f.value !== undefined)
        .map(f => `${f.key}=${f.value}`).join('\n');
      showDropdown(el, [
        { label: 'Copy .env',    fn: () => clipboardWrite(dotenv).then(() => showToast('Copied ✓', 'ok')) },
        { label: 'Download .env', fn: () => {
          const blob = new Blob([dotenv], { type: 'text/plain' });
          const url = URL.createObjectURL(blob);
          const a = Object.assign(document.createElement('a'), { href: url, download: `${chunk.name}.env` });
          document.body.appendChild(a); a.click(); document.body.removeChild(a);
          setTimeout(() => URL.revokeObjectURL(url), 1000);
          showToast('Downloaded', 'ok');
        }},
      ]);
      return;
    }

    if (action === 'import-env-chunk') {
      const doImportEnv = (text: string, filename: string) => {
        const vars = parseEnvFile(text);
        if (!vars.length) { showToast('No variables found in .env', 'err'); return; }
        const isSecretKey = (name: string) => /pass(word)?|secret|key|token|cred/i.test(name);
        const toFields = (v: { name: string; value: string }) => {
          const isRef = /^\$\{.+\}$/.test(v.value);
          const isSec = !isRef && isSecretKey(v.name) && v.value !== '';
          const ft: ChunkFieldType = isRef ? 'env_var' : isSec ? 'secret' : 'var';
          return { key: v.name, value: v.value, field_type: ft, secret: isSec };
        };
        const chunkName = filename.replace(/\.env$/, '').replace(/\.$/, '') || 'env-file';
        if (!proj.chunks) proj.chunks = [];
        const existing = proj.chunks.find(c => c.chunk_type === 'env_file' && c.name === chunkName);
        if (existing) {
          existing.fields = vars.map(toFields);
        } else {
          proj.chunks.push({ id: crypto.randomUUID(), name: chunkName, chunk_type: 'env_file', fields: vars.map(toFields) });
        }
        st.store.save(st.vault); render();
        showToast(`Imported ${vars.length} vars into "${chunkName}" ✓`, 'ok');
      };
      showDropdown(el, [
        { label: 'Import from file', fn: () => pickFileText('text/plain,.env', (text, filename) => doImportEnv(text, filename)) },
        { label: 'Paste .env text…', fn: async () => {
          const text = await showPromptLarge('Paste .env contents:', '');
          if (text) doImportEnv(text, 'env-file');
        }},
      ]);
      return;
    }

    const addChunkFns: Partial<Record<string, () => any>> = {
      'add-nginx-server': () => ({
        id: crypto.randomUUID(),
        name: `server-${(proj.chunks || []).filter(c => c.chunk_type === 'nginx_server').length + 1}`,
        chunk_type: 'nginx_server',
        fields: [
          { key: 'listen',      value: '80',          field_type: 'var' },
          { key: 'server_name', value: '',            field_type: 'var' },
          { key: 'root',        value: '/var/www/html', field_type: 'var' },
        ],
      }),
      'add-nginx-upstream': () => ({
        id: crypto.randomUUID(),
        name: `upstream-${(proj.chunks || []).filter(c => c.chunk_type === 'nginx_upstream').length + 1}`,
        chunk_type: 'nginx_upstream',
        fields: [{ key: 'server', value: 'app:8080', field_type: 'list' }],
      }),
      'add-nginx-location': () => ({
        id: crypto.randomUUID(),
        name: `location-${(proj.chunks || []).filter(c => c.chunk_type === 'nginx_location').length + 1}`,
        chunk_type: 'nginx_location',
        fields: [
          { key: 'path',       value: '/', field_type: 'var' },
          { key: 'proxy_pass', value: '',  field_type: 'var' },
        ],
      }),
      'add-nginx-key': () => ({
        id: crypto.randomUUID(),
        name: `key-${(proj.chunks || []).filter(c => c.chunk_type === 'nginx_key').length + 1}`,
        chunk_type: 'nginx_key' as const,
        fields: [
          { key: 'path',    value: '', field_type: 'var' as const },
          { key: 'content', value: '', field_type: 'multiline' as const },
        ],
      }),
      'add-k8s-deployment': () => ({
        id: crypto.randomUUID(), name: 'Deployment', chunk_type: 'k8s_deployment',
        fields: [
          { key: 'name',          value: 'my-app',       field_type: 'var' },
          { key: 'namespace',     value: 'default',      field_type: 'var' },
          { key: 'image',         value: 'nginx:latest', field_type: 'var' },
          { key: 'replicas',      value: '1',            field_type: 'var' },
          { key: 'containerPort', value: '80',           field_type: 'var' },
        ],
      }),
      'add-k8s-service': () => ({
        id: crypto.randomUUID(), name: 'Service', chunk_type: 'k8s_service',
        fields: [
          { key: 'name',       value: 'my-app',    field_type: 'var' },
          { key: 'namespace',  value: 'default',   field_type: 'var' },
          { key: 'port',       value: '80',        field_type: 'var' },
          { key: 'targetPort', value: '80',        field_type: 'var' },
          { key: 'type',       value: 'ClusterIP', field_type: 'var' },
        ],
      }),
      'add-k8s-configmap': () => ({
        id: crypto.randomUUID(), name: 'ConfigMap', chunk_type: 'k8s_configmap',
        fields: [
          { key: 'name',      value: 'my-config', field_type: 'var' },
          { key: 'namespace', value: 'default',   field_type: 'var' },
        ],
      }),
      'add-k8s-secret': () => ({
        id: crypto.randomUUID(), name: 'Secret', chunk_type: 'k8s_secret',
        fields: [
          { key: 'name',      value: 'my-secret', field_type: 'var' },
          { key: 'namespace', value: 'default',   field_type: 'var' },
        ],
      }),
      'add-k8s-ingress': () => ({
        id: crypto.randomUUID(), name: 'Ingress', chunk_type: 'k8s_ingress',
        fields: [
          { key: 'name',        value: 'my-ingress',  field_type: 'var' },
          { key: 'namespace',   value: 'default',     field_type: 'var' },
          { key: 'host',        value: 'example.com', field_type: 'var' },
          { key: 'serviceName', value: 'my-app',      field_type: 'var' },
          { key: 'servicePort', value: '80',          field_type: 'var' },
        ],
      }),
      'add-ssh-host': () => ({
        id: crypto.randomUUID(),
        name: `host-${(proj.chunks || []).filter(c => c.chunk_type === 'ssh_host').length + 1}`,
        chunk_type: 'ssh_host',
        fields: [
          { key: 'HostName',            value: '', field_type: 'var' },
          { key: 'User',                value: '', field_type: 'var' },
          { key: 'Port',                value: '22', field_type: 'var' },
          { key: 'IdentityFile',        value: '~/.ssh/id_ed25519', field_type: 'var' },
          { key: 'ServerAliveInterval', value: '60', field_type: 'var' },
        ],
      }),
      'add-traefik-router': () => ({
        id: crypto.randomUUID(),
        name: `router-${(proj.chunks || []).filter(c => c.chunk_type === 'traefik_router').length + 1}`,
        chunk_type: 'traefik_router',
        fields: [
          { key: 'entryPoints', value: 'websecure', field_type: 'list' },
          { key: 'rule',        value: '',           field_type: 'var' },
          { key: 'service',     value: '',           field_type: 'var' },
        ],
      }),
      'add-traefik-service': () => ({
        id: crypto.randomUUID(),
        name: `service-${(proj.chunks || []).filter(c => c.chunk_type === 'traefik_service').length + 1}`,
        chunk_type: 'traefik_service',
        fields: [
          { key: 'url',            value: '', field_type: 'var' },
          { key: 'passHostHeader', value: 'true', field_type: 'var' },
        ],
      }),
      'add-traefik-middleware': () => ({
        id: crypto.randomUUID(),
        name: `middleware-${(proj.chunks || []).filter(c => c.chunk_type === 'traefik_middleware').length + 1}`,
        chunk_type: 'traefik_middleware',
        fields: [{ key: 'type', value: 'redirectScheme', field_type: 'var' }],
      }),
      'add-apache-vhost': () => ({
        id: crypto.randomUUID(),
        name: `VirtualHost-${(proj.chunks || []).filter(c => c.chunk_type === 'apache_vhost').length + 1}`,
        chunk_type: 'apache_vhost' as const,
        fields: [
          { key: 'ServerName',   value: 'example.com', field_type: 'var' as const },
          { key: 'DocumentRoot', value: '/var/www/html', field_type: 'var' as const },
        ],
      }),
      'add-apache-directory': () => ({
        id: crypto.randomUUID(),
        name: `/var/www/html`,
        chunk_type: 'apache_directory' as const,
        fields: [
          { key: 'path',          value: '/var/www/html', field_type: 'var' as const },
          { key: 'AllowOverride', value: 'All', field_type: 'var' as const },
          { key: 'Require',       value: 'all granted', field_type: 'var' as const },
        ],
      }),
      'add-haproxy-frontend': () => ({
        id: crypto.randomUUID(),
        name: `frontend-${(proj.chunks || []).filter(c => c.chunk_type === 'haproxy_frontend').length + 1}`,
        chunk_type: 'haproxy_frontend' as const,
        fields: [
          { key: 'bind',    value: '*:80', field_type: 'port' as const },
          { key: 'mode',    value: 'http', field_type: 'var' as const },
          { key: 'default_backend', value: 'app', field_type: 'var' as const },
        ],
      }),
      'add-haproxy-backend': () => ({
        id: crypto.randomUUID(),
        name: `backend-${(proj.chunks || []).filter(c => c.chunk_type === 'haproxy_backend').length + 1}`,
        chunk_type: 'haproxy_backend' as const,
        fields: [
          { key: 'mode',    value: 'http',        field_type: 'var' as const },
          { key: 'balance', value: 'roundrobin',  field_type: 'var' as const },
          { key: 'server',  value: 'app1 127.0.0.1:8080 check', field_type: 'endpoint' as const },
        ],
      }),
      'add-ansible-vars': () => ({
        id: crypto.randomUUID(),
        name: `vars-${(proj.chunks || []).filter(c => c.chunk_type === 'ansible_vars').length + 1}`,
        chunk_type: 'ansible_vars' as const,
        fields: [{ key: 'example_var', value: 'example_value', field_type: 'var' as const }],
      }),
      'add-ansible-task': () => ({
        id: crypto.randomUUID(),
        name: `task-${(proj.chunks || []).filter(c => c.chunk_type === 'ansible_task').length + 1}`,
        chunk_type: 'ansible_task' as const,
        fields: [
          { key: 'name',   value: 'My task',        field_type: 'var' as const },
          { key: 'module', value: 'ansible.builtin.debug', field_type: 'var' as const },
          { key: 'msg',    value: 'Hello world',     field_type: 'var' as const },
        ],
      }),
      'add-pg-connection': () => ({
        id: crypto.randomUUID(),
        name: `db-${(proj.chunks || []).filter(c => c.chunk_type === 'pg_connection').length + 1}`,
        chunk_type: 'pg_connection' as const,
        fields: [
          { key: 'host',     value: 'localhost', field_type: 'var' as const },
          { key: 'port',     value: '5432',      field_type: 'port' as const },
          { key: 'dbname',   value: '',          field_type: 'var' as const },
          { key: 'user',     value: '',          field_type: 'var' as const },
          { key: 'password', value: '',          field_type: 'secret' as const, secret: true },
          { key: 'sslmode',  value: 'require',   field_type: 'var' as const },
        ],
      }),
      'add-pg-role': () => ({
        id: crypto.randomUUID(),
        name: `role-${(proj.chunks || []).filter(c => c.chunk_type === 'pg_role').length + 1}`,
        chunk_type: 'pg_role' as const,
        fields: [
          { key: 'rolname',     value: '',    field_type: 'var' as const },
          { key: 'rolpassword', value: '',    field_type: 'secret' as const, secret: true },
          { key: 'rolcanlogin', value: 'true', field_type: 'var' as const },
        ],
      }),
    };
    if (action in addChunkFns) {
      if (!proj.chunks) proj.chunks = [];
      proj.chunks.push(addChunkFns[action]!());
      st.store.save(st.vault); render();
      return;
    }

    const dlText = (content: string, filename: string) => {
      const blob = new Blob([content], { type: 'text/plain' });
      const url = URL.createObjectURL(blob);
      const a = Object.assign(document.createElement('a'), { href: url, download: filename });
      document.body.appendChild(a); a.click(); document.body.removeChild(a);
      setTimeout(() => URL.revokeObjectURL(url), 1000);
    };

    if (action === 'export-nginx') {
      const conf = exportNginx(proj);
      showDropdown(el, [
        { label: 'Copy nginx.conf', fn: () => clipboardWrite(conf).then(() => showToast('Copied ✓', 'ok')) },
        { label: 'Download nginx.conf', fn: () => { dlText(conf, 'nginx.conf'); showToast('Downloaded', 'ok'); } },
      ]);
      return;
    }

    if (action === 'export-k8s') {
      const yamlContent = exportK8s(proj);
      showDropdown(el, [
        { label: 'Copy YAML', fn: () => clipboardWrite(yamlContent).then(() => showToast('Copied ✓', 'ok')) },
        { label: 'Download manifests.yaml', fn: () => { dlText(yamlContent, `${proj.name}-manifests.yaml`); showToast('Downloaded', 'ok'); } },
      ]);
      return;
    }

    if (action === 'export-ssh') {
      const conf = exportSshConfig(proj);
      showDropdown(el, [
        { label: 'Copy config', fn: () => clipboardWrite(conf).then(() => showToast('Copied ✓', 'ok')) },
        { label: 'Download config', fn: () => { dlText(conf, 'config'); showToast('Downloaded', 'ok'); } },
      ]);
      return;
    }

    if (action === 'export-traefik') {
      const yamlContent = exportTraefik(proj);
      showDropdown(el, [
        { label: 'Copy traefik.yaml', fn: () => clipboardWrite(yamlContent).then(() => showToast('Copied ✓', 'ok')) },
        { label: 'Download traefik.yaml', fn: () => { dlText(yamlContent, 'traefik.yaml'); showToast('Downloaded', 'ok'); } },
      ]);
      return;
    }

    if (action === 'import-apache') {
      const doImport = async (text: string, merge: boolean) => {
        const parsed = parseApacheConf(text);
        if (!parsed.length) { showToast('No VirtualHost/Directory blocks found', 'err'); return; }
        if (!merge && proj.chunks?.length && !await showConfirm(`Replace ${proj.chunks.length} existing chunk(s)?`)) return;
        if (merge) { if (!proj.chunks) proj.chunks = []; proj.chunks.push(...parsed); }
        else proj.chunks = parsed;
        st.store.save(st.vault); render();
        showToast(`Imported ${parsed.length} chunks ✓`, 'ok');
      };
      showDropdown(el, [
        { label: 'Import from file', fn: () => pickFileText('text/plain,.conf', (t) => doImport(t, false)) },
        { label: 'Paste config…', fn: async () => { const t = await showPromptLarge('Paste Apache config:', ''); if (t) doImport(t, false); } },
        ...(proj.chunks?.length ? [{ label: 'Append to existing', fn: () => pickFileText('text/plain,.conf', (t) => doImport(t, true)) }] : []),
      ]);
      return;
    }

    if (action === 'export-apache') {
      const conf = exportApache(proj);
      showDropdown(el, [
        { label: 'Copy config', fn: () => clipboardWrite(conf).then(() => showToast('Copied ✓', 'ok')) },
        { label: 'Download config', fn: () => { dlText(conf, `${proj.name}.conf`); showToast('Downloaded', 'ok'); } },
      ]);
      return;
    }

    if (action === 'import-haproxy') {
      const doImport = async (text: string, merge: boolean) => {
        const parsed = parseHaproxyConf(text);
        if (!parsed.length) { showToast('No sections found', 'err'); return; }
        if (!merge && proj.chunks?.length && !await showConfirm(`Replace ${proj.chunks.length} existing chunk(s)?`)) return;
        if (merge) { if (!proj.chunks) proj.chunks = []; proj.chunks.push(...parsed); }
        else proj.chunks = parsed;
        st.store.save(st.vault); render();
        showToast(`Imported ${parsed.length} chunks ✓`, 'ok');
      };
      showDropdown(el, [
        { label: 'Import from file', fn: () => pickFileText('text/plain,.cfg', (t) => doImport(t, false)) },
        { label: 'Paste config…', fn: async () => { const t = await showPromptLarge('Paste HAProxy config:', ''); if (t) doImport(t, false); } },
        ...(proj.chunks?.length ? [{ label: 'Append to existing', fn: () => pickFileText('text/plain,.cfg', (t) => doImport(t, true)) }] : []),
      ]);
      return;
    }

    if (action === 'export-haproxy') {
      const conf = exportHaproxy(proj);
      showDropdown(el, [
        { label: 'Copy haproxy.cfg', fn: () => clipboardWrite(conf).then(() => showToast('Copied ✓', 'ok')) },
        { label: 'Download haproxy.cfg', fn: () => { dlText(conf, 'haproxy.cfg'); showToast('Downloaded', 'ok'); } },
      ]);
      return;
    }

    if (action === 'export-ansible') {
      const yamlContent = exportAnsible(proj);
      showDropdown(el, [
        { label: 'Copy YAML', fn: () => clipboardWrite(yamlContent).then(() => showToast('Copied ✓', 'ok')) },
        { label: 'Download playbook.yml', fn: () => { dlText(yamlContent, 'playbook.yml'); showToast('Downloaded', 'ok'); } },
      ]);
      return;
    }

    if (action === 'export-postgres') {
      const pgpass = exportPostgres(proj);
      showDropdown(el, [
        { label: 'Copy .pgpass', fn: () => clipboardWrite(pgpass).then(() => showToast('Copied ✓', 'ok')) },
        { label: 'Download .pgpass', fn: () => { dlText(pgpass, '.pgpass'); showToast('Downloaded', 'ok'); } },
      ]);
      return;
    }
  });
}

// ── Top-level render ───────────────────────────────────────────────────────

export function render() {
  renderSidebar();
  renderProjectTree();
  const selectedId = st.currentSelectedProjectIds[0];
  if (selectedId !== 'Universal' && !selectedId.startsWith('virtual:')) {
    const project = st.vault.projects.find(p => p.id === selectedId);
    if (project && project.project_type && project.project_type !== 'generic') {
      renderConfigView(project);
      updateCopyAllBtn();
      return;
    }
  }
  renderGrid();
  updateCopyAllBtn();
}

export function updateCopyAllBtn() {
  const wrap = document.getElementById('copy-all-wrap');
  if (!wrap) return;
  const items = getFiltered();
  wrap.style.display = items.length ? 'flex' : 'none';
  const btn = document.getElementById('copy-all-btn')!;
  const projectFiltered = st.currentSelectedProjectIds[0] !== 'Universal';
  const ST_LABELS: Record<string, string> = { api_key: 'API Keys', password: 'Passwords', env_var: 'Env Vars', connection_string: 'Connections', ssh_key: 'SSH Keys', certificate: 'Certificates', file_blob: 'File Blobs' };
  const label = st.filter.type === 'category' ? `Copy "${st.filter.value}"`
    : st.filter.type === 'price' ? `Copy ${st.filter.value}`
    : st.filter.type === 'secret_type' ? `Copy ${ST_LABELS[st.filter.value] || st.filter.value}`
    : projectFiltered ? 'Copy Category'
    : 'Copy All';
  btn.innerHTML = `${copySVG} ${label}`;
}

// Register render as the global render function
setRenderFn(render);
