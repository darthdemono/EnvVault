/**
 * @file
 * Render: sidebar, project tree, card grid, config view, copy-all button.
 */

import type {
  VaultEntry,
  SecretType,
  Project,
  ProjectType,
  SecretChunk,
  ChunkFieldType,
} from './types';
import {
  st,
  Settings,
  setRenderFn,
  applyGridSettings,
  dotenvKey,
  switchPanel,
  isSidebarSectionEnabled,
  persist,
  entryId,
  saveViewState,
} from './state';
import { getFiltered, sorted, buildProjectTree, getDescendantProjectIds } from './filters';
import { iconHTML } from './icons';
import { normalizeRateLimit } from './ratelimit';
import { poolsOf } from './pools';
import {
  esc,
  escAttr,
  maskKey,
  showToast,
  showConfirm,
  showPrompt,
  showPromptLarge,
  clipboardWrite,
  eyeSVG,
  copySVG,
  editSVG,
  delSVG,
  dupSVG,
} from './utils';
import { TYPE_CONFIG, showDropdown, markAsRotated, openModal } from './modals';
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
  buildEnvLinkMatches,
  nginxCertDomains,
  renderNginxCertCard,
  ensureCertForDomain,
  redundantCertKeyChunkIds,
} from './chunk-ops';
import type { EnvLinkMatch } from './chunk-ops';
import { parseEnvFile } from './import-export';

// ── Project tree renderers ─────────────────────────────────────────────────

export function renderProjectTree() {
  const container = document.getElementById('category-tree');
  if (!container) return;
  container.innerHTML = '';
  renderUserCatTree(container, st.vault.user_categories || [], st.vault.api_keys);
}

function renderProjectList(container: HTMLElement, projects: Project[], all: VaultEntry[]) {
  const tree = buildProjectTree(projects.filter((p) => p.id !== 'Universal'));
  function renderNode(node: any, depth: number) {
    const nodeId: string = node.virtual ? 'virtual:' + node.name : node.id;
    const descendantIds = getDescendantProjectIds(nodeId);
    const count = all.filter(
      (k) => k.projectIds && descendantIds.some((pid) => k.projectIds!.includes(pid)),
    ).length;
    const displayName = node.name.split('/').pop()!;
    const isActive = st.currentSelectedProjectIds[0] === nodeId;
    const _ptLabels: Record<string, string> = {
      wireguard: 'WG',
      docker: 'DC',
      nginx: 'Nginx',
      kubernetes: 'K8s',
      ssh_config: 'SSH',
      traefik: 'TF',
    };
    const ptBadge =
      !node.virtual && node.project_type && node.project_type !== 'generic'
        ? // The lookup hits a fixed table, but the fallback prints the raw stored
          // value, which an imported vault controls.
          ` <span class="badge badge-ptype">${esc(_ptLabels[node.project_type] ?? node.project_type)}</span>`
        : '';
    const row = document.createElement('div');
    row.className = 'sidebar-cat-row';
    row.style.paddingLeft = `${depth * 14}px`;
    if (node.virtual) {
      row.innerHTML = `
        <button class="sidebar-item${isActive ? ' active' : ''}"${isActive ? ' aria-current="true"' : ''} data-project-id="${escAttr(nodeId)}" style="color:var(--text3)">
          <span class="sidebar-label" style="font-weight:600;font-size:10.5px;text-transform:uppercase;letter-spacing:.06em">${esc(displayName)}</span>
          <span class="sidebar-count">${count}</span>
        </button>`;
    } else {
      row.innerHTML = `
        <button class="sidebar-item${isActive ? ' active' : ''}"${isActive ? ' aria-current="true"' : ''} data-project-id="${escAttr(nodeId)}">
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
  document.getElementById('count-free')!.textContent = String(
    all.filter((k) => k.price_type === 'free').length,
  );
  document.getElementById('count-local')!.textContent = String(
    all.filter((k) => k.price_type === 'local').length,
  );
  document.getElementById('count-paid')!.textContent = String(
    all.filter((k) => k.price_type === 'paid').length,
  );
  document.getElementById('count-conditional')!.textContent = String(
    all.filter((k) => k.price_type === 'conditional').length,
  );
  const stTypes: SecretType[] = [
    'api_key',
    'password',
    'env_var',
    'connection_string',
    'ssh_key',
    'certificate',
    'file_blob',
  ];
  stTypes.forEach((stType) => {
    const el = document.getElementById(`count-st-${stType}`);
    if (el)
      el.textContent = String(all.filter((k) => (k.secretType || 'api_key') === stType).length);
  });

  // Environment counts
  const envValues = ['production', 'staging', 'development', 'testing'] as const;
  envValues.forEach((env) => {
    const el = document.getElementById(`count-env-${env}`);
    if (el) el.textContent = String(all.filter((k) => k.environment === env).length);
  });

  // Update active state for both st.filter items and env filter items
  document.querySelectorAll<HTMLButtonElement>('.sidebar-item[data-filter-type]').forEach((btn) => {
    const t = btn.dataset.filterType;
    const v = btn.dataset.filterValue ?? '';
    const on =
      t === 'env'
        ? st.currentEnvFilter === v && v !== ''
        : (t === 'all' && st.filter.type === 'all' && !st.currentEnvFilter) ||
          (t === st.filter.type && v === st.filter.value);
    btn.classList.toggle('active', on);
    // Which filter is applied is the single most important piece of state in
    // this app — invariant 7 exists because a restored filter can hide every
    // secret. It cannot be conveyed by a colour alone.
    if (on) btn.setAttribute('aria-current', 'true');
    else btn.removeAttribute('aria-current');
  });

  const catList = document.getElementById('project-list')!;
  catList.innerHTML = '';
  renderProjectList(catList, st.vault.projects || [], all);

  renderTagSection(all);
  renderPoolSection(all);
  renderPrefixSection(all);
}

/**
 * Key Pools in the sidebar — every entry grouped under its pool name.
 *
 * Membership is the `pool` field on the entry and lives in the vault, so this
 * section needs no IPC and works on a remote vault and in the browser dev
 * server exactly as it does in Tauri. The *swap state* — cursor, cooldowns, use
 * counts — deliberately does not live in the vault (see `pools.ts`), so it is
 * not shown here; Tools → Key Pools is where that belongs, because it needs a
 * refresh cycle and this does not.
 *
 * Grouping goes through `poolsOf()` rather than a second pass over `pool`, so
 * the sidebar and the tool pane can never disagree about what a pool contains —
 * including the trim, and including the guard against a non-string `pool` in an
 * untrusted vault becoming a pool named "[object Object]" (invariant 4).
 */
function renderPoolSection(all: VaultEntry[]) {
  const container = document.getElementById('pool-filter-list');
  if (!container) return;

  // `poolsOf` reads a vault-shaped object, and `all` is the entry array the rest
  // of the sidebar is counting — filtered by the active workspace, not the raw
  // vault — so the counts here match the grid rather than the whole file.
  const pools = poolsOf({ api_keys: all });

  const section = document.getElementById('sidebar-section-pools');
  if (section)
    section.style.display = isSidebarSectionEnabled('pools') && pools.size > 0 ? '' : 'none';

  container.innerHTML = [...pools.entries()]
    .map(([name, members]) => {
      const active = st.activePoolFilter === name;
      return `<div class="sidebar-cat-row">
        <button class="sidebar-item pool-filter-btn${active ? ' active' : ''}"${active ? ' aria-current="true"' : ''} data-pool="${escAttr(name)}" title="${escAttr(`${members.length} interchangeable credential${members.length === 1 ? '' : 's'}`)}">
          <span class="pool-chip-sidebar">${esc(name)}</span>
          <span class="sidebar-count">${members.length}</span>
        </button>
      </div>`;
    })
    .join('');
}

function renderPrefixSection(all: VaultEntry[]) {
  const container = document.getElementById('prefix-filter-list');
  if (!container) return;
  const pfxMap = new Map<string, number>();
  for (const k of all)
    for (const p of k.env_prefixes ?? []) pfxMap.set(p, (pfxMap.get(p) ?? 0) + 1);

  const section = document.getElementById('sidebar-section-prefixes');
  if (section)
    section.style.display = isSidebarSectionEnabled('prefixes') && pfxMap.size > 0 ? '' : 'none';

  container.innerHTML = [...pfxMap.entries()]
    .sort((a, b) => a[0].localeCompare(b[0]))
    .map(([pfx, count]) => {
      const active = st.activePrefixFilter === pfx;
      return `<div class="sidebar-cat-row">
        <button class="sidebar-item prefix-filter-btn${active ? ' active' : ''}"${active ? ' aria-current="true"' : ''} data-prefix="${escAttr(pfx)}">
          <span class="badge badge-prefix">${esc(pfx)}_</span>
          <span class="sidebar-count">${count}</span>
        </button>
      </div>`;
    })
    .join('');
}

function renderTagSection(all: VaultEntry[]) {
  const container = document.getElementById('tag-filter-list');
  if (!container) return;

  // Collect unique tags with counts
  const tagMap = new Map<string, number>();
  for (const k of all) {
    for (const t of k.tags ?? []) {
      tagMap.set(t, (tagMap.get(t) ?? 0) + 1);
    }
  }

  const section = document.getElementById('sidebar-section-tags');
  if (section)
    section.style.display = isSidebarSectionEnabled('tags') && tagMap.size > 0 ? '' : 'none';

  container.innerHTML = [...tagMap.entries()]
    .sort((a, b) => a[0].localeCompare(b[0]))
    .map(([tag, count]) => {
      const active = st.activeTagFilter === tag;
      const style = tagColor(tag);
      return `<div class="sidebar-cat-row">
        <button class="sidebar-item tag-filter-btn${active ? ' active' : ''}"${active ? ' aria-current="true"' : ''} data-tag="${escAttr(tag)}">
          <span class="tag-chip-sidebar" style="${style}">${esc(tag)}</span>
          <span class="sidebar-count">${count}</span>
        </button>
      </div>`;
    })
    .join('');
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
    if (parts.length === 1) {
      roots.push(node);
    } else {
      byName.get(parts.slice(0, -1).join('/'))?.children.push(node);
    }
  }
  for (const [, node] of byName) node.children.sort((a, b) => a.name.localeCompare(b.name));
  roots.sort((a, b) => a.name.localeCompare(b.name));

  function renderCatNode(node: CatNode, depth: number) {
    const pfx = node.name + '/';
    const count = all.filter((k) =>
      (k.categories || []).some((c) => c === node.name || c.startsWith(pfx)),
    ).length;
    const displayName = node.name.split('/').pop()!;
    const isActive = st.filter.type === 'category' && st.filter.value === node.name;
    const indent = depth * 14;
    const row = document.createElement('div');
    row.className = 'sidebar-cat-row';
    row.style.paddingLeft = `${indent}px`;
    if (!node.real) {
      row.innerHTML = `
        <button class="sidebar-item${isActive ? ' active' : ''}"${isActive ? ' aria-current="true"' : ''} data-filter-type="category" data-filter-value="${escAttr(node.name)}" style="color:var(--text3)">
          <span class="sidebar-label" style="font-weight:600;font-size:10.5px;text-transform:uppercase;letter-spacing:.06em">${esc(displayName)}</span>
          <span class="sidebar-count">${count}</span>
        </button>`;
    } else {
      row.innerHTML = `
        <button class="sidebar-item${isActive ? ' active' : ''}"${isActive ? ' aria-current="true"' : ''} data-filter-type="category" data-filter-value="${escAttr(node.name)}">
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

/**
 * Reverse index: vault-entry key (`provider` or `provider_keyid`) → chunk fields
 * that reference it via `${ref}`. Powers the "Used by" row on each card.
 */
interface RefConsumer {
  project: string;
  chunk: string;
  field: string;
}
let _refIndex = new Map<string, RefConsumer[]>();

function buildRefIndex() {
  const idx = new Map<string, RefConsumer[]>();
  for (const project of st.vault.projects) {
    for (const chunk of project.chunks || []) {
      for (const f of chunk.fields) {
        const m = /^\$\{(.+)}$/.exec(f.value);
        if (!m) continue;
        const inner = m[1];
        if (inner.startsWith('chunk:')) continue; // chunk→chunk refs are not vault consumers
        const slash = inner.indexOf('/');
        const target = slash >= 0 ? inner.slice(0, slash) : inner; // provider or provider_keyid
        if (!idx.has(target)) idx.set(target, []);
        idx.get(target)!.push({ project: project.name, chunk: chunk.name, field: f.key });
      }
    }
  }
  _refIndex = idx;
}

/** Compare a freshly-resolved env snapshot to the chunk's last copy, toast the delta, and stash it. */
function diffAndStashCopy(chunk: SecretChunk, snapshot: Record<string, string>) {
  const prev = chunk.last_copied_snapshot;
  if (prev) {
    const changed = Object.keys(snapshot).filter((k) => k in prev && prev[k] !== snapshot[k]);
    const added = Object.keys(snapshot).filter((k) => !(k in prev));
    const removed = Object.keys(prev).filter((k) => !(k in snapshot));
    const parts: string[] = [];
    if (changed.length) parts.push(`${changed.length} changed`);
    if (added.length) parts.push(`${added.length} added`);
    if (removed.length) parts.push(`${removed.length} removed`);
    if (parts.length) {
      const names = [...changed, ...added].slice(0, 4).join(', ');
      showToast(
        `Copied ✓ — since last: ${parts.join(', ')}${names ? ` (${names})` : ''}`,
        'ok',
        3500,
      );
    } else {
      showToast('Copied ✓ — unchanged since last copy', 'ok', 1800);
    }
  } else {
    showToast('Copied ✓', 'ok', 1500);
  }
  chunk.last_copied_snapshot = snapshot;
  chunk.last_copied_at = new Date().toISOString();
  persist();
}

export function renderGrid() {
  buildRefIndex();
  const items = sorted(getFiltered());
  const grid = document.getElementById('card-grid')!;
  // Derived here rather than only flipped on click: lock, import and vault
  // switch all reset st.allExpanded, and the button was left reading
  // "Collapse All" with nothing expanded.
  const expandBtn = document.getElementById('expand-all-btn');
  if (expandBtn) expandBtn.textContent = st.allExpanded ? 'Collapse All' : 'Expand All';
  document.getElementById('result-count')!.textContent =
    `${items.length} secret${items.length !== 1 ? 's' : ''}`;
  applyGridSettings();
  if (!items.length) {
    grid.innerHTML = `<div class="empty-state"><svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg><p>No secrets found</p><small>${st.searchQ ? 'Try a different search' : 'Add a secret or import a backup'}</small></div>`;
    return;
  }
  grid.innerHTML = '';
  // One pass to map entry -> array position. `indexOf` per card made rendering
  // O(n²), which is invisible at 100 entries and very visible at a few thousand.
  const posOf = new Map<VaultEntry, number>();
  st.vault.api_keys.forEach((e, i) => posOf.set(e, i));
  const idxOf = (e: VaultEntry) => posOf.get(e) ?? -1;
  if (Settings.get('groupByType')) {
    const GROUP_ORDER: SecretType[] = [
      'api_key',
      'password',
      'env_var',
      'connection_string',
      'ssh_key',
      'certificate',
      'file_blob',
    ];
    const GROUP_LABELS: Record<string, string> = {
      api_key: 'API Keys',
      password: 'Passwords',
      env_var: 'Env Variables',
      connection_string: 'Connections',
      ssh_key: 'SSH Keys',
      certificate: 'Certificates',
      file_blob: 'File Blobs',
    };
    const groups = new Map<SecretType, VaultEntry[]>();
    items.forEach((entry) => {
      const stType = (entry.secretType || 'api_key') as SecretType;
      if (!groups.has(stType)) groups.set(stType, []);
      groups.get(stType)!.push(entry);
    });
    let animIdx = 0;
    GROUP_ORDER.forEach((stType) => {
      const groupItems = groups.get(stType);
      if (!groupItems?.length) return;
      const hdr = document.createElement('div');
      hdr.className = 'type-group-header';
      hdr.textContent = GROUP_LABELS[stType] || stType;
      grid.appendChild(hdr);
      groupItems.forEach((entry) => grid.appendChild(buildCard(entry, idxOf(entry), animIdx++)));
    });
  } else {
    items.forEach((entry, i) => grid.appendChild(buildCard(entry, idxOf(entry), i)));
  }
}

function buildCard(entry: VaultEntry, idx: number, animIdx: number): HTMLElement {
  const eid = entryId(entry);
  const isExp = st.allExpanded || st.expanded.has(eid);
  const pt = entry.price_type || 'free';
  const expiry = expiryBadge(entry);
  // `environment`, `secretType` and `price_type` are declared as unions, but the
  // type is erased at runtime and the vault is JSON off disk, off a remote
  // server, or out of an imported backup — none of which this app controls.
  // `key_id` on the next line was already escaped for exactly that reason.
  const envBadge = entry.environment
    ? `<span class="badge badge-env" data-env="${escAttr(entry.environment)}">${esc(entry.environment)}</span>`
    : '';
  const keyIdBadge = entry.key_id
    ? `<span class="badge badge-keyid">${esc(entry.key_id)}</span>`
    : '';
  const typeBadge =
    entry.secretType && entry.secretType !== 'api_key'
      ? `<span class="badge badge-keyid">${esc(entry.secretType)}</span>`
      : '';
  const compromisedBadge = entry.compromised
    ? `<span class="badge badge-compromised" title="Marked compromised — rotate immediately">⚠ LEAKED</span>`
    : '';
  const rotBadge = (() => {
    if (!entry.rotation_days || entry.rotation_days <= 0 || !entry.last_rotated_at) return '';
    const dueMs = new Date(entry.last_rotated_at).getTime() + entry.rotation_days * 86_400_000;
    if (dueMs >= Date.now()) return '';
    const overdue = Math.floor((Date.now() - dueMs) / 86_400_000);
    return `<span class="badge badge-rotation-due" title="Rotation cadence ${escAttr(entry.rotation_days)}d, overdue ${overdue}d">⟳ rotate</span>`;
  })();
  // Per-field mask state: default from settings, overridden by any explicit
  // reveal the user has toggled. Previously this read the setting alone, so a
  // revealed secret silently re-masked itself on the next re-render.
  const masked = (field: string) =>
    st.revealed[`${field}-${eid}`] !== undefined
      ? !st.revealed[`${field}-${eid}`]
      : Settings.get('maskKeysByDefault');
  const hasMask = masked('key');
  const secretMasked = masked('secret');
  const envFmt = Settings.get('defaultExportFormat');
  const envLabel = envFmt === 'yaml' ? 'YAML' : '.env';

  const card = document.createElement('div');
  const expiryBorderCls = getExpiryBorderClass(entry);
  const pinnedCls = entry.pinned ? ' pinned' : '';
  // Bulk ticks are keyed by entry id, so they survive a re-render that happens
  // mid-selection (a single delete, a pin, a sort change) instead of the grid
  // coming back with every card visually unticked but still in the set.
  const bulkCls = st.bulkMode && st.bulkSelected.has(eid) ? ' bulk-selected' : '';
  card.className = `card${isExp ? ' expanded' : ''}${expiryBorderCls}${pinnedCls}${bulkCls}`;
  card.style.animationDelay = `${Math.min(animIdx * 20, 180)}ms`;
  card.dataset.idx = String(idx);

  // Only http/https URLs are rendered as links — blocks javascript: and data: URIs.
  const safeUrl = (raw: string | null | undefined): string => {
    if (!raw) return '';
    const trimmed = raw.trim();
    if (/^https?:\/\//i.test(trimmed))
      return `<a href="${esc(trimmed)}" target="_blank" rel="noopener noreferrer">${esc(trimmed)}</a>`;
    return esc(trimmed); // render as plain text if not http/https
  };

  const metaRows: [string, string][] = [];
  if (entry.version) metaRows.push(['Version', esc(entry.version)]);
  // Normalised rather than read straight off the entry: this card may be
  // rendering data written by an older build that only had the free-text field,
  // by a remote server, or by a restored backup. Every branch below escapes —
  // vault data is untrusted input and the TypeScript types are erased at
  // runtime (CLAUDE.md invariant 4).
  const rl = normalizeRateLimit(entry);
  if (rl.rate_limit_count != null && rl.rate_limit_period) {
    metaRows.push([
      'Rate Limit',
      `${esc(rl.rate_limit_count)} <span class="meta-unit">per ${esc(rl.rate_limit_period)}</span>`,
    ]);
  } else if (rl.rate_limit_note) {
    // A limit nobody could express as a number and a window. Shown as the user
    // wrote it, because that text is the only description of it that exists.
    metaRows.push(['Rate Limit', esc(rl.rate_limit_note)]);
  }
  if (entry.purpose) metaRows.push(['Purpose', esc(entry.purpose)]);
  if (entry.pool) metaRows.push(['Key Pool', esc(entry.pool)]);
  if (entry.expires_at) metaRows.push(['Expires', esc(entry.expires_at)]);
  if (entry.api_url) metaRows.push(['API URL', safeUrl(entry.api_url)]);
  if (entry.callback_url) metaRows.push(['Callback', safeUrl(entry.callback_url)]);
  if (entry.details) metaRows.push(['Details', esc(entry.details)]);

  // Reverse "used by" — chunk fields that reference this entry via ${ref}.
  const uses = [
    ...(_refIndex.get(entry.provider) || []),
    ...(entry.key_id ? _refIndex.get(`${entry.provider}_${entry.key_id}`) || [] : []),
  ];
  if (uses.length) {
    const seen = new Set<string>();
    const chips = uses
      .filter((u) => {
        const k = `${u.project}|${u.field}`;
        if (seen.has(k)) return false;
        seen.add(k);
        return true;
      })
      .map(
        (u) =>
          `<span class="usedby-badge" title="${escAttr(`${u.chunk} · ${u.field}`)}">${esc(u.project)} · ${esc(u.field)}</span>`,
      )
      .join('');
    metaRows.push(['Used by', `<div class="usedby-row">${chips}</div>`]);
  }

  const projectBadges =
    entry.projectIds
      ?.filter((pid) => pid !== 'Universal')
      .map((pid) => {
        const proj = st.vault.projects.find((p) => p.id === pid);
        if (!proj) return '';
        const leaf = proj.name.includes('/') ? proj.name.split('/').pop()! : proj.name;
        return `<span class="badge badge-keyid" style="background:var(--accent-dim)" title="${escAttr(proj.name)}">${esc(leaf)}</span>`;
      })
      .join('') || '';

  card.innerHTML = `
    <div class="bulk-checkbox" data-action="bulk-toggle" data-idx="${idx}" role="checkbox" tabindex="0"
      aria-checked="${st.bulkSelected.has(eid)}" aria-label="${escAttr('Select ' + entry.provider)}"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><polyline points="20 6 9 20 4 15"/></svg></div>
    <div class="card-head" data-action="copy-env" data-idx="${idx}">
      <div class="provider-icon-wrap" data-action="icon" data-idx="${idx}">
        ${iconHTML(entry.provider, entry.custom_icon)}
      </div>
      <div class="card-meta">
        <div class="card-provider">
          <span class="card-provider-name" title="${escAttr(entry.provider)}">${esc(entry.provider)}</span>
          ${entry.pinned ? `<span class="pin-badge" title="Pinned"><svg width="9" height="9" viewBox="0 0 24 24" fill="currentColor" stroke="none"><path d="M5 17h14v-1.76a2 2 0 0 0-1.11-1.79l-1.78-.9A2 2 0 0 1 15 10.76V6h1a2 2 0 0 0 0-4H8a2 2 0 0 0 0 4h1v4.76a2 2 0 0 1-1.11 1.79l-1.78.9A2 2 0 0 0 5 15.24Z"/></svg></span>` : ''}
          <span class="badge badge-price" data-price="${escAttr(pt)}">${esc(pt)}</span>
          ${envBadge}${keyIdBadge}${typeBadge}${expiry}${compromisedBadge}${rotBadge}${entry.env_prefixes?.length ? entry.env_prefixes.map((p) => `<span class="badge badge-prefix" title="Env prefix">${esc(p)}_</span>`).join('') : ''}
        </div>
        <div class="card-account">${esc(entry.account_name || entry.username || entry.email || '')}</div>
        <div class="card-projects">${projectBadges}</div>
      </div>
      <button class="card-chevron" data-action="toggle" data-idx="${idx}"
        aria-expanded="${isExp}" aria-label="${escAttr((isExp ? 'Collapse ' : 'Expand ') + entry.provider)}"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="6 9 12 15 18 9"/></svg></button>
    </div>
    ${entry.api_description ? `<div class="card-apidesc">${esc(entry.api_description)}</div>` : ''}
    <div class="card-body">
      <div class="key-section">
        <div class="key-row">
          <div class="key-label">${(TYPE_CONFIG[entry.secretType || 'api_key']?.keyLabel || 'API Key').toUpperCase()}</div>
          <div class="key-value${hasMask ? '' : ' revealed'}" id="kv-key-${idx}" data-action="copy-field" data-value="${escAttr(entry.api_key)}">${hasMask ? maskKey(entry.api_key) : esc(entry.api_key)}</div>
          <div class="key-actions">
            <button class="icon-btn sm${hasMask ? '' : ' active'}" id="reveal-key-${idx}" data-action="reveal" data-field="key" data-idx="${idx}" data-value="${escAttr(entry.api_key)}" aria-pressed="${!hasMask}" aria-label="${escAttr('Reveal value for ' + entry.provider)}">${eyeSVG}</button>
            <button class="icon-btn sm" data-action="copy-field" data-value="${escAttr(entry.api_key)}" aria-label="${escAttr('Copy value for ' + entry.provider)}">${copySVG}</button>
          </div>
        </div>
        ${entry.api_secret ? `<div class="key-row"><div class="key-label">SECRET</div><div class="key-value${secretMasked ? '' : ' revealed'}" id="kv-secret-${idx}" data-action="copy-field" data-value="${escAttr(entry.api_secret)}">${secretMasked ? maskKey(entry.api_secret) : esc(entry.api_secret)}</div><div class="key-actions"><button class="icon-btn sm${secretMasked ? '' : ' active'}" id="reveal-secret-${idx}" data-action="reveal" data-field="secret" data-idx="${idx}" data-value="${escAttr(entry.api_secret)}" aria-pressed="${!secretMasked}" aria-label="${escAttr('Reveal secret for ' + entry.provider)}">${eyeSVG}</button><button class="icon-btn sm" data-action="copy-field" data-value="${escAttr(entry.api_secret)}" aria-label="${escAttr('Copy secret for ' + entry.provider)}">${copySVG}</button></div></div>` : ''}
        ${entry.username ? `<div class="key-row"><div class="key-label">USERNAME</div><div class="key-value" data-action="copy-field" data-value="${escAttr(entry.username)}">${esc(entry.username)}</div><button class="icon-btn sm" data-action="copy-field" data-value="${escAttr(entry.username)}" aria-label="Copy username">${copySVG}</button></div>` : ''}
        ${entry.email ? `<div class="key-row"><div class="key-label">EMAIL</div><div class="key-value" data-action="copy-field" data-value="${escAttr(entry.email)}">${esc(entry.email)}</div><button class="icon-btn sm" data-action="copy-field" data-value="${escAttr(entry.email)}" aria-label="Copy email">${copySVG}</button></div>` : ''}
        ${(entry.extra_vars || [])
          .filter((xv) => xv.key)
          .map((xv) => {
            const display = xv.secret ? maskKey(xv.value) : esc(xv.value);
            return `<div class="key-row"><div class="key-label">${esc(xv.key.toUpperCase())}</div><div class="key-value${xv.secret ? '' : ' revealed'}" data-action="copy-field" data-value="${escAttr(xv.value)}">${display}</div><button class="icon-btn sm" data-action="copy-field" data-value="${escAttr(xv.value)}" aria-label="${escAttr('Copy ' + xv.key)}">${copySVG}</button></div>`;
          })
          .join('')}
      </div>
      ${entry.scopes?.length ? `<div class="scopes-row">${entry.scopes.map((s) => `<span class="scope-pill">${esc(s)}</span>`).join('')}</div>` : ''}
      ${entry.description ? `<div class="desc-section"><button class="desc-toggle" data-action="toggle-desc" aria-expanded="false"><svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="9 18 15 12 9 6"/></svg>General Description</button><div class="desc-content">${esc(entry.description)}</div></div>` : ''}
      ${metaRows.length ? `<div class="meta-section">${metaRows.map(([k, v]) => `<div class="meta-row"><span class="meta-key">${k}</span><span class="meta-val">${v}</span></div>`).join('')}</div>` : ''}
      ${entry.categories?.length ? `<div class="cat-pills">${entry.categories.map((c) => `<span class="cat-pill">${esc(c)}</span>`).join('')}</div>` : ''}
      ${entry.last_rotated_at ? `<div class="meta-section"><div class="meta-row"><span class="meta-key">Last Rotated</span><span class="meta-val" style="color:var(--text2)">${esc(entry.last_rotated_at)}</span> ${rotationAgeBadge(entry)}</div></div>` : ''}
    </div>
    ${entry.tags?.length ? `<div class="card-tags">${entry.tags.map((t) => `<span class="tag-chip-card" style="${tagColor(t)}">${esc(t)}</span>`).join('')}</div>` : ''}
    <div class="card-foot">
      <button class="env-copy-btn" id="env-btn-${idx}" data-action="copy-env" data-idx="${idx}" aria-label="${escAttr('Copy ' + entry.provider + ' as ' + envLabel)}">${copySVG}<span class="env-format-badge">${envLabel}</span><span id="env-label-${idx}">${dotenvKey(entry)}</span></button>
      <button class="icon-btn sm" data-action="rotate" data-idx="${idx}" title="Mark as rotated" aria-label="${escAttr('Mark ' + entry.provider + ' as rotated')}" style="font-size:11px;gap:3px;">↺</button>
      <button class="icon-btn sm${entry.pinned ? ' pin-btn active' : ' pin-btn'}" data-action="pin" data-idx="${idx}" title="${entry.pinned ? 'Unpin' : 'Pin to top'}" aria-pressed="${!!entry.pinned}" aria-label="${escAttr((entry.pinned ? 'Unpin ' : 'Pin ') + entry.provider)}"><svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="12" y1="17" x2="12" y2="22"/><path d="M5 17h14v-1.76a2 2 0 0 0-1.11-1.79l-1.78-.9A2 2 0 0 1 15 10.76V6h1a2 2 0 0 0 0-4H8a2 2 0 0 0 0 4h1v4.76a2 2 0 0 1-1.11 1.79l-1.78.9A2 2 0 0 0 5 15.24Z"/></svg></button>
      <button class="icon-btn sm" data-action="duplicate" data-idx="${idx}" title="Duplicate" aria-label="${escAttr('Duplicate ' + entry.provider)}">${dupSVG}</button>
      <button class="icon-btn sm" data-action="edit" data-idx="${idx}" title="Edit" aria-label="${escAttr('Edit ' + entry.provider)}">${editSVG}</button>
      <button class="icon-btn sm danger" data-action="delete" data-idx="${idx}" title="Delete" aria-label="${escAttr('Delete ' + entry.provider)}">${delSVG}</button>
    </div>`;
  return card;
}

function getExpiryBorderClass(entry: VaultEntry): string {
  if (!entry.expires_at) return '';
  const days = Math.round((new Date(entry.expires_at).getTime() - Date.now()) / 86400000);
  if (days < 0) return ' expiry-urgent';
  if (days <= 7) return ' expiry-urgent';
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
  if (days < 0)
    return `<span class="badge badge-expiry-expired" title="${escAttr(entry.expires_at)}">Expired ${Math.abs(days)}d ago</span>`;
  if (days <= Settings.get('expiryWarningDays'))
    return `<span class="badge badge-expiry-warn" title="${escAttr(entry.expires_at)}">Expires in ${days}d</span>`;
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
  const typeChunks = chunks.filter((c) => c.chunk_type !== 'env_file');
  const envChunks = chunks.filter((c) => c.chunk_type === 'env_file');

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
    const ifaceChunks = chunks.filter((c) => c.chunk_type === 'wg_interface');
    const peerChunks = chunks.filter((c) => c.chunk_type === 'wg_peer');
    const otherChunks = chunks.filter(
      (c) => c.chunk_type !== 'wg_interface' && c.chunk_type !== 'wg_peer',
    );
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
    const nginxChunks = chunks.filter(
      (c) => c.chunk_type !== 'nginx_key' && c.chunk_type !== 'env_file',
    );
    const allKeyChunks = chunks.filter((c) => c.chunk_type === 'nginx_key');
    const nginxEnvChunks = chunks.filter((c) => c.chunk_type === 'env_file');
    // Auto-link: certificate vault entries whose site matches a domain this project references.
    const certDomains = nginxCertDomains(project);
    // Hide nginx_key chunks whose PEM duplicates a shown cert entry — the cert card is canonical.
    const redundantIds = new Set(redundantCertKeyChunkIds(project));
    const keyChunks = allKeyChunks.filter((c) => !redundantIds.has(c.id));
    if (keyChunks.length > 0 || nginxEnvChunks.length > 0 || certDomains.length > 0) {
      const twoCol = document.createElement('div');
      twoCol.className = 'chunks-two-col';
      const leftGrid = document.createElement('div');
      leftGrid.className = 'chunks-grid nginx-grid';
      for (const chunk of nginxChunks) leftGrid.appendChild(renderChunkCard(chunk, project));
      twoCol.appendChild(leftGrid);
      const rightCol = document.createElement('div');
      rightCol.className = 'chunks-col';
      if (certDomains.length) {
        const hdrC = document.createElement('div');
        hdrC.className = 'chunks-col-label';
        hdrC.textContent = 'TLS Certificates';
        rightCol.appendChild(hdrC);
        const certWrap = document.createElement('div');
        certWrap.innerHTML = certDomains.map((d) => renderNginxCertCard(d)).join('');
        rightCol.appendChild(certWrap);
        if (redundantIds.size) {
          const cleanup = document.createElement('button');
          cleanup.className = 'btn btn-ghost btn-xs cert-cleanup-btn';
          cleanup.dataset.action = 'remove-redundant-cert-chunks';
          cleanup.dataset.projectId = project.id;
          cleanup.textContent = `Remove ${redundantIds.size} duplicate key-file chunk${redundantIds.size > 1 ? 's' : ''} (shown above)`;
          rightCol.appendChild(cleanup);
        }
      }
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
    const netChunks = chunks.filter((c) => c.chunk_type === 'docker_network');
    const volChunks = chunks.filter((c) => c.chunk_type === 'docker_volume');
    const efChunks = chunks.filter((c) => c.chunk_type === 'env_file');

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
      hdr.className = 'chunks-col-label';
      hdr.textContent = 'Environment Files';
      rightCol.appendChild(hdr);
      for (const chunk of efChunks) rightCol.appendChild(renderChunkCard(chunk, project));
    }
    if (netChunks.length) {
      const hdr = document.createElement('div');
      hdr.className = 'chunks-col-label';
      hdr.textContent = 'Networks';
      rightCol.appendChild(hdr);
      for (const chunk of netChunks) rightCol.appendChild(renderChunkCard(chunk, project));
    }
    if (volChunks.length) {
      const hdr = document.createElement('div');
      hdr.className = 'chunks-col-label';
      hdr.textContent = 'Volumes';
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
      wireguard: 'No sections yet — import a wg0.conf or click "+ Add Peer".',
      docker: 'No services yet — import a docker-compose.yml or click "+ Add Service".',
      nginx: 'No blocks yet — use "+ Server", "+ Upstream" or "+ Location".',
      kubernetes: 'No resources yet — use "+ Deploy", "+ Service", "+ ConfigMap", etc.',
      ssh_config: 'No hosts yet — import a ~/.ssh/config or click "+ Add Host".',
      traefik: 'No routes yet — use "+ Router", "+ Service" or "+ Middleware".',
    };
    const empty = document.createElement('div');
    empty.style.cssText = 'color:var(--text3);font-size:12px;padding:20px 0;text-align:center';
    empty.textContent =
      _emptyMsgs[project.project_type!] || 'No chunks yet. Use the buttons above to add sections.';
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

    // Auto-linked cert: create a stub certificate entry for a referenced domain.
    if (action === 'create-cert-stub') {
      const domain = el.dataset.domain || '';
      if (!domain) return;
      ensureCertForDomain(domain, projId);
      persist();
      showToast(`Created certificate entry for ${domain} — paste the PEMs`, 'ok');
      render();
      return;
    }

    // Auto-linked cert: open the matched certificate entry in the edit modal.
    if (action === 'edit-cert-entry') {
      const provider = el.dataset.provider || '';
      const idx = st.vault.api_keys.findIndex(
        (en) => en.secretType === 'certificate' && en.provider === provider,
      );
      if (idx < 0) {
        showToast('Certificate entry not found', 'err');
        return;
      }
      openModal('Edit Secret', idx);
      return;
    }

    // Delete nginx_key chunks that duplicate a shown cert entry (the cert card is canonical).
    if (action === 'remove-redundant-cert-chunks') {
      const p = st.vault.projects.find((pr) => pr.id === el.dataset.projectId);
      if (!p) return;
      const ids = new Set(redundantCertKeyChunkIds(p));
      if (!ids.size) return;
      p.chunks = (p.chunks || []).filter((c) => !ids.has(c.id));
      persist();
      showToast(`Removed ${ids.size} duplicate key-file chunk${ids.size > 1 ? 's' : ''}`, 'ok');
      render();
      return;
    }

    // Click a ${ref} badge → jump to the linked vault entry in the secrets panel.
    if (action === 'jump-ref') {
      const ref = el.dataset.ref || '';
      const provPart = ref.includes('/') ? ref.slice(0, ref.indexOf('/')) : ref;
      let i = st.vault.api_keys.findIndex((en) => en.provider === provPart);
      if (i < 0 && provPart.includes('_')) {
        const us = provPart.lastIndexOf('_');
        const p = provPart.slice(0, us),
          k = provPart.slice(us + 1);
        i = st.vault.api_keys.findIndex((en) => en.provider === p && en.key_id === k);
      }
      if (i < 0) {
        showToast(`No vault entry matches "${ref}"`, 'err');
        return;
      }
      switchPanel('secrets');
      st.expanded.add(entryId(st.vault.api_keys[i]));
      render();
      setTimeout(() => {
        const cardEl = document.querySelector<HTMLElement>(`#card-grid [data-idx="${i}"]`);
        cardEl?.scrollIntoView({ behavior: 'smooth', block: 'center' });
        cardEl?.classList.add('flash-highlight');
        setTimeout(() => cardEl?.classList.remove('flash-highlight'), 1500);
      }, 80);
      return;
    }

    const proj = st.vault.projects.find((p) => p.id === projId);
    if (!proj) return;

    if (action === 'edit-chunk') {
      const chunk = proj.chunks?.find((c) => c.id === chunkId);
      if (chunk) openChunkEditModal(proj, chunk);
      return;
    }

    if (action === 'copy-chunk-full') {
      const chunk = proj.chunks?.find((c) => c.id === chunkId);
      if (chunk) {
        clipboardWrite(chunkToString(chunk)).then(() => showToast('Copied ✓', 'ok', 1500));
      }
      return;
    }

    if (action === 'copy-chunk-raw') {
      const chunk = proj.chunks?.find((c) => c.id === chunkId);
      if (chunk) {
        const envF = chunk.fields.filter(
          (f) =>
            f.description === 'env' ||
            f.field_type === 'env_var' ||
            chunk.chunk_type === 'env_file',
        );
        const snapshot: Record<string, string> = {};
        const text = envF
          .map((f) => {
            const { resolved } = resolveFieldRef(f.value, false);
            const v = resolved ?? f.value;
            snapshot[f.key] = v;
            return `${f.key}=${v}`;
          })
          .join('\n');
        clipboardWrite(text).then(() => diffAndStashCopy(chunk, snapshot));
      }
      return;
    }

    if (action === 'copy-chunk-env') {
      const chunk = proj.chunks?.find((c) => c.id === chunkId);
      if (chunk) {
        const envF = chunk.fields.filter(
          (f) => f.description === 'env' || f.field_type === 'env_var',
        );
        const snapshot: Record<string, string> = {};
        const text = envF
          .map((f) => {
            const v = resolveFieldRef(f.value, true).resolved ?? f.value;
            snapshot[f.key] = v;
            return `${f.key}=${v}`;
          })
          .join('\n');
        clipboardWrite(text).then(() => diffAndStashCopy(chunk, snapshot));
      }
      return;
    }

    if (action === 'delete-chunk') {
      if (
        !(await showConfirm(`Delete chunk "${proj.chunks?.find((c) => c.id === chunkId)?.name}"?`))
      )
        return;
      proj.chunks = (proj.chunks || []).filter((c) => c.id !== chunkId);
      persist();
      render();
      return;
    }

    if (action === 'chunk-up' || action === 'chunk-down') {
      const _cks = proj.chunks || [];
      const _ci = _cks.findIndex((c) => c.id === chunkId);
      if (_ci < 0) return;
      if (action === 'chunk-up' && _ci > 0) [_cks[_ci - 1], _cks[_ci]] = [_cks[_ci], _cks[_ci - 1]];
      if (action === 'chunk-down' && _ci < _cks.length - 1)
        [_cks[_ci], _cks[_ci + 1]] = [_cks[_ci + 1], _cks[_ci]];
      proj.chunks = _cks;
      persist();
      render();
      return;
    }

    if (action === 'dup-chunk') {
      const _src = proj.chunks?.find((c) => c.id === chunkId);
      if (!_src) return;
      const _dup = {
        ..._src,
        id: crypto.randomUUID(),
        name: _src.name + ' (copy)',
        fields: _src.fields.map((f) => ({ ...f })),
      };
      if (!proj.chunks) proj.chunks = [];
      const _ci2 = proj.chunks.findIndex((c) => c.id === chunkId);
      proj.chunks.splice(_ci2 + 1, 0, _dup);
      persist();
      render();
      showToast(`Duplicated "${_src.name}"`, 'ok');
      return;
    }

    if (action === 'add-wg-peer') {
      const newPeer = {
        id: crypto.randomUUID(),
        name: `Peer ${(proj.chunks || []).filter((c) => c.chunk_type === 'wg_peer').length + 1}`,
        chunk_type: 'wg_peer' as const,
        fields: [
          { key: 'PublicKey', value: '', field_type: 'var' as const },
          { key: 'AllowedIPs', value: '', field_type: 'var' as const },
          { key: 'Endpoint', value: '', field_type: 'var' as const },
          { key: 'PersistentKeepalive', value: '', field_type: 'var' as const },
          { key: 'PresharedKey', value: '', field_type: 'secret' as const, secret: true },
        ],
      };
      if (!proj.chunks) proj.chunks = [];
      proj.chunks.push(newPeer);
      persist();
      render();
      return;
    }

    if (action === 'add-docker-service') {
      const n = (proj.chunks || []).filter((c) => c.chunk_type === 'docker_service').length + 1;
      if (!proj.chunks) proj.chunks = [];
      proj.chunks.push({
        id: crypto.randomUUID(),
        name: `service-${n}`,
        chunk_type: 'docker_service',
        fields: [],
      });
      persist();
      render();
      return;
    }

    if (action === 'add-docker-network') {
      const name = await showPrompt('Network name:', 'my-network');
      if (!name) return;
      if (!proj.chunks) proj.chunks = [];
      const nc = proj.chunks.find((c) => c.chunk_type === 'docker_network');
      if (nc) {
        nc.fields.push({ key: name, value: '', field_type: 'var' });
      } else {
        proj.chunks.push({
          id: crypto.randomUUID(),
          name: 'networks',
          chunk_type: 'docker_network',
          fields: [{ key: name, value: '', field_type: 'var' }],
        });
      }
      persist();
      render();
      return;
    }

    if (action === 'add-docker-volume') {
      const name = await showPrompt('Volume name:', 'my-volume');
      if (!name) return;
      if (!proj.chunks) proj.chunks = [];
      const vc = proj.chunks.find((c) => c.chunk_type === 'docker_volume');
      if (vc) {
        vc.fields.push({ key: name, value: '', field_type: 'var' });
      } else {
        proj.chunks.push({
          id: crypto.randomUUID(),
          name: 'volumes',
          chunk_type: 'docker_volume',
          fields: [{ key: name, value: '', field_type: 'var' }],
        });
      }
      persist();
      render();
      return;
    }

    if (action === 'export-wg') {
      const conf = exportWireGuard(proj);
      showDropdown(el, [
        {
          label: 'Copy wg0.conf',
          fn: () => clipboardWrite(conf).then(() => showToast('Copied ✓', 'ok')),
        },
        {
          label: 'Download wg0.conf',
          fn: () => {
            const blob = new Blob([conf], { type: 'text/plain' });
            const url = URL.createObjectURL(blob);
            const a = Object.assign(document.createElement('a'), {
              href: url,
              download: `${proj.name}.conf`,
            });
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            setTimeout(() => URL.revokeObjectURL(url), 1000);
            showToast('Downloaded', 'ok');
          },
        },
      ]);
      return;
    }

    if (action === 'export-docker') {
      const { yaml, envFile } = exportDockerCompose(proj);
      showDropdown(el, [
        {
          label: 'Copy YAML',
          fn: () => clipboardWrite(yaml).then(() => showToast('Copied YAML ✓', 'ok')),
        },
        {
          label: 'Copy .env',
          fn: () => clipboardWrite(envFile).then(() => showToast('Copied .env ✓', 'ok')),
        },
        {
          label: 'Download YAML',
          fn: () => {
            const blob = new Blob([yaml], { type: 'text/plain' });
            const url = URL.createObjectURL(blob);
            const a = Object.assign(document.createElement('a'), {
              href: url,
              download: 'docker-compose.yml',
            });
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            setTimeout(() => URL.revokeObjectURL(url), 1000);
          },
        },
        {
          label: 'Download .env',
          fn: () => {
            const blob = new Blob([envFile], { type: 'text/plain' });
            const url = URL.createObjectURL(blob);
            const a = Object.assign(document.createElement('a'), {
              href: url,
              download: `${proj.name}.env`,
            });
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            setTimeout(() => URL.revokeObjectURL(url), 1000);
          },
        },
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
        if (!parsed.length) {
          showToast('No WireGuard sections found', 'err');
          return;
        }
        if (
          proj.chunks?.length &&
          !(await showConfirm(
            `Replace ${proj.chunks.length} existing chunk(s) with ${parsed.length} imported sections?`,
          ))
        )
          return;
        proj.chunks = parsed;
        persist();
        render();
        showToast(`Imported ${parsed.length} sections ✓`, 'ok');
      };
      showDropdown(el, [
        {
          label: 'Import from file',
          fn: () => pickFileText('text/plain,.conf', (text) => doImportWg(text)),
        },
        {
          label: 'Paste wg0.conf text…',
          fn: async () => {
            const text = await showPromptLarge('Paste wg0.conf contents:', '');
            if (text) doImportWg(text);
          },
        },
      ]);
      return;
    }

    if (action === 'import-docker') {
      const doImportDocker = async (text: string) => {
        const parsed = parseDockerCompose(text);
        if (!parsed.length) {
          showToast('No services/networks/volumes found', 'err');
          return;
        }
        if (
          proj.chunks?.length &&
          !(await showConfirm(
            `Replace ${proj.chunks.length} existing chunk(s) with ${parsed.length} imported chunks?`,
          ))
        )
          return;
        proj.chunks = parsed;
        persist();
        render();
        showToast(`Imported ${parsed.length} chunks ✓`, 'ok');
      };
      showDropdown(el, [
        {
          label: 'Import from file',
          fn: () => pickFileText('text/plain,text/yaml,.yaml,.yml', (text) => doImportDocker(text)),
        },
        {
          label: 'Paste YAML…',
          fn: async () => {
            const text = await showPromptLarge('Paste docker-compose.yml contents:', '');
            if (text) doImportDocker(text);
          },
        },
      ]);
      return;
    }

    if (action === 'import-ssh') {
      pickFileText('', async (text) => {
        const parsed = parseSshConfig(text);
        if (!parsed.length) {
          showToast('No Host blocks found in file', 'err');
          return;
        }
        if (
          proj.chunks?.length &&
          !(await showConfirm(
            `Replace ${proj.chunks.length} existing chunk(s) with ${parsed.length} imported host blocks?`,
          ))
        )
          return;
        proj.chunks = parsed;
        persist();
        render();
        showToast(`Imported ${parsed.length} host blocks ✓`, 'ok');
      });
      return;
    }

    if (action === 'import-nginx') {
      const doImportNginx = async (text: string, merge: boolean) => {
        const parsed = parseNginxConf(text);
        if (!parsed.length) {
          showToast('No server/upstream blocks found', 'err');
          return;
        }
        if (!merge) {
          if (
            proj.chunks?.length &&
            !(await showConfirm(
              `Replace ${proj.chunks.length} existing chunk(s) with ${parsed.length} imported chunks?`,
            ))
          )
            return;
          proj.chunks = parsed;
        } else {
          if (!proj.chunks) proj.chunks = [];
          proj.chunks.push(...parsed);
        }
        persist();
        render();
        // Surface any SSL cert domains found so user can add them to vault
        const certDomains = new Set<string>();
        for (const chunk of parsed) {
          for (const field of chunk.fields) {
            if (field.field_type === 'cert') {
              const m = /\/live\/([^/]+)\//.exec(field.value);
              if (m) certDomains.add(m[1]);
            }
          }
        }
        const certNote =
          certDomains.size > 0
            ? ` — SSL cert domains: ${[...certDomains].join(', ')} (add certificate vault entries to auto-link)`
            : '';
        showToast(`Imported ${parsed.length} chunks ✓${certNote}`, 'ok');
      };
      const hasExisting = (proj.chunks?.length ?? 0) > 0;
      showDropdown(el, [
        {
          label: 'Import from file',
          fn: () => pickFileText('text/plain,.conf,.nginx', (text) => doImportNginx(text, false)),
        },
        {
          label: 'Paste nginx config…',
          fn: async () => {
            const text = await showPromptLarge('Paste nginx site config:', '');
            if (text) doImportNginx(text, false);
          },
        },
        ...(hasExisting
          ? [
              {
                label: 'Append to existing',
                fn: () =>
                  pickFileText('text/plain,.conf,.nginx', (text) => doImportNginx(text, true)),
              },
            ]
          : []),
      ]);
      return;
    }

    if (action === 'export-env-chunk') {
      const chunk = proj.chunks?.find((c) => c.id === chunkId);
      if (!chunk) return;
      const dotenv = chunk.fields
        .filter((f) => f.key && f.value !== undefined)
        .map((f) => `${f.key}=${resolveFieldRef(f.value, true).resolved ?? f.value}`)
        .join('\n');
      showDropdown(el, [
        {
          label: 'Copy .env',
          fn: () => clipboardWrite(dotenv).then(() => showToast('Copied ✓', 'ok')),
        },
        {
          label: 'Download .env',
          fn: () => {
            const blob = new Blob([dotenv], { type: 'text/plain' });
            const url = URL.createObjectURL(blob);
            const a = Object.assign(document.createElement('a'), {
              href: url,
              download: `${chunk.name}.env`,
            });
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            setTimeout(() => URL.revokeObjectURL(url), 1000);
            showToast('Downloaded', 'ok');
          },
        },
      ]);
      return;
    }

    if (action === 'link-env-chunk') {
      const chunk = proj.chunks?.find((c) => c.id === chunkId);
      if (chunk) openEnvLinkModal(proj, chunk);
      return;
    }

    if (action === 'import-env-chunk') {
      const doImportEnv = (text: string, filename: string) => {
        const vars = parseEnvFile(text);
        if (!vars.length) {
          showToast('No variables found in .env', 'err');
          return;
        }
        const isSecretKey = (name: string) => /pass(word)?|secret|key|token|cred/i.test(name);
        const toFields = (v: { name: string; value: string }) => {
          const isRef = /^\$\{.+\}$/.test(v.value);
          const isSec = !isRef && isSecretKey(v.name) && v.value !== '';
          const ft: ChunkFieldType = isRef ? 'env_var' : isSec ? 'secret' : 'var';
          return { key: v.name, value: v.value, field_type: ft, secret: isSec };
        };
        const chunkName = filename.replace(/\.env$/, '').replace(/\.$/, '') || 'env-file';
        if (!proj.chunks) proj.chunks = [];
        const existing = proj.chunks.find(
          (c) => c.chunk_type === 'env_file' && c.name === chunkName,
        );
        if (existing) {
          existing.fields = vars.map(toFields);
        } else {
          proj.chunks.push({
            id: crypto.randomUUID(),
            name: chunkName,
            chunk_type: 'env_file',
            fields: vars.map(toFields),
          });
        }
        persist();
        render();
        showToast(`Imported ${vars.length} vars into "${chunkName}" ✓`, 'ok');
      };
      showDropdown(el, [
        {
          label: 'Import from file',
          fn: () =>
            pickFileText('text/plain,.env', (text, filename) => doImportEnv(text, filename)),
        },
        {
          label: 'Paste .env text…',
          fn: async () => {
            const text = await showPromptLarge('Paste .env contents:', '');
            if (text) doImportEnv(text, 'env-file');
          },
        },
      ]);
      return;
    }

    const addChunkFns: Partial<Record<string, () => any>> = {
      'add-nginx-server': () => ({
        id: crypto.randomUUID(),
        name: `server-${(proj.chunks || []).filter((c) => c.chunk_type === 'nginx_server').length + 1}`,
        chunk_type: 'nginx_server',
        fields: [
          { key: 'listen', value: '80', field_type: 'var' },
          { key: 'server_name', value: '', field_type: 'var' },
          { key: 'root', value: '/var/www/html', field_type: 'var' },
        ],
      }),
      'add-nginx-upstream': () => ({
        id: crypto.randomUUID(),
        name: `upstream-${(proj.chunks || []).filter((c) => c.chunk_type === 'nginx_upstream').length + 1}`,
        chunk_type: 'nginx_upstream',
        fields: [{ key: 'server', value: 'app:8080', field_type: 'list' }],
      }),
      'add-nginx-location': () => ({
        id: crypto.randomUUID(),
        name: `location-${(proj.chunks || []).filter((c) => c.chunk_type === 'nginx_location').length + 1}`,
        chunk_type: 'nginx_location',
        fields: [
          { key: 'path', value: '/', field_type: 'var' },
          { key: 'proxy_pass', value: '', field_type: 'var' },
        ],
      }),
      // 'add-nginx-key' handled separately below (needs dropdown + file picker)
      'add-k8s-deployment': () => ({
        id: crypto.randomUUID(),
        name: 'Deployment',
        chunk_type: 'k8s_deployment',
        fields: [
          { key: 'name', value: 'my-app', field_type: 'var' },
          { key: 'namespace', value: 'default', field_type: 'var' },
          { key: 'image', value: 'nginx:latest', field_type: 'var' },
          { key: 'replicas', value: '1', field_type: 'var' },
          { key: 'containerPort', value: '80', field_type: 'var' },
        ],
      }),
      'add-k8s-service': () => ({
        id: crypto.randomUUID(),
        name: 'Service',
        chunk_type: 'k8s_service',
        fields: [
          { key: 'name', value: 'my-app', field_type: 'var' },
          { key: 'namespace', value: 'default', field_type: 'var' },
          { key: 'port', value: '80', field_type: 'var' },
          { key: 'targetPort', value: '80', field_type: 'var' },
          { key: 'type', value: 'ClusterIP', field_type: 'var' },
        ],
      }),
      'add-k8s-configmap': () => ({
        id: crypto.randomUUID(),
        name: 'ConfigMap',
        chunk_type: 'k8s_configmap',
        fields: [
          { key: 'name', value: 'my-config', field_type: 'var' },
          { key: 'namespace', value: 'default', field_type: 'var' },
        ],
      }),
      'add-k8s-secret': () => ({
        id: crypto.randomUUID(),
        name: 'Secret',
        chunk_type: 'k8s_secret',
        fields: [
          { key: 'name', value: 'my-secret', field_type: 'var' },
          { key: 'namespace', value: 'default', field_type: 'var' },
        ],
      }),
      'add-k8s-ingress': () => ({
        id: crypto.randomUUID(),
        name: 'Ingress',
        chunk_type: 'k8s_ingress',
        fields: [
          { key: 'name', value: 'my-ingress', field_type: 'var' },
          { key: 'namespace', value: 'default', field_type: 'var' },
          { key: 'host', value: 'example.com', field_type: 'var' },
          { key: 'serviceName', value: 'my-app', field_type: 'var' },
          { key: 'servicePort', value: '80', field_type: 'var' },
        ],
      }),
      'add-ssh-host': () => ({
        id: crypto.randomUUID(),
        name: `host-${(proj.chunks || []).filter((c) => c.chunk_type === 'ssh_host').length + 1}`,
        chunk_type: 'ssh_host',
        fields: [
          { key: 'HostName', value: '', field_type: 'var' },
          { key: 'User', value: '', field_type: 'var' },
          { key: 'Port', value: '22', field_type: 'var' },
          { key: 'IdentityFile', value: '~/.ssh/id_ed25519', field_type: 'var' },
          { key: 'ServerAliveInterval', value: '60', field_type: 'var' },
        ],
      }),
      'add-traefik-router': () => ({
        id: crypto.randomUUID(),
        name: `router-${(proj.chunks || []).filter((c) => c.chunk_type === 'traefik_router').length + 1}`,
        chunk_type: 'traefik_router',
        fields: [
          { key: 'entryPoints', value: 'websecure', field_type: 'list' },
          { key: 'rule', value: '', field_type: 'var' },
          { key: 'service', value: '', field_type: 'var' },
        ],
      }),
      'add-traefik-service': () => ({
        id: crypto.randomUUID(),
        name: `service-${(proj.chunks || []).filter((c) => c.chunk_type === 'traefik_service').length + 1}`,
        chunk_type: 'traefik_service',
        fields: [
          { key: 'url', value: '', field_type: 'var' },
          { key: 'passHostHeader', value: 'true', field_type: 'var' },
        ],
      }),
      'add-traefik-middleware': () => ({
        id: crypto.randomUUID(),
        name: `middleware-${(proj.chunks || []).filter((c) => c.chunk_type === 'traefik_middleware').length + 1}`,
        chunk_type: 'traefik_middleware',
        fields: [{ key: 'type', value: 'redirectScheme', field_type: 'var' }],
      }),
      'add-apache-vhost': () => ({
        id: crypto.randomUUID(),
        name: `VirtualHost-${(proj.chunks || []).filter((c) => c.chunk_type === 'apache_vhost').length + 1}`,
        chunk_type: 'apache_vhost' as const,
        fields: [
          { key: 'ServerName', value: 'example.com', field_type: 'var' as const },
          { key: 'DocumentRoot', value: '/var/www/html', field_type: 'var' as const },
        ],
      }),
      'add-apache-directory': () => ({
        id: crypto.randomUUID(),
        name: `/var/www/html`,
        chunk_type: 'apache_directory' as const,
        fields: [
          { key: 'path', value: '/var/www/html', field_type: 'var' as const },
          { key: 'AllowOverride', value: 'All', field_type: 'var' as const },
          { key: 'Require', value: 'all granted', field_type: 'var' as const },
        ],
      }),
      'add-haproxy-frontend': () => ({
        id: crypto.randomUUID(),
        name: `frontend-${(proj.chunks || []).filter((c) => c.chunk_type === 'haproxy_frontend').length + 1}`,
        chunk_type: 'haproxy_frontend' as const,
        fields: [
          { key: 'bind', value: '*:80', field_type: 'port' as const },
          { key: 'mode', value: 'http', field_type: 'var' as const },
          { key: 'default_backend', value: 'app', field_type: 'var' as const },
        ],
      }),
      'add-haproxy-backend': () => ({
        id: crypto.randomUUID(),
        name: `backend-${(proj.chunks || []).filter((c) => c.chunk_type === 'haproxy_backend').length + 1}`,
        chunk_type: 'haproxy_backend' as const,
        fields: [
          { key: 'mode', value: 'http', field_type: 'var' as const },
          { key: 'balance', value: 'roundrobin', field_type: 'var' as const },
          { key: 'server', value: 'app1 127.0.0.1:8080 check', field_type: 'endpoint' as const },
        ],
      }),
      'add-ansible-vars': () => ({
        id: crypto.randomUUID(),
        name: `vars-${(proj.chunks || []).filter((c) => c.chunk_type === 'ansible_vars').length + 1}`,
        chunk_type: 'ansible_vars' as const,
        fields: [{ key: 'example_var', value: 'example_value', field_type: 'var' as const }],
      }),
      'add-ansible-task': () => ({
        id: crypto.randomUUID(),
        name: `task-${(proj.chunks || []).filter((c) => c.chunk_type === 'ansible_task').length + 1}`,
        chunk_type: 'ansible_task' as const,
        fields: [
          { key: 'name', value: 'My task', field_type: 'var' as const },
          { key: 'module', value: 'ansible.builtin.debug', field_type: 'var' as const },
          { key: 'msg', value: 'Hello world', field_type: 'var' as const },
        ],
      }),
      'add-pg-connection': () => ({
        id: crypto.randomUUID(),
        name: `db-${(proj.chunks || []).filter((c) => c.chunk_type === 'pg_connection').length + 1}`,
        chunk_type: 'pg_connection' as const,
        fields: [
          { key: 'host', value: 'localhost', field_type: 'var' as const },
          { key: 'port', value: '5432', field_type: 'port' as const },
          { key: 'dbname', value: '', field_type: 'var' as const },
          { key: 'user', value: '', field_type: 'var' as const },
          { key: 'password', value: '', field_type: 'secret' as const, secret: true },
          { key: 'sslmode', value: 'require', field_type: 'var' as const },
        ],
      }),
      'add-pg-role': () => ({
        id: crypto.randomUUID(),
        name: `role-${(proj.chunks || []).filter((c) => c.chunk_type === 'pg_role').length + 1}`,
        chunk_type: 'pg_role' as const,
        fields: [
          { key: 'rolname', value: '', field_type: 'var' as const },
          { key: 'rolpassword', value: '', field_type: 'secret' as const, secret: true },
          { key: 'rolcanlogin', value: 'true', field_type: 'var' as const },
        ],
      }),
    };
    if (action in addChunkFns) {
      if (!proj.chunks) proj.chunks = [];
      proj.chunks.push(addChunkFns[action]!());
      persist();
      render();
      return;
    }

    if (action === 'add-nginx-key') {
      const makeKeyChunk = (keyType: 'fullchain' | 'privkey', path = '', content = '') => ({
        id: crypto.randomUUID(),
        name: path
          ? path
              .split('/')
              .pop()!
              .replace(/\.pem$/i, '')
          : `key-${(proj.chunks || []).filter((c) => c.chunk_type === 'nginx_key').length + 1}`,
        chunk_type: 'nginx_key' as const,
        fields: [
          { key: 'path', value: path, field_type: 'var' as const },
          { key: 'key_type', value: keyType, field_type: 'var' as const },
          { key: 'content', value: content, field_type: 'cert' as const },
        ],
      });
      const doImportKey = (keyType: 'fullchain' | 'privkey') =>
        pickFileText('.pem,.crt,.key,.cer', (text, name) => {
          const pem = text.trim();
          const domains = nginxCertDomains(proj);
          if (domains.length === 1) {
            // Single domain → store in that domain's cert entry. No redundant nginx_key chunk.
            const entry = ensureCertForDomain(domains[0], proj.id);
            if (keyType === 'fullchain') entry.certificate_data = pem;
            else entry.cert_key_data = pem;
            persist();
            render();
            showToast(`Imported ${name} into ${domains[0]} certificate ✓`, 'ok');
          } else {
            // No single domain to attach to → fall back to a standalone key-file chunk.
            if (!proj.chunks) proj.chunks = [];
            proj.chunks.push(makeKeyChunk(keyType, name, pem));
            persist();
            render();
            showToast(`Imported ${name} ✓`, 'ok');
          }
        });
      showDropdown(el, [
        { label: 'Import fullchain.pem', fn: () => doImportKey('fullchain') },
        { label: 'Import privkey.pem', fn: () => doImportKey('privkey') },
        {
          label: 'Blank key file',
          fn: () => {
            if (!proj.chunks) proj.chunks = [];
            proj.chunks.push(makeKeyChunk('fullchain'));
            persist();
            render();
          },
        },
      ]);
      return;
    }

    if (action === 'import-nginx-key-file') {
      const chunk = proj.chunks?.find((c) => c.id === chunkId);
      if (!chunk) return;
      pickFileText('.pem,.crt,.key,.cer', (text, name) => {
        const isPrivkey =
          /privkey|private[-_.]?key/i.test(name) && !/cert|chain|fullchain/i.test(name);
        const ktF = chunk.fields.find((f) => f.key === 'key_type');
        if (ktF) ktF.value = isPrivkey ? 'privkey' : 'fullchain';
        else
          chunk.fields.unshift({
            key: 'key_type',
            value: isPrivkey ? 'privkey' : 'fullchain',
            field_type: 'var',
          });
        const cF = chunk.fields.find((f) => f.key === 'content');
        if (cF) cF.value = text.trim();
        else chunk.fields.push({ key: 'content', value: text.trim(), field_type: 'cert' });
        persist();
        render();
        showToast(`Imported ${name} ✓`, 'ok');
      });
      return;
    }

    const dlText = (content: string, filename: string) => {
      const blob = new Blob([content], { type: 'text/plain' });
      const url = URL.createObjectURL(blob);
      const a = Object.assign(document.createElement('a'), { href: url, download: filename });
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      setTimeout(() => URL.revokeObjectURL(url), 1000);
    };

    if (action === 'export-nginx') {
      const conf = exportNginx(proj);
      showDropdown(el, [
        {
          label: 'Copy nginx.conf',
          fn: () => clipboardWrite(conf).then(() => showToast('Copied ✓', 'ok')),
        },
        {
          label: 'Download nginx.conf',
          fn: () => {
            dlText(conf, 'nginx.conf');
            showToast('Downloaded', 'ok');
          },
        },
      ]);
      return;
    }

    if (action === 'export-k8s') {
      const yamlContent = exportK8s(proj);
      showDropdown(el, [
        {
          label: 'Copy YAML',
          fn: () => clipboardWrite(yamlContent).then(() => showToast('Copied ✓', 'ok')),
        },
        {
          label: 'Download manifests.yaml',
          fn: () => {
            dlText(yamlContent, `${proj.name}-manifests.yaml`);
            showToast('Downloaded', 'ok');
          },
        },
      ]);
      return;
    }

    if (action === 'export-ssh') {
      const conf = exportSshConfig(proj);
      showDropdown(el, [
        {
          label: 'Copy config',
          fn: () => clipboardWrite(conf).then(() => showToast('Copied ✓', 'ok')),
        },
        {
          label: 'Download config',
          fn: () => {
            dlText(conf, 'config');
            showToast('Downloaded', 'ok');
          },
        },
      ]);
      return;
    }

    if (action === 'export-traefik') {
      const yamlContent = exportTraefik(proj);
      showDropdown(el, [
        {
          label: 'Copy traefik.yaml',
          fn: () => clipboardWrite(yamlContent).then(() => showToast('Copied ✓', 'ok')),
        },
        {
          label: 'Download traefik.yaml',
          fn: () => {
            dlText(yamlContent, 'traefik.yaml');
            showToast('Downloaded', 'ok');
          },
        },
      ]);
      return;
    }

    if (action === 'import-apache') {
      const doImport = async (text: string, merge: boolean) => {
        const parsed = parseApacheConf(text);
        if (!parsed.length) {
          showToast('No VirtualHost/Directory blocks found', 'err');
          return;
        }
        if (
          !merge &&
          proj.chunks?.length &&
          !(await showConfirm(`Replace ${proj.chunks.length} existing chunk(s)?`))
        )
          return;
        if (merge) {
          if (!proj.chunks) proj.chunks = [];
          proj.chunks.push(...parsed);
        } else proj.chunks = parsed;
        persist();
        render();
        showToast(`Imported ${parsed.length} chunks ✓`, 'ok');
      };
      showDropdown(el, [
        {
          label: 'Import from file',
          fn: () => pickFileText('text/plain,.conf', (t) => doImport(t, false)),
        },
        {
          label: 'Paste config…',
          fn: async () => {
            const t = await showPromptLarge('Paste Apache config:', '');
            if (t) doImport(t, false);
          },
        },
        ...(proj.chunks?.length
          ? [
              {
                label: 'Append to existing',
                fn: () => pickFileText('text/plain,.conf', (t) => doImport(t, true)),
              },
            ]
          : []),
      ]);
      return;
    }

    if (action === 'export-apache') {
      const conf = exportApache(proj);
      showDropdown(el, [
        {
          label: 'Copy config',
          fn: () => clipboardWrite(conf).then(() => showToast('Copied ✓', 'ok')),
        },
        {
          label: 'Download config',
          fn: () => {
            dlText(conf, `${proj.name}.conf`);
            showToast('Downloaded', 'ok');
          },
        },
      ]);
      return;
    }

    if (action === 'import-haproxy') {
      const doImport = async (text: string, merge: boolean) => {
        const parsed = parseHaproxyConf(text);
        if (!parsed.length) {
          showToast('No sections found', 'err');
          return;
        }
        if (
          !merge &&
          proj.chunks?.length &&
          !(await showConfirm(`Replace ${proj.chunks.length} existing chunk(s)?`))
        )
          return;
        if (merge) {
          if (!proj.chunks) proj.chunks = [];
          proj.chunks.push(...parsed);
        } else proj.chunks = parsed;
        persist();
        render();
        showToast(`Imported ${parsed.length} chunks ✓`, 'ok');
      };
      showDropdown(el, [
        {
          label: 'Import from file',
          fn: () => pickFileText('text/plain,.cfg', (t) => doImport(t, false)),
        },
        {
          label: 'Paste config…',
          fn: async () => {
            const t = await showPromptLarge('Paste HAProxy config:', '');
            if (t) doImport(t, false);
          },
        },
        ...(proj.chunks?.length
          ? [
              {
                label: 'Append to existing',
                fn: () => pickFileText('text/plain,.cfg', (t) => doImport(t, true)),
              },
            ]
          : []),
      ]);
      return;
    }

    if (action === 'export-haproxy') {
      const conf = exportHaproxy(proj);
      showDropdown(el, [
        {
          label: 'Copy haproxy.cfg',
          fn: () => clipboardWrite(conf).then(() => showToast('Copied ✓', 'ok')),
        },
        {
          label: 'Download haproxy.cfg',
          fn: () => {
            dlText(conf, 'haproxy.cfg');
            showToast('Downloaded', 'ok');
          },
        },
      ]);
      return;
    }

    if (action === 'export-ansible') {
      const yamlContent = exportAnsible(proj);
      showDropdown(el, [
        {
          label: 'Copy YAML',
          fn: () => clipboardWrite(yamlContent).then(() => showToast('Copied ✓', 'ok')),
        },
        {
          label: 'Download playbook.yml',
          fn: () => {
            dlText(yamlContent, 'playbook.yml');
            showToast('Downloaded', 'ok');
          },
        },
      ]);
      return;
    }

    if (action === 'export-postgres') {
      const pgpass = exportPostgres(proj);
      showDropdown(el, [
        {
          label: 'Copy .pgpass',
          fn: () => clipboardWrite(pgpass).then(() => showToast('Copied ✓', 'ok')),
        },
        {
          label: 'Download .pgpass',
          fn: () => {
            dlText(pgpass, '.pgpass');
            showToast('Downloaded', 'ok');
          },
        },
      ]);
      return;
    }
  });
}

// ── Top-level render ───────────────────────────────────────────────────────

export function render() {
  // Single hook for view persistence, mirroring resetViewState's single hook for
  // clearing it. Every filter/project/tag change routes through triggerRender(),
  // so snapshotting here catches all of them without each call site remembering.
  saveViewState();
  renderSidebar();
  renderProjectTree();
  const selectedId = st.currentSelectedProjectIds[0] ?? 'Universal';
  if (selectedId !== 'Universal' && !selectedId.startsWith('virtual:')) {
    const project = st.vault.projects.find((p) => p.id === selectedId);
    if (project?.project_type && project.project_type !== 'generic') {
      renderConfigView(project);
      updateCopyAllBtn();
      return;
    }
  }
  renderGrid();
  updateCopyAllBtn();
}

/**
 * Every filter currently narrowing the grid, as human-readable labels.
 *
 * Project ids are resolved to names — a raw UUID in the toolbar tells the user
 * nothing about what is being hidden.
 */
export function activeFilterLabels(): string[] {
  const out: string[] = [];
  if (st.filter.type !== 'all' && st.filter.value)
    out.push(`${st.filter.type}: ${st.filter.value}`);
  if (st.currentEnvFilter) out.push(`env: ${st.currentEnvFilter}`);
  if (st.activeTagFilter) out.push(`tag: ${st.activeTagFilter}`);
  if (st.activePrefixFilter) out.push(`prefix: ${st.activePrefixFilter}`);
  if (st.activePoolFilter) out.push(`pool: ${st.activePoolFilter}`);
  if (st.searchQ) out.push(`search: ${st.searchQ}`);
  const proj = st.currentSelectedProjectIds.filter((id) => id !== 'Universal');
  proj.forEach((id) => {
    const p = st.vault.projects.find((x) => x.id === id);
    out.push(`project: ${p?.name ?? id}`);
  });
  return out;
}

/** Shows or hides the "Clear filters" button and its count. */
export function updateActiveFilterBar(): void {
  const btn = document.getElementById('clear-filters-btn');
  if (!btn) return;
  const labels = activeFilterLabels();
  btn.style.display = labels.length ? '' : 'none';
  const countEl = document.getElementById('clear-filters-count');
  if (countEl) countEl.textContent = labels.length > 1 ? `(${labels.length})` : '';
  btn.title = labels.length
    ? `Active — ${labels.join(', ')}\nClear every filter (Shift+Esc)`
    : 'Clear every active filter (Shift+Esc)';
}

export function updateCopyAllBtn() {
  updateActiveFilterBar();
  const wrap = document.getElementById('copy-all-wrap');
  if (!wrap) return;
  const items = getFiltered();
  wrap.style.display = items.length ? 'flex' : 'none';
  const btn = document.getElementById('copy-all-btn')!;
  const projectFiltered = (st.currentSelectedProjectIds[0] ?? 'Universal') !== 'Universal';
  const ST_LABELS: Record<string, string> = {
    api_key: 'API Keys',
    password: 'Passwords',
    env_var: 'Env Vars',
    connection_string: 'Connections',
    ssh_key: 'SSH Keys',
    certificate: 'Certificates',
    file_blob: 'File Blobs',
  };
  const label =
    st.filter.type === 'category'
      ? `Copy "${st.filter.value}"`
      : st.filter.type === 'price'
        ? `Copy ${st.filter.value}`
        : st.filter.type === 'secret_type'
          ? `Copy ${ST_LABELS[st.filter.value] || st.filter.value}`
          : projectFiltered
            ? 'Copy Category'
            : 'Copy All';
  btn.innerHTML = `${copySVG} ${label}`;
}

// Register render as the global render function
setRenderFn(render);

// ── ENV chunk ↔ vault link modal ───────────────────────────────────────────

let _envLinkProj: import('./types').Project | null = null;
let _envLinkChunk: import('./types').SecretChunk | null = null;

function _renderEnvLinkRow(m: EnvLinkMatch): string {
  if (m.alreadyLinked) {
    return `<div class="env-link-row env-link-row--linked">
      <span class="env-link-key">${esc(m.key)}</span>
      <span class="env-link-badge env-link-badge--linked" title="Linked to ${esc(m.existingRef || '')}">→ ${esc(m.existingRef || '')} ✓</span>
    </div>`;
  }
  if (m.match) {
    const { entry, ref, field, confidence } = m.match;
    return `<div class="env-link-row env-link-row--match" data-key="${escAttr(m.key)}" data-ref="${escAttr(ref)}">
      <label class="env-link-check-label">
        <input type="checkbox" class="env-link-cb" checked>
        <span class="env-link-key">${esc(m.key)}</span>
      </label>
      <span class="env-link-badge env-link-badge--vault">→ ${esc(entry.provider)} / ${esc(field)} <span class="env-link-conf">${confidence}%</span></span>
    </div>`;
  }
  if (m.suggestCreate) {
    const { provider, keyId, secretType } = m.suggestCreate;
    const typeOpts = (
      ['api_key', 'password', 'connection_string', 'env_var', 'ssh_key'] as SecretType[]
    )
      .map((t) => `<option value="${t}"${t === secretType ? ' selected' : ''}>${t}</option>`)
      .join('');
    return `<div class="env-link-row env-link-row--create" data-key="${escAttr(m.key)}" data-key-id="${escAttr(keyId || '')}">
      <label class="env-link-check-label">
        <input type="checkbox" class="env-link-cb">
        <span class="env-link-key">${esc(m.key)}</span>
      </label>
      <span class="env-link-badge env-link-badge--new">New:</span>
      <input class="form-input env-link-name-input" value="${escAttr(provider)}" placeholder="provider name" style="width:130px;height:24px;padding:2px 6px;font-size:11px">
      <select class="form-input env-link-type-select" style="width:130px;height:24px;padding:2px 4px;font-size:11px">${typeOpts}</select>
    </div>`;
  }
  return `<div class="env-link-row env-link-row--skip">
    <span class="env-link-key">${esc(m.key)}</span>
    <span class="env-link-badge" style="color:var(--text3)">empty — skip</span>
  </div>`;
}

export function openEnvLinkModal(
  proj: import('./types').Project,
  chunk: import('./types').SecretChunk,
) {
  _envLinkProj = proj;
  _envLinkChunk = chunk;
  const matches = buildEnvLinkMatches(chunk);
  const sub = document.getElementById('env-link-subtitle');
  if (sub) sub.textContent = `${chunk.name} — ${matches.length} fields`;
  const list = document.getElementById('env-link-list');
  if (list) list.innerHTML = matches.map(_renderEnvLinkRow).join('');
  document.getElementById('env-link-overlay')?.classList.add('open');
}

export function closeEnvLinkModal() {
  document.getElementById('env-link-overlay')?.classList.remove('open');
  _envLinkProj = null;
  _envLinkChunk = null;
}

export function applyEnvLink() {
  if (!_envLinkProj || !_envLinkChunk) return;
  const chunk = _envLinkChunk;
  const projectId = _envLinkProj.id !== 'Universal' ? _envLinkProj.id : null;
  let linked = 0,
    created = 0;

  for (const row of document.querySelectorAll<HTMLElement>('.env-link-row')) {
    const key = row.dataset.key;
    if (!key) continue;
    const cb = row.querySelector<HTMLInputElement>('.env-link-cb');
    if (!cb?.checked) continue;
    const field = chunk.fields.find((f) => f.key === key);
    if (!field) continue;

    if (row.classList.contains('env-link-row--match')) {
      const ref = row.dataset.ref!;
      field.value = `\${${ref}}`;
      // Auto-assign the containing project to the matched vault entry.
      if (projectId) {
        const provPart = ref.includes('/') ? ref.slice(0, ref.indexOf('/')) : ref;
        let entry = st.vault.api_keys.find((e) => e.provider === provPart);
        if (!entry && provPart.includes('_')) {
          const lastUs = provPart.lastIndexOf('_');
          entry = st.vault.api_keys.find(
            (e) =>
              e.provider === provPart.slice(0, lastUs) && e.key_id === provPart.slice(lastUs + 1),
          );
        }
        if (entry && !entry.projectIds.includes(projectId)) entry.projectIds.push(projectId);
      }
      linked++;
    } else if (row.classList.contains('env-link-row--create')) {
      const provider =
        row.querySelector<HTMLInputElement>('.env-link-name-input')?.value.trim() || key;
      const keyId = row.dataset.keyId || undefined;
      const secretType = (row.querySelector<HTMLSelectElement>('.env-link-type-select')?.value ||
        'api_key') as SecretType;
      const baseProjectIds = ['Universal', ...(projectId ? [projectId] : [])];

      // The provider name is editable, so the user can type one that already
      // exists. References resolve by name and take the first match, so
      // creating a second entry under the same name would point the new
      // reference at the *old* secret and orphan the one just created. Adopt
      // the existing entry instead.
      const clash = st.vault.api_keys.find(
        (e) => e.provider === provider && (e.key_id ?? undefined) === keyId,
      );
      if (clash) {
        if (projectId && !clash.projectIds.includes(projectId)) clash.projectIds.push(projectId);
        const clashRef = keyId ? `${provider}_${keyId}` : provider;
        const clashIsUser = /user(name)?$/i.test(key) && clash.secretType === 'password';
        field.value = `\${${clashRef}/${clashIsUser ? 'username' : clash.secretType === 'password' ? 'password' : 'key'}}`;
        linked++;
        continue;
      }

      const newEntry: import('./types').VaultEntry = {
        provider,
        ...(keyId ? { key_id: keyId } : {}),
        api_key: /user(name)?$/i.test(key) && secretType === 'password' ? '' : field.value,
        ...(/user(name)?$/i.test(key) && secretType === 'password'
          ? { username: field.value }
          : {}),
        secretType,
        price_type: 'local',
        categories: [],
        projectIds: baseProjectIds,
        scopes: [],
      };
      st.vault.api_keys.push(newEntry);
      // Use slash notation for new refs. Point at the field the value was stored in:
      // username for user-style password entries, password for other password entries.
      const provRef = keyId ? `${provider}_${keyId}` : provider;
      const isUserField = /user(name)?$/i.test(key) && secretType === 'password';
      const refField = isUserField ? 'username' : secretType === 'password' ? 'password' : 'key';
      field.value = `\${${provRef}/${refField}}`;
      created++;
    }
  }

  if (linked + created === 0) {
    showToast('Nothing selected', '', 1500);
    return;
  }
  persist();
  render();
  closeEnvLinkModal();
  showToast(`${linked} linked, ${created} created ✓`, 'ok');
}
