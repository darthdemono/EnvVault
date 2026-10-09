import { bundleSuggestions } from './bundle-scope';
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
  primaryEnvName,
  switchPanel,
  isSidebarSectionEnabled,
  persist,
  entryId,
  clearAllFilters,
  saveViewState,
  quoteEnvValue,
  findNameCollisions,
} from './state';
import { getFiltered, sorted, buildProjectTree, getDescendantProjectIds } from './filters';
import { timeUntil } from './ui-qol';
import { newStackChunk, stackAdapter, stackAdapters, stackChunkSpec } from './stack';
import { iconHTML } from './icons';
import { normalizeRateLimit } from './ratelimit';
import { poolsOf, poolBadgeInfo } from './pools';
import { secretTypeLabel } from './secret-types';
import { hasTotp, startTotpTicker, stopTotpTicker } from './totp';
import { codeStatus } from './recovery-codes';
import { renderComposite, renderErrorMessage } from './composite';
import {
  maskKey,
  showToast,
  showConfirm,
  showPrompt,
  showPromptLarge,
  clipboardWrite,
  saveFile,
  eyeSVG,
  copySVG,
  editSVG,
  delSVG,
  dupSVG,
} from './utils';
import { TYPE_CONFIG, showDropdown, openModal } from './modals';
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
  exportStack,
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
  findEntryByRef,
  isEntryFieldPublic,
  chunkToString,
  buildEnvLinkMatches,
  nginxCertDomains,
  renderNginxCertCard,
  ensureCertForDomain,
  redundantCertKeyChunkIds,
} from './chunk-ops';
import type { EnvLinkMatch } from './chunk-ops';
import type { ProjectTreeNode } from './filters';
import { parseEnvFile } from './import-export';
import { renderBundleComposite, resolveBundleTemplate } from './bundle-scope';
import { html, raw, setHtml, type SafeHtml, type HtmlValue } from './html';
import { mountConfigCheck } from './config-check';

// Attribute fragment: a fixed literal, vouched for once rather than at each use.
const PIN_BADGE = html`<span class="pin-badge" title="Pinned"
  ><svg width="9" height="9" viewBox="0 0 24 24" fill="currentColor" stroke="none">
    <path
      d="M5 17h14v-1.76a2 2 0 0 0-1.11-1.79l-1.78-.9A2 2 0 0 1 15 10.76V6h1a2 2 0 0 0 0-4H8a2 2 0 0 0 0 4h1v4.76a2 2 0 0 1-1.11 1.79l-1.78.9A2 2 0 0 0 5 15.24Z"
    /></svg
></span>`;
const ARIA_CURRENT = raw(' aria-current="true"');

// ── Project tree renderers ─────────────────────────────────────────────────

export function renderProjectTree() {
  const container = document.getElementById('category-tree');
  if (!container) return;
  setHtml(container, '');
  renderUserCatTree(container, st.vault.user_categories || [], st.vault.api_keys);
}

function renderProjectList(container: HTMLElement, projects: Project[], all: VaultEntry[]) {
  const tree = buildProjectTree(projects.filter((p) => p.id !== 'Universal'));
  function renderNode(node: ProjectTreeNode, depth: number) {
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
      // Stack integrations (Phase 38) name their own badge in the descriptor.
      ...Object.fromEntries(stackAdapters().map((a) => [a.id, a.abbr])),
    };
    const ptBadge =
      !node.virtual && node.project_type && node.project_type !== 'generic'
        ? // The lookup hits a fixed table, but the fallback prints the raw stored
          // value, which an imported vault controls.
          html` <span class="badge badge-ptype"
            >${_ptLabels[node.project_type] ?? node.project_type}</span
          >`
        : '';
    const row = document.createElement('div');
    row.className = 'sidebar-cat-row';
    row.style.paddingLeft = `${depth * 14}px`;
    if (node.virtual) {
      setHtml(
        row,
        html` <button
          class="sidebar-item${isActive ? ' active' : ''}"
          ${isActive ? ARIA_CURRENT : ''}
          data-project-id="${nodeId}"
          style="color:var(--text3)"
        >
          <span
            class="sidebar-label"
            style="font-weight:600;font-size:10.5px;text-transform:uppercase;letter-spacing:.06em"
            >${displayName}</span
          >
          <span class="sidebar-count">${count}</span>
        </button>`,
      );
    } else {
      setHtml(
        row,
        html` <button
            class="sidebar-item${isActive ? ' active' : ''}"
            ${isActive ? ARIA_CURRENT : ''}
            data-project-id="${nodeId}"
          >
            <span class="sidebar-label">${displayName}${ptBadge}</span>
            <span class="sidebar-count">${count}</span>
          </button>
          <button class="sidebar-cat-del rename-proj" data-project="${node.id}" title="Rename">
            ✎
          </button>
          <button class="sidebar-cat-del delete-proj" data-project="${node.id}" title="Delete">
            ✕
          </button>`,
      );
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
  // Per-type counts live in the type chip bar now (`renderTypeChipBar`,
  // called from `renderGrid`) — see the removal note in index.html for why
  // the old `#count-st-*` sidebar sub-list is gone.

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
  setHtml(catList, '');
  renderProjectList(catList, st.vault.projects || [], all);

  renderTagSection(all);
  renderPoolSection(all);
  // A2 (2026-09-14): the Authenticator *sidebar section* is gone — two
  // surfaces for one feature, and the one that showed nothing (A1) read as
  // the feature being broken. The `auth` activity-bar panel below is the path.
  //
  // The Authenticator screen shows the same seeds, so it repaints with them —
  // a vault edited anywhere must not leave a stale card behind (invariant 1).
  if (Settings.get('activePanel') === 'auth') {
    void import('./auth-panel').then((m) => m.renderAuthPanel());
  }
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

  setHtml(
    container,
    html`${[...pools.entries()].map(([name, members]) => {
      const active = st.activePoolFilter === name;
      return html`<div class="sidebar-cat-row">
        <button
          class="sidebar-item pool-filter-btn${active ? ' active' : ''}"
          ${active ? ARIA_CURRENT : ''}
          data-pool="${name}"
          title="${`${members.length} interchangeable credential${members.length === 1 ? '' : 's'}`}"
        >
          <span class="pool-chip-sidebar">${name}</span>
          <span class="sidebar-count">${members.length}</span>
        </button>
      </div>`;
    })}`,
  );
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

  setHtml(
    container,
    html`${[...pfxMap.entries()]
      .sort((a, b) => a[0].localeCompare(b[0]))
      .map(([pfx, count]) => {
        const active = st.activePrefixFilter === pfx;
        return html`<div class="sidebar-cat-row">
          <button
            class="sidebar-item prefix-filter-btn${active ? ' active' : ''}"
            ${active ? ARIA_CURRENT : ''}
            data-prefix="${pfx}"
          >
            <span class="badge badge-prefix">${pfx}_</span>
            <span class="sidebar-count">${count}</span>
          </button>
        </div>`;
      })}`,
  );
}

/**
 * The multi-toggle type chip bar above the grid (Phase 24.2).
 *
 * One chip per `SecretType` actually present, plus one virtual chip — 2FA
 * (carries a stored authenticator seed), which is not a `secretType` value on
 * its own. OR-combined within the bar, ANDed with every other active filter
 * in `getFiltered()`.
 *
 * **Deliberately no "Pool" chip.** Key-pool membership already has its own
 * sidebar section (`#sidebar-section-pools`, `activePoolFilter`) — the chip
 * bar's whole reason to exist is covering what the sidebar does not (every
 * secret type, and 2FA now that the old Authenticator sidebar section is
 * gone). Adding a Pool chip here would be the exact same redundant-overlap
 * this bar was built to remove from the sidebar, just in the other direction.
 *
 * Counts are computed over the **whole vault**, matching the sidebar's own
 * price/type counters — narrowing them by the currently active chips would
 * make every chip's own number drop to zero the moment it is pressed, which
 * reads as "nothing else matches" rather than "here is what else exists".
 */
function renderTypeChipBar(all: VaultEntry[]) {
  const bar = document.getElementById('type-chip-bar');
  if (!bar) return;

  const byType = new Map<string, number>();
  let totpCount = 0;
  for (const k of all) {
    const t = k.secretType || 'api_key';
    byType.set(t, (byType.get(t) ?? 0) + 1);
    if (k.totp_secret && k.totp_secret.trim() !== '') totpCount++;
  }

  // Bundle members (fields exist since Phase 24.1 step 2, no card yet) are a
  // real type on the entry — no special-casing needed here.
  const chips: { key: string; label: string; count: number }[] = [...byType.entries()]
    .sort((a, b) => b[1] - a[1])
    .map(([type, count]) => ({ key: type, label: secretTypeLabel(type), count }));
  if (totpCount) chips.push({ key: '__totp', label: '2FA', count: totpCount });

  // Nothing to choose between: one type, no seeds, no pools. A chip bar with a
  // single always-on chip is a control that cannot do anything.
  if (chips.length < 2) {
    bar.style.display = 'none';
    setHtml(bar, '');
    return;
  }

  bar.style.display = '';
  setHtml(
    bar,
    html`${chips.map(({ key, label, count }) => {
      const active = st.activeTypeChips.has(key);
      return html`<button
        type="button"
        class="type-chip${active ? ' active' : ''}"
        aria-pressed="${active}"
        data-chip="${key}"
      >
        <span class="type-chip-label">${label}</span>
        <span class="type-chip-count">${count}</span>
      </button>`;
    })}`,
  );
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

  setHtml(
    container,
    html`${[...tagMap.entries()]
      .sort((a, b) => a[0].localeCompare(b[0]))
      .map(([tag, count]) => {
        const active = st.activeTagFilter === tag;
        const style = tagColor(tag);
        return html`<div class="sidebar-cat-row">
          <button
            class="sidebar-item tag-filter-btn${active ? ' active' : ''}"
            ${active ? ARIA_CURRENT : ''}
            data-tag="${tag}"
          >
            <span class="tag-chip-sidebar" style="${style}">${tag}</span>
            <span class="sidebar-count">${count}</span>
          </button>
        </div>`;
      })}`,
  );
}

// The Authenticator *sidebar section* that used to live here was removed in
// A2 (2026-09-14) — see the migration note in `state.ts`'s `Settings.init()`.
// The `auth` activity-bar panel (`src/ts/auth-panel.ts`) is the surface now;
// the per-card 2FA row (`buildCard`, below) is the other.

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
      setHtml(
        row,
        html` <button
          class="sidebar-item${isActive ? ' active' : ''}"
          ${isActive ? ARIA_CURRENT : ''}
          data-filter-type="category"
          data-filter-value="${node.name}"
          style="color:var(--text3)"
        >
          <span
            class="sidebar-label"
            style="font-weight:600;font-size:10.5px;text-transform:uppercase;letter-spacing:.06em"
            >${displayName}</span
          >
          <span class="sidebar-count">${count}</span>
        </button>`,
      );
    } else {
      setHtml(
        row,
        html` <button
            class="sidebar-item${isActive ? ' active' : ''}"
            ${isActive ? ARIA_CURRENT : ''}
            data-filter-type="category"
            data-filter-value="${node.name}"
          >
            <span class="sidebar-label">${displayName}</span>
            <span class="sidebar-count">${count}</span>
          </button>
          <button class="sidebar-cat-del rename-cat" data-category="${node.name}" title="Rename">
            ✎
          </button>
          <button class="sidebar-cat-del delete-cat" data-category="${node.name}" title="Delete">
            ✕
          </button>`,
      );
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
  void persist();
}

/**
 * "3 Spotify entries — bundle them?" Suggested, never automatic: one banner for
 * the largest undismissed provider group, above the grid. Dismissal is per
 * provider and persisted in settings.
 */
function renderBundleSuggestion(grid: HTMLElement): void {
  let banner = document.getElementById('bundle-suggest');
  const pick = Settings.get('groupBundles')
    ? bundleSuggestions(st.vault.api_keys, Settings.get('dismissedBundleSuggestions') ?? []).sort(
        (a, b) => b.entries.length - a.entries.length,
      )[0]
    : undefined;
  if (!pick) {
    banner?.remove();
    return;
  }
  if (!banner) {
    banner = document.createElement('div');
    banner.id = 'bundle-suggest';
    banner.className = 'bundle-suggest';
    banner.setAttribute('role', 'status');
    grid.parentElement?.insertBefore(banner, grid);
  }
  setHtml(
    banner,
    html`<span>${pick.entries.length} ${pick.provider} entries belong together. Bundle them?</span>
      <button
        type="button"
        class="btn btn-ghost btn-sm"
        data-action="bundle-suggest-accept"
        data-provider="${pick.provider}"
      >
        Bundle them
      </button>
      <button
        type="button"
        class="btn btn-ghost btn-sm"
        data-action="bundle-suggest-dismiss"
        data-provider="${pick.provider}"
      >
        Not now
      </button>`,
  );
}

export function renderGrid() {
  buildRefIndex();
  renderTypeChipBar(st.vault.api_keys || []);
  const items = sorted(getFiltered());
  const grid = document.getElementById('card-grid')!;
  const validBundleIds = new Set(
    st.vault.api_keys
      .filter((entry) => entry.secretType === 'bundle' && entry.id)
      .map((entry) => entry.id!),
  );
  // Derived here rather than only flipped on click: lock, import and vault
  // switch all reset st.allExpanded, and the button was left reading
  // "Collapse All" with nothing expanded.
  const expandBtn = document.getElementById('expand-all-btn');
  if (expandBtn) expandBtn.textContent = st.allExpanded ? 'Collapse All' : 'Expand All';
  const secretCount = items.filter((entry) => entry.secretType !== 'bundle').length;
  const visibleBundleIds = new Set<string>();
  for (const entry of items) {
    if (entry.secretType === 'bundle' && entry.id) visibleBundleIds.add(entry.id);
    else if (entry.bundle_id && validBundleIds.has(entry.bundle_id))
      visibleBundleIds.add(entry.bundle_id);
  }
  const bundleCount = visibleBundleIds.size;
  document.getElementById('result-count')!.textContent =
    `${secretCount} secret${secretCount !== 1 ? 's' : ''}${bundleCount ? ` · ${bundleCount} bundle${bundleCount !== 1 ? 's' : ''}` : ''}`;
  applyGridSettings();
  renderBundleSuggestion(grid);
  // A2 (2026-09-14): the sidebar Authenticator section used to own the
  // ticker's start/stop; removing it left nothing driving the ticker for the
  // per-card 2FA row. The card grid is now what decides whether a seed is on
  // screen — idempotent by assignment either way (invariant 9).
  if (items.some(hasTotp)) startTotpTicker();
  else stopTotpTicker();
  if (!items.length) {
    setHtml(
      grid,
      html`<div class="empty-state">
        <svg
          width="40"
          height="40"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          stroke-width="1.5"
        >
          <rect x="3" y="11" width="18" height="11" rx="2" />
          <path d="M7 11V7a5 5 0 0 1 10 0v4" />
        </svg>
        <p>No secrets found</p>
        <small>${st.searchQ ? 'Try a different search' : 'Add a secret or import a backup'}</small>
      </div>`,
    );
    return;
  }
  setHtml(grid, '');
  // One pass to map entry -> array position. `indexOf` per card made rendering
  // O(n²), which is invisible at 100 entries and very visible at a few thousand.
  const posOf = new Map<VaultEntry, number>();
  st.vault.api_keys.forEach((e, i) => posOf.set(e, i));
  const idxOf = (e: VaultEntry) => posOf.get(e) ?? -1;
  if (Settings.get('groupBundles') && validBundleIds.size > 0) {
    const bundles = new Map(
      st.vault.api_keys.filter((e) => e.secretType === 'bundle' && e.id).map((e) => [e.id!, e]),
    );
    const consumed = new Set<string>();
    const allMembers = new Map<string, VaultEntry[]>();
    for (const member of st.vault.api_keys) {
      const bundleId = member.bundle_id;
      if (bundleId && bundles.has(bundleId)) {
        const list = allMembers.get(bundleId) ?? [];
        list.push(member);
        allMembers.set(bundleId, list);
      }
    }
    const fullPoolsOf = poolsOf(st.vault);
    const plainPools = poolsOf({
      api_keys: items.filter(
        (e) => e.secretType !== 'bundle' && !(e.bundle_id && bundles.has(e.bundle_id)),
      ),
    });
    const consumedPools = new Set<string>();
    let animIdx = 0;
    for (const entry of items) {
      const bundleId = entry.secretType === 'bundle' ? entry.id : entry.bundle_id;
      const bundle = bundleId ? bundles.get(bundleId) : undefined;
      if (!bundle?.id) {
        // A vault with one bundle used to stop collapsing pools altogether: this
        // branch returns before the pool branch below ever runs, so every pooled
        // key showed as its own card (found by the Phase 32.1 probe, which never
        // saw a pool card in a vault that also held a bundle).
        const poolName = typeof entry.pool === 'string' ? entry.pool.trim() : '';
        const poolMembers = poolName ? plainPools.get(poolName) : undefined;
        if (Settings.get('groupPools') && poolName && poolMembers && poolMembers.length >= 2) {
          if (consumedPools.has(poolName)) continue;
          consumedPools.add(poolName);
          const partialMatch =
            !!st.searchQ && poolMembers.length < (fullPoolsOf.get(poolName)?.length ?? 0);
          grid.appendChild(buildPoolCard(poolName, poolMembers, idxOf, animIdx++, partialMatch));
          continue;
        }
        grid.appendChild(buildCard(entry, idxOf(entry), animIdx++));
        continue;
      }
      if (consumed.has(bundle.id)) continue;
      consumed.add(bundle.id);
      const visibleMembers = (allMembers.get(bundle.id) ?? []).filter((m) => items.includes(m));
      const partial =
        !items.includes(bundle) && visibleMembers.length < (allMembers.get(bundle.id)?.length ?? 0);
      const shownMembers = items.includes(bundle)
        ? (allMembers.get(bundle.id) ?? [])
        : visibleMembers;
      grid.appendChild(
        buildBundleCard(
          bundle,
          shownMembers,
          idxOf,
          animIdx++,
          partial,
          allMembers.get(bundle.id) ?? [],
        ),
      );
    }
    return;
  }
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
  } else if (Settings.get('groupPools')) {
    const fullPools = poolsOf(st.vault);
    const filteredPools = poolsOf({ api_keys: items });
    const consumed = new Set<string>();
    let animIdx = 0;
    items.forEach((entry) => {
      const poolName = typeof entry.pool === 'string' ? entry.pool.trim() : '';
      const poolMembers = poolName ? filteredPools.get(poolName) : undefined;
      if (poolName && poolMembers && poolMembers.length >= 2) {
        if (consumed.has(poolName)) return;
        consumed.add(poolName);
        // A search that matches only some of a pool's members forces it open
        // on those members, rather than hiding the reason the card matched
        // behind a collapsed summary the user did not ask to expand.
        const partialMatch =
          !!st.searchQ && poolMembers.length < (fullPools.get(poolName)?.length ?? 0);
        grid.appendChild(buildPoolCard(poolName, poolMembers, idxOf, animIdx++, partialMatch));
        return;
      }
      grid.appendChild(buildCard(entry, idxOf(entry), animIdx++));
    });
  } else {
    items.forEach((entry, i) => grid.appendChild(buildCard(entry, idxOf(entry), i)));
  }
}

function buildBundleCard(
  bundle: VaultEntry,
  members: VaultEntry[],
  idxOf: (entry: VaultEntry) => number,
  animIdx: number,
  forceExpanded: boolean,
  scopeMembers: VaultEntry[],
): HTMLElement {
  const id = entryId(bundle);
  const expanded = forceExpanded || st.expandedBundles.has(id);
  const wrap = document.createElement('div');
  wrap.className = `pool-card-wrap bundle-card-wrap${expanded ? ' expanded' : ''}`;
  wrap.dataset.bundle = id;
  const summary = document.createElement('div');
  summary.className = 'pool-card-summary';
  const primary = members.find((m) => m.id === bundle.bundle_primary) ?? members[0];
  const collisions = findNameCollisions([bundle, ...members]);
  const projectIds = [...new Set(scopeMembers.flatMap((member) => member.projectIds ?? []))].filter(
    (projectId) => projectId !== 'Universal',
  );
  const projectNames = projectIds.map(
    (projectId) => st.vault.projects.find((project) => project.id === projectId)?.name ?? projectId,
  );
  const categories = [...new Set(scopeMembers.flatMap((member) => member.categories ?? []))].sort();
  const tags = [...new Set(scopeMembers.flatMap((member) => member.tags ?? []))].sort();
  const unionChip = (label: string, values: string[]) =>
    values.length
      ? html`<span class="bundle-union" title="${`${label}: ${values.join(', ')}`}"
          >${label}: ${values.slice(0, 3).join(', ')}${values.length > 3 ? ` +${values.length - 3}` : ''}</span
        >`
      : '';
  setHtml(
    summary,
    html`
      <button
        type="button"
        class="pool-card-expand"
        data-action="bundle-toggle"
        data-bundle="${id}"
        aria-expanded="${String(expanded)}"
        title="${expanded ? 'Collapse' : 'Expand'} bundle"
      >
        <span class="pool-card-chevron" aria-hidden="true">▸</span>
      </button>
      <button
        type="button"
        class="btn btn-ghost btn-sm bundle-bulk-select"
        data-action="bundle-bulk-toggle"
        data-bundle="${id}"
      >
        Select visible members
      </button>
      <span class="pool-card-icon" aria-hidden="true">▣</span>
      <span class="pool-card-name">${bundle.provider}</span>
      <span class="pool-card-badge">bundle: ${members.length}</span>${collisions.length ? html`<span class="badge badge-warning bundle-collision" title="${collisions.map((collision) => `${collision.name}: ${collision.sources.map((source) => `${source.entry.provider}/${source.role || 'value'}`).join(', ')}`).join('\n')}">${collisions.length} name collision${collisions.length === 1 ? '' : 's'}</span>` : ''}
      ${unionChip('Projects', projectNames)}${unionChip('Categories', categories)}${unionChip('Tags', tags)}
      <button
        type="button"
        class="btn btn-ghost btn-sm"
        data-action="edit"
        data-idx="${idxOf(bundle)}"
      >
        Edit
      </button>${primary ? html`<button type="button" class="btn btn-ghost btn-sm" data-action="copy-field" data-value="${primary.api_key || primary.api_secret || ''}">Copy ${primary.bundle_slot || primary.provider}</button>` : ''}
      <button
        type="button"
        class="btn btn-ghost btn-sm"
        data-action="bundle-export"
        data-bundle="${id}"
      >
        Export all…
      </button>
      <button
        type="button"
        class="btn btn-ghost btn-sm"
        data-action="bundle-dissolve"
        data-bundle="${id}"
      >
        Dissolve
      </button>
      <button
        type="button"
        class="btn btn-ghost btn-sm"
        data-action="bundle-delete-all"
        data-bundle="${id}"
      >
        Delete bundle and members
      </button>
    `,
  );
  wrap.appendChild(summary);
  const body = document.createElement('div');
  body.className = 'pool-card-members';
  body.hidden = !expanded;
  if (bundle.extra_vars?.length) {
    const locals = document.createElement('section');
    locals.className = 'bundle-local-vars';
    locals.setAttribute('aria-label', 'Bundle variables');
    setHtml(
      locals,
      html`${bundle.extra_vars.map((v) => {
        const resolved =
          v.kind === 'template'
            ? resolveBundleTemplate(bundle, scopeMembers, v.value, [], (reference) => {
                const result = resolveFieldRef(`\${${reference}}`, true);
                if (result.resolved === null) return null;
                const slash = reference.indexOf('/');
                const entry = findEntryByRef(slash < 0 ? reference : reference.slice(0, slash));
                const isPublic = entry
                  ? slash < 0
                    ? entry.primary_public === true
                    : isEntryFieldPublic(entry, reference.slice(slash + 1))
                  : false;
                return { value: result.resolved, secret: !isPublic };
              })
            : null;
        const display = resolved
          ? resolved.ok
            ? resolved.value.secret || (v.public !== true && v.secret !== false)
              ? maskKey(resolved.value.value)
              : resolved.value.value
            : html`<span class="text-warning" title="${resolved.error.kind}"
                >Unresolved:
                ${resolved.error.kind === 'unresolved' ? resolved.error.reference : resolved.error.kind === 'cycle' ? resolved.error.path.join(' → ') : resolved.error.kind === 'depth' ? resolved.error.reference : resolved.error.message}</span
              >`
          : v.secret || (v.public !== true && v.secret !== false)
            ? maskKey(v.value)
            : v.value;
        return html`<div class="key-row">
          <div class="key-label">${v.key}</div>
          <div class="key-value">${display}
            <button
              type="button"
              class="btn btn-ghost btn-sm"
              data-action="bundle-var-remove"
              data-bundle="${id}"
              data-key="${v.key}"
              aria-label="Remove ${v.key}"
            >
              ×
            </button>
          </div>
        </div>`;
      })}`,
    );
    body.appendChild(locals);
  }
  const sortedMembers = members
    .slice()
    .sort((a, b) => (a.bundle_order ?? 0) - (b.bundle_order ?? 0));
  const activeMemberId =
    sortedMembers.find((member) => member.id === st.bundleSlotTabs[id])?.id ??
    sortedMembers.find((member) => member.id === bundle.bundle_primary)?.id ??
    sortedMembers[0]?.id;
  if (sortedMembers.length > 3) {
    const tabs = document.createElement('div');
    tabs.className = 'bundle-slot-tabs';
    tabs.setAttribute('role', 'tablist');
    tabs.setAttribute('aria-label', `${bundle.provider} slots`);
    setHtml(
      tabs,
      html`${sortedMembers.map((member) => {
        const selected = member.id === activeMemberId;
        const label = member.version || member.bundle_slot || member.provider;
        return html`<button
          type="button"
          role="tab"
          class="btn btn-ghost btn-sm${selected ? ' active' : ''}"
          data-action="bundle-slot-tab"
          data-bundle="${id}"
          data-member="${entryId(member)}"
          aria-selected="${String(selected)}"
        >${label}</button>`;
      })}`,
    );
    body.appendChild(tabs);
  }
  const consumedPools = new Set<string>();
  const visibleMembers =
    sortedMembers.length > 3
      ? sortedMembers.filter((member) => member.id === activeMemberId)
      : sortedMembers;
  visibleMembers.forEach((member, i) => {
    const poolName = typeof member.pool === 'string' ? member.pool.trim() : '';
    const poolMembers = poolName
      ? sortedMembers.filter((candidate) => candidate.pool?.trim() === poolName)
      : [];
    if (poolName && poolMembers.length > 1) {
      if (consumedPools.has(poolName)) return;
      consumedPools.add(poolName);
      body.appendChild(buildPoolCard(poolName, poolMembers, idxOf, animIdx + i, false));
      return;
    }
    const section = document.createElement('section');
    section.className = 'bundle-member';
    section.dataset.slot = member.bundle_slot || '';
    const title = document.createElement('h4');
    title.textContent = member.bundle_slot || member.provider;
    const controls = document.createElement('div');
    controls.className = 'bundle-member-controls';
    setHtml(
      controls,
      html` <button
          type="button"
          class="btn btn-ghost btn-sm"
          data-action="bundle-primary"
          data-bundle="${id}"
          data-member="${entryId(member)}"
        >${bundle.bundle_primary === member.id ? 'Primary ✓' : 'Set primary'}</button>
        <button
          type="button"
          class="btn btn-ghost btn-sm"
          data-action="bundle-rename-slot"
          data-bundle="${id}"
          data-member="${entryId(member)}"
          data-slot="${member.bundle_slot || ''}"
        >
          Rename slot
        </button>
        <button
          type="button"
          class="btn btn-ghost btn-sm"
          data-action="bundle-order"
          data-bundle="${id}"
          data-member="${entryId(member)}"
          data-direction="-1"
          aria-label="Move ${member.bundle_slot || member.provider} up"
        >
          ↑
        </button>
        <button
          type="button"
          class="btn btn-ghost btn-sm"
          data-action="bundle-order"
          data-bundle="${id}"
          data-member="${entryId(member)}"
          data-direction="1"
          aria-label="Move ${member.bundle_slot || member.provider} down"
        >
          ↓
        </button>
        <button
          type="button"
          class="btn btn-ghost btn-sm"
          data-action="bundle-remove-member"
          data-bundle="${id}"
          data-member="${entryId(member)}"
        >
          Remove
        </button>`,
    );
    section.append(title, controls, buildCard(member, idxOf(member), animIdx + i));
    body.appendChild(section);
  });
  const controls = document.createElement('div');
  controls.className = 'bundle-actions';
  setHtml(
    controls,
    html` <button
        type="button"
        class="btn btn-ghost btn-sm"
        data-action="bundle-add-member"
        data-bundle="${id}"
      >
        Add member
      </button>
      <button
        type="button"
        class="btn btn-ghost btn-sm"
        data-action="bundle-add-var"
        data-bundle="${id}"
      >
        Add variable
      </button>
      <button
        type="button"
        class="btn btn-ghost btn-sm"
        data-action="bundle-add-project"
        data-bundle="${id}"
      >
        Assign project to members
      </button>
      <button
        type="button"
        class="btn btn-ghost btn-sm"
        data-action="bundle-add-category"
        data-bundle="${id}"
      >
        Assign category to members
      </button>
      <button
        type="button"
        class="btn btn-ghost btn-sm"
        data-action="bundle-add-tag"
        data-bundle="${id}"
      >
        Assign tag to members
      </button>`,
  );
  body.appendChild(controls);
  wrap.appendChild(body);
  return wrap;
}

/**
 * One card for every entry sharing a key pool (Phase 24.2), collapsed by
 * default. Copy takes the pool cursor (`unv pool next`), which is why it is
 * wired separately from a member's own Copy button — that one never advances
 * the cursor, this one always does.
 *
 * Wraps `buildCard` rather than reimplementing a card body: every per-type
 * rendering rule (masking, the 2FA row, cookie handling) already lives there,
 * and a pool member is still, in full, whatever type it is.
 */
function buildPoolCard(
  poolName: string,
  members: VaultEntry[],
  idxOf: (e: VaultEntry) => number,
  animIdx: number,
  forceExpanded: boolean,
): HTMLElement {
  const expanded = forceExpanded || st.expandedPools.has(poolName);

  const wrap = document.createElement('div');
  wrap.className = `pool-card-wrap${expanded ? ' expanded' : ''}`;
  wrap.dataset.pool = poolName;

  const badgeId = `pool-card-badge-${animIdx}`;
  const summary = document.createElement('div');
  summary.className = 'pool-card-summary';
  setHtml(
    summary,
    html`
      <button
        type="button"
        class="pool-card-expand"
        data-action="pool-card-toggle"
        data-pool="${poolName}"
        aria-expanded="${String(expanded)}"
        title="${expanded ? 'Collapse' : 'Expand'} pool"
      >
        <svg
          class="pool-card-chevron"
          width="12"
          height="12"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          stroke-width="2.5"
        >
          <polyline points="9 18 15 12 9 6" />
        </svg>
      </button>
      <span class="pool-card-icon" aria-hidden="true">⧉</span>
      <span class="pool-card-name">${poolName}</span>
      <span class="pool-card-badge" id="${badgeId}">pool: ${members.length}</span>
      <button
        type="button"
        class="btn btn-ghost btn-sm pool-card-copy"
        data-action="pool-card-copy"
        data-pool="${poolName}"
        title="Copy the next available key and advance the cursor"
      >
        Copy
      </button>
    `,
  );
  wrap.appendChild(summary);

  const body = document.createElement('div');
  body.className = 'pool-card-members';
  body.hidden = !expanded;
  members.forEach((m, i) => body.appendChild(buildCard(m, idxOf(m), animIdx + i)));
  wrap.appendChild(body);

  // Ready/cooling needs an IPC round trip; paint the plain count first and
  // enrich it if (and only if) an answer comes back, rather than blocking the
  // grid paint on it.
  void poolBadgeInfo(poolName, members).then((info) => {
    if (!info) return;
    const el = document.getElementById(badgeId);
    if (el)
      el.textContent = `pool: ${members.length} · ${info.ready} ready${info.cooling ? ` · ${info.cooling} cooling` : ''}`;
  });

  return wrap;
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
    ? html`<span class="badge badge-env" data-env="${entry.environment}"
        >${entry.environment}</span
      >`
    : '';
  const keyIdBadge = entry.key_id
    ? html`<span class="badge badge-keyid">${entry.key_id}</span>`
    : '';
  const typeBadge =
    entry.secretType && entry.secretType !== 'api_key'
      ? html`<span class="badge badge-keyid">${secretTypeLabel(entry.secretType)}</span>`
      : '';
  const compromisedBadge = entry.compromised
    ? html`<span class="badge badge-compromised" title="Marked compromised — rotate immediately"
        >⚠ LEAKED</span
      >`
    : '';
  const rotBadge = (() => {
    // A browser session shows no rotation badge (E13): rotating one means
    // logging in again in a browser, so the badge would sit there forever
    // pointing at something the user cannot do from here.
    if (entry.secretType === 'cookie') return '';
    if (!entry.rotation_days || entry.rotation_days <= 0 || !entry.last_rotated_at) return '';
    const dueMs = new Date(entry.last_rotated_at).getTime() + entry.rotation_days * 86_400_000;
    if (dueMs >= Date.now()) return '';
    const overdue = Math.floor((Date.now() - dueMs) / 86_400_000);
    return html`<span
      class="badge badge-rotation-due"
      title="Rotation cadence ${entry.rotation_days}d, overdue ${overdue}d"
      >⟳ rotate</span
    >`;
  })();
  // Per-field mask state: default from settings, overridden by any explicit
  // reveal the user has toggled. Previously this read the setting alone, so a
  // revealed secret silently re-masked itself on the next re-render.
  const masked = (field: string) => {
    // A value marked public is never masked (Phase 23, E5). A client id, a
    // publishable key and a region are printed in the issuer's own
    // documentation; hiding them behind a reveal click protects nothing and
    // makes the card unreadable for the half of a credential that is meant to be
    // read. An explicit reveal toggle still wins, in both directions.
    if (field === 'key' && entry.primary_public) return false;
    if (field === 'secret' && entry.secret_public) return false;
    return st.revealed[`${field}-${eid}`] !== undefined
      ? !st.revealed[`${field}-${eid}`]
      : Settings.get('maskKeysByDefault');
  };
  const hasMask = masked('key');
  // A composite's "value" is its rendered template, never `api_key` (which it
  // does not use). Rendered here, once, rather than in the template string
  // below, so a render error shows as text instead of breaking card markup.
  const bundleParent = entry.bundle_id
    ? st.vault.api_keys.find(
        (candidate) => candidate.id === entry.bundle_id && candidate.secretType === 'bundle',
      )
    : undefined;
  const resolveGlobal = (reference: string) => {
    const result = resolveFieldRef(`\${${reference}}`, true);
    if (result.resolved === null) return null;
    const slash = reference.indexOf('/');
    const sourceEntry = findEntryByRef(slash < 0 ? reference : reference.slice(0, slash));
    const isPublic = sourceEntry
      ? slash < 0
        ? sourceEntry.primary_public === true
        : isEntryFieldPublic(sourceEntry, reference.slice(slash + 1))
      : false;
    return { value: result.resolved, secret: !isPublic };
  };
  const scopedComposite =
    entry.secretType === 'composite' && bundleParent
      ? renderBundleComposite(
          bundleParent,
          st.vault.api_keys.filter((candidate) => candidate.bundle_id === bundleParent.id),
          entry.composite_template || '',
          entry.extra_vars || [],
          entry.composite_kind || 'link',
          resolveGlobal,
        )
      : null;
  const compositeRendered =
    entry.secretType === 'composite' && !bundleParent
      ? renderComposite(
          entry.composite_template || '',
          (entry.extra_vars || []).map((v) => ({ key: v.key, value: v.value })),
          entry.composite_kind || 'link',
        )
      : null;
  const compositeValue = scopedComposite
    ? scopedComposite.ok
      ? scopedComposite.value
      : ''
    : compositeRendered
      ? compositeRendered.ok
        ? compositeRendered.result.text
        : ''
      : '';
  const compositeError = scopedComposite
    ? scopedComposite.ok
      ? ''
      : scopedComposite.error.kind === 'unresolved'
        ? `Unresolved: ${scopedComposite.error.reference}`
        : scopedComposite.error.kind === 'cycle'
          ? `Cycle: ${scopedComposite.error.path.join(' → ')}`
          : scopedComposite.error.kind === 'depth'
            ? `Depth limit at ${scopedComposite.error.reference}`
            : scopedComposite.error.kind === 'invalid'
              ? scopedComposite.error.message
              : renderErrorMessage(scopedComposite.error)
    : compositeRendered && !compositeRendered.ok
      ? renderErrorMessage(compositeRendered.error)
      : '';
  const compositeMask = scopedComposite?.ok ? (scopedComposite.secret ? hasMask : false) : hasMask;
  const compositeActive = entry.secretType === 'composite';
  const compositeOk = scopedComposite?.ok ?? compositeRendered?.ok ?? false;
  const secretMasked = masked('secret');
  const envFmt = Settings.get('defaultExportFormat');
  const envLabel = envFmt === 'yaml' ? 'YAML' : '.env';

  // The caret beside the copy button is what keeps `copyProfile` a *default*
  // rather than a wall: the other two profiles and "Value only" are one click
  // away on every card, and the one-off choice made there is deliberately not
  // persisted as the new default (Phase 23).
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
  const safeUrl = (url: string | null | undefined): SafeHtml | string => {
    if (!url) return '';
    const trimmed = url.trim();
    if (/^https?:\/\//i.test(trimmed))
      return html`<a href="${trimmed}" target="_blank" rel="noopener noreferrer">${trimmed}</a>`;
    return trimmed; // render as plain text if not http/https
  };

  const metaRows: [string, HtmlValue][] = [];
  if (entry.version) metaRows.push(['Version', entry.version]);
  // Normalised rather than read straight off the entry: this card may be
  // rendering data written by an older build that only had the free-text field,
  // by a remote server, or by a restored backup. Every branch below escapes —
  // vault data is untrusted input and the TypeScript types are erased at
  // runtime (CLAUDE.md invariant 4).
  const rl = normalizeRateLimit(entry);
  if (rl.rate_limit_count != null && rl.rate_limit_period) {
    metaRows.push([
      'Rate Limit',
      html`${rl.rate_limit_count} <span class="meta-unit">per ${rl.rate_limit_period}</span>`,
    ]);
  } else if (rl.rate_limit_note) {
    // A limit nobody could express as a number and a window. Shown as the user
    // wrote it, because that text is the only description of it that exists.
    metaRows.push(['Rate Limit', rl.rate_limit_note]);
  }
  if (entry.purpose) metaRows.push(['Purpose', entry.purpose]);
  if (entry.pool) metaRows.push(['Key Pool', entry.pool]);
  if (entry.expires_at) metaRows.push(['Expires', entry.expires_at]);
  if (entry.api_url) metaRows.push(['API URL', safeUrl(entry.api_url)]);
  if (entry.callback_url) metaRows.push(['Callback', safeUrl(entry.callback_url)]);
  if (entry.details) metaRows.push(['Details', entry.details]);

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
          html`<span class="usedby-badge" title="${`${u.chunk} · ${u.field}`}"
            >${u.project} · ${u.field}</span
          >`,
      );
    metaRows.push(['Used by', html`<div class="usedby-row">${chips}</div>`]);
  }

  const projectBadges =
    entry.projectIds
      ?.filter((pid) => pid !== 'Universal')
      .map((pid) => {
        const proj = st.vault.projects.find((p) => p.id === pid);
        if (!proj) return '';
        const leaf = proj.name.includes('/') ? proj.name.split('/').pop()! : proj.name;
        return html`<span
          class="badge badge-keyid"
          style="background:var(--accent-dim)"
          title="${proj.name}"
          >${leaf}</span
        >`;
      }) ?? '';

  setHtml(
    card,
    html` <div
        class="bulk-checkbox"
        data-action="bulk-toggle"
        data-idx="${idx}"
        role="checkbox"
        tabindex="0"
        aria-checked="${st.bulkSelected.has(eid)}"
        aria-label="${'Select ' + entry.provider}"
      >
        <svg
          width="12"
          height="12"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          stroke-width="3"
        >
          <polyline points="20 6 9 20 4 15" />
        </svg>
      </div>
      <div class="card-head" data-action="copy-env" data-idx="${idx}">
        <div
          class="provider-icon-wrap"
          data-action="icon"
          data-idx="${idx}"
          role="button"
          tabindex="0"
          aria-label="${'Change icon for ' + entry.provider}"
        >${iconHTML(entry.provider, entry.custom_icon)}</div>
        <div class="card-meta">
          <div class="card-provider">
            <span class="card-provider-name" title="${entry.provider}">${entry.provider}</span>${entry.pinned ? PIN_BADGE : ''}
            <span class="badge badge-price" data-price="${pt}">${pt}</span>${envBadge}${keyIdBadge}${typeBadge}${expiry}${compromisedBadge}${rotBadge}${entry.env_prefixes?.length ? entry.env_prefixes.map((p) => html`<span class="badge badge-prefix" title="Env prefix">${p}_</span>`) : ''}</div>
          <div class="card-account">${entry.account_name || entry.username || entry.email || ''}</div>
          <div class="card-projects">${projectBadges}</div>
        </div>
        <button
          class="card-chevron"
          data-action="toggle"
          data-idx="${idx}"
          aria-expanded="${String(isExp)}"
          aria-label="${(isExp ? 'Collapse ' : 'Expand ') + entry.provider}"
        >
          <svg
            width="12"
            height="12"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            stroke-width="2.5"
          >
            <polyline points="6 9 12 15 18 9" />
          </svg>
        </button>
      </div>${entry.api_description ? html`<div class="card-apidesc">${entry.api_description}</div>` : ''}
      <div class="card-body">
        <div class="key-section">${
          compositeActive
            ? compositeOk
              ? html`<div class="key-row">
                    <div class="key-label">VALUE</div>
                    <div
                      class="key-value${compositeMask ? '' : ' revealed'}"
                      id="kv-key-${idx}"
                      data-action="copy-field"
                      data-value="${compositeValue}"
                      title="${entry.composite_template || ''}"
                    >${compositeMask ? maskKey(compositeValue) : compositeValue}</div>
                    <div class="key-actions">
                      <button
                        class="icon-btn sm${compositeMask ? '' : ' active'}"
                        id="reveal-key-${idx}"
                        data-action="reveal"
                        data-field="key"
                        data-idx="${idx}"
                        data-value="${compositeValue}"
                        aria-pressed="${!compositeMask}"
                        aria-label="${'Reveal value for ' + entry.provider}"
                      >${eyeSVG}</button
                      ><button
                        class="icon-btn sm"
                        data-action="copy-field"
                        data-value="${compositeValue}"
                        aria-label="${'Copy value for ' + entry.provider}"
                      >${copySVG}</button>
                    </div>
                  </div>
                  <div class="key-row">
                    <div class="key-label">TEMPLATE</div>
                    <div
                      class="key-value revealed mono"
                      style="font-size:11px;opacity:.7"
                      title="${entry.composite_template || ''}"
                    >${entry.composite_template || ''}</div>
                  </div>`
              : html`<div class="key-row">
                    <div class="key-label">VALUE</div>
                    <div class="key-value revealed" style="color:var(--danger,#e07070)">${compositeError}</div>
                  </div>
                  <div class="key-row">
                    <div class="key-label">TEMPLATE</div>
                    <div class="key-value revealed mono" style="font-size:11px;opacity:.7">${entry.composite_template || ''}</div>
                  </div>`
            : html`<div class="key-row">
                <div class="key-label">${(TYPE_CONFIG[entry.secretType || 'api_key']?.keyLabel || 'API Key').toUpperCase()}</div>
                <div
                  class="key-value${hasMask ? '' : ' revealed'}"
                  id="kv-key-${idx}"
                  data-action="copy-field"
                  data-value="${entry.api_key}"
                >${hasMask ? maskKey(entry.api_key) : entry.api_key}</div>
                <div class="key-actions">
                  <button
                    class="icon-btn sm${hasMask ? '' : ' active'}"
                    id="reveal-key-${idx}"
                    data-action="reveal"
                    data-field="key"
                    data-idx="${idx}"
                    data-value="${entry.api_key}"
                    aria-pressed="${!hasMask}"
                    aria-label="${'Reveal value for ' + entry.provider}"
                  >${eyeSVG}</button>
                  <button
                    class="icon-btn sm"
                    data-action="copy-field"
                    data-value="${entry.api_key}"
                    aria-label="${'Copy value for ' + entry.provider}"
                  >${copySVG}</button>
                </div>
              </div>`
        }
          ${
            entry.api_secret
              ? html`<div class="key-row">
                <div class="key-label">SECRET</div>
                <div
                  class="key-value${secretMasked ? '' : ' revealed'}"
                  id="kv-secret-${idx}"
                  data-action="copy-field"
                  data-value="${entry.api_secret}"
                >${secretMasked ? maskKey(entry.api_secret) : entry.api_secret}</div>
                <div class="key-actions">
                  <button
                    class="icon-btn sm${secretMasked ? '' : ' active'}"
                    id="reveal-secret-${idx}"
                    data-action="reveal"
                    data-field="secret"
                    data-idx="${idx}"
                    data-value="${entry.api_secret}"
                    aria-pressed="${!secretMasked}"
                    aria-label="${'Reveal secret for ' + entry.provider}"
                  >${eyeSVG}</button
                  ><button
                    class="icon-btn sm"
                    data-action="copy-field"
                    data-value="${entry.api_secret}"
                    aria-label="${'Copy secret for ' + entry.provider}"
                  >${copySVG}</button>
                </div>
              </div>`
              : ''
          }
          ${
            entry.username
              ? html`<div class="key-row">
                <div class="key-label">USERNAME</div>
                <div class="key-value" data-action="copy-field" data-value="${entry.username}">${entry.username}</div>
                <button
                  class="icon-btn sm"
                  data-action="copy-field"
                  data-value="${entry.username}"
                  aria-label="Copy username"
                >${copySVG}</button>
              </div>`
              : ''
          }
          ${
            entry.email
              ? html`<div class="key-row">
                <div class="key-label">EMAIL</div>
                <div class="key-value" data-action="copy-field" data-value="${entry.email}">${entry.email}</div>
                <button
                  class="icon-btn sm"
                  data-action="copy-field"
                  data-value="${entry.email}"
                  aria-label="Copy email"
                >${copySVG}</button>
              </div>`
              : ''
          }
          ${
            entry.extra_vars?.some((xv) => xv.key)
              ? html`<section
                class="key-group key-vars"
                role="group"
                aria-label="${`Variables (${entry.extra_vars.filter((xv) => xv.key).length})`}"
              >
                <div class="key-group-title">
                  Variables (${entry.extra_vars.filter((xv) => xv.key).length})
                </div>${entry.extra_vars
                  .filter((xv) => xv.key)
                  .map((xv) => {
                    const display = xv.secret ? maskKey(xv.value) : xv.value;
                    return html`<div class="key-row">
                      <div class="key-label">${xv.key.toUpperCase()}</div>
                      <div
                        class="key-value${xv.secret ? '' : ' revealed'}"
                        data-action="copy-field"
                        data-value="${xv.value}"
                      >${display}</div>
                      <button
                        class="icon-btn sm"
                        data-action="copy-field"
                        data-value="${xv.value}"
                        aria-label="${'Copy ' + xv.key}"
                      >${copySVG}</button>
                    </div>`;
                  })}</section>`
              : ''
          }
          ${
            entry.secretType === 'recovery_codes'
              ? (() => {
                  const { total, remaining } = codeStatus(entry);
                  return html`<div class="key-row">
                  <div class="key-label">UNUSED</div>
                  <div class="key-value revealed${remaining <= 2 && total > 0 ? ' key-low' : ''}">${remaining} of ${total}</div>
                  <button
                    class="btn btn-ghost btn-sm"
                    data-action="codes-use"
                    data-idx="${idx}"
                    ${remaining ? '' : 'disabled'}
                  >
                    Mark next used
                  </button>
                </div>`;
                })()
              : ''
          }
          ${
            hasTotp(entry)
              ? html`<section
                class="key-group key-second-factor"
                role="group"
                aria-label="Second factor"
              >
                <div class="key-group-title">Second factor</div>
                <div class="key-row totp-key-row" data-totp-for="${entry.id ?? ''}">
                  <div class="key-label">2FA</div>
                  <div class="key-value revealed totp-code" data-action="copy-totp">— — —</div>
                  <span class="totp-countdown"><i class="totp-countdown-fill"></i></span
                  ><span class="totp-secs" aria-hidden="true"></span
                  ><button
                    class="icon-btn sm"
                    data-action="copy-totp"
                    aria-label="${'Copy the authenticator code for ' + entry.provider}"
                  >${copySVG}</button>
                </div>
              </section>`
              : ''
          }</div>${entry.scopes?.length ? html`<div class="scopes-row">${entry.scopes.map((s) => html`<span class="scope-pill">${s}</span>`)}</div>` : ''}
        ${
          entry.description
            ? html`<div class="desc-section">
              <button class="desc-toggle" data-action="toggle-desc" aria-expanded="false">
                <svg
                  width="10"
                  height="10"
                  viewBox="0 0 24 24"
                  fill="none"
                  stroke="currentColor"
                  stroke-width="2.5"
                >
                  <polyline points="9 18 15 12 9 6" /></svg
                >General Description
              </button>
              <div class="desc-content">${entry.description}</div>
            </div>`
            : ''
        }
        ${metaRows.length ? html`<div class="meta-section">${metaRows.map(([k, v]) => html`<div class="meta-row"><span class="meta-key">${k}</span><span class="meta-val">${v}</span></div>`)}</div>` : ''}
        ${entry.categories?.length ? html`<div class="cat-pills">${entry.categories.map((c) => html`<span class="cat-pill">${c}</span>`)}</div>` : ''}
        ${
          entry.last_rotated_at
            ? html`<div class="meta-section">
              <div class="meta-row">
                <span class="meta-key">Last Rotated</span
                ><span class="meta-val" style="color:var(--text2)">${entry.last_rotated_at}</span>${rotationAgeBadge(entry)}</div>
            </div>`
            : ''
        }</div>${entry.tags?.length ? html`<div class="card-tags">${entry.tags.map((t) => html`<span class="tag-chip-card" style="${tagColor(t)}">${t}</span>`)}</div>` : ''}
      <div class="card-foot">
        <button
          class="env-copy-btn"
          id="env-btn-${idx}"
          data-action="copy-env"
          data-idx="${idx}"
          aria-label="${'Copy ' + entry.provider + ' as ' + envLabel}"
        >${copySVG}<span class="env-format-badge">${envLabel}</span
          ><span id="env-label-${idx}">${primaryEnvName(entry)}</span>
        </button>
        <button
          class="icon-btn sm env-copy-caret"
          data-action="copy-env-menu"
          data-idx="${idx}"
          title="Copy as…"
          aria-label="${'Copy ' + entry.provider + ' as…'}"
          aria-haspopup="true"
        >
          ▾
        </button>${entry.secretType === 'cookie' ? html`<button class="icon-btn sm" data-action="verify" data-idx="${idx}" title="${entry.last_verified_at ? 'Last verified ' + entry.last_verified_at : 'Never verified — open the site and confirm you are still signed in'}" aria-label="${'Mark ' + entry.provider + ' as still signed in'}" style="font-size:11px;gap:3px;">✓</button>` : html`<button class="icon-btn sm" data-action="rotate" data-idx="${idx}" title="Mark as rotated" aria-label="${'Mark ' + entry.provider + ' as rotated'}" style="font-size:11px;gap:3px;">↺</button>`}
        <button
          class="icon-btn sm${entry.pinned ? ' pin-btn active' : ' pin-btn'}"
          data-action="pin"
          data-idx="${idx}"
          title="${entry.pinned ? 'Unpin' : 'Pin to top'}"
          aria-pressed="${!!entry.pinned}"
          aria-label="${(entry.pinned ? 'Unpin ' : 'Pin ') + entry.provider}"
        >
          <svg
            width="11"
            height="11"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            stroke-width="2"
            stroke-linecap="round"
            stroke-linejoin="round"
          >
            <line x1="12" y1="17" x2="12" y2="22" />
            <path
              d="M5 17h14v-1.76a2 2 0 0 0-1.11-1.79l-1.78-.9A2 2 0 0 1 15 10.76V6h1a2 2 0 0 0 0-4H8a2 2 0 0 0 0 4h1v4.76a2 2 0 0 1-1.11 1.79l-1.78.9A2 2 0 0 0 5 15.24Z"
            />
          </svg>
        </button>
        <button
          class="icon-btn sm"
          data-action="duplicate"
          data-idx="${idx}"
          title="Duplicate"
          aria-label="${'Duplicate ' + entry.provider}"
        >${dupSVG}</button>
        <button
          class="icon-btn sm"
          data-action="edit"
          data-idx="${idx}"
          title="Edit"
          aria-label="${'Edit ' + entry.provider}"
        >${editSVG}</button>
        <button
          class="icon-btn sm danger"
          data-action="delete"
          data-idx="${idx}"
          title="Delete"
          aria-label="${'Delete ' + entry.provider}"
        >${delSVG}</button>
      </div>`,
  );
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

function rotationAgeBadge(entry: VaultEntry): SafeHtml | '' {
  if (!entry.last_rotated_at) return '';
  const days = Math.round((Date.now() - new Date(entry.last_rotated_at).getTime()) / 86400000);
  const cls = days < 30 ? ' fresh' : '';
  const label = days === 0 ? 'today' : days === 1 ? '1d ago' : `${days}d ago`;
  return html`<span class="rotation-age-badge${cls}">${label}</span>`;
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

/**
 * The expiry badge.
 *
 * Phase 23, E7: rendered by `timeUntil`, which counts in minutes and hours below
 * a day. `expires_at` already holds an ISO-8601 string, so a full timestamp
 * needs no schema change — the work was entirely in the readers, which compared
 * whole days and therefore showed "expires today" for the whole life of an AWS
 * STS token, an OAuth access token and every scraped cookie.
 *
 * **Below one day the warning is unconditional**, whatever `expiryWarningDays`
 * says. That setting exists to tune how far ahead a *long-lived* credential
 * warns; a credential dying within the hour is not a matter of taste.
 */
function expiryBadge(entry: VaultEntry): SafeHtml | '' {
  if (!Settings.get('showExpiryWarning') || !entry.expires_at) return '';
  const words = timeUntil(entry.expires_at);
  if (!words) return '';
  const bareDate = /^\d{4}-\d{2}-\d{2}$/.test(entry.expires_at.trim());
  const then = Date.parse(bareDate ? `${entry.expires_at.trim()}T23:59:59` : entry.expires_at);
  const secs = (then - Date.now()) / 1000;
  if (secs <= 0)
    return html`<span class="badge badge-expiry-expired" title="${entry.expires_at}"
      >${words}</span
    >`;
  if (secs < 86400 || secs / 86400 <= Settings.get('expiryWarningDays'))
    return html`<span class="badge badge-expiry-warn" title="${entry.expires_at}">${words}</span>`;
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
  setHtml(
    header,
    html`
      <div class="config-view-header-meta">
        <span class="config-view-title">${project.name}</span>
        <span class="config-type-badge">${typeLabel}</span>${project.description ? html`<span style="font-size:11px;color:var(--text3)">${project.description}</span>` : ''}</div>
      <div class="config-view-header-btns">
        <button
          class="btn btn-ghost btn-sm"
          data-action="import-env-chunk"
          data-project-id="${project.id}"
        >
          Import .env
        </button>${makeConfigViewHeaderBtns(project)}</div>
    `,
  );
  wrapper.appendChild(header);

  // Phase 29: cross-chunk findings, painted when Rust answers.
  const checkHost = document.createElement('section');
  checkHost.className = 'config-check';
  checkHost.hidden = true;
  checkHost.setAttribute('role', 'region');
  checkHost.setAttribute('aria-label', 'Config checks');
  wrapper.appendChild(checkHost);
  void mountConfigCheck(project, checkHost);

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
        setHtml(certWrap, html`${certDomains.map((d) => renderNginxCertCard(d))}`);
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

  setHtml(grid, '');
  grid.appendChild(wrapper);

  wrapper.addEventListener('click', (e) => {
    void (async () => {
      const el = (e.target as HTMLElement).closest<HTMLElement>('[data-action]');
      if (!el) return;
      const action = el.dataset.action!;
      const projId = el.dataset.projectId!;
      const chunkId = el.dataset.chunkId;

      if (action === 'chunk-copy') {
        void clipboardWrite(el.dataset.value || '').then(() => showToast('Copied ✓', 'ok', 1500));
        return;
      }

      // Auto-linked cert: create a stub certificate entry for a referenced domain.
      if (action === 'create-cert-stub') {
        const domain = el.dataset.domain || '';
        if (!domain) return;
        ensureCertForDomain(domain, projId);
        void persist();
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
        void persist();
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
        revealEntry(st.vault.api_keys[i]);
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
          void clipboardWrite(chunkToString(chunk)).then(() => showToast('Copied ✓', 'ok', 1500));
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
          void clipboardWrite(text).then(() => diffAndStashCopy(chunk, snapshot));
        }
        return;
      }

      if (action === 'delete-chunk') {
        if (
          !(await showConfirm(
            `Delete chunk "${proj.chunks?.find((c) => c.id === chunkId)?.name}"?`,
          ))
        )
          return;
        proj.chunks = (proj.chunks || []).filter((c) => c.id !== chunkId);
        void persist();
        render();
        return;
      }

      if (action === 'chunk-up' || action === 'chunk-down') {
        const _cks = proj.chunks || [];
        const _ci = _cks.findIndex((c) => c.id === chunkId);
        if (_ci < 0) return;
        // The config view lists chunks grouped by type (the Interface, then the
        // peers), so a move has to swap with the nearest chunk of the SAME type.
        // Swapping with a neighbour of another type reorders the stored array and
        // the exported file while the screen stays exactly as it was: a button
        // that changed the data and showed nothing (found by the Phase 32.1
        // probe on wireguard, docker and ssh_config).
        const step = action === 'chunk-up' ? -1 : 1;
        let _cj = _ci + step;
        while (_cj >= 0 && _cj < _cks.length && _cks[_cj].chunk_type !== _cks[_ci].chunk_type)
          _cj += step;
        if (_cj < 0 || _cj >= _cks.length) {
          showToast(step < 0 ? 'Already first of its kind' : 'Already last of its kind', '', 1500);
          return;
        }
        [_cks[_ci], _cks[_cj]] = [_cks[_cj], _cks[_ci]];
        proj.chunks = _cks;
        void persist();
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
        void persist();
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
        void persist();
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
        void persist();
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
        void persist();
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
        void persist();
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
            // A3: was a blob-anchor click with no download handler behind it in
            // Tauri — `saveFile` actually writes the bytes now.
            fn: () =>
              void saveFile(conf, `${proj.name}.conf`).then((res) =>
                showToast(
                  res.ok
                    ? res.path
                      ? `Downloaded to ${res.path}`
                      : 'Downloaded'
                    : `Failed: ${res.error}`,
                  res.ok ? 'ok' : 'error',
                ),
              ),
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
            // A3: `saveFile` writes real bytes; the old blob-anchor click had no
            // download handler behind it in Tauri's webview.
            fn: () =>
              void saveFile(yaml, 'docker-compose.yml').then((res) =>
                showToast(
                  res.ok
                    ? res.path
                      ? `Downloaded to ${res.path}`
                      : 'Downloaded'
                    : `Failed: ${res.error}`,
                  res.ok ? 'ok' : 'error',
                ),
              ),
          },
          {
            label: 'Download .env',
            fn: () =>
              void saveFile(envFile, `${proj.name}.env`).then((res) =>
                showToast(
                  res.ok
                    ? res.path
                      ? `Downloaded to ${res.path}`
                      : 'Downloaded'
                    : `Failed: ${res.error}`,
                  res.ok ? 'ok' : 'error',
                ),
              ),
          },
        ]);
        return;
      }

      if (action === 'export-docker-services') {
        const yaml = exportServicesSection(proj);
        if (yaml)
          void clipboardWrite(yaml).then(() => showToast('Services YAML copied ✓', 'ok', 1800));
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
          void persist();
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
              if (text) void doImportWg(text);
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
          void persist();
          render();
          showToast(`Imported ${parsed.length} chunks ✓`, 'ok');
        };
        showDropdown(el, [
          {
            label: 'Import from file',
            fn: () =>
              pickFileText('text/plain,text/yaml,.yaml,.yml', (text) => doImportDocker(text)),
          },
          {
            label: 'Paste YAML…',
            fn: async () => {
              const text = await showPromptLarge('Paste docker-compose.yml contents:', '');
              if (text) void doImportDocker(text);
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
          void persist();
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
          void persist();
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
              if (text) void doImportNginx(text, false);
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
          // Quoted (E1). An unresolved reference is left raw rather than escaped
          // into an unrecognisable literal — see `export_project_env` in the CLI.
          .map((f) => {
            const r = resolveFieldRef(f.value, true);
            return r.resolved === null || r.unresolved
              ? `${f.key}=${f.value}`
              : `${f.key}=${quoteEnvValue(r.resolved)}`;
          })
          .join('\n');
        showDropdown(el, [
          {
            label: 'Copy .env',
            fn: () => clipboardWrite(dotenv).then(() => showToast('Copied ✓', 'ok')),
          },
          {
            label: 'Download .env',
            fn: () =>
              void saveFile(dotenv, `${chunk.name}.env`).then((res) =>
                showToast(
                  res.ok
                    ? res.path
                      ? `Downloaded to ${res.path}`
                      : 'Downloaded'
                    : `Failed: ${res.error}`,
                  res.ok ? 'ok' : 'error',
                ),
              ),
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
          void persist();
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

      const addChunkFns: Partial<Record<string, () => SecretChunk>> = {
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
        void persist();
        render();
        return;
      }

      // A stack integration's chunk (Prometheus job, Grafana datasource, Homepage
      // service): what it holds comes from the descriptor, not from code here.
      if (action === 'add-stack-chunk') {
        const adapter = stackAdapter(proj.project_type);
        const spec = adapter && stackChunkSpec(adapter, el.dataset.chunkType ?? '');
        if (!spec) return;
        const have = (proj.chunks || []).filter((c) => c.chunk_type === spec.type).length;
        if (spec.singleton && have) {
          showToast(`This project already has its ${spec.label.toLowerCase()} section`, 'err');
          return;
        }
        if (!proj.chunks) proj.chunks = [];
        const base = spec.type.replace(/^[a-z]+_/, '').replace(/_/g, '-');
        proj.chunks.push(newStackChunk(spec, `${base}-${have + 1}`));
        void persist();
        render();
        return;
      }

      if (action === 'export-stack') {
        const file = stackAdapter(proj.project_type)?.file ?? 'config.yml';
        const content = exportStack(proj);
        showDropdown(el, [
          {
            label: `Copy ${file}`,
            fn: () => clipboardWrite(content).then(() => showToast('Copied ✓', 'ok')),
          },
          {
            label: `Download ${file}`,
            fn: () => {
              dlText(content, file);
              showToast('Downloaded', 'ok');
            },
          },
        ]);
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
              void persist();
              render();
              showToast(`Imported ${name} into ${domains[0]} certificate ✓`, 'ok');
            } else {
              // No single domain to attach to → fall back to a standalone key-file chunk.
              if (!proj.chunks) proj.chunks = [];
              proj.chunks.push(makeKeyChunk(keyType, name, pem));
              void persist();
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
              void persist();
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
          void persist();
          render();
          showToast(`Imported ${name} ✓`, 'ok');
        });
        return;
      }

      // A3: real bytes on disk via `saveFile`, not a blob-anchor click WebKitGTK
      // has no download handler for.
      const dlText = (content: string, filename: string) => {
        void saveFile(content, filename).then((res) =>
          showToast(
            res.ok
              ? res.path
                ? `Downloaded to ${res.path}`
                : 'Downloaded'
              : `Failed: ${res.error}`,
            res.ok ? 'ok' : 'error',
          ),
        );
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
          void persist();
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
              if (t) void doImport(t, false);
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
          void persist();
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
              if (t) void doImport(t, false);
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
    })();
  });
}

/**
 * Brings one entry's card into view from anywhere: a `${ref}` badge in the config
 * view, a health-scan finding. Both used to expand the card and repaint, which
 * shows nothing when a project, search or tag filter is hiding the entry, or
 * when the config view (which replaces the card grid) is what is on screen: the
 * Phase 32.2 probe found the badge's click had no visible effect for exactly
 * that reason. So if the entry is not in the filtered set, the filters go.
 * Addressed by id (invariant 1); the card is looked up fresh after the repaint.
 */
export function revealEntry(entry: VaultEntry): void {
  const id = entryId(entry);
  switchPanel('secrets');
  const inView = getFiltered().includes(entry);
  const onConfigView = st.currentSelectedProjectIds[0] !== 'Universal';
  if (!inView || onConfigView) clearAllFilters();
  st.expanded.add(id);
  // A collapsed pool card hides its members; expand it too, or the card this
  // promises to show stays behind the summary.
  if (typeof entry.pool === 'string' && entry.pool.trim()) st.expandedPools.add(entry.pool.trim());
  render();
  setTimeout(() => {
    const idx = st.vault.api_keys.findIndex((e) => entryId(e) === id);
    const cardEl = document.querySelector<HTMLElement>(`#card-grid [data-idx="${idx}"]`);
    cardEl?.scrollIntoView({ behavior: 'smooth', block: 'center' });
    cardEl?.classList.add('flash-highlight');
    setTimeout(() => cardEl?.classList.remove('flash-highlight'), 1500);
  }, 80);
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
      // Structured project types (`renderConfigView`) reuse `#card-grid` for a
      // chunk tree, not entry cards — the type chip bar has nothing to filter
      // there and would otherwise linger from the last "All Secrets" render.
      const bar = document.getElementById('type-chip-bar');
      if (bar) bar.style.display = 'none';
      renderConfigView(project);
      updateCopyAllBtn();
      return;
    }
  }
  renderGrid();
  updateCopyAllBtn();
}

/** A chip's display label — the one place this mapping lives, shared by the
 * "Copy All" button and the active-filter summary below. `secretTypeLabel`
 * already handles every real `SecretType`; `__totp` is the only token that
 * needs a name of its own. */
function chipLabel(chip: string): string {
  return chip === '__totp' ? '2FA' : secretTypeLabel(chip);
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
  if (st.activeTypeChips.size)
    out.push(`type: ${[...st.activeTypeChips].map(chipLabel).join(', ')}`);
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
  const chips = [...st.activeTypeChips];
  const label =
    st.filter.type === 'category'
      ? `Copy "${st.filter.value}"`
      : st.filter.type === 'price'
        ? `Copy ${st.filter.value}`
        : chips.length === 1
          ? `Copy ${chipLabel(chips[0])}`
          : chips.length > 1
            ? `Copy ${chips.length} types`
            : projectFiltered
              ? 'Copy Category'
              : 'Copy All';
  setHtml(btn, html`${copySVG} ${label}`);
}

// Register render as the global render function
setRenderFn(render);

// ── ENV chunk ↔ vault link modal ───────────────────────────────────────────

let _envLinkProj: import('./types').Project | null = null;
let _envLinkChunk: import('./types').SecretChunk | null = null;

function _renderEnvLinkRow(m: EnvLinkMatch): SafeHtml {
  if (m.alreadyLinked) {
    return html`<div class="env-link-row env-link-row--linked">
      <span class="env-link-key">${m.key}</span>
      <span class="env-link-badge env-link-badge--linked" title="Linked to ${m.existingRef || ''}"
        >→ ${m.existingRef || ''} ✓</span
      >
    </div>`;
  }
  if (m.match) {
    const { entry, ref, field, confidence } = m.match;
    return html`<div class="env-link-row env-link-row--match" data-key="${m.key}" data-ref="${ref}">
      <label class="env-link-check-label">
        <input type="checkbox" class="env-link-cb" checked />
        <span class="env-link-key">${m.key}</span>
      </label>
      <span class="env-link-badge env-link-badge--vault"
        >→ ${entry.provider} / ${field} <span class="env-link-conf">${confidence}%</span></span
      >
    </div>`;
  }
  if (m.suggestCreate) {
    const { provider, keyId, secretType } = m.suggestCreate;
    const typeOpts = (
      ['api_key', 'password', 'connection_string', 'env_var', 'ssh_key'] as SecretType[]
    ).map((t) => html`<option value="${t}" ${t === secretType ? ' selected' : ''}>${t}</option>`);
    return html`<div
      class="env-link-row env-link-row--create"
      data-key="${m.key}"
      data-key-id="${keyId || ''}"
    >
      <label class="env-link-check-label">
        <input type="checkbox" class="env-link-cb" />
        <span class="env-link-key">${m.key}</span>
      </label>
      <span class="env-link-badge env-link-badge--new">New:</span>
      <input
        class="form-input env-link-name-input"
        value="${provider}"
        placeholder="provider name"
        style="width:130px;height:24px;padding:2px 6px;font-size:11px"
      />
      <select
        class="form-input env-link-type-select"
        style="width:130px;height:24px;padding:2px 4px;font-size:11px"
      >${typeOpts}</select>
    </div>`;
  }
  return html`<div class="env-link-row env-link-row--skip">
    <span class="env-link-key">${m.key}</span>
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
  if (list) setHtml(list, html`${matches.map(_renderEnvLinkRow)}`);
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
  void persist();
  render();
  closeEnvLinkModal();
  showToast(`${linked} linked, ${created} created ✓`, 'ok');
}
