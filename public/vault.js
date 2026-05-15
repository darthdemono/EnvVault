/* =============================================================================
 * API VAULT — vault.js
 *
 * Architecture note (future v2 migration):
 *   This file is structured so that LocalVaultStore can be swapped for
 *   RemoteVaultStore (HTTPS + auth) with zero changes to the UI layer.
 *   Look for the STORE INTERFACE and AUTH STUB sections below.
 * ============================================================================= */

/* ── AUTH STUB ─────────────────────────────────────────────────────────────────
 * Placeholder for future multi-user, role-based auth.
 * Roles: owner | editor | viewer
 */
const Auth = {
  user: null,
  role: 'owner',
  vaults: [{ id: 'local', name: 'Local Vault', type: 'local' }],
  currentVaultId: 'local',
  can: (action) => true, // future: check role permissions
};

/* ── STORE INTERFACE ──────────────────────────────────────────────────────────
 * VaultStore defines the contract. Swap LocalVaultStore for RemoteVaultStore
 * in init() to switch backends without touching UI code.
 */
class VaultStore {
  async load()           { throw new Error('Not implemented'); }
  async save(data)       { throw new Error('Not implemented'); }
  get isRemote()         { return false; }
  get vaultId()          { return 'local'; }
}

class LocalVaultStore extends VaultStore {
  // Keys go to sessionStorage (cleared on tab close — intentional security choice)
  // Settings go to localStorage (not sensitive)
  async load() {
    const raw = sessionStorage.getItem('api-vault');
    return raw ? JSON.parse(raw) : null;
  }
  async save(data) {
    try { sessionStorage.setItem('api-vault', JSON.stringify(data)); }
    catch { showToast('Session storage full — export to save changes', 'err'); }
  }
  get isRemote() { return false; }
  get vaultId()  { return 'local'; }
}

/* ── TAURI VAULT STORE ────────────────────────────────────────────────────────
 * Active when running as a compiled Tauri app.
 * Phase 2: load/save unchanged — Rust now requires vault to be unlocked first.
 * New surface: unlock(), lock(), exists(), isUnlocked(), reset().
 */
class TauriVaultStore extends VaultStore {
  #invoke = window.__TAURI__?.core?.invoke?.bind(window.__TAURI__.core);

  /** Derive key from password and open the SQLCipher DB. */
  async unlock(password) {
    return this.#invoke('unlock_vault', { password });
  }
  /** Zeroize the in-memory key. */
  async lock() {
    return this.#invoke('lock_vault');
  }
  /** True when a derived key is held in process memory. */
  async isUnlocked() {
    return this.#invoke('vault_is_unlocked');
  }
  /** True when vault.db already exists on disk (returning user vs first run). */
  async exists() {
    return this.#invoke('vault_exists');
  }
  /** Permanently delete vault.db + vault.salt (forgotten password). */
  async reset() {
    return this.#invoke('reset_vault');
  }

  // ── load/save signatures identical to Phase 1 ──
  async load() {
    const data = await this.#invoke('load_vault');
    return data ?? null;
  }
  async save(data) {
    await this.#invoke('save_vault', { data });
  }
  async vaultFilePath() {
    return this.#invoke('get_vault_path').catch(() => '');
  }
  get isRemote() { return false; }
  get vaultId()  { return 'local-native'; }
}

/* ── SETTINGS MANAGER ─────────────────────────────────────────────────────────
 * Seeded from settings.json, overrides in localStorage (settings are not sensitive)
 */
const DEFAULT_SETTINGS = {
  theme: 'dark', accentColor: '#7364c9',
  cardSize: 'medium', gridColumns: 'auto',
  defaultAccount: '', defaultExportFormat: 'dotenv',
  autoLockMinutes: 20, maskKeysByDefault: true,
  showExpiryWarning: true, expiryWarningDays: 30,
};

const Settings = {
  _data: { ...DEFAULT_SETTINGS },
  get(k)    { return this._data[k]; },
  set(k, v) { this._data[k] = v; this._persist(); },
  setAll(o) { Object.assign(this._data, o); this._persist(); },
  getAll()  { return { ...this._data }; },
  _persist(){ try { localStorage.setItem('apivault-settings', JSON.stringify(this._data)); } catch {} },
  async init() {
    // 1. fetch settings.json defaults
    try {
      const r = await fetch('./settings.json');
      if (r.ok) Object.assign(this._data, await r.json());
    } catch {}
    // 2. localStorage overrides
    try {
      const stored = localStorage.getItem('apivault-settings');
      if (stored) Object.assign(this._data, JSON.parse(stored));
    } catch {}
    this._apply();
  },
  _apply() {
    const d = this._data;
    document.documentElement.setAttribute('data-theme', d.theme);
    document.documentElement.style.setProperty('--accent', d.accentColor);
    document.documentElement.style.setProperty('--accent-dim', hexAlpha(d.accentColor, .14));
    document.documentElement.style.setProperty('--accent-mid', hexAlpha(d.accentColor, .3));
    applyGridSettings();
  },
};

function hexAlpha(hex, a) {
  const r = parseInt(hex.slice(1,3),16), g = parseInt(hex.slice(3,5),16), b = parseInt(hex.slice(5,7),16);
  return `rgba(${r},${g},${b},${a})`;
}

function applyGridSettings() {
  const grid = document.getElementById('card-grid');
  if (!grid) return;
  const size = Settings.get('cardSize') || 'medium';
  const minW = { compact: 280, medium: 360, large: 460 }[size] || 360;
  const cols = Settings.get('gridColumns') || 'auto';
  grid.style.gridTemplateColumns = cols === 'auto'
    ? `repeat(auto-fill, minmax(${minW}px, 1fr))`
    : `repeat(${cols}, minmax(${minW}px, 1fr))`;
}

/* ── CLIPBOARD ──────────────────────────────────────────────────────────────── */
function clipboardWrite(text) {
  if (navigator.clipboard?.writeText) {
    return navigator.clipboard.writeText(text).catch(() => _execCopy(text));
  }
  return _execCopy(text);
}
function _execCopy(text) {
  const ta = Object.assign(document.createElement('textarea'), { value: text });
  Object.assign(ta.style, { position:'fixed', left:'-9999px', top:'-9999px', opacity:'0' });
  document.body.appendChild(ta);
  ta.focus(); ta.select();
  try    { document.execCommand('copy'); return Promise.resolve(); }
  catch(e){ return Promise.reject(e); }
  finally { document.body.removeChild(ta); }
}

/* ── EXPORT FORMATS ───────────────────────────────────────────────────────────*/
const Exporter = {
  dotenv(keys) {
    return keys.map(k => {
      const b = dotenvKey(k);
      let out = `# ${k.provider}${k.account_name ? ' — ' + k.account_name : ''}\n${b}_API_KEY=${k.api_key}`;
      if (k.api_secret) out += `\n${b}_API_SECRET=${k.api_secret}`;
      if (k.api_url)    out += `\n${b}_API_URL=${k.api_url}`;
      return out;
    }).join('\n\n');
  },
  yaml(keys) {
    const lines = ['# API Vault Export', '# Generated: ' + new Date().toISOString(), ''];
    keys.forEach(k => {
      const b = dotenvKey(k);
      lines.push(`# ${k.provider}`);
      lines.push(`${b}_API_KEY: "${k.api_key}"`);
      if (k.api_secret) lines.push(`${b}_API_SECRET: "${k.api_secret}"`);
      if (k.api_url)    lines.push(`${b}_API_URL: "${k.api_url}"`);
      lines.push('');
    });
    return lines.join('\n');
  },
  yamlStructured(keys) {
    const indent = (s, n=2) => s.split('\n').map(l => ' '.repeat(n)+l).join('\n');
    const lines = ['api_keys:'];
    keys.forEach(k => {
      lines.push(`  - provider: "${esc(k.provider)}"`);
      if (k.account_name)    lines.push(`    account_name: "${esc(k.account_name)}"`);
      lines.push(`    api_key: "${esc(k.api_key)}"`);
      if (k.api_secret)      lines.push(`    api_secret: "${esc(k.api_secret)}"`);
      if (k.key_id)          lines.push(`    key_id: "${esc(k.key_id)}"`);
      if (k.price_type)      lines.push(`    price_type: ${k.price_type}`);
      if (k.environment)     lines.push(`    environment: ${k.environment}`);
      if (k.api_url)         lines.push(`    api_url: "${esc(k.api_url)}"`);
      if (k.callback_url)    lines.push(`    callback_url: "${esc(k.callback_url)}"`);
      if (k.expires_at)      lines.push(`    expires_at: "${k.expires_at}"`);
      if (k.categories?.length) lines.push(`    categories: [${k.categories.map(c=>`"${c}"`).join(', ')}]`);
    });
    return lines.join('\n');
  },
  json(keys) { return JSON.stringify({ api_keys: keys }, null, 2); },
};

/* ── STATE ─────────────────────────────────────────────────────────────────── */
let vault    = { api_keys: [], user_categories: [] };
let schema   = null;
let store; // instantiated in init() — TauriVaultStore when running in Tauri, LocalVaultStore otherwise
let filter   = { type: 'all', value: '' };
let searchQ  = '';
let expanded = new Set();
let allExpanded = false;
let lockTimer;
let undoStack = []; // { action, data, timeout }
let revealed  = {};

/* ── EXPIRY UTILS ─────────────────────────────────────────────────────────────*/
function expiryStatus(dateStr) {
  if (!dateStr) return null;
  const exp = new Date(dateStr), now = new Date();
  exp.setHours(23,59,59); // end of expiry day
  const days = Math.round((exp - now) / 86400000);
  if (days < 0) return { status: 'expired', label: `Expired ${Math.abs(days)}d ago`, days };
  if (days <= (Settings.get('expiryWarningDays') || 30)) return { status: 'soon', label: `Expires in ${days}d`, days };
  return { status: 'ok', label: dateStr, days };
}

function expiryBadge(entry) {
  if (!Settings.get('showExpiryWarning') || !entry.expires_at) return '';
  const e = expiryStatus(entry.expires_at);
  if (!e || e.status === 'ok') return '';
  const cls = e.status === 'expired' ? 'badge-expiry-expired' : 'badge-expiry-warn';
  return `<span class="badge ${cls}" title="${entry.expires_at}">${e.label}</span>`;
}

/* ── FILTER & SORT ──────────────────────────────────────────────────────────── */
function parseSearch(q) {
  // Supports: price:free  cat:media  env:prod  plus free text
  const filters = {}, words = [];
  q.split(/\s+/).forEach(t => {
    const [k, v] = t.split(':');
    if (v) filters[k.toLowerCase()] = v.toLowerCase();
    else if (t) words.push(t.toLowerCase());
  });
  return { filters, text: words.join(' ') };
}

function getFiltered() {
  const { filters, text } = parseSearch(searchQ);
  return vault.api_keys.filter(k => {
    if (filters.price && k.price_type !== filters.price) return false;
    if (filters.cat   && !(k.categories||[]).some(c => c.includes(filters.cat))) return false;
    if (filters.env   && k.environment !== filters.env) return false;
    if (text) {
      const hay = [k.provider,k.account_name,k.key_id,k.api_description,
                   k.description,k.details,...(k.categories||[])].join(' ').toLowerCase();
      if (!hay.includes(text)) return false;
    }
    if (filter.type === 'price')    return k.price_type === filter.value;
    if (filter.type === 'category') return (k.categories||[]).includes(filter.value);
    return true;
  });
}

function sorted(arr) {
  const by = document.getElementById('sort-select')?.value || 'provider';
  const priceOrder = { free:0, local:1, conditional:2, paid:3 };
  return [...arr].sort((a,b) => {
    if (by === 'price')    return (priceOrder[a.price_type]||9)-(priceOrder[b.price_type]||9) || a.provider.localeCompare(b.provider);
    if (by === 'category') return (a.categories?.[0]||'zzz').localeCompare(b.categories?.[0]||'zzz') || a.provider.localeCompare(b.provider);
    if (by === 'expiry') {
      const ae = a.expires_at ? new Date(a.expires_at).getTime() : Infinity;
      const be = b.expires_at ? new Date(b.expires_at).getTime() : Infinity;
      return ae - be;
    }
    return a.provider.localeCompare(b.provider);
  });
}

/* ── RENDER ─────────────────────────────────────────────────────────────────── */
function render() { renderSidebar(); renderGrid(); updateCopyAllBtn(); }

function renderSidebar() {
  const all = vault.api_keys;
  const pc = p => all.filter(k => k.price_type === p).length;
  document.getElementById('count-all').textContent         = all.length;
  document.getElementById('count-free').textContent        = pc('free');
  document.getElementById('count-local').textContent       = pc('local');
  document.getElementById('count-paid').textContent        = pc('paid');
  document.getElementById('count-conditional').textContent = pc('conditional');

  document.querySelectorAll('.sidebar-item[data-filter-type]').forEach(btn => {
    const t = btn.dataset.filterType, v = btn.dataset.filterValue;
    btn.classList.toggle('active',
      (t==='all' && filter.type==='all') ||
      (t===filter.type && v===filter.value)
    );
  });

  const catList = document.getElementById('category-list');
  catList.innerHTML = '';
  (vault.user_categories||[]).forEach(cat => {
    const count = all.filter(k=>(k.categories||[]).includes(cat)).length;
    const row = document.createElement('div');
    row.className = 'sidebar-cat-row';
    const isActive = filter.type==='category' && filter.value===cat;
    row.innerHTML = `
      <button class="sidebar-item${isActive?' active':''}" data-filter-type="category" data-filter-value="${esc(cat)}">
        <span class="sidebar-icon" style="font-size:9px;color:var(--accent)">◆</span>
        <span class="sidebar-label">${esc(cat)}</span>
        <span class="sidebar-count">${count}</span>
      </button>
      <button class="sidebar-cat-del" title="Delete '${esc(cat)}'" onclick="deleteCategory('${escAttr(cat)}')">✕</button>`;
    row.querySelector('.sidebar-item').addEventListener('click', () => setFilter('category', cat));
    catList.appendChild(row);
  });
}

function renderGrid() {
  const items = sorted(getFiltered());
  const grid  = document.getElementById('card-grid');
  document.getElementById('result-count').textContent = `${items.length} key${items.length!==1?'s':''}`;
  applyGridSettings();

  if (!items.length) {
    grid.innerHTML = `<div class="empty-state">
      <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
        <rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>
      </svg>
      <p>No keys found</p>
      <small>${searchQ ? 'Try a different search — supports price:free cat:media env:prod' : 'Add a key or import from a backup (.env, JSON, YAML)'}</small>
    </div>`;
    return;
  }

  grid.innerHTML = '';
  items.forEach((entry, i) => {
    grid.appendChild(buildCard(entry, vault.api_keys.indexOf(entry), i));
  });
}

function updateCopyAllBtn() {
  const wrap = document.getElementById('copy-all-wrap');
  const items = getFiltered();
  const hasFilter = filter.type !== 'all' || searchQ;
  wrap.style.display = (hasFilter && items.length) ? 'flex' : 'none';
  const btn = document.getElementById('copy-all-btn');
  const label = filter.type==='category' ? `Copy "${filter.value}"` :
                filter.type==='price'    ? `Copy ${filter.value}` : 'Copy All';
  btn.innerHTML = `<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg> ${label}`;
}

/* ── BUILD CARD ─────────────────────────────────────────────────────────────── */
function buildCard(entry, idx, animIdx) {
  const isExp  = allExpanded || expanded.has(idx);
  const pt     = entry.price_type || 'free';
  const expiry = expiryBadge(entry);
  const envBadge  = entry.environment
    ? `<span class="badge badge-env" data-env="${entry.environment}">${entry.environment}</span>` : '';
  const keyIdBadge = entry.key_id
    ? `<span class="badge badge-keyid">${esc(entry.key_id)}</span>` : '';

  const hasMask = Settings.get('maskKeysByDefault');
  const envFmt  = Settings.get('defaultExportFormat') || 'dotenv';
  const envLabel = envFmt === 'yaml' ? 'YAML' : '.env';

  const card = document.createElement('div');
  card.className = 'card' + (isExp ? ' expanded' : '');
  card.style.animationDelay = `${Math.min(animIdx*20,180)}ms`;
  card.dataset.idx = idx;

  const metaRows = [];
  if (entry.version)      metaRows.push(['Version',   esc(entry.version)]);
  if (entry.rate_limit)   metaRows.push(['Rate Limit', esc(entry.rate_limit)]);
  if (entry.expires_at)   metaRows.push(['Expires',   esc(entry.expires_at)]);
  if (entry.api_url)      metaRows.push(['API URL',   `<a href="${esc(entry.api_url)}" target="_blank" rel="noopener">${esc(entry.api_url)}</a>`]);
  if (entry.callback_url) metaRows.push(['Callback',  `<a href="${esc(entry.callback_url)}" target="_blank" rel="noopener">${esc(entry.callback_url)}</a>`]);
  if (entry.details)      metaRows.push(['Details',   esc(entry.details)]);

  card.innerHTML = `
    <div class="card-head" data-action="copy-env" data-idx="${idx}">
      <div class="provider-icon-wrap" data-action="icon" data-idx="${idx}" title="Change icon">
        ${iconHTML(entry.provider, entry.custom_icon)}
      </div>
      <div class="card-meta">
        <div class="card-provider">
          ${esc(entry.provider)}
          <span class="badge badge-price" data-price="${pt}">${pt}</span>
          ${envBadge}${keyIdBadge}${expiry}
        </div>
        <div class="card-account">${esc(entry.account_name||'')}</div>
      </div>
      <button class="card-chevron" data-action="toggle" data-idx="${idx}" title="Expand">
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="6 9 12 15 18 9"/></svg>
      </button>
    </div>

    ${entry.api_description ? `<div class="card-apidesc">${esc(entry.api_description)}</div>` : ''}

    <div class="card-body">
      <div class="key-section">
        <div class="key-row">
          <div class="key-label">API KEY</div>
          <div class="key-value${hasMask?'':' revealed'}" id="kv-key-${idx}"
               data-action="copy-field" data-value="${escAttr(entry.api_key)}" title="Click to copy">
            ${hasMask ? maskKey(entry.api_key) : esc(entry.api_key)}
          </div>
          <div class="key-actions">
            <button class="icon-btn sm${hasMask?'':' active'}" id="reveal-key-${idx}"
              data-action="reveal" data-field="key" data-idx="${idx}" data-value="${escAttr(entry.api_key)}"
              title="Reveal/Hide">${eyeSVG}</button>
            <button class="icon-btn sm"
              data-action="copy-field" data-value="${escAttr(entry.api_key)}"
              title="Copy">${copySVG}</button>
          </div>
        </div>
        ${entry.api_secret ? `
        <div class="key-row">
          <div class="key-label">SECRET</div>
          <div class="key-value${hasMask?'':' revealed'}" id="kv-secret-${idx}"
               data-action="copy-field" data-value="${escAttr(entry.api_secret)}" title="Click to copy">
            ${hasMask ? maskKey(entry.api_secret) : esc(entry.api_secret)}
          </div>
          <div class="key-actions">
            <button class="icon-btn sm${hasMask?'':' active'}" id="reveal-secret-${idx}"
              data-action="reveal" data-field="secret" data-idx="${idx}" data-value="${escAttr(entry.api_secret)}"
              title="Reveal/Hide">${eyeSVG}</button>
            <button class="icon-btn sm"
              data-action="copy-field" data-value="${escAttr(entry.api_secret)}"
              title="Copy">${copySVG}</button>
          </div>
        </div>` : ''}
      </div>

      ${entry.scopes?.length ? `
      <div class="scopes-row">${entry.scopes.map(s=>`<span class="scope-pill">${esc(s)}</span>`).join('')}</div>` : ''}

      ${entry.description ? `
      <div class="desc-section">
        <button class="desc-toggle" data-action="toggle-desc">
          <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="9 18 15 12 9 6"/></svg>
          General Description
        </button>
        <div class="desc-content">${esc(entry.description)}</div>
      </div>` : ''}

      ${metaRows.length ? `
      <div class="meta-section">${metaRows.map(([k,v])=>`
        <div class="meta-row"><span class="meta-key">${k}</span><span class="meta-val">${v}</span></div>`).join('')}
      </div>` : ''}

      ${entry.categories?.length ? `
      <div class="cat-pills">${entry.categories.map(c=>`<span class="cat-pill">${esc(c)}</span>`).join('')}</div>` : ''}
    </div>

    <div class="card-foot">
      <button class="env-copy-btn" id="env-btn-${idx}"
              data-action="copy-env" data-idx="${idx}" title="Copy as ${envLabel}">
        ${copySVG}
        <span class="env-format-badge">${envLabel}</span>
        <span id="env-label-${idx}">${dotenvKey(entry)}_API_KEY</span>
      </button>
      <button class="icon-btn sm" data-action="duplicate" data-idx="${idx}" title="Duplicate">${dupSVG}</button>
      <button class="icon-btn sm" data-action="edit"      data-idx="${idx}" title="Edit">${editSVG}</button>
      <button class="icon-btn sm danger" data-action="delete" data-idx="${idx}" title="Delete">${delSVG}</button>
    </div>`;

  // No addEventListener here — handled by the delegated listener below
  return card;
}

/* ── SVG CONSTANTS ──────────────────────────────────────────────────────────── */
const eyeSVG  = `<svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>`;
const copySVG = `<svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>`;
const editSVG = `<svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>`;
const delSVG  = `<svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/><path d="M10 11v6M14 11v6M9 6V4h6v2"/></svg>`;
const dupSVG  = `<svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="1" y="1" width="13" height="13" rx="2"/><path d="M8 8h13v13H8z"/></svg>`;

/* ── CARD INTERACTIONS ──────────────────────────────────────────────────────── */
function toggleCard(e, idx) {
  e.stopPropagation();
  const card = document.querySelector(`.card[data-idx="${idx}"]`);
  if (!card) return;
  card.classList.toggle('expanded');
  if (card.classList.contains('expanded')) expanded.add(idx);
  else expanded.delete(idx);
}

function toggleReveal(e, field, idx, value) {
  e.stopPropagation();
  const k   = `${field}-${idx}`;
  const el  = document.getElementById(`kv-${field}-${idx}`);
  const btn = document.getElementById(`reveal-${field}-${idx}`);
  if (!el) return;
  revealed[k] = !revealed[k];
  el.textContent  = revealed[k] ? value : maskKey(value);
  el.classList.toggle('revealed', revealed[k]);
  btn.classList.toggle('active', revealed[k]);
}

function toggleDesc(btn) {
  btn.classList.toggle('open');
  btn.nextElementSibling.classList.toggle('open');
}

function copyField(e, value, btn) {
  if (e) e.stopPropagation();
  clipboardWrite(value).then(() => {
    if (btn?.classList) { btn.classList.add('active'); setTimeout(()=>btn.classList.remove('active'),1200); }
    showToast('Copied ✓', 'ok', 1500);
  }).catch(() => showToast('Copy failed — check browser permissions', 'err'));
}

function doCopyEnv(e, idx) {
  if (e) e.stopPropagation();
  const entry = vault.api_keys[idx];
  if (!entry) return;
  const fmt  = Settings.get('defaultExportFormat') || 'dotenv';
  const text = fmt === 'yaml' ? Exporter.yaml([entry]) : Exporter.dotenv([entry]);
  clipboardWrite(text).then(() => {
    const btn = document.getElementById(`env-btn-${idx}`);
    if (btn) { btn.classList.add('env-copied'); setTimeout(()=>btn.classList.remove('env-copied'),1600); }
    showToast(`Copied as ${fmt === 'yaml' ? 'YAML' : '.env'} ✓`, 'ok');
  }).catch(() => showToast('Copy failed', 'err'));
}

function onIconWrapClick(e, idx) {
  e.stopPropagation();
  const fieldEl   = document.getElementById('f-icon');
  const previewEl = document.getElementById('f-icon-preview');
  // Temporarily open modal just for icon pick with a callback
  _pendingIconTarget = idx;
  openIconPickerFor(idx);
}

let _pendingIconTarget = null;
function openIconPickerFor(idx) {
  const entry   = vault.api_keys[idx];
  _iconPickerTarget = {
    onClose: (slug) => {
      vault.api_keys[idx] = { ...vault.api_keys[idx], custom_icon: slug || null };
      store.save(vault);
      render();
    }
  };
  _iconSelected = entry.custom_icon || null;
  document.getElementById('icon-search').value = '';
  renderIconGrid('');
  document.getElementById('icon-picker-overlay').classList.add('open');
}

/* ── DOTENV KEY ─────────────────────────────────────────────────────────────── */
function dotenvKey(entry) {
  const p = (entry.provider||'UNKNOWN').toUpperCase().replace(/[^A-Z0-9]/g,'_');
  const k = entry.key_id ? '_'+entry.key_id.toUpperCase().replace(/[^A-Z0-9]/g,'_') : '';
  return `${p}${k}`;
}

/* ── CRUD ───────────────────────────────────────────────────────────────────── */
function duplicateKey(e, idx) {
  e.stopPropagation();
  const copy = { ...vault.api_keys[idx], key_id: (vault.api_keys[idx].key_id||'copy')+'_copy' };
  vault.api_keys.splice(idx+1, 0, copy);
  store.save(vault);
  render();
  showToast('Duplicated ✓', 'ok');
}

function deleteKey(e, idx) {
  e.stopPropagation();
  const entry   = vault.api_keys[idx];
  const removed = vault.api_keys.splice(idx, 1)[0];
  store.save(vault);
  expanded.delete(idx);
  render();
  pushUndo(`Deleted "${removed.provider}"`, () => {
    vault.api_keys.splice(idx, 0, removed);
    store.save(vault);
    render();
  });
}

/* ── UNDO ───────────────────────────────────────────────────────────────────── */
function pushUndo(msg, fn) {
  const bar = document.getElementById('undo-bar');
  document.getElementById('undo-msg').textContent = msg;
  bar.style.display = 'flex';
  undoStack.push({ fn, t: setTimeout(() => { bar.style.display='none'; undoStack.pop(); }, 5000) });
}
document.getElementById('undo-btn').addEventListener('click', () => {
  const item = undoStack.pop();
  if (item) { clearTimeout(item.t); item.fn(); document.getElementById('undo-bar').style.display='none'; }
});

/* ── CATEGORIES ─────────────────────────────────────────────────────────────── */
function setFilter(type, value) {
  filter = (filter.type===type && filter.value===value) ? { type:'all', value:'' } : { type, value };
  render();
}
document.querySelectorAll('.sidebar-item[data-filter-type]').forEach(btn =>
  btn.addEventListener('click', () => setFilter(btn.dataset.filterType, btn.dataset.filterValue))
);

document.getElementById('new-category-btn').addEventListener('click', () => {
  const f = document.getElementById('new-category-form');
  f.style.display = f.style.display==='none' ? 'flex' : 'none';
  if (f.style.display==='flex') document.getElementById('new-category-input').focus();
});
document.getElementById('new-category-save').addEventListener('click', () => {
  const inp  = document.getElementById('new-category-input');
  const name = inp.value.trim().toLowerCase();
  if (!name) return;
  if ((vault.user_categories||[]).includes(name)) { showToast('Already exists', 'err'); return; }
  vault.user_categories = [...(vault.user_categories||[]), name];
  store.save(vault);
  inp.value = '';
  document.getElementById('new-category-form').style.display = 'none';
  render();
});
document.getElementById('new-category-cancel').addEventListener('click', () => {
  document.getElementById('new-category-form').style.display = 'none';
});
document.getElementById('new-category-input').addEventListener('keydown', e => {
  if (e.key==='Enter') document.getElementById('new-category-save').click();
  if (e.key==='Escape') document.getElementById('new-category-cancel').click();
});

function deleteCategory(name) {
  if (!confirm(`Delete category "${name}"? It will be removed from all keys.`)) return;
  vault.user_categories = (vault.user_categories||[]).filter(c=>c!==name);
  vault.api_keys.forEach(k => { if (k.categories) k.categories = k.categories.filter(c=>c!==name); });
  if (filter.type==='category' && filter.value===name) filter = { type:'all', value:'' };
  store.save(vault);
  render();
}

/* ── COPY ALL ───────────────────────────────────────────────────────────────── */
function copyAll(fmt) {
  const keys = sorted(getFiltered());
  const text = fmt==='yaml' ? Exporter.yaml(keys) :
               fmt==='json' ? Exporter.json(keys) : Exporter.dotenv(keys);
  navigator.clipboard.writeText(text).then(() =>
    showToast(`${keys.length} keys copied as ${fmt==='yaml'?'YAML':fmt==='json'?'JSON':'.env'} ✓`, 'ok')
  );
}

/* ── ADD / EDIT MODAL ───────────────────────────────────────────────────────── */
function applySchemaTooltips() {
  if (!schema) return;
  const props = schema.properties?.api_keys?.items?.properties || {};
  document.querySelectorAll('.form-label[data-field]').forEach(el => {
    const d = props[el.dataset.field]?.description;
    if (d) el.title = d;
  });
}

function buildCatChips(selected=[]) {
  const wrap = document.getElementById('f-categories');
  wrap.innerHTML = '';
  if (!(vault.user_categories||[]).length) {
    wrap.innerHTML = `<span style="font-size:10px;color:var(--text3)">No categories yet — add one in the sidebar</span>`;
    return;
  }
  vault.user_categories.forEach(cat => {
    const chip = Object.assign(document.createElement('button'), {
      type:'button', className:'cat-chip'+(selected.includes(cat)?' selected':''), textContent: cat
    });
    chip.addEventListener('click', () => chip.classList.toggle('selected'));
    wrap.appendChild(chip);
  });
}

function formToEntry() {
  const scopes = document.getElementById('f-scopes').value.split(',').map(s=>s.trim()).filter(Boolean);
  const cats   = [...document.querySelectorAll('#f-categories .cat-chip.selected')].map(c=>c.textContent);
  return {
    provider:        document.getElementById('f-provider').value.trim(),
    account_name:    document.getElementById('f-account').value.trim() || Settings.get('defaultAccount') || undefined,
    api_key:         document.getElementById('f-key').value.trim(),
    api_secret:      document.getElementById('f-secret').value.trim() || null,
    key_id:          document.getElementById('f-keyid').value.trim()   || null,
    price_type:      document.getElementById('f-price').value          || 'free',
    environment:     document.getElementById('f-env').value            || null,
    api_url:         document.getElementById('f-apiurl').value.trim()  || null,
    callback_url:    document.getElementById('f-cburl').value.trim()   || null,
    version:         document.getElementById('f-version').value.trim() || null,
    rate_limit:      document.getElementById('f-ratelimit').value.trim()||null,
    expires_at:      document.getElementById('f-expires').value        || null,
    scopes:          scopes.length ? scopes : [],
    api_description: document.getElementById('f-apidesc').value.trim() || null,
    description:     document.getElementById('f-desc').value.trim()    || null,
    details:         document.getElementById('f-details').value.trim() || null,
    custom_icon:     document.getElementById('f-icon').value.trim()    || null,
    categories:      cats,
  };
}

function fillForm(entry) {
  document.getElementById('f-provider').value   = entry.provider || '';
  document.getElementById('f-account').value    = entry.account_name || Settings.get('defaultAccount') || '';
  document.getElementById('f-key').value        = entry.api_key || '';
  document.getElementById('f-secret').value     = entry.api_secret || '';
  document.getElementById('f-keyid').value      = entry.key_id || '';
  document.getElementById('f-price').value      = entry.price_type || 'free';
  document.getElementById('f-env').value        = entry.environment || '';
  document.getElementById('f-apiurl').value     = entry.api_url || '';
  document.getElementById('f-cburl').value      = entry.callback_url || '';
  document.getElementById('f-version').value    = entry.version || '';
  document.getElementById('f-ratelimit').value  = entry.rate_limit || '';
  document.getElementById('f-expires').value    = entry.expires_at || '';
  document.getElementById('f-scopes').value     = (entry.scopes||[]).join(', ');
  document.getElementById('f-apidesc').value    = entry.api_description || '';
  document.getElementById('f-desc').value       = entry.description || '';
  document.getElementById('f-details').value    = entry.details || '';
  document.getElementById('f-icon').value       = entry.custom_icon || '';
  const prev = document.getElementById('f-icon-preview');
  prev.innerHTML = entry.custom_icon ? iconHTML('', entry.custom_icon) : '';
}

function openModal(title, idx) {
  document.getElementById('modal-title').textContent = title;
  document.getElementById('edit-index').value = idx;
  document.getElementById('modal-duplicate').style.display = idx>=0 ? 'block' : 'none';
  applySchemaTooltips();
  document.getElementById('modal-overlay').classList.add('open');
  document.getElementById('f-provider').focus();
}

function openAdd(e) {
  if (e) e.stopPropagation();
  fillForm({});
  buildCatChips([]);
  openModal('Add API Key', -1);
}

function openEdit(e, idx) {
  if (e) e.stopPropagation();
  fillForm(vault.api_keys[idx]);
  buildCatChips(vault.api_keys[idx].categories||[]);
  openModal('Edit API Key', idx);
}

function closeModal() { document.getElementById('modal-overlay').classList.remove('open'); }

function saveModal() {
  const entry = formToEntry();
  if (!entry.provider || !entry.api_key) { showToast('Provider and API Key are required', 'err'); return; }
  const idx = parseInt(document.getElementById('edit-index').value);
  if (idx >= 0) { vault.api_keys[idx] = entry; showToast('Updated ✓', 'ok'); }
  else          { vault.api_keys.push(entry);   showToast('Added ✓', 'ok'); }
  store.save(vault);
  closeModal();
  document.getElementById('load-banner').style.display = 'none';
  render();
}

document.getElementById('add-btn').addEventListener('click', openAdd);
document.getElementById('modal-close').addEventListener('click', closeModal);
document.getElementById('modal-cancel').addEventListener('click', closeModal);
document.getElementById('modal-save').addEventListener('click', saveModal);
document.getElementById('modal-duplicate').addEventListener('click', () => {
  const idx = parseInt(document.getElementById('edit-index').value);
  if (idx>=0) duplicateKey(new Event('click'), idx);
  closeModal();
});
document.getElementById('modal-overlay').addEventListener('click', e => { if(e.target===e.currentTarget) closeModal(); });
document.getElementById('key-modal').addEventListener('keydown', e => {
  if (e.key==='Enter' && !e.target.matches('select,input[type=date]')) { e.preventDefault(); saveModal(); }
  if (e.key==='Escape') closeModal();
});

// Icon field browse button
document.getElementById('f-icon-pick').addEventListener('click', () => {
  openIconPicker(document.getElementById('f-icon'), document.getElementById('f-icon-preview'));
});
document.getElementById('f-icon').addEventListener('input', e => {
  const prev = document.getElementById('f-icon-preview');
  prev.innerHTML = e.target.value ? iconHTML('', e.target.value) : '';
});

/* ── SETTINGS PANEL ─────────────────────────────────────────────────────────── */
const THEMES = [
  { id:'dark',       label:'Dark',       bg:'#0e0e0e', accent:'#7364c9' },
  { id:'midnight',   label:'Midnight',   bg:'#09090f', accent:'#5b8dd9' },
  { id:'dracula',    label:'Dracula',    bg:'#282a36', accent:'#bd93f9' },
  { id:'nord',       label:'Nord',       bg:'#2e3440', accent:'#88c0d0' },
  { id:'catppuccin', label:'Catppuccin', bg:'#1e1e2e', accent:'#cba6f7' },
  { id:'light',      label:'Light',      bg:'#f0f0f6', accent:'#6355b5' },
];

function buildThemeSwatches() {
  const wrap = document.getElementById('theme-swatches');
  wrap.innerHTML = '';
  THEMES.forEach(t => {
    const sw = document.createElement('div');
    sw.className = 'theme-swatch' + (Settings.get('theme')===t.id?' active':'');
    sw.title = t.label;
    sw.style.cssText = `background:${t.bg};box-shadow:inset 0 0 0 4px ${t.accent}55`;
    sw.addEventListener('click', () => {
      Settings.set('theme', t.id);
      Settings._apply();
      buildThemeSwatches();
    });
    wrap.appendChild(sw);
  });
}

function openSettings() {
  const s = Settings.getAll();
  buildThemeSwatches();
  document.getElementById('s-accent').value       = s.accentColor;
  document.getElementById('s-accent-val').textContent = s.accentColor;
  document.getElementById('s-autolock').value     = s.autoLockMinutes;
  document.getElementById('s-mask').checked       = s.maskKeysByDefault;
  document.getElementById('s-expiry-warn').checked= s.showExpiryWarning;
  document.getElementById('s-expiry-days').value  = s.expiryWarningDays;
  document.getElementById('s-default-account').value = s.defaultAccount||'';
  document.getElementById('s-export-format').value= s.defaultExportFormat;
  // Seg controls
  ['s-card-size','s-grid-cols'].forEach(id => {
    const key = id==='s-card-size' ? 'cardSize' : 'gridColumns';
    document.querySelectorAll(`#${id} button`).forEach(btn => {
      btn.classList.toggle('active', btn.dataset.val===String(s[key]));
    });
  });
  document.getElementById('settings-overlay').classList.add('open');
}

function saveSettings() {
  Settings.setAll({
    accentColor:        document.getElementById('s-accent').value,
    autoLockMinutes:    parseInt(document.getElementById('s-autolock').value)||20,
    maskKeysByDefault:  document.getElementById('s-mask').checked,
    showExpiryWarning:  document.getElementById('s-expiry-warn').checked,
    expiryWarningDays:  parseInt(document.getElementById('s-expiry-days').value)||30,
    defaultAccount:     document.getElementById('s-default-account').value.trim(),
    defaultExportFormat:document.getElementById('s-export-format').value,
  });
  Settings._apply();
  render();
}

function closeSettings() { document.getElementById('settings-overlay').classList.remove('open'); }

document.getElementById('settings-btn').addEventListener('click', openSettings);
document.getElementById('settings-close').addEventListener('click', () => { saveSettings(); closeSettings(); });
document.getElementById('settings-overlay').addEventListener('click', e => { if(e.target===e.currentTarget){ saveSettings(); closeSettings(); } });
document.getElementById('settings-export-btn').addEventListener('click', () => {
  const blob = new Blob([JSON.stringify(Settings.getAll(),null,2)],{type:'application/json'});
  const a = Object.assign(document.createElement('a'),{href:URL.createObjectURL(blob),download:'settings.json'});
  a.click(); URL.revokeObjectURL(a.href);
});

// Seg control wiring
document.querySelectorAll('.seg-control').forEach(ctrl => {
  ctrl.addEventListener('click', e => {
    const btn = e.target.closest('button[data-val]');
    if (!btn) return;
    ctrl.querySelectorAll('button').forEach(b=>b.classList.remove('active'));
    btn.classList.add('active');
    const key = ctrl.id==='s-card-size' ? 'cardSize' : 'gridColumns';
    Settings.set(key, btn.dataset.val);
    Settings._apply();
    render();
  });
});

// Accent color live update
document.getElementById('s-accent').addEventListener('input', e => {
  document.getElementById('s-accent-val').textContent = e.target.value;
  Settings.set('accentColor', e.target.value);
  Settings._apply();
});
document.getElementById('s-accent-reset').addEventListener('click', () => {
  const def = '#7364c9';
  document.getElementById('s-accent').value = def;
  document.getElementById('s-accent-val').textContent = def;
  Settings.set('accentColor', def);
  Settings._apply();
});

/* ── FILE I/O ───────────────────────────────────────────────────────────────── */
function handleFileSelect(input) {
  const file = input?.files?.[0];
  if (!file) return;
  const reader = new FileReader();
  reader.onload = ev => {
    try {
      const data = JSON.parse(ev.target.result);
      if (!Array.isArray(data.api_keys)) throw new Error('Missing api_keys array');
      vault = { api_keys: data.api_keys, user_categories: data.user_categories||[] };
      store.save(vault);
      expanded.clear();
      render();
      document.getElementById('load-banner').style.display='none';
      showToast(`Loaded ${vault.api_keys.length} keys ✓`, 'ok');
    } catch(err) { showToast(`Invalid: ${err.message}`, 'err', 4000); }
  };
  reader.readAsText(file);
}

document.getElementById('file-input').addEventListener('change', function() { handleFileSelect(this); this.value=''; });

function exportAs(fmt) {
  const keys = vault.api_keys;
  let content, ext;
  if (fmt==='yaml')   { content = Exporter.yamlStructured(keys); ext = 'yaml'; }
  else if (fmt==='json') { content = JSON.stringify(vault,null,2); ext = 'json'; }
  else                { content = Exporter.dotenv(keys); ext = 'env'; }
  const blob = new Blob([content],{type:'text/plain'});
  const a = Object.assign(document.createElement('a'),{href:URL.createObjectURL(blob),download:`api-vault.${ext}`});
  a.click(); URL.revokeObjectURL(a.href);
  showToast(`Exported as .${ext} ✓`, 'ok');
}

/* ── DROPDOWN HELPER ────────────────────────────────────────────────────────── */
function showDropdown(anchorEl, items) {
  const dd = document.getElementById('dropdown');
  const r  = anchorEl.getBoundingClientRect();
  dd.innerHTML = items.map(item =>
    item === '---' ? `<div class="dropdown-sep"></div>` :
    `<div class="dropdown-item${item.active?' active':''}" onclick="(${item.fn})()">${item.label}</div>`
  ).join('');
  dd.style.cssText = `display:block;top:${r.bottom+6}px;right:${document.documentElement.clientWidth-r.right}px`;
  const close = e => { if(!dd.contains(e.target)&&e.target!==anchorEl){dd.style.display='none';document.removeEventListener('click',close);} };
  setTimeout(()=>document.addEventListener('click',close),50);
}

document.getElementById('export-arrow').addEventListener('click', e => {
  showDropdown(e.currentTarget,[
    { label:'Export as .env',  fn:`()=>exportAs('dotenv')` },
    { label:'Export as YAML',  fn:`()=>exportAs('yaml')` },
    { label:'Export as JSON',  fn:`()=>exportAs('json')` },
  ]);
});
document.getElementById('export-btn').addEventListener('click', () => exportAs(Settings.get('defaultExportFormat')||'dotenv'));

document.getElementById('copy-all-arrow').addEventListener('click', e => {
  showDropdown(e.currentTarget,[
    { label:'Copy as .env',  fn:`()=>copyAll('dotenv')` },
    { label:'Copy as YAML',  fn:`()=>copyAll('yaml')` },
    { label:'Copy as JSON',  fn:`()=>copyAll('json')` },
  ]);
});
document.getElementById('copy-all-btn').addEventListener('click', () => copyAll(Settings.get('defaultExportFormat')||'dotenv'));

/* ── LOCK ───────────────────────────────────────────────────────────────────── */
function lockVault() {
  // Clear Rust-side key first (Tauri only)
  if (store instanceof TauriVaultStore) {
    store.lock().catch(() => {});
  }

  vault = { api_keys: [], user_categories: [] };
  sessionStorage.removeItem('api-vault');
  expanded.clear();
  revealed = {};
  render();

  if (store instanceof TauriVaultStore) {
    // Re-show the password prompt instead of the load banner
    showUnlockModal(false);
  } else {
    document.getElementById('load-banner').style.display = 'flex';
    showToast('Vault locked', 'err', 3500);
  }
}
function resetLock() {
  clearTimeout(lockTimer);
  const mins = Settings.get('autoLockMinutes') || 20;
  lockTimer = setTimeout(lockVault, mins*60000);
  document.getElementById('lock-status').textContent = `Auto-lock: ${mins}min`;
}
['click','keydown','mousemove'].forEach(ev =>
  document.addEventListener(ev, () => { if(vault.api_keys.length) resetLock(); }, { passive:true })
);
document.getElementById('lock-btn').addEventListener('click', () => { if(confirm('Lock vault? All key data will be cleared.')) lockVault(); });

/* ── SEARCH ─────────────────────────────────────────────────────────────────── */
document.getElementById('search').addEventListener('input', e => { searchQ = e.target.value; renderGrid(); updateCopyAllBtn(); });
document.getElementById('sort-select').addEventListener('change', renderGrid);
document.getElementById('expand-all-btn').addEventListener('click', function() {
  allExpanded = !allExpanded;
  this.textContent = allExpanded ? 'Collapse All' : 'Expand All';
  if (allExpanded) vault.api_keys.forEach((_,i)=>expanded.add(i)); else expanded.clear();
  renderGrid();
});
document.getElementById('sidebar-toggle').addEventListener('click', () => {
  const sb = document.getElementById('sidebar');
  sb.classList.toggle('collapsed');
  if (window.innerWidth <= 700) sb.classList.toggle('mobile-open');
});

/* ── SHORTCUTS ──────────────────────────────────────────────────────────────── */
document.getElementById('shortcuts-btn').addEventListener('click', () => {
  document.getElementById('shortcuts-overlay').style.display='flex';
});
document.getElementById('shortcuts-close').addEventListener('click', () => {
  document.getElementById('shortcuts-overlay').style.display='none';
});
document.getElementById('shortcuts-overlay').addEventListener('click', e => {
  if (e.target===e.currentTarget) document.getElementById('shortcuts-overlay').style.display='none';
});
document.addEventListener('keydown', e => {
  const tag = document.activeElement.tagName;
  const inInput = ['INPUT','SELECT','TEXTAREA'].includes(tag);
  if ((e.ctrlKey||e.metaKey) && e.key==='k') { e.preventDefault(); document.getElementById('search').focus(); document.getElementById('search').select(); return; }
  if ((e.ctrlKey||e.metaKey) && e.key==='n') { e.preventDefault(); openAdd(); return; }
  if (!inInput && e.key==='s') openSettings();
  if (!inInput && e.key==='b') document.getElementById('sidebar-toggle').click();
  if (!inInput && e.key==='?') document.getElementById('shortcuts-overlay').style.display='flex';
  if (e.key==='Escape') {
    document.getElementById('shortcuts-overlay').style.display='none';
    closeSettings();
    closeModal();
    if (searchQ) { searchQ=''; document.getElementById('search').value=''; renderGrid(); }
  }
});

/* ── CARD GRID DELEGATION ────────────────────────────────────────────────────
 * Replaces all inline onclick= handlers in buildCard.
 * Works in Tauri WebView where WebKitGTK blocks inline handlers even with
 * unsafe-inline CSP. One listener handles the entire grid.
 */
document.getElementById('card-grid').addEventListener('click', e => {
  const el = e.target.closest('[data-action]');
  if (!el) return;

  const action = el.dataset.action;
  const idx    = el.dataset.idx   !== undefined ? parseInt(el.dataset.idx)  : -1;
  const value  = el.dataset.value ?? '';
  const field  = el.dataset.field ?? '';

  // card-head has data-action="copy-env" but should only fire when clicking
  // the head background — not when a child element handles the click itself.
  if (action === 'copy-env' && el.classList.contains('card-head')) {
    if (e.target !== el && e.target.closest('[data-action]') !== el) return;
  }

  e.stopPropagation();

  switch (action) {
    case 'toggle':      toggleCard(e, idx);                  break;
    case 'reveal':      toggleReveal(e, field, idx, value);  break;
    case 'copy-field':  copyField(e, value, el);             break;
    case 'copy-env':    doCopyEnv(e, idx);                   break;
    case 'duplicate':   duplicateKey(e, idx);                break;
    case 'edit':        openEdit(e, idx);                    break;
    case 'delete':      deleteKey(e, idx);                   break;
    case 'icon':        onIconWrapClick(e, idx);             break;
    case 'toggle-desc': toggleDesc(el);                      break;
  }
});

/* ── VAULT SWITCHER STUB ────────────────────────────────────────────────────── */
document.getElementById('vault-switcher').addEventListener('click', () => {
  showToast('Multi-vault support coming in v2', '', 3000);
});

/* ── UTILS ──────────────────────────────────────────────────────────────────── */
function maskKey(val) {
  if (!val) return '—';
  if (val.length <= 8) return '•'.repeat(val.length);
  return val.slice(0,4)+'••••••••••••'+val.slice(-4);
}
function esc(s) {
  if (s==null) return '';
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
function escAttr(s) {
  if (s==null) return '';
  return String(s).replace(/\\/g,'\\\\').replace(/'/g,"\\'").replace(/"/g,'&quot;');
}

let _toastTimer;
function showToast(msg, type='', duration=2500) {
  const el = document.getElementById('toast');
  el.textContent = msg;
  el.className = 'show'+(type?' '+type:'');
  clearTimeout(_toastTimer);
  _toastTimer = setTimeout(()=>{ el.className=''; }, duration);
}

/* ── BOOT ───────────────────────────────────────────────────────────────────── */

/**
 * Shared finalisation step: load schema, load vault data, render.
 * Called from init() (non-Tauri) or from showUnlockModal() after a
 * successful unlock (Tauri).
 */
async function finishInit() {
  try {
    const r = await fetch('./schema.json');
    if (r.ok) schema = await r.json();
  } catch {}

  try {
    const data = await store.load();
    if (data) {
      vault = data;
      document.getElementById('load-banner').style.display = 'none';
      showToast(`Loaded ${vault.api_keys.length} keys`, 'ok', 1800);
    } else {
      document.getElementById('load-banner').style.display = 'flex';
    }
  } catch {
    document.getElementById('load-banner').style.display = 'flex';
  }

  render();
  resetLock();
}

/**
 * Show the master-password overlay.
 * @param {boolean} isFirstRun  true = create mode, false = unlock mode
 *
 * Resolves when the vault has been successfully unlocked, then calls finishInit().
 */
async function showUnlockModal(isFirstRun) {
  const overlay      = document.getElementById('unlock-overlay');
  const titleEl      = document.getElementById('unlock-title');
  const subtitleEl   = document.getElementById('unlock-subtitle');
  const confirmGroup = document.getElementById('unlock-confirm-group');
  const submitBtn    = document.getElementById('unlock-submit-btn');
  const resetBtn     = document.getElementById('unlock-reset-btn');
  const pwField      = document.getElementById('unlock-password');
  const confirmField = document.getElementById('unlock-confirm');
  const errEl        = document.getElementById('unlock-error');

  function configure(firstRun) {
    isFirstRun = firstRun;
    if (firstRun) {
      titleEl.textContent    = 'Create Master Password';
      subtitleEl.textContent = 'This password encrypts your vault with AES-256 + Argon2id. There is no recovery — keep it safe.';
      confirmGroup.style.display = 'block';
      submitBtn.textContent  = 'Create Vault';
      resetBtn.style.display = 'none';
    } else {
      titleEl.textContent    = 'Unlock Vault';
      subtitleEl.textContent = 'Enter your master password to decrypt the vault.';
      confirmGroup.style.display = 'none';
      submitBtn.textContent  = 'Unlock';
      resetBtn.style.display = '';
    }
  }

  configure(isFirstRun);
  overlay.classList.add('open');
  pwField.value    = '';
  confirmField.value = '';
  errEl.style.display = 'none';
  setTimeout(() => pwField.focus(), 80);

  function showErr(msg) {
    errEl.textContent    = msg;
    errEl.style.display  = 'block';
    pwField.focus();
  }

  async function doUnlock() {
    errEl.style.display = 'none';
    const pw = pwField.value;

    if (!pw)                                      { showErr('Password cannot be empty.'); return; }
    if (isFirstRun && pw.length < 8)              { showErr('Use at least 8 characters.'); return; }
    if (isFirstRun && pw !== confirmField.value)  { showErr('Passwords do not match.'); return; }

    submitBtn.disabled    = true;
    submitBtn.textContent = isFirstRun ? 'Creating…' : 'Unlocking…';

    try {
      await store.unlock(pw);
      overlay.classList.remove('open');
      await finishInit();
    } catch (err) {
      submitBtn.disabled    = false;
      submitBtn.textContent = isFirstRun ? 'Create Vault' : 'Unlock';
      showErr(err?.message || String(err) || 'Wrong password');
    }
  }

  submitBtn.onclick         = doUnlock;
  pwField.onkeydown         = e => { if (e.key === 'Enter') doUnlock(); };
  confirmField.onkeydown    = e => { if (e.key === 'Enter') doUnlock(); };

  resetBtn.onclick = async () => {
    if (!confirm('⚠️ This permanently deletes all vault data and cannot be undone.\n\nContinue?')) return;
    try {
      await store.reset();
    } catch {}
    pwField.value = '';
    confirmField.value = '';
    configure(true); // switch to create mode
    showToast('Vault reset. Set a new master password.', '', 4000);
  };
}

async function init() {
  await Settings.init();
  initIconPicker();

  const inTauri = '__TAURI__' in window;
  store = inTauri ? new TauriVaultStore() : new LocalVaultStore();

  if (inTauri) {
    store.vaultFilePath().then(p => {
      const el = document.getElementById('lock-status');
      if (el && p) el.title = `Vault file: ${p}`;
    });
    document.getElementById('vault-name').textContent = 'Local Vault';

    // Gate everything behind the password prompt
    const exists = await store.exists();
    await showUnlockModal(!exists); // !exists → first-run create mode
    // finishInit() is called inside showUnlockModal after success
    return;
  }

  if (location.protocol === 'file:') {
    showToast('Serving over file:// — use a local server or the desktop app', '', 5000);
  }

  await finishInit();
}

init();