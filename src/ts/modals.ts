/**
 * @file Modals, dropdowns, card interactions, and form helpers.
 */

import type { VaultEntry, SecretType } from './types';
import { st, Settings, triggerRender, Exporter, dotenvKey } from './state';
import { esc, escAttr, maskKey, showToast, showConfirm, clipboardWrite, eyeSVG, copySVG, dupSVG, editSVG, delSVG } from './utils';
import { iconHTML, openIconPicker, iconPicker } from './icons';

// ── Schema tooltips & category chips ──────────────────────────────────────

export function applySchemaTooltips() {
  if (!st.schema) return;
  const props = st.schema.properties?.api_keys?.items?.properties || {};
  document.querySelectorAll<HTMLElement>('.form-label[data-field]').forEach(el => {
    const d = props[el.dataset.field!]?.description;
    if (d) el.title = d;
  });
}

export function buildCatChips(selected: string[] = []) {
  const wrap = document.getElementById('f-categories')!;
  wrap.innerHTML = '';
  if (!st.vault.user_categories.length) {
    wrap.innerHTML = `<span style="font-size:10px;color:var(--text3)">No categories — add in sidebar</span>`;
    return;
  }
  st.vault.user_categories.forEach(cat => {
    const chip = document.createElement('button');
    chip.type = 'button';
    chip.className = `cat-chip${selected.includes(cat) ? ' selected' : ''}`;
    chip.textContent = cat;
    chip.addEventListener('click', () => chip.classList.toggle('selected'));
    wrap.appendChild(chip);
  });
}

// ── Type config ───────────────────────────────────────────────────────────

export type TypeConfig = {
  providerLabel: string;
  providerPlaceholder: string;
  showAccount: boolean;
  keyLabel: string;
  keyPlaceholder: string;
};

export const TYPE_CONFIG: Record<SecretType, TypeConfig> = {
  api_key:           { providerLabel: 'Provider',         providerPlaceholder: 'e.g. GitHub',          showAccount: true,  keyLabel: 'API Key',           keyPlaceholder: 'Your API key or access token' },
  password:          { providerLabel: 'Service / App',    providerPlaceholder: 'e.g. Gmail',            showAccount: false, keyLabel: 'Password',          keyPlaceholder: 'Your password' },
  env_var:           { providerLabel: 'Variable Name',    providerPlaceholder: 'e.g. DATABASE_URL',     showAccount: false, keyLabel: 'Value',             keyPlaceholder: 'Variable value' },
  connection_string: { providerLabel: 'Service',          providerPlaceholder: 'e.g. PostgreSQL',       showAccount: false, keyLabel: 'Connection String', keyPlaceholder: 'postgresql://user:pass@host/db' },
  ssh_key:           { providerLabel: 'Host / Service',   providerPlaceholder: 'e.g. github.com',       showAccount: true,  keyLabel: 'SSH Key',           keyPlaceholder: '-----BEGIN OPENSSH PRIVATE KEY-----' },
  certificate:       { providerLabel: 'Provider / Issuer',providerPlaceholder: "e.g. Let's Encrypt",   showAccount: false, keyLabel: 'API Key',           keyPlaceholder: '' },
  file_blob:         { providerLabel: 'Name',             providerPlaceholder: 'e.g. config.yaml',      showAccount: false, keyLabel: 'API Key',           keyPlaceholder: '' },
};

// ── Dynamic form fields ───────────────────────────────────────────────────

export function dynamicSecretFields() {
  const type = (document.getElementById('f-secret-type') as HTMLSelectElement).value as SecretType;
  const cfg = TYPE_CONFIG[type] || TYPE_CONFIG.api_key;

  const keyGroup          = document.getElementById('f-key-group');
  const keyLabelEl        = document.getElementById('f-key-label');
  const secretGroup       = document.getElementById('f-secret-group');
  const usernameRow       = document.getElementById('f-username-row');
  const certGroup         = document.getElementById('f-cert-group');
  const certKeyGroup      = document.getElementById('f-cert-key-group');
  const blobGroup         = document.getElementById('f-blob-group');
  const accountGroup      = document.getElementById('f-account-group');
  const providerLabel     = document.getElementById('f-provider-label');
  const providerInput     = document.getElementById('f-provider') as HTMLInputElement | null;
  const envvarSubtypeGroup = document.getElementById('f-envvar-subtype-group');

  const showKey    = type !== 'certificate' && type !== 'file_blob';
  const showSecret = type === 'api_key';
  const showUser   = type === 'password' || type === 'ssh_key';

  if (keyGroup)           keyGroup.style.display           = showKey                    ? 'flex' : 'none';
  if (secretGroup)        secretGroup.style.display        = showSecret                 ? 'flex' : 'none';
  if (usernameRow)        usernameRow.style.display        = showUser                   ? 'grid' : 'none';
  if (certGroup)          certGroup.style.display          = type === 'certificate'     ? 'flex' : 'none';
  if (certKeyGroup)       certKeyGroup.style.display       = type === 'certificate'     ? 'flex' : 'none';
  if (blobGroup)          blobGroup.style.display          = type === 'file_blob'       ? 'flex' : 'none';
  if (accountGroup)       accountGroup.style.display       = cfg.showAccount            ? ''     : 'none';
  if (envvarSubtypeGroup) envvarSubtypeGroup.style.display = type === 'env_var'         ? 'flex' : 'none';

  if (providerLabel) providerLabel.innerHTML = `${cfg.providerLabel} <span class="req">*</span>`;
  if (providerInput) providerInput.placeholder = cfg.providerPlaceholder;
  if (keyLabelEl && showKey) keyLabelEl.innerHTML = `${cfg.keyLabel} <span class="req">*</span>`;
  const keyInput = document.getElementById('f-key') as HTMLInputElement | null;
  if (keyInput && showKey) keyInput.placeholder = cfg.keyPlaceholder;
}

// ── Form to entry & fill form ─────────────────────────────────────────────

export function formToEntry(): VaultEntry {
  const getVal = (id: string, fallback: string = '') => {
    const el = document.getElementById(id) as HTMLInputElement | HTMLSelectElement | null;
    return el?.value?.trim?.() ?? fallback;
  };

  const scopes = getVal('f-scopes').split(',').map(s => s.trim()).filter(Boolean);
  const cats = [...document.querySelectorAll<HTMLElement>('#f-categories .cat-chip.selected')].map(c => c.textContent!);
  const secretType = (getVal('f-secret-type') || 'api_key') as SecretType;

  const selectedProjectIds = [...document.querySelectorAll<HTMLElement>('#f-project .project-pick-item.selected')]
    .map(el => el.dataset.value!);

  return {
    provider: getVal('f-provider'),
    account_name: getVal('f-account') || undefined,
    username: getVal('f-username') || undefined,
    email: getVal('f-email') || undefined,
    api_key: getVal('f-key'),
    api_secret: getVal('f-secret') || undefined,
    key_id: getVal('f-keyid') || undefined,
    price_type: getVal('f-price', 'free') as VaultEntry['price_type'],
    environment: getVal('f-env') as VaultEntry['environment'] || undefined,
    projectIds: selectedProjectIds.length ? selectedProjectIds : ['Universal'],
    api_url: getVal('f-apiurl') || undefined,
    callback_url: getVal('f-cburl') || undefined,
    version: getVal('f-version') || undefined,
    rate_limit: getVal('f-ratelimit') || undefined,
    expires_at: getVal('f-expires') || undefined,
    scopes,
    api_description: getVal('f-apidesc') || undefined,
    description: getVal('f-desc') || undefined,
    details: getVal('f-details') || undefined,
    custom_icon: getVal('f-icon') || undefined,
    categories: cats,
    secretType,
    certificate_data: secretType === 'certificate' ? getVal('f-cert') : undefined,
    cert_key_data: secretType === 'certificate' ? (getVal('f-cert-key') || undefined) : undefined,
    blob_ref: secretType === 'file_blob' ? getVal('f-blob') : undefined,
    env_var_subtype: secretType === 'env_var' ? (getVal('f-envvar-subtype') as VaultEntry['env_var_subtype'] || undefined) : undefined,
  };
}

export function fillForm(entry: Partial<VaultEntry>) {
  (document.getElementById('f-provider') as HTMLInputElement).value = entry.provider || '';
  (document.getElementById('f-account') as HTMLInputElement).value = entry.account_name || Settings.get('defaultAccount') || '';
  (document.getElementById('f-username') as HTMLInputElement).value = entry.username || '';
  (document.getElementById('f-email') as HTMLInputElement).value = entry.email || '';
  (document.getElementById('f-key') as HTMLInputElement).value = entry.api_key || '';
  (document.getElementById('f-secret') as HTMLInputElement).value = entry.api_secret || '';
  (document.getElementById('f-keyid') as HTMLInputElement).value = entry.key_id || '';
  const fPrice = document.getElementById('f-price') as HTMLSelectElement;
  fPrice.value = entry.price_type || 'free';
  st.formCustomSelects.get('f-price')?.setValue(entry.price_type || 'free');
  const fEnv = document.getElementById('f-env') as HTMLSelectElement;
  fEnv.value = entry.environment || '';
  st.formCustomSelects.get('f-env')?.setValue(entry.environment || '');
  if (entry.projectIds) {
    document.querySelectorAll<HTMLElement>('#f-project .project-pick-item').forEach(el => {
      el.classList.toggle('selected', entry.projectIds!.includes(el.dataset.value!));
    });
  }
  (document.getElementById('f-apiurl') as HTMLInputElement).value = entry.api_url || '';
  (document.getElementById('f-cburl') as HTMLInputElement).value = entry.callback_url || '';
  (document.getElementById('f-version') as HTMLInputElement).value = entry.version || '';
  (document.getElementById('f-ratelimit') as HTMLInputElement).value = entry.rate_limit || '';
  (document.getElementById('f-expires') as HTMLInputElement).value = entry.expires_at || '';
  (document.getElementById('f-scopes') as HTMLInputElement).value = (entry.scopes || []).join(', ');
  (document.getElementById('f-apidesc') as HTMLInputElement).value = entry.api_description || '';
  (document.getElementById('f-desc') as HTMLInputElement).value = entry.description || '';
  (document.getElementById('f-details') as HTMLInputElement).value = entry.details || '';
  (document.getElementById('f-icon') as HTMLInputElement).value = entry.custom_icon || '';
  (document.getElementById('f-icon-preview')!).innerHTML = entry.custom_icon ? iconHTML('', entry.custom_icon) : '';
  const stVal = entry.secretType || 'api_key';
  (document.getElementById('f-secret-type') as HTMLSelectElement).value = stVal;
  st.formCustomSelects.get('f-secret-type')?.setValue(stVal);
  if (entry.secretType === 'certificate') {
    (document.getElementById('f-cert') as HTMLInputElement).value = entry.certificate_data || '';
    (document.getElementById('f-cert-key') as HTMLInputElement).value = entry.cert_key_data || '';
  }
  if (entry.secretType === 'file_blob') (document.getElementById('f-blob') as HTMLInputElement).value = entry.blob_ref || '';
  if (entry.secretType === 'env_var') {
    const envSubtype = document.getElementById('f-envvar-subtype') as HTMLSelectElement | null;
    if (envSubtype) envSubtype.value = entry.env_var_subtype || 'string';
  }
  dynamicSecretFields();
}

export function populateProjectSelect() {
  const container = document.getElementById('f-project')!;
  const cats = st.vault.projects.filter(p => p.id !== 'Universal');
  container.innerHTML = cats.map(p =>
    `<div class="project-pick-item" data-value="${escAttr(p.id)}">${esc(p.name)}</div>`
  ).join('');
  container.querySelectorAll<HTMLElement>('.project-pick-item').forEach(item => {
    item.addEventListener('click', () => item.classList.toggle('selected'));
  });
}

// ── Modal open/close/save ─────────────────────────────────────────────────

export function openModal(title: string, idx: number) {
  document.getElementById('modal-title')!.textContent = title;
  (document.getElementById('edit-index') as HTMLInputElement).value = String(idx);
  document.getElementById('modal-duplicate')!.style.display = idx >= 0 ? 'block' : 'none';
  applySchemaTooltips();
  document.getElementById('modal-overlay')!.classList.add('open');
  (document.getElementById('f-provider') as HTMLInputElement).focus();
  populateProjectSelect();
}

const DRAFT_KEY = 'apivault-form-draft';

export function openAdd(e?: Event) {
  if (e) e.stopPropagation();
  // Restore draft if available (item 11)
  const draft = sessionStorage.getItem(DRAFT_KEY);
  try {
    const parsed = draft ? JSON.parse(draft) : null;
    if (parsed) {
      fillForm(parsed);
      buildCatChips(parsed.categories || []);
    } else {
      fillForm({});
      buildCatChips([]);
    }
  } catch {
    fillForm({});
    buildCatChips([]);
  }
  openModal('Add Secret', -1);
  // Auto-save draft on any input change
  const overlay = document.getElementById('modal-overlay')!;
  const saveDraft = () => {
    try { sessionStorage.setItem(DRAFT_KEY, JSON.stringify(formToEntry())); } catch {}
  };
  overlay.querySelectorAll('input, textarea, select').forEach(el => {
    el.addEventListener('input', saveDraft);
    el.addEventListener('change', saveDraft);
  });
}

function clearDraft() { sessionStorage.removeItem(DRAFT_KEY); }

export function openEdit(e: Event, idx: number) {
  e.stopPropagation();
  fillForm(st.vault.api_keys[idx]);
  buildCatChips(st.vault.api_keys[idx].categories || []);
  openModal('Edit Secret', idx);
}

export function closeModal() {
  document.getElementById('modal-overlay')!.classList.remove('open');
  clearDraft();
}

export function saveModal() {
  try {
    const entry = formToEntry();
    const t = entry.secretType || 'api_key';
    if (!entry.provider) { showToast(`${TYPE_CONFIG[t]?.providerLabel || 'Provider'} is required`, 'err'); return; }
    if (t === 'certificate' && !entry.certificate_data) { showToast('Certificate data is required', 'err'); return; }
    if (t === 'file_blob'   && !entry.blob_ref)         { showToast('File path/reference is required', 'err'); return; }
    if (t !== 'certificate' && t !== 'file_blob' && !entry.api_key) {
      showToast(`${TYPE_CONFIG[t]?.keyLabel || 'Value'} is required`, 'err'); return;
    }
    const idx = parseInt((document.getElementById('edit-index') as HTMLInputElement).value);
    if (idx >= 0) {
      // Preserve fields not represented in the form
      const old = st.vault.api_keys[idx];
      st.vault.api_keys[idx] = {
        ...entry,
        last_rotated_at: old.last_rotated_at,
        version_history: old.version_history,
      };
    } else {
      st.vault.api_keys.push(entry);
    }
    st.store.save(st.vault);
    closeModal();
    document.getElementById('load-banner')!.style.display = 'none';
    triggerRender();
  } catch (err: any) {
    showToast('Save failed: ' + (err?.message || err), 'err', 4000);
  }
}

/** Sets last_rotated_at to today on the given entry and saves. */
export function markAsRotated(idx: number) {
  const entry = st.vault.api_keys[idx];
  if (!entry) return;
  const today = new Date().toISOString().slice(0, 10); // YYYY-MM-DD
  st.vault.api_keys[idx] = { ...entry, last_rotated_at: today };
  st.store.save(st.vault);
  triggerRender();
  showToast(`Marked as rotated on ${today}`, 'ok', 2500);
}

export function duplicateKey(e: Event, idx: number) {
  e.stopPropagation();
  const copy = { ...st.vault.api_keys[idx], key_id: (st.vault.api_keys[idx].key_id || 'copy') + '_copy' };
  st.vault.api_keys.splice(idx + 1, 0, copy);
  st.store.save(st.vault);
  triggerRender();
  showToast('Duplicated ✓', 'ok');
}

export function deleteKey(e: Event, idx: number) {
  e.stopPropagation();
  const removed = st.vault.api_keys.splice(idx, 1)[0];
  st.store.save(st.vault);
  st.expanded.delete(idx);
  triggerRender();
  pushUndo(`Deleted "${removed.provider}"`, () => {
    st.vault.api_keys.splice(idx, 0, removed);
    st.store.save(st.vault);
    triggerRender();
  });
}

export function pushUndo(msg: string, fn: () => void) {
  const bar = document.getElementById('undo-bar')!;
  document.getElementById('undo-msg')!.textContent = msg;
  bar.classList.add('visible');
  st.undoStack.push({ fn, t: setTimeout(() => { bar.classList.remove('visible'); st.undoStack.pop(); }, 5000) });
}

// ── Form helpers ──────────────────────────────────────────────────────────

export function injectIntoForm(value: string) {
  const fKey = document.getElementById('f-key') as HTMLInputElement | null;
  if (fKey) { fKey.value = value; fKey.focus(); showToast('Injected into form', 'ok'); }
  else showToast('Open Add/Edit form first', 'err');
}

export async function quickGenerate() {
  const invoke = (window as any).__TAURI__?.core?.invoke?.bind((window as any).__TAURI__?.core);
  const typeEl = document.getElementById('f-secret-type') as HTMLSelectElement | null;
  const type = typeEl?.value || 'api_key';

  if (type === 'password') {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-_=+[]{}|;:,.<>?';
    const buf = new Uint32Array(20);
    crypto.getRandomValues(buf);
    const fKey = document.getElementById('f-key') as HTMLInputElement | null;
    if (fKey) { fKey.value = Array.from(buf).map(n => chars[n % chars.length]).join(''); fKey.focus(); }
    showToast('Password generated', 'ok');
    return;
  }

  if (type === 'ssh_key') {
    if (!invoke) { showToast('Tauri not available', 'err'); return; }
    try {
      const result: { public_key: string; private_key: string } = await invoke('generate_ssh_keypair', { comment: '' });
      const fKey = document.getElementById('f-key') as HTMLInputElement | null;
      if (fKey) { fKey.value = result.private_key; fKey.focus(); }
      showToast('SSH key pair generated (private key inserted)', 'ok');
    } catch (e) { showToast(String(e), 'err'); }
    return;
  }

  if (type === 'certificate') {
    if (!invoke) { showToast('Tauri not available', 'err'); return; }
    try {
      const result: { cert_pem: string; key_pem: string } = await invoke('generate_certificate', { commonName: 'localhost', validityDays: 365 });
      const fCert = document.getElementById('f-cert') as HTMLTextAreaElement | null;
      const fCertKey = document.getElementById('f-cert-key') as HTMLTextAreaElement | null;
      if (fCert) fCert.value = result.cert_pem;
      if (fCertKey) fCertKey.value = result.key_pem;
      showToast('Certificate generated', 'ok');
    } catch (e) { showToast(String(e), 'err'); }
    return;
  }

  // Default: 32 random bytes hex
  const buf = new Uint8Array(32);
  crypto.getRandomValues(buf);
  const hex = Array.from(buf).map(b => b.toString(16).padStart(2, '0')).join('');
  const fKey = document.getElementById('f-key') as HTMLInputElement | null;
  if (fKey) { fKey.value = hex; fKey.focus(); }
  showToast('Value generated', 'ok');
}

// ── Card interactions ─────────────────────────────────────────────────────

export function toggleCard(e: Event, idx: number) {
  e.stopPropagation();
  const card = document.querySelector(`.card[data-idx="${idx}"]`);
  card?.classList.toggle('expanded');
  if (card?.classList.contains('expanded')) st.expanded.add(idx);
  else st.expanded.delete(idx);
}

export function toggleReveal(e: Event, field: string, idx: number, value: string) {
  e.stopPropagation();
  const key = `${field}-${idx}`;
  const el = document.getElementById(`kv-${field}-${idx}`);
  if (!el) return;
  st.revealed[key] = !st.revealed[key];
  el.textContent = st.revealed[key] ? value : maskKey(value);
  el.classList.toggle('revealed', st.revealed[key]);
  document.getElementById(`reveal-${field}-${idx}`)?.classList.toggle('active', st.revealed[key]);
}

export function copyField(e: Event, value: string, btn?: HTMLElement) {
  e.stopPropagation();
  clipboardWrite(value).then(() => {
    btn?.classList.add('active');
    setTimeout(() => btn?.classList.remove('active'), 1200);
    showToast('Copied ✓', 'ok', 1500);
  }).catch(() => showToast('Copy failed', 'err'));
}

export function doCopyEnv(e: Event, idx: number) {
  e.stopPropagation();
  const entry = st.vault.api_keys[idx];
  if (!entry) return;
  const fmt = Settings.get('defaultExportFormat');
  const text = fmt === 'yaml' ? Exporter.yaml([entry]) : Exporter.dotenv([entry]);
  clipboardWrite(text).then(() => {
    const btn = document.getElementById(`env-btn-${idx}`);
    btn?.classList.add('env-copied');
    setTimeout(() => btn?.classList.remove('env-copied'), 1600);
    showToast(`Copied as ${fmt === 'yaml' ? 'YAML' : '.env'} ✓`, 'ok');
  });
}

export function onIconWrapClick(e: Event, idx: number) {
  e.stopPropagation();
  openIconPickerFor(idx);
}

export function openIconPickerFor(idx: number) {
  const entry = st.vault.api_keys[idx];
  openIconPicker(undefined, undefined, (slug) => {
    st.vault.api_keys[idx] = { ...st.vault.api_keys[idx], custom_icon: slug || undefined };
    st.store.save(st.vault);
    triggerRender();
  });
  iconPicker.selected = entry.custom_icon || null;
  (document.getElementById('icon-search') as HTMLInputElement).value = '';
  document.getElementById('icon-picker-overlay')!.classList.add('open');
}

// ── Dropdown ──────────────────────────────────────────────────────────────

export interface DropdownItem {
  label: string;
  fn: () => void;
  active?: boolean;
}

const _dropdownCallbacks = new Map<number, () => void>();
let _dropdownItemId = 0;

export function showDropdown(anchorEl: HTMLElement, items: Array<DropdownItem | '---'>) {
  const dd = document.getElementById('dropdown')!;
  const r = anchorEl.getBoundingClientRect();
  _dropdownCallbacks.clear();

  dd.innerHTML = items
    .map((item) => {
      if (item === '---') return '<div class="dropdown-sep"></div>';
      const id = _dropdownItemId++;
      _dropdownCallbacks.set(id, item.fn);
      return `<div class="dropdown-item${item.active ? ' active' : ''}" data-ddid="${id}">${item.label}</div>`;
    })
    .join('');

  dd.style.cssText = `display:block;top:${r.bottom + 6}px;right:${document.documentElement.clientWidth - r.right}px;left:auto`;

  const onClick = (e: MouseEvent) => {
    const target = e.target as HTMLElement;
    const item = target.closest<HTMLElement>('[data-ddid]');
    if (item) {
      const id = parseInt(item.dataset.ddid!);
      const fn = _dropdownCallbacks.get(id);
      if (fn) fn();
      dd.style.display = 'none';
    }
  };

  const close = (e: MouseEvent) => {
    if (!dd.contains(e.target as Node) && e.target !== anchorEl) {
      dd.style.display = 'none';
      document.removeEventListener('click', close);
      dd.removeEventListener('click', onClick);
    }
  };

  dd.addEventListener('click', onClick);
  setTimeout(() => document.addEventListener('click', close), 50);
}

export function showContextMenu(x: number, y: number, items: Array<DropdownItem | '---'>) {
  const dd = document.getElementById('dropdown')!;
  _dropdownCallbacks.clear();
  dd.innerHTML = items.map(item => {
    if (item === '---') return '<div class="dropdown-sep"></div>';
    const id = _dropdownItemId++;
    _dropdownCallbacks.set(id, item.fn);
    return `<div class="dropdown-item${item.active ? ' active' : ''}" data-ddid="${id}">${item.label}</div>`;
  }).join('');
  dd.style.cssText = `display:block;top:${y}px;left:${x}px;right:auto`;
  requestAnimationFrame(() => {
    const r = dd.getBoundingClientRect();
    if (r.right  > window.innerWidth)  dd.style.left = `${x - r.width}px`;
    if (r.bottom > window.innerHeight) dd.style.top  = `${y - r.height}px`;
  });
  const onClick = (e: MouseEvent) => {
    const item = (e.target as HTMLElement).closest<HTMLElement>('[data-ddid]');
    if (item) { _dropdownCallbacks.get(parseInt(item.dataset.ddid!))?.(); dd.style.display = 'none'; }
  };
  const close = (e: MouseEvent) => {
    if (!dd.contains(e.target as Node)) {
      dd.style.display = 'none';
      document.removeEventListener('click', close);
      dd.removeEventListener('click', onClick);
    }
  };
  dd.addEventListener('click', onClick);
  setTimeout(() => document.addEventListener('click', close), 50);
}

// ── Custom Select ─────────────────────────────────────────────────────────

export class CustomSelect {
  el: HTMLDivElement;
  select: HTMLSelectElement;
  _btn: HTMLButtonElement;

  constructor(selectEl: HTMLSelectElement) {
    this.select = selectEl;
    const wrap = document.createElement('div');
    wrap.className = 'custom-select-wrap';
    selectEl.parentNode!.insertBefore(wrap, selectEl);
    wrap.appendChild(selectEl);
    selectEl.style.display = 'none';

    const button = document.createElement('button');
    button.type = 'button';
    button.className = 'custom-select-btn form-input mono';
    button.textContent = selectEl.options[selectEl.selectedIndex]?.text || '';

    button.addEventListener('click', (e) => {
      e.stopPropagation();
      const items = Array.from(selectEl.options).map((opt, i) => ({
        label: opt.text,
        active: selectEl.selectedIndex === i,
        fn: () => {
          selectEl.selectedIndex = i;
          button.textContent = opt.text;
          selectEl.dispatchEvent(new Event('change'));
        },
      }));
      showDropdown(button, items);
    });

    wrap.appendChild(button);
    this.el = wrap;
    this._btn = button;
  }

  setValue(v: string) {
    const idx = Array.from(this.select.options).findIndex(o => o.value === v);
    if (idx >= 0) {
      this.select.selectedIndex = idx;
      this._btn.textContent = this.select.options[idx].text;
    }
  }
}
