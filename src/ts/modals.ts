/**
 * @file
 * Modals, dropdowns, card interactions, and form helpers.
 */

import type { VaultEntry, SecretType } from './types';
import {
  st,
  Settings,
  triggerRender,
  Exporter,
  dotenvKey,
  persist,
  entryId,
  newEntryId,
} from './state';
import {
  esc,
  escAttr,
  maskKey,
  showToast,
  showConfirm,
  clipboardWrite,
  eyeSVG,
  copySVG,
  dupSVG,
  editSVG,
  delSVG,
} from './utils';
import { iconHTML, openIconPicker, iconPicker, setIconField, readIconField } from './icons';
import { renameProviderRefs } from './chunk-ops';
import { normalizeRateLimit } from './ratelimit';

/**
 * Rate-limit text the structured count/period pair cannot express, carried from
 * the entry being edited through to the next save.
 *
 * Module-level state that points at the entry currently in the form, so it has
 * the problem CLAUDE.md's invariants are about: something holds a reference and
 * the thing it points at changes. What clears it is `fillForm`, which every path
 * into the form goes through — `fillForm({})` for a new entry normalises to no
 * note and blanks it. Do not read this without having gone through `fillForm`
 * first, or a note from the last entry edited lands on a different one.
 */
let pendingRateLimitNote = '';

// ── Schema tooltips & category chips ──────────────────────────────────────

export function applySchemaTooltips() {
  if (!st.schema) return;
  const props = st.schema.properties?.api_keys?.items?.properties || {};
  document.querySelectorAll<HTMLElement>('.form-label[data-field]').forEach((el) => {
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
  st.vault.user_categories.forEach((cat) => {
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
  api_key: {
    providerLabel: 'Provider',
    providerPlaceholder: 'e.g. GitHub',
    showAccount: true,
    keyLabel: 'API Key',
    keyPlaceholder: 'Your API key or access token',
  },
  password: {
    providerLabel: 'Service / App',
    providerPlaceholder: 'e.g. Gmail',
    showAccount: false,
    keyLabel: 'Password',
    keyPlaceholder: 'Your password',
  },
  env_var: {
    providerLabel: 'Variable Name',
    providerPlaceholder: 'e.g. DATABASE_URL',
    showAccount: false,
    keyLabel: 'Value',
    keyPlaceholder: 'Variable value',
  },
  connection_string: {
    providerLabel: 'Service',
    providerPlaceholder: 'e.g. PostgreSQL',
    showAccount: false,
    keyLabel: 'Connection String',
    keyPlaceholder: 'postgresql://user:pass@host/db',
  },
  ssh_key: {
    providerLabel: 'Host / Service',
    providerPlaceholder: 'e.g. github.com',
    showAccount: true,
    keyLabel: 'SSH Key',
    keyPlaceholder: '-----BEGIN OPENSSH PRIVATE KEY-----',
  },
  certificate: {
    providerLabel: 'Site / Domain',
    providerPlaceholder: 'e.g. darthdemono.com',
    showAccount: false,
    keyLabel: 'Fullchain',
    keyPlaceholder: '',
  },
  file_blob: {
    providerLabel: 'Name',
    providerPlaceholder: 'e.g. config.yaml',
    showAccount: false,
    keyLabel: 'File Reference',
    keyPlaceholder: '',
  },
};

// ── Dynamic form fields ───────────────────────────────────────────────────

export function dynamicSecretFields() {
  const type = (document.getElementById('f-secret-type') as HTMLSelectElement).value as SecretType;
  const cfg = TYPE_CONFIG[type] || TYPE_CONFIG.api_key;

  const keyGroup = document.getElementById('f-key-group');
  const keyLabelEl = document.getElementById('f-key-label');
  const secretGroup = document.getElementById('f-secret-group');
  const usernameRow = document.getElementById('f-username-row');
  const certGroup = document.getElementById('f-cert-group');
  const certKeyGroup = document.getElementById('f-cert-key-group');
  const certIssuerGroup = document.getElementById('f-cert-issuer-group');
  const blobGroup = document.getElementById('f-blob-group');
  const accountGroup = document.getElementById('f-account-group');
  const providerLabel = document.getElementById('f-provider-label');
  const providerInput = document.getElementById('f-provider') as HTMLInputElement | null;
  const envvarSubtypeGroup = document.getElementById('f-envvar-subtype-group');

  const showKey = type !== 'certificate' && type !== 'file_blob';
  const showSecret = type === 'api_key';
  const showUser = type === 'password' || type === 'ssh_key';

  if (keyGroup) keyGroup.style.display = showKey ? 'flex' : 'none';
  if (secretGroup) secretGroup.style.display = showSecret ? 'flex' : 'none';
  if (usernameRow) usernameRow.style.display = showUser ? 'grid' : 'none';
  if (certGroup) certGroup.style.display = type === 'certificate' ? 'flex' : 'none';
  if (certKeyGroup) certKeyGroup.style.display = type === 'certificate' ? 'flex' : 'none';
  if (certIssuerGroup) certIssuerGroup.style.display = type === 'certificate' ? 'flex' : 'none';
  if (blobGroup) blobGroup.style.display = type === 'file_blob' ? 'flex' : 'none';
  if (accountGroup) accountGroup.style.display = cfg.showAccount ? '' : 'none';
  if (envvarSubtypeGroup) envvarSubtypeGroup.style.display = type === 'env_var' ? 'flex' : 'none';

  if (providerLabel) providerLabel.innerHTML = `${cfg.providerLabel} <span class="req">*</span>`;
  if (providerInput) providerInput.placeholder = cfg.providerPlaceholder;
  if (keyLabelEl && showKey) keyLabelEl.innerHTML = `${cfg.keyLabel} <span class="req">*</span>`;
  const keyInput = document.getElementById('f-key') as HTMLInputElement | null;
  if (keyInput && showKey) keyInput.placeholder = cfg.keyPlaceholder;
}

// ── Form to entry & fill form ─────────────────────────────────────────────

export function formToEntry(): VaultEntry {
  const getVal = (id: string, fallback = '') => {
    const el = document.getElementById(id) as HTMLInputElement | HTMLSelectElement | null;
    return el?.value?.trim?.() ?? fallback;
  };

  const scopes = getVal('f-scopes')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
  const cats = [...document.querySelectorAll<HTMLElement>('#f-categories .cat-chip.selected')].map(
    (c) => c.textContent!,
  );
  const secretType = (getVal('f-secret-type') || 'api_key') as SecretType;

  const selectedProjectIds = [
    ...document.querySelectorAll<HTMLElement>('#f-project .project-pick-item.selected'),
  ]
    .map((el) => el.dataset.value!)
    .filter(Boolean);

  return {
    provider: getVal('f-provider'),
    account_name: getVal('f-account') || undefined,
    username: getVal('f-username') || undefined,
    email: getVal('f-email') || undefined,
    api_key: getVal('f-key'),
    api_secret: getVal('f-secret') || undefined,
    key_id: getVal('f-keyid') || undefined,
    price_type: getVal('f-price', 'free') as VaultEntry['price_type'],
    environment: (getVal('f-env') as VaultEntry['environment']) || undefined,
    projectIds: selectedProjectIds.includes('Universal')
      ? selectedProjectIds
      : ['Universal', ...selectedProjectIds],
    api_url: getVal('f-apiurl') || undefined,
    callback_url: getVal('f-cburl') || undefined,
    version: getVal('f-version') || undefined,
    // The rate limit is three fields that must agree, so it is read as a unit
    // and normalised rather than field by field. `normalizeRateLimit` also
    // regenerates the legacy `rate_limit` string from the pair, which is what
    // keeps a vault edited here readable to an older build.
    ...(() => {
      const rl = normalizeRateLimit({
        rate_limit_count: getVal('f-ratelimit') ? Number(getVal('f-ratelimit')) : undefined,
        rate_limit_period: getVal('f-ratelimit-period') || undefined,
        // The note is only ever carried, never typed: it holds whatever the old
        // free-text field said when it could not be read as a number and a
        // period, and the form has no input for it.
        rate_limit: pendingRateLimitNote,
      });
      return {
        rate_limit: rl.rate_limit || undefined,
        rate_limit_count: rl.rate_limit_count ?? undefined,
        rate_limit_period: rl.rate_limit_period ?? undefined,
        rate_limit_note: rl.rate_limit_note || undefined,
      };
    })(),
    purpose: getVal('f-purpose') || undefined,
    pool: getVal('f-pool') || undefined,
    expires_at: getVal('f-expires') || undefined,
    rotation_days: getVal('f-rotation-days')
      ? parseInt(getVal('f-rotation-days')) || undefined
      : undefined,
    compromised:
      (document.getElementById('f-compromised') as HTMLInputElement | null)?.checked || undefined,
    scopes,
    api_description: getVal('f-apidesc') || undefined,
    description: getVal('f-desc') || undefined,
    details: getVal('f-details') || undefined,
    custom_icon: readIconField(document.getElementById('f-icon') as HTMLInputElement | null),
    categories: cats,
    tags: getVal('f-tags-input').split(/\s+/).filter(Boolean).length
      ? getVal('f-tags-input').split(/\s+/).filter(Boolean)
      : undefined,
    secretType,
    certificate_data: secretType === 'certificate' ? getVal('f-cert') : undefined,
    cert_key_data: secretType === 'certificate' ? getVal('f-cert-key') || undefined : undefined,
    cert_issuer: secretType === 'certificate' ? getVal('f-cert-issuer') || undefined : undefined,
    blob_ref: secretType === 'file_blob' ? getVal('f-blob') : undefined,
    env_var_subtype:
      secretType === 'env_var'
        ? (getVal('f-envvar-subtype') as VaultEntry['env_var_subtype']) || undefined
        : undefined,
    extra_vars: (() => {
      const rows = [...document.querySelectorAll<HTMLElement>('#f-extra-vars-list .extra-var-row')];
      const result = rows
        .map((row) => ({
          key: row.querySelector<HTMLInputElement>('.extra-var-key')?.value.trim() || '',
          value: row.querySelector<HTMLInputElement>('.extra-var-value')?.value.trim() || '',
          secret: row.querySelector<HTMLInputElement>('.extra-var-secret')?.checked || false,
        }))
        .filter((v) => v.key);
      return result.length ? result : undefined;
    })(),
    env_prefixes: (() => {
      const raw = getVal('f-env-prefixes');
      const parts = raw
        .split(/[,\s]+/)
        .map((p) => p.trim().replace(/_+$/, ''))
        .filter(Boolean);
      return parts.length ? parts : undefined;
    })(),
  };
}

export function fillForm(entry: Partial<VaultEntry>) {
  (document.getElementById('f-provider') as HTMLInputElement).value = entry.provider || '';
  (document.getElementById('f-account') as HTMLInputElement).value =
    entry.account_name || Settings.get('defaultAccount') || '';
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
    document.querySelectorAll<HTMLElement>('#f-project .project-pick-item').forEach((el) => {
      el.classList.toggle('selected', entry.projectIds!.includes(el.dataset.value!));
    });
  }
  (document.getElementById('f-apiurl') as HTMLInputElement).value = entry.api_url || '';
  (document.getElementById('f-cburl') as HTMLInputElement).value = entry.callback_url || '';
  (document.getElementById('f-version') as HTMLInputElement).value = entry.version || '';
  // Normalised on read, not trusted: this entry may have been written by an
  // older build that only had the free-text field, by a remote server, or by an
  // imported backup. `normalizeRateLimit` is the one reader (CLAUDE.md
  // invariant 4 — vault data is untrusted input and the TS union is erased).
  const rl = normalizeRateLimit(entry);
  (document.getElementById('f-ratelimit') as HTMLInputElement).value =
    rl.rate_limit_count == null ? '' : String(rl.rate_limit_count);
  const rlPeriod = document.getElementById('f-ratelimit-period') as HTMLSelectElement | null;
  if (rlPeriod) rlPeriod.value = rl.rate_limit_period || '';
  // Text the number/period pair cannot express is shown beneath the inputs and
  // carried through the next save. Dropping it would lose what the user wrote.
  pendingRateLimitNote = rl.rate_limit_note || '';
  const rlNote = document.getElementById('f-ratelimit-note');
  if (rlNote) {
    rlNote.textContent = pendingRateLimitNote ? `was: ${pendingRateLimitNote}` : '';
    rlNote.hidden = !pendingRateLimitNote;
  }
  (document.getElementById('f-purpose') as HTMLInputElement).value = entry.purpose || '';
  (document.getElementById('f-pool') as HTMLInputElement).value = entry.pool || '';
  (document.getElementById('f-expires') as HTMLInputElement).value = entry.expires_at || '';
  const rotEl = document.getElementById('f-rotation-days') as HTMLInputElement | null;
  if (rotEl) rotEl.value = entry.rotation_days ? String(entry.rotation_days) : '';
  const compEl = document.getElementById('f-compromised') as HTMLInputElement | null;
  if (compEl) compEl.checked = !!entry.compromised;
  (document.getElementById('f-scopes') as HTMLInputElement).value = (entry.scopes || []).join(', ');
  (document.getElementById('f-apidesc') as HTMLInputElement).value = entry.api_description || '';
  (document.getElementById('f-desc') as HTMLInputElement).value = entry.description || '';
  (document.getElementById('f-details') as HTMLInputElement).value = entry.details || '';
  setIconField(document.getElementById('f-icon') as HTMLInputElement | null, entry.custom_icon);
  const tagsInput = document.getElementById('f-tags-input') as HTMLInputElement | null;
  if (tagsInput) tagsInput.value = (entry.tags || []).join(' ');
  document.getElementById('f-icon-preview')!.innerHTML = entry.custom_icon
    ? iconHTML('', entry.custom_icon)
    : '';
  const stVal = entry.secretType || 'api_key';
  (document.getElementById('f-secret-type') as HTMLSelectElement).value = stVal;
  st.formCustomSelects.get('f-secret-type')?.setValue(stVal);
  if (entry.secretType === 'certificate') {
    (document.getElementById('f-cert') as HTMLInputElement).value = entry.certificate_data || '';
    (document.getElementById('f-cert-key') as HTMLInputElement).value = entry.cert_key_data || '';
    (document.getElementById('f-cert-issuer') as HTMLInputElement).value = entry.cert_issuer || '';
  }
  if (entry.secretType === 'file_blob')
    (document.getElementById('f-blob') as HTMLInputElement).value = entry.blob_ref || '';
  if (entry.secretType === 'env_var') {
    const envSubtype = document.getElementById('f-envvar-subtype') as HTMLSelectElement | null;
    if (envSubtype) envSubtype.value = entry.env_var_subtype || 'string';
  }
  const extraList = document.getElementById('f-extra-vars-list');
  if (extraList) {
    extraList.innerHTML = '';
    for (const xv of entry.extra_vars || []) {
      extraList.appendChild(_makeExtraVarRow(xv.key, xv.value, xv.secret));
    }
  }
  const pfxInput = document.getElementById('f-env-prefixes') as HTMLInputElement | null;
  if (pfxInput) pfxInput.value = (entry.env_prefixes || []).join(', ');
  dynamicSecretFields();
}

export function populateProjectSelect() {
  const container = document.getElementById('f-project')!;
  const cats = st.vault.projects.filter((p) => p.id !== 'Universal');
  container.innerHTML = cats
    .map((p) => `<div class="project-pick-item" data-value="${escAttr(p.id)}">${esc(p.name)}</div>`)
    .join('');
  container.querySelectorAll<HTMLElement>('.project-pick-item').forEach((item) => {
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

const DRAFT_KEY = 'envvault-form-draft';

function _saveDraft() {
  try {
    sessionStorage.setItem(DRAFT_KEY, JSON.stringify(formToEntry()));
  } catch {}
}
let _draftBound = false;

function _makeExtraVarRow(key = '', value = '', secret = false): HTMLElement {
  const row = document.createElement('div');
  row.className = 'extra-var-row';
  row.innerHTML = `
    <input class="form-input mono extra-var-key" placeholder="KEY" value="${escAttr(key)}">
    <input class="form-input mono extra-var-value" placeholder="value" value="${escAttr(value)}"${secret ? ' type="password"' : ''}>
    <label class="extra-var-secret-label" title="Mask value in UI"><input type="checkbox" class="extra-var-secret"${secret ? ' checked' : ''}> secret</label>
    <button type="button" class="icon-btn sm extra-var-remove" title="Remove">×</button>
  `;
  const inp = row.querySelector<HTMLInputElement>('.extra-var-value')!;
  row.querySelector<HTMLInputElement>('.extra-var-secret')!.addEventListener('change', (ev) => {
    inp.type = (ev.target as HTMLInputElement).checked ? 'password' : 'text';
  });
  row.querySelector('.extra-var-remove')!.addEventListener('click', () => row.remove());
  return row;
}

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
  // Bind auto-save draft listeners once — the overlay and its inputs are permanent DOM nodes.
  if (!_draftBound) {
    const overlay = document.getElementById('modal-overlay')!;
    overlay.querySelectorAll('input, textarea, select').forEach((el) => {
      el.addEventListener('input', _saveDraft);
      el.addEventListener('change', _saveDraft);
    });
    document.getElementById('f-extra-vars-add')?.addEventListener('click', () => {
      const row = _makeExtraVarRow();
      document.getElementById('f-extra-vars-list')?.appendChild(row);
      row.querySelector<HTMLInputElement>('.extra-var-key')?.focus();
    });
    _draftBound = true;
  }
}

function clearDraft() {
  sessionStorage.removeItem(DRAFT_KEY);
}

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
    if (!entry.provider) {
      showToast(`${TYPE_CONFIG[t]?.providerLabel || 'Provider'} is required`, 'err');
      return;
    }
    if (t === 'certificate' && !entry.certificate_data) {
      showToast('Certificate data is required', 'err');
      return;
    }
    if (t === 'file_blob' && !entry.blob_ref) {
      showToast('File path/reference is required', 'err');
      return;
    }
    if (t !== 'certificate' && t !== 'file_blob' && !entry.api_key) {
      showToast(`${TYPE_CONFIG[t]?.keyLabel || 'Value'} is required`, 'err');
      return;
    }
    const idx = parseInt((document.getElementById('edit-index') as HTMLInputElement).value);
    if (idx >= 0) {
      // Preserve fields not represented in the form.
      // `id` above all: it is this entry's identity for audit attribution,
      // version history and RBAC write scoping. Dropping it on every edit would
      // make each save look like a delete-plus-create.
      const old = st.vault.api_keys[idx];
      st.vault.api_keys[idx] = {
        ...entry,
        id: old.id ?? newEntryId(),
        last_rotated_at: old.last_rotated_at,
        version_history: old.version_history,
        pinned: old.pinned,
      };
      // Chunk references address entries by provider name, so a rename has to
      // carry them or every `${Provider/field}` pointing here goes stale.
      if (old.provider !== entry.provider || (old.key_id ?? '') !== (entry.key_id ?? '')) {
        const moved = renameProviderRefs(old.provider, old.key_id, entry.provider, entry.key_id);
        if (moved)
          showToast(`Updated ${moved} project reference${moved === 1 ? '' : 's'}`, 'ok', 2500);
      }
    } else {
      st.vault.api_keys.push({ ...entry, id: newEntryId() });
    }
    persist();
    closeModal();
    document.getElementById('load-banner')!.style.display = 'none';
    triggerRender();
  } catch (err: any) {
    showToast('Save failed: ' + (err?.message || err), 'err', 4000);
  }
}

/**
 * Marks an entry as rotated: stamps last_rotated_at, snapshots the current
 * value into version_history (capped 50), resets the rotation clock, and
 * clears the compromised flag. Links three previously separate rotation facts.
 */
export function markAsRotated(idx: number) {
  const entry = st.vault.api_keys[idx];
  if (!entry) return;
  const today = new Date().toISOString().slice(0, 10); // YYYY-MM-DD
  const history = [...(entry.version_history || [])];
  if (entry.api_key) {
    history.unshift({ value: entry.api_key, saved_at: new Date().toISOString() });
    if (history.length > 50) history.length = 50;
  }
  st.vault.api_keys[idx] = {
    ...entry,
    last_rotated_at: today,
    version_history: history,
    compromised: false,
  };
  persist();
  triggerRender();
  showToast(
    `Rotated ${today}${entry.compromised ? ' — compromised flag cleared' : ''}`,
    'ok',
    2500,
  );
}

export function duplicateKey(e: Event, idx: number) {
  e.stopPropagation();
  // A duplicate is a *new* entry — it must not inherit the source's identity,
  // and that includes its rotation record. Copying version_history handed the
  // new entry a log of *another* entry's previous secret values, which then
  // showed in its history panel and rode along into every future export.
  const copy = {
    ...st.vault.api_keys[idx],
    id: newEntryId(),
    key_id: (st.vault.api_keys[idx].key_id || 'copy') + '_copy',
    version_history: undefined,
    last_rotated_at: undefined,
  };
  st.vault.api_keys.splice(idx + 1, 0, copy);
  persist();
  triggerRender();
  showToast('Duplicated ✓', 'ok');
}

export function deleteKey(e: Event, idx: number) {
  e.stopPropagation();
  const removed = st.vault.api_keys.splice(idx, 1)[0];
  // Anchor the undo to the identity of the entry that followed, not to a raw
  // index. Deleting a second entry before undoing the first shifted every
  // higher position, so the restore landed in the wrong slot.
  const anchorId = st.vault.api_keys[idx]?.id ?? null;
  persist();
  if (removed?.id) {
    st.expanded.delete(removed.id);
    // Reveal state is keyed by entry id. Left behind, it both grows unbounded
    // and re-reveals the secret if the entry comes back via undo.
    delete st.revealed[`key-${removed.id}`];
    delete st.revealed[`secret-${removed.id}`];
  }
  triggerRender();
  pushUndo(`Deleted "${removed.provider}"`, () => {
    const at = anchorId ? st.vault.api_keys.findIndex((k) => k.id === anchorId) : -1;
    st.vault.api_keys.splice(at >= 0 ? at : st.vault.api_keys.length, 0, removed);
    persist();
    triggerRender();
  });
}

export function pushUndo(msg: string, fn: () => void) {
  const bar = document.getElementById('undo-bar')!;
  document.getElementById('undo-msg')!.textContent = msg;
  bar.classList.add('visible');
  // Use a unique token so the timeout removes *this* entry, not whatever happens to be last.
  const entry: { fn: () => void; t: ReturnType<typeof setTimeout> } = {
    fn,
    t: 0 as unknown as ReturnType<typeof setTimeout>,
  };
  entry.t = setTimeout(() => {
    const idx = st.undoStack.indexOf(entry);
    if (idx >= 0) st.undoStack.splice(idx, 1);
    if (!st.undoStack.length) bar.classList.remove('visible');
  }, 5000);
  st.undoStack.push(entry);
}

// ── Form helpers ──────────────────────────────────────────────────────────

export function injectIntoForm(value: string) {
  const fKey = document.getElementById('f-key') as HTMLInputElement | null;
  if (fKey) {
    fKey.value = value;
    fKey.focus();
    showToast('Injected into form', 'ok');
  } else showToast('Open Add/Edit form first', 'err');
}

export async function quickGenerate() {
  const invoke = (window as any).__TAURI__?.core?.invoke?.bind((window as any).__TAURI__?.core);
  const typeEl = document.getElementById('f-secret-type') as HTMLSelectElement | null;
  const type = typeEl?.value || 'api_key';

  if (type === 'password') {
    const chars =
      'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-_=+[]{}|;:,.<>?';
    const buf = new Uint32Array(20);
    crypto.getRandomValues(buf);
    const fKey = document.getElementById('f-key') as HTMLInputElement | null;
    if (fKey) {
      fKey.value = Array.from(buf)
        .map((n) => chars[n % chars.length])
        .join('');
      fKey.focus();
    }
    showToast('Password generated', 'ok');
    return;
  }

  if (type === 'ssh_key') {
    if (!invoke) {
      showToast('Tauri not available', 'err');
      return;
    }
    try {
      const result: { public_key: string; private_key: string } = await invoke(
        'generate_ssh_keypair',
        { comment: '' },
      );
      const fKey = document.getElementById('f-key') as HTMLInputElement | null;
      if (fKey) {
        fKey.value = result.private_key;
        fKey.focus();
      }
      showToast('SSH key pair generated (private key inserted)', 'ok');
    } catch (e) {
      showToast(String(e), 'err');
    }
    return;
  }

  if (type === 'certificate') {
    if (!invoke) {
      showToast('Tauri not available', 'err');
      return;
    }
    try {
      const result: { cert_pem: string; key_pem: string } = await invoke('generate_certificate', {
        commonName: 'localhost',
        validityDays: 365,
      });
      const fCert = document.getElementById('f-cert') as HTMLTextAreaElement | null;
      const fCertKey = document.getElementById('f-cert-key') as HTMLTextAreaElement | null;
      if (fCert) fCert.value = result.cert_pem;
      if (fCertKey) fCertKey.value = result.key_pem;
      showToast('Certificate generated', 'ok');
    } catch (e) {
      showToast(String(e), 'err');
    }
    return;
  }

  // Default: 32 random bytes hex
  const buf = new Uint8Array(32);
  crypto.getRandomValues(buf);
  const hex = Array.from(buf)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
  const fKey = document.getElementById('f-key') as HTMLInputElement | null;
  if (fKey) {
    fKey.value = hex;
    fKey.focus();
  }
  showToast('Value generated', 'ok');
}

// ── Card interactions ─────────────────────────────────────────────────────

export function toggleCard(e: Event, idx: number) {
  e.stopPropagation();
  const entry = st.vault.api_keys[idx];
  if (!entry) return;
  const card = document.querySelector(`.card[data-idx="${idx}"]`);
  card?.classList.toggle('expanded');
  // Track by stable id, not array position — see st.expanded.
  if (card?.classList.contains('expanded')) st.expanded.add(entryId(entry));
  else st.expanded.delete(entryId(entry));
}

export function toggleReveal(e: Event, field: string, idx: number, value: string) {
  e.stopPropagation();
  const entry = st.vault.api_keys[idx];
  if (!entry) return;
  const key = `${field}-${entryId(entry)}`;
  const el = document.getElementById(`kv-${field}-${idx}`);
  if (!el) return;
  st.revealed[key] = !st.revealed[key];
  el.textContent = st.revealed[key] ? value : maskKey(value);
  el.classList.toggle('revealed', st.revealed[key]);
  document.getElementById(`reveal-${field}-${idx}`)?.classList.toggle('active', st.revealed[key]);
}

export function copyField(e: Event, value: string, btn?: HTMLElement) {
  e.stopPropagation();
  clipboardWrite(value)
    .then(() => {
      btn?.classList.add('active');
      setTimeout(() => btn?.classList.remove('active'), 1200);
      showToast('Copied ✓', 'ok', 1500);
    })
    .catch(() => showToast('Copy failed', 'err'));
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
    persist();
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
let _ddCleanup: (() => void) | null = null;

function _ddClose() {
  if (_ddCleanup) {
    _ddCleanup();
    _ddCleanup = null;
  }
  const dd = document.getElementById('dropdown');
  if (dd) dd.style.display = 'none';
}

export function showDropdown(anchorEl: HTMLElement, items: (DropdownItem | '---')[]) {
  const dd = document.getElementById('dropdown')!;
  // Remove any listeners from a previously open dropdown that was not explicitly closed.
  if (_ddCleanup) {
    _ddCleanup();
    _ddCleanup = null;
  }

  const r = anchorEl.getBoundingClientRect();
  _dropdownCallbacks.clear();

  dd.innerHTML = items
    .map((item) => {
      if (item === '---') return '<div class="dropdown-sep"></div>';
      const id = _dropdownItemId++;
      _dropdownCallbacks.set(id, item.fn);
      // Labels from callers are already escaped or are static strings — render as-is.
      // Callers that include user data (e.g. entry.provider) must pre-escape with esc().
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
      _ddClose();
      if (fn) fn();
    }
  };

  const close = (e: MouseEvent) => {
    if (!dd.contains(e.target as Node) && e.target !== anchorEl) {
      _ddClose();
    }
  };

  _ddCleanup = () => {
    dd.removeEventListener('click', onClick);
    document.removeEventListener('click', close);
  };

  dd.addEventListener('click', onClick);
  setTimeout(() => document.addEventListener('click', close), 50);
}

export function showContextMenu(x: number, y: number, items: (DropdownItem | '---')[]) {
  const dd = document.getElementById('dropdown')!;
  if (_ddCleanup) {
    _ddCleanup();
    _ddCleanup = null;
  }

  _dropdownCallbacks.clear();
  dd.innerHTML = items
    .map((item) => {
      if (item === '---') return '<div class="dropdown-sep"></div>';
      const id = _dropdownItemId++;
      _dropdownCallbacks.set(id, item.fn);
      return `<div class="dropdown-item${item.active ? ' active' : ''}" data-ddid="${id}">${item.label}</div>`;
    })
    .join('');
  dd.style.cssText = `display:block;top:${y}px;left:${x}px;right:auto`;
  requestAnimationFrame(() => {
    const r = dd.getBoundingClientRect();
    if (r.right > window.innerWidth) dd.style.left = `${x - r.width}px`;
    if (r.bottom > window.innerHeight) dd.style.top = `${y - r.height}px`;
  });
  const onClick = (e: MouseEvent) => {
    const item = (e.target as HTMLElement).closest<HTMLElement>('[data-ddid]');
    if (item) {
      const fn = _dropdownCallbacks.get(parseInt(item.dataset.ddid!));
      _ddClose();
      fn?.();
    }
  };
  const close = (e: MouseEvent) => {
    if (!dd.contains(e.target as Node)) {
      _ddClose();
    }
  };

  _ddCleanup = () => {
    dd.removeEventListener('click', onClick);
    document.removeEventListener('click', close);
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
    const idx = Array.from(this.select.options).findIndex((o) => o.value === v);
    if (idx >= 0) {
      this.select.selectedIndex = idx;
      this._btn.textContent = this.select.options[idx].text;
    }
  }
}
