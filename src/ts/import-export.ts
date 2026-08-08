/**
 * @file Import / export: copyAll, exportAs, .env import modal, file import.
 */

import type { VaultEntry, SecretType } from './types';
import { st, triggerRender, Exporter, persist, resetViewState } from './state';
import { showToast, clipboardWrite } from './utils';
import { getFiltered, sorted } from './filters';
import * as yaml from 'js-yaml';

// ── Copy All / Export As ──────────────────────────────────────────────────

export function copyAll(fmt: string) {
  const keys = sorted(getFiltered());
  const text = fmt === 'yaml' ? Exporter.yaml(keys) : fmt === 'json' ? Exporter.json(keys) : Exporter.dotenv(keys);
  clipboardWrite(text).then(() => showToast(`${keys.length} keys copied`, 'ok'));
}

export function exportAs(fmt: string) {
  const keys = st.vault.api_keys;
  const content = fmt === 'yaml' ? Exporter.yaml(keys) : fmt === 'json' ? JSON.stringify(st.vault, null, 2) : Exporter.dotenv(keys);
  const blob = new Blob([content], { type: 'text/plain' });
  const url = URL.createObjectURL(blob);
  const a = Object.assign(document.createElement('a'), {
    href: url,
    download: `envvault.${fmt === 'yaml' ? 'yaml' : fmt === 'json' ? 'json' : 'env'}`,
  });
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  setTimeout(() => URL.revokeObjectURL(url), 1000);
  showToast(`Exported as .${fmt}`, 'ok');
}

// ── Infra-as-code export formats ───────────────────────────────────────────

function envKey(provider: string): string {
  return provider.toUpperCase().replace(/[^A-Z0-9]/g, '_');
}

function downloadText(content: string, filename: string, okMsg: string) {
  const blob = new Blob([content], { type: 'text/plain' });
  const url = URL.createObjectURL(blob);
  const a = Object.assign(document.createElement('a'), { href: url, download: filename });
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  setTimeout(() => URL.revokeObjectURL(url), 1000);
  showToast(okMsg, 'ok');
}

/** Kubernetes Secret manifest (stringData — values kept readable, not base64). */
export function exportK8sSecret(name = 'envvault') {
  const keys = st.vault.api_keys;
  const lines = [
    'apiVersion: v1',
    'kind: Secret',
    'metadata:',
    `  name: ${name}`,
    'type: Opaque',
    'stringData:',
    ...keys.map(e => `  ${envKey(e.provider)}: ${JSON.stringify(e.api_key)}`),
  ];
  downloadText(lines.join('\n'), `${name}-secret.yaml`, 'Exported k8s Secret ✓');
}

/** Terraform .tfvars — variable = "value" pairs. */
export function exportTfvars() {
  const keys = st.vault.api_keys;
  const lines = keys.map(e => `${envKey(e.provider).toLowerCase()} = ${JSON.stringify(e.api_key)}`);
  downloadText(lines.join('\n'), 'envvault.tfvars', 'Exported .tfvars ✓');
}

// ── Encrypted backup (AES-256-GCM, PBKDF2-SHA256) ──────────────────────────

const BAK_MAGIC = 'ENVVBAK1';
const PBKDF2_ITERS = 210_000;

async function deriveBackupKey(
  password: string,
  salt: BufferSource,
  iterations = PBKDF2_ITERS,
): Promise<CryptoKey> {
  const baseKey = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' },
    baseKey, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}

/**
 * Base64 a buffer in chunks.
 *
 * `String.fromCharCode(...bytes)` spreads every byte as a separate argument, so
 * it blew the call stack once the ciphertext passed roughly 100 KB — which any
 * vault holding a few PEM certificates does. Nothing caught the RangeError, so
 * "Export encrypted backup" simply did nothing, and it failed for exactly the
 * vaults with the most to lose.
 */
function b64(buf: ArrayBuffer): string {
  const bytes = new Uint8Array(buf);
  const CHUNK = 0x8000;
  let out = '';
  for (let i = 0; i < bytes.length; i += CHUNK) {
    out += String.fromCharCode(...bytes.subarray(i, i + CHUNK));
  }
  return btoa(out);
}
function fromB64(s: string): Uint8Array<ArrayBuffer> {
  const bin = atob(s);
  const buf = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) buf[i] = bin.charCodeAt(i);
  return buf;
}

/** Encrypt the full vault JSON with a separate backup password (not the master key). */
export async function exportEncryptedBackup(password: string) {
  // 12, matching the master-password minimum. This file is the whole vault and
  // is meant to leave the machine, so it should not be the weakest link — an
  // 8-character floor here quietly undercut the 12 enforced on the vault
  // itself.
  if (password.length < 12) { showToast('Backup password must be at least 12 characters', 'err', 4000); return; }
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv   = crypto.getRandomValues(new Uint8Array(12));
  const key  = await deriveBackupKey(password, salt);
  const plain = new TextEncoder().encode(JSON.stringify(st.vault));
  const cipher = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, plain);
  const envelope = JSON.stringify({
    magic: BAK_MAGIC,
    kdf: { name: 'PBKDF2', hash: 'SHA-256', iters: PBKDF2_ITERS },
    salt: b64(salt.buffer), iv: b64(iv.buffer), ct: b64(cipher),
  });
  downloadText(envelope, `envvault-${new Date().toISOString().slice(0, 10)}.vaultbak`, 'Encrypted backup exported ✓');
}

/** Decrypt a .vaultbak envelope and replace the current vault. */
export async function importEncryptedBackup(text: string, password: string) {
  let env: any;
  try { env = JSON.parse(text); } catch { showToast('Not a valid backup file', 'err'); return; }
  if (env.magic !== BAK_MAGIC) { showToast('Unrecognised backup format', 'err'); return; }
  try {
    const salt = fromB64(env.salt);
    const iv   = fromB64(env.iv);
    // Honour the iteration count recorded in the envelope. It was written but
    // never read, so a backup made with any other count would fail to decrypt
    // and be reported as a wrong password.
    const iters = Number.isInteger(env.kdf?.iters) && env.kdf.iters > 0 ? env.kdf.iters : PBKDF2_ITERS;
    const key  = await deriveBackupKey(password, salt, iters);
    const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, fromB64(env.ct));
    const data = JSON.parse(new TextDecoder().decode(plain));
    if (!Array.isArray(data.api_keys)) throw new Error('Missing api_keys');
    st.vault.api_keys = data.api_keys;
    st.vault.user_categories = data.user_categories || [];
    st.vault.projects = data.projects || [{ id: 'Universal', name: 'Universal', description: 'All keys belong here by default' }];
    persist();
    resetViewState();
    triggerRender();
    showToast(`Restored ${st.vault.api_keys.length} keys ✓`, 'ok');
  } catch {
    showToast('Decryption failed — wrong password or corrupt file', 'err', 4000);
  }
}

// ── Env file parsing ──────────────────────────────────────────────────────

export interface EnvVar { name: string; value: string; }

export function parseEnvFile(text: string): EnvVar[] {
  const result: EnvVar[] = [];
  const rawLines = text.split(/\r?\n/);
  let i = 0;
  while (i < rawLines.length) {
    let combined = rawLines[i++];
    while (combined.trimEnd().endsWith('\\') && i < rawLines.length) {
      combined = combined.trimEnd().slice(0, -1) + rawLines[i++].trim();
    }
    const trimmed = combined.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const eqIdx = trimmed.indexOf('=');
    if (eqIdx < 0) continue;
    let name = trimmed.slice(0, eqIdx).trim();
    if (name.toUpperCase().startsWith('EXPORT ')) name = name.slice(7).trim();
    let value = trimmed.slice(eqIdx + 1).trim();
    if (value.length >= 2 &&
        ((value.startsWith('"') && value.endsWith('"')) ||
         (value.startsWith("'") && value.endsWith("'")))) {
      value = value.slice(1, -1);
    }
    if (name) result.push({ name, value });
  }
  return result;
}

// ── Env import modal ──────────────────────────────────────────────────────

export function openEnvImportModal(vars: EnvVar[]) {
  const list = document.getElementById('env-import-list')!;
  list.innerHTML = '';
  vars.forEach((v, i) => {
    const row = document.createElement('label');
    row.className = 'env-import-row';
    const valPreview = v.value.length > 40 ? v.value.slice(0, 40) + '…' : v.value;
    const safeVal = v.value.length > 40
      ? v.value.slice(0, 40).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;') + '…'
      : v.value.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
    const safeName = v.name.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
    row.innerHTML = `<input type="checkbox" class="env-import-check" data-idx="${i}" checked><span class="env-import-name mono">${safeName}</span><span class="env-import-val mono">${safeVal}</span>`;
    list.appendChild(row);
  });
  document.getElementById('env-import-subtitle')!.textContent = `Found ${vars.length} variable${vars.length !== 1 ? 's' : ''}. Set options and select which to import.`;
  const catSel = document.getElementById('env-import-category') as HTMLSelectElement;
  catSel.innerHTML = '<option value="">— none —</option>';
  (st.vault.user_categories || []).forEach(cat => {
    const opt = document.createElement('option');
    opt.value = cat; opt.textContent = cat;
    catSel.appendChild(opt);
  });
  const projSel = document.getElementById('env-import-project') as HTMLSelectElement;
  projSel.innerHTML = '';
  st.vault.projects.filter(p => p.name !== 'Universal').forEach(p => {
    const opt = document.createElement('option');
    opt.value = p.id; opt.textContent = p.name;
    projSel.appendChild(opt);
  });
  const univOpt = document.createElement('option');
  univOpt.value = 'Universal'; univOpt.textContent = 'Universal';
  projSel.appendChild(univOpt);
  (list as any)._envVars = vars;
  document.getElementById('env-import-overlay')!.classList.add('open');
}

export function closeEnvImportModal() {
  document.getElementById('env-import-overlay')!.classList.remove('open');
}

export function confirmEnvImport() {
  const list = document.getElementById('env-import-list')!;
  const vars: EnvVar[] = (list as any)._envVars || [];
  const checked = Array.from(list.querySelectorAll<HTMLInputElement>('.env-import-check:checked'))
    .map(cb => parseInt(cb.dataset.idx!)).filter(i => !isNaN(i));
  if (!checked.length) { showToast('No variables selected', 'err'); return; }
  const catVal = (document.getElementById('env-import-category') as HTMLSelectElement).value;
  const projId = (document.getElementById('env-import-project') as HTMLSelectElement).value || 'Universal';
  const price = (document.getElementById('env-import-price') as HTMLSelectElement).value as VaultEntry['price_type'] || 'free';
  const envVal = (document.getElementById('env-import-env') as HTMLSelectElement).value as VaultEntry['environment'] || undefined;
  const cats = catVal ? [catVal] : [];
  const ids = projId === 'Universal' ? ['Universal'] : [projId, 'Universal'];
  const imported: VaultEntry[] = checked.map(i => ({
    provider: vars[i].name,
    api_key: vars[i].value,
    secretType: 'env_var' as SecretType,
    price_type: price,
    environment: envVal || null,
    categories: cats,
    projectIds: ids,
    scopes: [],
  }));
  st.vault.api_keys.push(...imported);
  persist();
  triggerRender();
  closeEnvImportModal();
  showToast(`Imported ${imported.length} variable${imported.length !== 1 ? 's' : ''} ✓`, 'ok');
}

// ── File select handler ───────────────────────────────────────────────────

export function handleFileSelect(input: HTMLInputElement) {
  const file = input.files?.[0];
  if (!file) return;
  const lower = file.name.toLowerCase();
  if (lower.endsWith('.env')) {
    const reader = new FileReader();
    reader.onload = (ev) => {
      const vars = parseEnvFile(ev.target!.result as string);
      if (!vars.length) { showToast('No variables found in .env file', 'err'); return; }
      openEnvImportModal(vars);
    };
    reader.readAsText(file);
    return;
  }
  if (lower.endsWith('.yaml') || lower.endsWith('.yml')) {
    const reader = new FileReader();
    reader.onload = (ev) => {
      try {
        const data: any = yaml.load(ev.target!.result as string);
        if (data && Array.isArray(data.api_keys)) { loadFullVault(data); return; }
        // Flat KEY: value map → env-import modal.
        const vars: EnvVar[] = data && typeof data === 'object' && !Array.isArray(data)
          ? Object.entries(data).map(([name, v]) => ({ name, value: typeof v === 'string' ? v : JSON.stringify(v) }))
          : [];
        if (!vars.length) { showToast('No importable data in YAML', 'err'); return; }
        openEnvImportModal(vars);
      } catch (err: any) { showToast(`Invalid YAML: ${err.message}`, 'err', 4000); }
    };
    reader.readAsText(file);
    return;
  }
  const reader = new FileReader();
  reader.onload = (ev) => {
    try {
      const data = JSON.parse(ev.target!.result as string);
      if (!Array.isArray(data.api_keys)) throw new Error('Missing api_keys array');
      loadFullVault(data);
    } catch (err: any) {
      showToast(`Invalid: ${err.message}`, 'err', 4000);
    }
  };
  reader.readAsText(file);
}

/** Replace the whole vault from a parsed `{ api_keys, projects?, user_categories? }` object. */
function loadFullVault(data: any) {
  const projects = data.projects || [{ id: 'Universal', name: 'Universal', description: 'All keys belong here by default' }];
  for (const key of data.api_keys) {
    if (!key.projectIds) key.projectIds = ['Universal'];
    else if (!key.projectIds.includes('Universal')) key.projectIds.push('Universal');
    if (!key.secretType) key.secretType = 'api_key';
  }
  st.vault.api_keys = data.api_keys;
  st.vault.user_categories = data.user_categories || [];
  st.vault.projects = projects;
  persist();
  // The whole vault was replaced — a project/tag/category selected against the
  // old one no longer resolves, and the freshly imported entries would render
  // into an empty grid.
  resetViewState();
  triggerRender();
  const banner = document.getElementById('load-banner');
  if (banner) banner.style.display = 'none';
  showToast(`Loaded ${st.vault.api_keys.length} keys ✓`, 'ok');
}
