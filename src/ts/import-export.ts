/**
 * @file Import / export: copyAll, exportAs, .env import modal, file import.
 */

import type { VaultEntry, SecretType } from './types';
import { st, triggerRender, Exporter } from './state';
import { showToast, clipboardWrite } from './utils';
import { getFiltered, sorted } from './filters';

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
    download: `api-vault.${fmt === 'yaml' ? 'yaml' : fmt === 'json' ? 'json' : 'env'}`,
  });
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  setTimeout(() => URL.revokeObjectURL(url), 1000);
  showToast(`Exported as .${fmt}`, 'ok');
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
  st.store.save(st.vault);
  triggerRender();
  closeEnvImportModal();
  showToast(`Imported ${imported.length} variable${imported.length !== 1 ? 's' : ''} ✓`, 'ok');
}

// ── File select handler ───────────────────────────────────────────────────

export function handleFileSelect(input: HTMLInputElement) {
  const file = input.files?.[0];
  if (!file) return;
  if (file.name.toLowerCase().endsWith('.env')) {
    const reader = new FileReader();
    reader.onload = (ev) => {
      const vars = parseEnvFile(ev.target!.result as string);
      if (!vars.length) { showToast('No variables found in .env file', 'err'); return; }
      openEnvImportModal(vars);
    };
    reader.readAsText(file);
    return;
  }
  const reader = new FileReader();
  reader.onload = (ev) => {
    try {
      const data = JSON.parse(ev.target!.result as string);
      if (!Array.isArray(data.api_keys)) throw new Error('Missing api_keys array');
      const projects = data.projects || [{ id: 'Universal', name: 'Universal', description: 'All keys belong here by default' }];
      for (const key of data.api_keys) {
        if (!key.projectIds) key.projectIds = ['Universal'];
        else if (!key.projectIds.includes('Universal')) key.projectIds.push('Universal');
        if (!key.secretType) key.secretType = 'api_key';
      }
      st.vault.api_keys = data.api_keys;
      st.vault.user_categories = data.user_categories || [];
      st.vault.projects = projects;
      st.store.save(st.vault);
      st.expanded.clear();
      triggerRender();
      document.getElementById('load-banner')!.style.display = 'none';
      showToast(`Loaded ${st.vault.api_keys.length} keys ✓`, 'ok');
    } catch (err: any) {
      showToast(`Invalid: ${err.message}`, 'err', 4000);
    }
  };
  reader.readAsText(file);
}
