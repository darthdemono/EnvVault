/**
 * @file
 * FIDO Credential Exchange (CXF) import/export — Phase 24.5, desktop half.
 *
 * Same split as `totp-io.ts`: this module holds no parser and no mapping
 * rule. `vault_core::cxf` owns both, reached over IPC exactly as
 * `envv cxf import|export` reaches them directly — one implementation, not a
 * twin, so the app and the CLI cannot disagree about what a CXF item meant.
 *
 * Import is **append-only** (see the module doc on the Rust side for why):
 * re-running this against the same file produces duplicates rather than
 * being idempotent. The confirmation before writing says so.
 */

import { st, inTauri, persist, triggerRender } from './state';
import { showToast, showConfirm, saveFile } from './utils';
import type { VaultEntry } from './types';

const invoke = (cmd: string, args?: Record<string, unknown>) =>
  (
    window as unknown as { __TAURI__?: { core?: { invoke?: (c: string, a?: unknown) => unknown } } }
  ).__TAURI__?.core?.invoke?.(cmd, args) as Promise<unknown> | undefined;

/**
 * Parse a CXF document's text into entries ready to append. Never touches
 * `st.vault` itself — the caller decides whether to, after the user has
 * confirmed what is about to happen.
 */
export async function parseCxfFile(text: string): Promise<VaultEntry[]> {
  const entries = (await invoke('cxf_import', { text })) as VaultEntry[] | undefined;
  return entries ?? [];
}

/** The whole import flow: parse, confirm, append, save, repaint. */
export async function runCxfImport(text: string): Promise<void> {
  if (!inTauri) {
    showToast('Importing a CXF file needs the desktop app', 'err', 3500);
    return;
  }
  let entries: VaultEntry[];
  try {
    entries = await parseCxfFile(text);
  } catch (err) {
    showToast(String((err as Error)?.message ?? err), 'err', 6000);
    return;
  }
  if (!entries.length) {
    showToast('No items found in that file', 'err');
    return;
  }

  const names = entries
    .slice(0, 8)
    .map((e) => `  • ${e.provider}${e.secretType ? ` (${e.secretType})` : ''}`)
    .join('\n');
  const more = entries.length > 8 ? `\n  … and ${entries.length - 8} more` : '';
  const ok = await showConfirm(
    `Import ${entries.length} item${entries.length === 1 ? '' : 's'}?\n\n${names}${more}\n\n` +
      'Every item is appended as a new entry — re-importing the same file will ' +
      'create duplicates, not update the ones already here.',
  );
  if (!ok) return;

  st.vault.api_keys.push(...entries);
  void persist();
  triggerRender();
  showToast(`Imported ${entries.length} item${entries.length === 1 ? '' : 's'} ✓`, 'ok', 3500);
}

/** Build a CXF document from every entry currently visible. Returns the
 * document text, or `null` on failure/cancellation — never handed to a
 * toast, a log, or the clipboard, only to `saveFile`. */
async function buildCxfExport(): Promise<string | null> {
  if (!inTauri) {
    showToast('Exporting a CXF file needs the desktop app', 'err', 3500);
    return null;
  }
  return (
    ((await invoke('cxf_export', { entries: st.vault.api_keys })) as string | undefined) ?? null
  );
}

/** The whole export flow: confirm, build, write. */
export async function runCxfExport(): Promise<void> {
  const count = st.vault.api_keys.length;
  if (!count) {
    showToast('Nothing to export', 'err');
    return;
  }
  const ok = await showConfirm(
    `Write ${count} entr${count === 1 ? 'y' : 'ies'} as one CXF document?\n\n` +
      'The file is NOT encrypted — every secret value in the vault ends up in it, ' +
      'in whatever another password manager can read. Move it to the new app and delete it.',
  );
  if (!ok) return;

  let text: string | null;
  try {
    text = await buildCxfExport();
  } catch (err) {
    showToast(String((err as Error)?.message ?? err), 'err', 5000);
    return;
  }
  if (!text) return;
  const stamp = new Date().toISOString().slice(0, 10);
  const result = await saveFile(text, `envvault-${stamp}.cxf.json`, 'application/json');
  if (!result.ok) {
    showToast(`Could not write the file: ${result.error}`, 'err', 5000);
    return;
  }
  showToast(
    `Exported ${count} entr${count === 1 ? 'y' : 'ies'}${result.path ? ` → ${result.path}` : ''} ✓`,
    'ok',
    3500,
  );
}
