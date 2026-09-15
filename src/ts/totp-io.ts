/**
 * @file
 * Importing and exporting authenticator seeds (Phase 22).
 * @description Ente Auth, Aegis, 2FAS, andOTP, Bitwarden and Google
 *              Authenticator on the way in; a portable `otpauth://` list, Aegis
 *              or 2FAS on the way out.
 *
 * ## Everything hard happens in Rust
 *
 * Six formats parsed twice is six chances for the app and the CLI to disagree
 * about what a file meant, and a disagreement here is a seed that imports with
 * the wrong period and produces codes the issuer rejects. So this module holds
 * no parser, no format writer and — the part with real consequences — **no merge
 * rules**. `vault_core::totp_import` owns all three; `envv totp import` and the
 * button wired up here call the same functions.
 *
 * What is left here is the file picker, the confirmation, and turning the report
 * into a sentence.
 *
 * ## The export is a file full of secrets
 *
 * `buildTotpExport` returns plaintext seeds. It is handed straight to a download
 * and never to a toast, a log or the clipboard — the app's equivalent of the
 * CLI's `--out`, which is the only way a real value leaves there either.
 */

import { st, inTauri, persist, triggerRender } from './state';
import { showToast, showConfirm } from './utils';
import { downloadText } from './import-export';
import type { VaultEntry } from './types';

const invoke = (cmd: string, args?: Record<string, unknown>) =>
  (
    window as unknown as { __TAURI__?: { core?: { invoke?: (c: string, a?: unknown) => unknown } } }
  ).__TAURI__?.core?.invoke?.(cmd, args) as Promise<unknown> | undefined;

/** One entry the importer declined, and why. Never carries a secret. */
export interface SkippedImport {
  name: string;
  reason: string;
}

/** What `totp_import_merge` hands back. */
export interface MergeReport {
  entries: VaultEntry[];
  format: string;
  created: { provider: string; account: string }[];
  updated: { provider: string; account: string }[];
  unchanged: { provider: string; account: string }[];
  /** Entries already holding a *different* seed. Left alone; see the note below. */
  conflicts: { provider: string; account: string }[];
  skipped: SkippedImport[];
}

/** Formats the exporter can write, in the order the picker offers them. */
export const EXPORT_FORMATS: { value: string; label: string; ext: string }[] = [
  { value: 'otpauth', label: 'otpauth:// list — Ente, KeePassXC, most apps', ext: 'txt' },
  { value: 'aegis', label: 'Aegis (unencrypted JSON)', ext: 'json' },
  { value: '2fas', label: '2FAS (unencrypted JSON)', ext: 'json' },
];

/**
 * Read an export and merge it into the vault.
 *
 * **Never overwrites a seed that is already there with a different one.** A
 * stored second factor is not recoverable once gone, and an import is exactly
 * the moment a stale export gets pointed at a vault that has since been
 * re-enrolled. Those are reported and left alone; `force` is how the user says
 * they meant it, and the old value still lands in `version_history`.
 *
 * @param text the file's contents, whatever app wrote it
 * @param force replace a differing seed instead of reporting it
 */
export async function importTotpFile(text: string, force = false): Promise<MergeReport | null> {
  if (!inTauri) {
    showToast('Importing authenticator files needs the desktop app', 'err', 3500);
    return null;
  }
  const res = (await invoke('totp_import_merge', {
    entries: st.vault.api_keys,
    text,
    force,
    project: null,
    category: null,
  })) as MergeReport | undefined;
  return res ?? null;
}

/** Turn a merge report into the one sentence a toast can hold. */
export function summarise(r: MergeReport): string {
  const bits: string[] = [];
  if (r.created.length) bits.push(`${r.created.length} added`);
  if (r.updated.length) bits.push(`${r.updated.length} updated`);
  if (r.unchanged.length) bits.push(`${r.unchanged.length} already current`);
  if (r.conflicts.length) bits.push(`${r.conflicts.length} left alone`);
  if (r.skipped.length) bits.push(`${r.skipped.length} skipped`);
  return bits.length ? bits.join(', ') : 'nothing to import';
}

/**
 * The whole import flow: parse, confirm, apply, repaint.
 *
 * The confirmation is not ceremony. An import can create dozens of entries and
 * the only thing standing between "I picked the right file" and "I picked last
 * year's export" is being shown the counts and the conflicts before anything is
 * written.
 */
export async function runTotpImport(text: string): Promise<void> {
  let report: MergeReport | null;
  try {
    report = await importTotpFile(text, false);
  } catch (err) {
    // The Rust side names the app and the fix for an encrypted export, which is
    // the common failure. Passing it through verbatim beats paraphrasing it.
    showToast(String((err as Error)?.message ?? err), 'err', 6000);
    return;
  }
  if (!report) return;

  const total =
    report.created.length +
    report.updated.length +
    report.unchanged.length +
    report.conflicts.length;
  if (!total) {
    showToast(
      report.skipped.length
        ? `Nothing importable — ${report.skipped.length} entries were skipped`
        : 'No seeds found in that file',
      'err',
      4000,
    );
    return;
  }

  const lines = [`Read a ${report.format} export: ${summarise(report)}.`];
  if (report.conflicts.length) {
    lines.push(
      '',
      `${report.conflicts.length} of these already hold a different seed and will NOT be touched:`,
      report.conflicts
        .map((c) => `  • ${c.provider}${c.account ? ` (${c.account})` : ''}`)
        .join('\n'),
      '',
      'Replace them only if this file is newer than what is in the vault.',
    );
  }
  if (report.skipped.length) {
    lines.push(
      '',
      'Skipped:',
      report.skipped
        .slice(0, 8)
        .map((s) => `  • ${s.name} — ${s.reason}`)
        .join('\n'),
    );
  }
  lines.push('', 'Import?');

  if (!(await showConfirm(lines.join('\n')))) return;

  st.vault.api_keys = report.entries;
  void persist();
  triggerRender();
  showToast(`Imported: ${summarise(report)}`, 'ok', 4000);

  if (report.conflicts.length) {
    showToast(
      `${report.conflicts.length} entries kept their existing seed. Edit them by hand if the import was the newer one.`,
      'err',
      7000,
    );
  }
}

/**
 * Build an export file from every entry carrying a seed.
 *
 * Returns plaintext secret material. The one caller hands it to a download and
 * nothing else.
 */
export async function buildTotpExport(format: string): Promise<string | null> {
  if (!inTauri) {
    showToast('Exporting authenticator seeds needs the desktop app', 'err', 3500);
    return null;
  }
  const items = st.vault.api_keys
    .filter((e) => !!e.totp_secret && String(e.totp_secret).trim() !== '')
    .map((e) => ({
      issuer: e.provider,
      account: e.account_name || null,
      secret: String(e.totp_secret),
      algorithm: e.totp_algorithm || 'SHA1',
      digits: e.totp_digits || 6,
      period: e.totp_period || 30,
      note: null,
    }));
  if (!items.length) {
    showToast('No entry carries an authenticator seed', 'err');
    return null;
  }
  return ((await invoke('totp_export_build', { items, format })) as string | undefined) ?? null;
}

/**
 * The whole export flow: confirm, build, download.
 *
 * The confirmation says what the file is in plain words. Every other export in
 * this app produces something redacted or non-secret; this one is the seeds
 * themselves, and a user who does not know that will leave it in Downloads.
 */
export async function runTotpExport(format: string): Promise<void> {
  const meta = EXPORT_FORMATS.find((f) => f.value === format) ?? EXPORT_FORMATS[0];
  const count = st.vault.api_keys.filter(
    (e) => !!e.totp_secret && String(e.totp_secret).trim() !== '',
  ).length;
  if (!count) {
    showToast('No entry carries an authenticator seed', 'err');
    return;
  }
  const ok = await showConfirm(
    `Write ${count} authenticator seeds as ${meta.label}?\n\n` +
      'The file is NOT encrypted — it is the seeds themselves, and anyone ' +
      'holding it can generate your codes forever.\n\n' +
      'Move it to the new device and delete it.',
  );
  if (!ok) return;

  let body: string | null;
  try {
    body = await buildTotpExport(format);
  } catch (err) {
    showToast(String((err as Error)?.message ?? err), 'err', 5000);
    return;
  }
  if (!body) return;
  const stamp = new Date().toISOString().slice(0, 10);
  void downloadText(body, `envvault-2fa-${format}-${stamp}.${meta.ext}`, `Exported ${count} seeds`);
}
