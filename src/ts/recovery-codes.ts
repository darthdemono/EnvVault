/**
 * Single-use recovery codes (Phase 24.5). Twin of the `code_*`/`mark_used`
 * functions in `vault-core/src/type_emit.rs`, pinned by
 * `tests/fixtures/parity/recovery-codes.json`.
 *
 * One code per line in the entry's `codes` variable. A used code is not removed:
 * it keeps its text and gains `\tUSED <date>`, so "which did I burn?" is still
 * answerable. **Reading never consumes** (the HOTP rule) — a code is spent when
 * the service accepts it, and only the user knows that.
 */
import type { VaultEntry } from './types';

function lines(entry: Pick<VaultEntry, 'extra_vars'>): string[] {
  const raw = entry.extra_vars?.find((v) => v.key === 'codes')?.value ?? '';
  return raw
    .split('\n')
    .map((l) => l.replace(/\s+$/, ''))
    .filter((l) => l.trim() !== '');
}

export function codeStatus(entry: Pick<VaultEntry, 'extra_vars'>): {
  total: number;
  remaining: number;
} {
  const all = lines(entry);
  return { total: all.length, remaining: all.filter((l) => !l.includes('\t')).length };
}

export function nextCode(entry: Pick<VaultEntry, 'extra_vars'>): string | null {
  return lines(entry).find((l) => !l.includes('\t')) ?? null;
}

/** New value for `codes`, or throws with the reason. */
export function markUsed(
  entry: Pick<VaultEntry, 'extra_vars'>,
  code: string | null,
  date: string,
): string {
  const all = lines(entry);
  const idx =
    code === null
      ? all.findIndex((l) => !l.includes('\t'))
      : all.findIndex((l) => l.split('\t')[0] === code.trim());
  if (idx < 0)
    throw new Error(code === null ? 'no unused codes remain' : 'that code is not in this entry');
  if (all[idx].includes('\t')) throw new Error('that code is already marked used');
  all[idx] = `${all[idx]}\tUSED ${date}`;
  return all.join('\n');
}
