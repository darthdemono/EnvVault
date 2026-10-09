/**
 * @file
 * File-shaped credentials — Phase 23, E17.
 * @description The twin of `unv-cli/src/filecred.rs`, pinned by
 *              `tests/fixtures/parity/file-creds.json`.
 *
 * ## Some credentials are a file, and the variable names the path
 *
 * A GCP service-account JSON, an Apple `.p8`, an mTLS bundle and a `kubeconfig`
 * are consumed by pointing at them:
 * `GOOGLE_APPLICATION_CREDENTIALS=/etc/gcp/sa.json`. Copy-to-clipboard is the
 * wrong verb for all of them — pasting a 2 KB JSON blob into a `.env` produces a
 * variable the library will try to `open()` as a path, and the error names the
 * blob rather than the mistake.
 *
 * Two fields that had each solved half of it: `blob_ref` held a path and not the
 * file, so a fresh machine had the reference and not the credential;
 * `certificate_data` held the PEM and no path, so exporting it for a consumer
 * that wants a file had nowhere to write. This separates **what is stored** from
 * **how it is delivered** and lets one entry do both.
 *
 * ## Materialising by construction
 *
 * Writing the file *is* the delivery, so this is a `Resolver::materialising`
 * path by construction and the Phase 14 rule needs no special case: an exporter
 * that cannot get a materialising resolver simply cannot write the file. The
 * `.env` line this emits names the path, never the contents.
 */

import type { VaultEntry } from './types';

/**
 * The cap on stored file contents.
 *
 * A service-account JSON is ~2.3 KB and an embedded icon is already allowed
 * 96 KB, so storing content is cheap. A `kubeconfig` with several clusters or a
 * full chain bundle is a different promise, and **refusing above the cap beats
 * silently storing a truncated credential** — which would fail at deploy time
 * with an error about malformed JSON rather than about a vault.
 */
export const BLOB_MAX_BYTES = 128 * 1024;

/** True when this entry's payload is a file rather than a string. */
export function isFileShaped(entry: VaultEntry): boolean {
  return !!(entry.blob_data || entry.certificate_data || entry.cert_key_data || entry.mount_path);
}

/**
 * The contents this entry would write, and the extension they want.
 *
 * `blob_data` first: it is the general case and the one E17 added.
 * `certificate_data` is the pre-existing shape, and it is kept working rather
 * than migrated — a certificate entry that has worked for twenty phases must not
 * need editing to keep working.
 */
export function fileContentsOf(entry: VaultEntry): { text: string; ext: string } | null {
  if (entry.blob_data) return { text: entry.blob_data, ext: guessExt(entry.blob_data) };
  if (entry.certificate_data) return { text: entry.certificate_data, ext: 'pem' };
  if (entry.cert_key_data) return { text: entry.cert_key_data, ext: 'key' };
  return null;
}

/** A file extension guessed from the content's own shape, not from a name. */
function guessExt(text: string): string {
  const t = text.trimStart();
  if (t.startsWith('{') || t.startsWith('[')) return 'json';
  if (t.startsWith('-----BEGIN')) return 'pem';
  if (/^(apiVersion|kind|clusters):/m.test(t)) return 'yaml';
  return 'txt';
}

/**
 * The `.env` line a file-shaped entry contributes: the **path**, never the bytes.
 *
 * Returns `null` without a `mount_path`, because the honest answer to "what
 * variable does this set" is nothing until the user has said where the file
 * goes. Emitting the contents instead is the mistake this whole item exists to
 * stop.
 */
export function fileEnvLine(entry: VaultEntry, name: string): string | null {
  if (!entry.mount_path) return null;
  return `${name}=${entry.mount_path}`;
}
