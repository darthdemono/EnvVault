/**
 * @file
 * Pure secret-generation logic, shared by the Tools panel's generator panes
 * and the add/edit form's generator popover (A8, 2026-09-15).
 *
 * These used to live only in `tools.ts`, each wired straight to its own pane's
 * DOM. The form's "Generate" button had no way to reach the same logic without
 * either reimplementing it (a second place to get a character set or a byte
 * count wrong) or opening the Tools panel — which A8 is the fix for, because
 * the Tools panel sits behind the modal overlay and is unreachable while the
 * form is open. Moved here rather than copied: `tools.ts` now calls these too.
 *
 * Deliberately DOM-free: every function takes plain options and returns a
 * value (or, for the hash, a promise), so both a Tools pane and a popover pane
 * can wire whatever inputs they have to the same function without either one
 * reaching into the other's markup.
 */

// ── Entropy source (Phase 33.4) ──────────────────────────────────────────────
// The CLI's `--entropy-source` in the app. Generators here are synchronous, the
// Rust side is not, so a non-OS source works from a pool the app tops up over IPC
// (`entropy_fill`). An empty pool is an error the caller must show: silently
// falling back to the OS CSPRNG would tell a user who chose a hardware device that
// their secret came from it.

export class EntropyPoolEmpty extends Error {
  constructor() {
    super('The chosen entropy source is still filling its pool: try again in a moment.');
  }
}

let source = 'os';
let pool = new Uint8Array(0);
let refilling = false;
const POOL_BYTES = 8192;

/** Choose the source for every generator in the app; `os` needs no pool. */
export async function setEntropySource(id: string): Promise<void> {
  source = id || 'os';
  pool = new Uint8Array(0);
  if (source !== 'os') await refill();
}

export function entropySource(): string {
  return source;
}

async function refill(): Promise<void> {
  if (source === 'os' || refilling) return;
  refilling = true;
  try {
    const { invokeTauri } = await import('./tauri');
    const hex = await invokeTauri<string>('entropy_fill', { source, length: POOL_BYTES });
    const next = new Uint8Array(hex.length / 2);
    for (let i = 0; i < next.length; i++) next[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    pool = next;
  } finally {
    refilling = false;
  }
}

/** Fills `buf` from the chosen source: the OS CSPRNG, or the pool. */
export function fillRandom<T extends Uint8Array | Uint32Array>(buf: T): T {
  if (source === 'os') {
    crypto.getRandomValues(buf);
    return buf;
  }
  const need = buf.byteLength;
  if (pool.length < need) {
    void refill().catch(() => {});
    throw new EntropyPoolEmpty();
  }
  new Uint8Array(buf.buffer, buf.byteOffset, need).set(pool.subarray(0, need));
  pool = pool.slice(need);
  if (pool.length < POOL_BYTES / 2) void refill().catch(() => {});
  return buf;
}

/**
 * Runs a generator, turning an empty pool into a visible message instead of an
 * uncaught exception behind a button that then appears to do nothing.
 */
export function guardEntropy<T>(
  generate: () => T,
  onEmpty: (message: string) => void,
): T | undefined {
  try {
    return generate();
  } catch (e) {
    if (e instanceof EntropyPoolEmpty) {
      onEmpty(e.message);
      return undefined;
    }
    throw e;
  }
}

/** Bytes of randomness, encoded as hex, base64 or URL-safe base64. */
export function generateRandomBytes(
  nBytes: number,
  format: 'hex' | 'base64' | 'base64url',
): string {
  const buf = fillRandom(new Uint8Array(nBytes));
  if (format === 'hex')
    return Array.from(buf)
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('');
  const b64 = btoa(String.fromCharCode(...buf));
  if (format === 'base64url') return b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
  return b64;
}

export interface PasswordOptions {
  length: number;
  upper: boolean;
  lower: boolean;
  digits: boolean;
  symbols: boolean;
  /** Drops visually ambiguous characters (`0`/`O`, `1`/`l`/`I`, …). */
  noAmbig: boolean;
}

/**
 * The character set `generatePassword` draws from, for the strength meter that
 * wants to know its size without generating a password first.
 *
 * Kept as the single place these literal alphabets are written — two copies is
 * how the meter and the generator disagree the first time either is edited.
 */
export function passwordCharset(opts: Omit<PasswordOptions, 'length'>): string {
  let chars = '';
  if (opts.upper) chars += opts.noAmbig ? 'ABCDEFGHJKLMNPQRSTUVWXYZ' : 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  if (opts.lower) chars += opts.noAmbig ? 'abcdefghjkmnpqrstuvwxyz' : 'abcdefghijklmnopqrstuvwxyz';
  if (opts.digits) chars += opts.noAmbig ? '23456789' : '0123456789';
  if (opts.symbols) chars += '!@#$%^&*()-_=+[]{}|;:,.<>?';
  return chars;
}

/** A random password from the selected character sets, or `null` when none are selected. */
export function generatePassword(opts: PasswordOptions): string | null {
  const chars = passwordCharset(opts);
  if (!chars) return null;
  const buf = fillRandom(new Uint32Array(opts.length));
  return Array.from(buf)
    .map((n) => chars[n % chars.length])
    .join('');
}

/** Shannon entropy in bits for a password of this length over this many symbols. */
export function passwordEntropyBits(length: number, alphabetSize: number): number {
  return length * Math.log2(Math.max(alphabetSize, 1));
}

export type ApiKeyPattern =
  'jwt-secret' | 'base64-32' | 'hex-32' | 'hex-16' | 'bearer' | 'sk-prefix';

/** A value shaped like a real issuer's API key or signing secret. */
export function generateApiKeyPattern(pattern: ApiKeyPattern): string {
  const buf = fillRandom(new Uint8Array(64));
  const toHex = (b: Uint8Array) =>
    Array.from(b)
      .map((x) => x.toString(16).padStart(2, '0'))
      .join('');
  const toB64 = (b: Uint8Array) => btoa(String.fromCharCode(...b));
  const toB64url = (b: Uint8Array) =>
    toB64(b).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
  switch (pattern) {
    case 'jwt-secret':
      return toHex(buf.slice(0, 32));
    case 'base64-32':
      return toB64(buf.slice(0, 32));
    case 'hex-32':
      return toHex(buf.slice(0, 32));
    case 'hex-16':
      return toHex(buf.slice(0, 16));
    case 'bearer':
      return toB64url(buf.slice(0, 32));
    case 'sk-prefix':
      return 'sk-' + toB64url(buf.slice(0, 32)).slice(0, 48);
  }
}

/** A digest of `input`, formatted as hex or base64. */
export async function generateHash(
  input: string,
  algorithm: 'SHA-1' | 'SHA-256' | 'SHA-384' | 'SHA-512',
  format: 'hex' | 'base64',
): Promise<string> {
  const enc = new TextEncoder().encode(input);
  const hashBuf = await crypto.subtle.digest(algorithm, enc);
  const hashArr = new Uint8Array(hashBuf);
  if (format === 'base64') return btoa(String.fromCharCode(...hashArr));
  return Array.from(hashArr)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}
