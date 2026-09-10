/**
 * @file
 * Stored TOTP seeds — the authenticator half of the vault (Phase 22).
 * @description A `totp_secret` on an entry is a seed a *third-party service*
 *              issued, from which EnvVault produces the six digits you type
 *              into that service. It is the mirror image of the Phase 19 TOTP,
 *              which is a second factor on EnvVault's own sub-user login and
 *              lives in the `users` table; the two share the RFC 6238
 *              arithmetic in `vault-core/src/totp.rs` and nothing else.
 *
 * ## What is here and what is deliberately not
 *
 * **Parsing** lives here and in `vault-core/src/totp.rs`, as a twin pair pinned
 * by `tests/fixtures/parity/totp-seeds.json` — the same arrangement as
 * `ratelimit.ts`/`ratelimit.rs`. It has to exist here because the add/edit form
 * splits a pasted `otpauth://` URI as you type, before anything is saved.
 *
 * **Code generation does not.** There is exactly one HMAC implementation in
 * this project and it is the Rust one: a second would be a second thing to get
 * wrong, and getting it wrong produces six digits that look right and are
 * rejected by a service with no explanation. The app asks Rust over IPC
 * (`entry_totp_code`), which is the shape `pools.ts` already uses and the one
 * CLAUDE.md's twin-pair table says to prefer.
 *
 * The cost of that choice is that a browser-only dev server (`npm run dev`,
 * no Tauri) cannot show a code. It says so rather than showing a wrong one.
 */

import { st, inTauri } from './state';
import type { VaultEntry } from './types';

// ── Shape ─────────────────────────────────────────────────────────────────

/** HMAC an `otpauth://` URI may name. */
export type TotpAlgorithm = 'SHA1' | 'SHA256' | 'SHA512';

/** What a URI means when it omits the parameter — and so what a bare seed means. */
export const TOTP_DEFAULTS = {
  algorithm: 'SHA1' as TotpAlgorithm,
  digits: 6,
  period: 30,
} as const;

/** Fewest digits a code may carry (RFC 4226's floor). */
export const MIN_DIGITS = 6;
/**
 * Most digits a code may carry.
 *
 * Ten is where the 31-bit truncated value runs out; an eleventh digit would be
 * a constant zero that looks like part of the code.
 */
export const MAX_DIGITS = 10;
/** Longest step a stored seed may name. An hour; nothing real uses more. */
export const MAX_PERIOD_SECS = 3600;

/** The three numbers a seed is generated under. */
export interface TotpParams {
  algorithm: TotpAlgorithm;
  digits: number;
  period: number;
}

/** A parsed seed: the secret plus everything the URI said about it. */
export interface TotpStored extends TotpParams {
  /** Uppercase base32, no spaces, dashes or padding. */
  secret: string;
  /** The service, when the URI named one. Offered to the form, never forced. */
  issuer: string | null;
  /** The account at that service, when the URI named one. */
  account: string | null;
}

// ── Parsing (twin of vault-core/src/totp.rs) ──────────────────────────────

const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

/**
 * Uppercase, strip the grouping spaces, dashes and any `=` padding.
 *
 * The value that reaches the vault, so the same seed typed two ways is one
 * string with one fingerprint.
 */
export function normalizeB32(raw: string): string {
  return [...raw]
    .filter((c) => !/\s/.test(c) && c !== '-' && c !== '=')
    .join('')
    .toUpperCase();
}

/**
 * True when every character is in the RFC 4648 base32 alphabet and there is at
 * least one whole byte's worth.
 *
 * A seed that decodes to nothing is worse stored than refused: the entry then
 * shows a code field that is permanently blank and nothing distinguishes that
 * from a bug.
 */
function decodesToAtLeastOneByte(secret: string): boolean {
  if (!secret) return false;
  for (const c of secret) if (!B32.includes(c)) return false;
  // 5 bits per character; 8 bits to a byte.
  return Math.floor((secret.length * 5) / 8) >= 1;
}

/**
 * Percent-decode, leaving anything malformed alone.
 *
 * A label ending in a bare `%` is a typo in somebody's export, not an attack,
 * and `decodeURIComponent` throws on it — losing the whole seed over a stray
 * character helps nobody.
 */
function pctDecode(s: string): string {
  return s.replace(/\+/g, ' ').replace(/%[0-9a-fA-F]{2}/g, (m) => {
    try {
      return decodeURIComponent(m);
    } catch {
      return m;
    }
  });
}

/** Read the spelling `otpauth://` uses, case- and dash-insensitively. */
function parseAlgorithm(raw: string): TotpAlgorithm | null {
  const up = raw.trim().toUpperCase().replace(/-/g, '');
  return up === 'SHA1' || up === 'SHA256' || up === 'SHA512' ? up : null;
}

/**
 * Parse an `otpauth://totp/…` URI.
 *
 * Strict about the scheme and the type, forgiving about everything else: an
 * unknown parameter is ignored and an unreadable `digits` falls back to the
 * default. Only a missing or unusable `secret` is fatal. Half the URIs people
 * paste come out of a third party's export and are slightly wrong.
 *
 * @throws Error naming what was wrong, for the form to show verbatim.
 */
export function parseOtpauth(uri: string): TotpStored {
  if (uri.slice(0, 10).toLowerCase() !== 'otpauth://') throw new Error('not an otpauth:// URI');
  const rest = uri.slice(10);
  const q = rest.indexOf('?');
  const path = q < 0 ? rest : rest.slice(0, q);
  const query = q < 0 ? '' : rest.slice(q + 1);
  const slash = path.indexOf('/');
  const kind = slash < 0 ? path : path.slice(0, slash);
  const rawLabel = slash < 0 ? '' : path.slice(slash + 1);

  // `otpauth://hotp/` is counter-based: it has no clock, so "the current code"
  // does not exist for it. Storing one produces a card whose code never changes.
  if (kind.toLowerCase() !== 'totp')
    throw new Error(`only otpauth://totp/ is supported, got 'otpauth://${kind}/'`);

  let secret = '';
  let issuerParam: string | null = null;
  let algorithm: TotpAlgorithm = TOTP_DEFAULTS.algorithm;
  let digits: number = TOTP_DEFAULTS.digits;
  let period: number = TOTP_DEFAULTS.period;

  for (const pair of query.split('&').filter(Boolean)) {
    const eq = pair.indexOf('=');
    const k = (eq < 0 ? pair : pair.slice(0, eq)).toLowerCase();
    const v = eq < 0 ? '' : pair.slice(eq + 1);
    if (k === 'secret') secret = normalizeB32(pctDecode(v));
    else if (k === 'issuer') {
      const decoded = pctDecode(v).trim();
      if (decoded) issuerParam = decoded;
    } else if (k === 'algorithm') {
      const a = parseAlgorithm(pctDecode(v));
      if (a) algorithm = a;
    } else if (k === 'digits') {
      const d = Number(pctDecode(v).trim());
      if (Number.isInteger(d) && d >= MIN_DIGITS && d <= MAX_DIGITS) digits = d;
    } else if (k === 'period') {
      const p = Number(pctDecode(v).trim());
      if (Number.isInteger(p) && p > 0 && p <= MAX_PERIOD_SECS) period = p;
    }
  }

  if (!secret) throw new Error('the URI carries no secret= parameter');
  if (!decodesToAtLeastOneByte(secret)) throw new Error('the secret is not usable base32');

  // The label is `issuer:account` and the `issuer` parameter repeats it. Where
  // they disagree the parameter wins: it is what an exporter wrote deliberately,
  // while the label half is often text a user typed into a phone years ago.
  const label = pctDecode(rawLabel);
  const colon = label.indexOf(':');
  const labelIssuer = colon >= 0 ? label.slice(0, colon).trim() : '';
  const account = (colon >= 0 ? label.slice(colon + 1) : label).trim();

  return {
    secret,
    algorithm,
    digits,
    period,
    issuer: issuerParam || labelIssuer || null,
    account: account || null,
  };
}

/**
 * Read either a bare base32 seed or a full `otpauth://` URI.
 *
 * One entry point, because the form field, the paste handler and the CLI flag
 * all take whichever the user has to hand — and someone pasting a URI into a box
 * labelled "secret" is doing the reasonable thing.
 *
 * @throws Error naming what was wrong.
 */
export function parseTotpSeed(input: string): TotpStored {
  const trimmed = input.trim();
  if (!trimmed) throw new Error('empty TOTP secret');
  if (trimmed.slice(0, 8).toLowerCase() === 'otpauth:') return parseOtpauth(trimmed);
  const secret = normalizeB32(trimmed);
  if (!decodesToAtLeastOneByte(secret)) throw new Error('not usable base32');
  return { secret, ...TOTP_DEFAULTS, issuer: null, account: null };
}

/** Percent-encode everything outside the URI unreserved set. */
function pct(s: string): string {
  return [...s]
    .map((c) => (/[A-Za-z0-9\-._~]/.test(c) ? c : encodeURIComponent(c).replace(/%2F/gi, '%2F')))
    .join('')
    .replace(/[!'()*]/g, (c) => '%' + c.charCodeAt(0).toString(16).toUpperCase());
}

/**
 * Rebuild the `otpauth://` URI, for moving the seed to a phone.
 *
 * **The URI contains the secret**, so every caller of this is a materialising
 * path: it is refused to stdout in the CLI without `--reveal`, exactly as the
 * seed is, and the app only ever puts it on the clipboard at the user's request.
 *
 * `issuerFallback` and `accountFallback` are the entry's own provider and
 * account — vault data, therefore untrusted (invariant 4). They are escaped
 * here, not at the call site, so a provider named `a&issuer=Evil` cannot append
 * a parameter of its own choosing.
 */
export function buildOtpauthUri(
  stored: TotpStored,
  issuerFallback = '',
  accountFallback = '',
): string {
  const issuer = stored.issuer ?? issuerFallback;
  const account = stored.account ?? accountFallback;
  const label = issuer ? `${pct(issuer)}:${pct(account)}` : pct(account);
  let uri = `otpauth://totp/${label}?secret=${stored.secret}`;
  if (issuer) uri += `&issuer=${pct(issuer)}`;
  uri += `&algorithm=${stored.algorithm}&digits=${stored.digits}&period=${stored.period}`;
  return uri;
}

// ── Entry helpers ─────────────────────────────────────────────────────────

/** True when this entry carries an authenticator seed. */
export function hasTotp(entry: Pick<VaultEntry, 'totp_secret'>): boolean {
  return !!entry.totp_secret && entry.totp_secret.trim() !== '';
}

/**
 * The parameters an entry generates under, filling in every omitted default.
 *
 * Vault data is untrusted (invariant 4) and the TypeScript unions are erased at
 * runtime, so a `totp_period` of `0` or `"thirty"` arrives here from an imported
 * backup exactly as easily as from the form. Anything out of range falls back to
 * the default rather than reaching the divider.
 */
export function totpParamsOf(entry: VaultEntry): TotpParams {
  const algorithm = parseAlgorithm(String(entry.totp_algorithm ?? '')) ?? TOTP_DEFAULTS.algorithm;
  const rawDigits = Number(entry.totp_digits);
  const rawPeriod = Number(entry.totp_period);
  return {
    algorithm,
    digits:
      Number.isInteger(rawDigits) && rawDigits >= MIN_DIGITS && rawDigits <= MAX_DIGITS
        ? rawDigits
        : TOTP_DEFAULTS.digits,
    period:
      Number.isInteger(rawPeriod) && rawPeriod > 0 && rawPeriod <= MAX_PERIOD_SECS
        ? rawPeriod
        : TOTP_DEFAULTS.period,
  };
}

/** The stored seed of an entry, as the parser's shape. */
export function totpStoredOf(entry: VaultEntry): TotpStored {
  return {
    secret: normalizeB32(entry.totp_secret || ''),
    ...totpParamsOf(entry),
    issuer: null,
    account: null,
  };
}

/**
 * Seconds until the current code is replaced.
 *
 * Never returns 0: at a step boundary the *new* code has a full period ahead of
 * it, and a countdown that reads zero for one second in every period is a
 * countdown users report as a bug.
 */
export function totpRemainingSecs(period: number, unixSecs: number): number {
  const p = Math.min(Math.max(Math.trunc(period) || 1, 1), MAX_PERIOD_SECS);
  return p - (Math.floor(unixSecs) % p);
}

/** Split a code into two halves, the way every authenticator displays it. */
export function groupCode(code: string): string {
  if (code.length < 6) return code;
  const half = Math.ceil(code.length / 2);
  return `${code.slice(0, half)} ${code.slice(half)}`;
}

// ── Live codes (asks Rust; see the file header) ───────────────────────────

const invoke = (cmd: string, args?: Record<string, unknown>) =>
  (
    window as unknown as { __TAURI__?: { core?: { invoke?: (c: string, a?: unknown) => unknown } } }
  ).__TAURI__?.core?.invoke?.(cmd, args) as Promise<unknown> | undefined;

/** What `entry_totp_code` hands back. */
export interface LiveCode {
  code: string;
  remaining_secs: number;
  period: number;
  digits: number;
  algorithm: TotpAlgorithm;
}

/**
 * Cache of codes in flight, keyed by seed **and** parameters.
 *
 * Keyed by the seed rather than by entry id on purpose: two entries sharing a
 * seed show the same code, and an entry whose seed was just edited must not show
 * the code of the one it replaced. `expiresAt` is a wall-clock millisecond
 * stamp, so a tick that arrives after the step boundary refetches rather than
 * repainting a dead code.
 */
const codeCache = new Map<string, { code: string; expiresAt: number; period: number }>();
/** Seeds a request is already outstanding for, so a slow IPC call is not queued once a second. */
const inFlight = new Set<string>();

function cacheKey(secret: string, p: TotpParams): string {
  return `${secret}|${p.algorithm}|${p.digits}|${p.period}`;
}

/** Drops every cached code. Called on lock and on vault switch — see invariant 3. */
export function resetTotpCache(): void {
  codeCache.clear();
  inFlight.clear();
}

/**
 * The current code for an entry, or `null` while one is being fetched.
 *
 * Never throws: this is called from a one-second timer, and a rejected promise
 * per tick per card is a console nobody can read.
 */
export async function liveCodeFor(entry: VaultEntry): Promise<LiveCode | null> {
  if (!hasTotp(entry) || !inTauri) return null;
  const params = totpParamsOf(entry);
  const secret = normalizeB32(entry.totp_secret || '');
  const key = cacheKey(secret, params);
  const hit = codeCache.get(key);
  if (hit && hit.expiresAt > Date.now()) {
    return {
      code: hit.code,
      remaining_secs: Math.max(1, Math.ceil((hit.expiresAt - Date.now()) / 1000)),
      period: hit.period,
      digits: params.digits,
      algorithm: params.algorithm,
    };
  }
  if (inFlight.has(key)) return null;
  inFlight.add(key);
  try {
    const res = (await invoke('entry_totp_code', {
      secret,
      algorithm: params.algorithm,
      digits: params.digits,
      period: params.period,
    })) as LiveCode | undefined;
    if (!res) return null;
    codeCache.set(key, {
      code: res.code,
      expiresAt: Date.now() + res.remaining_secs * 1000,
      period: res.period,
    });
    return res;
  } catch {
    return null;
  } finally {
    inFlight.delete(key);
  }
}

// ── The ticker ────────────────────────────────────────────────────────────

let tickerId: ReturnType<typeof setInterval> | null = null;

/**
 * Repaint every `[data-totp-for]` element on screen once a second.
 *
 * Holds **no references** to entries or elements between ticks — it re-queries
 * the document and re-looks-up the entry by id each time (invariant 1: an index
 * or a node captured across a render points at whatever took its place). That is
 * also what makes it safe to call after any render without tearing anything
 * down.
 *
 * Idempotent by assignment, not by `addEventListener` (invariant 9): calling it
 * twice leaves one interval, not two racing ones.
 */
export function startTotpTicker(): void {
  if (tickerId !== null) return;
  tickerId = setInterval(() => {
    void tickTotp();
  }, 1000);
  void tickTotp();
}

/** Stops the ticker. Called on lock, so a locked vault has no timer running. */
export function stopTotpTicker(): void {
  if (tickerId !== null) {
    clearInterval(tickerId);
    tickerId = null;
  }
}

/**
 * One repaint pass. Exported for the tests, which cannot wait a second.
 *
 * The DOM contract is three elements per slot, all optional:
 * `[data-totp-for]` is the container and names the entry id;
 * `.totp-code` holds the digits; `.totp-countdown` is a bar whose width is the
 * fraction of the period remaining; `.totp-secs` is the number of seconds.
 */
export async function tickTotp(): Promise<void> {
  const slots = [...document.querySelectorAll<HTMLElement>('[data-totp-for]')];
  if (!slots.length) return;
  for (const slot of slots) {
    const id = slot.dataset.totpFor!;
    const entry = st.vault?.api_keys?.find((e) => e.id === id);
    const codeEl = slot.querySelector<HTMLElement>('.totp-code');
    const barEl = slot.querySelector<HTMLElement>('.totp-countdown-fill');
    const secsEl = slot.querySelector<HTMLElement>('.totp-secs');
    if (!entry || !hasTotp(entry)) {
      slot.hidden = true;
      continue;
    }
    slot.hidden = false;
    if (!inTauri) {
      // A browser-only dev server has no Rust to ask. Saying so beats showing
      // six digits that came from somewhere else.
      if (codeEl) codeEl.textContent = '— — —';
      slot.title = 'Codes are generated by the desktop app.';
      slot.dataset.totpCode = '';
      continue;
    }
    const live = await liveCodeFor(entry);
    if (!live) continue;
    if (codeEl) codeEl.textContent = groupCode(live.code);
    // The copy action reads the code off the container, so it copies what is on
    // screen rather than re-deriving it a tick later.
    slot.dataset.totpCode = live.code;
    if (secsEl) secsEl.textContent = String(live.remaining_secs);
    if (barEl) {
      const frac = Math.max(0, Math.min(1, live.remaining_secs / live.period));
      barEl.style.width = `${(frac * 100).toFixed(1)}%`;
      // Under ten seconds the bar turns warning-coloured; a class rather than an
      // inline colour so the theme controls which colour that is.
      barEl.classList.toggle('expiring', live.remaining_secs <= 10);
    }
    slot.setAttribute(
      'aria-label',
      `Authenticator code for ${entry.provider}: ${live.code}, ${live.remaining_secs} seconds remaining`,
    );
  }
}
