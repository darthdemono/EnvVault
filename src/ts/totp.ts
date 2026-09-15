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

/**
 * What a stored seed *is*, which decides what "the current code" means for it.
 *
 * The three differ in where the counter comes from, not in the arithmetic:
 * `totp` divides the clock by the period, `steam` does the same and renders the
 * result in Steam's five-character alphabet, and `hotp` has no clock at all and
 * uses a number the vault stores and the user advances.
 *
 * Phase 22 refused the last two. That was right while nothing could store a
 * counter — an `hotp` entry with nowhere to keep its position shows a code that
 * never changes — and Phase 22.2 gives it somewhere.
 */
export type TotpKind = 'totp' | 'hotp' | 'steam';

/** Characters a Steam code is drawn from. Here only to validate what Rust made. */
export const STEAM_ALPHABET = '23456789BCDFGHJKMNPQRTVWXY';

/** How many characters a Steam code carries. Steam fixes it; it is not a setting. */
export const STEAM_DIGITS = 5;

/** What a URI means when it omits the parameter — and so what a bare seed means. */
export const TOTP_DEFAULTS = {
  kind: 'totp' as TotpKind,
  algorithm: 'SHA1' as TotpAlgorithm,
  digits: 6,
  period: 30,
  counter: 0,
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

/** What a seed is, and the numbers it is generated under. */
export interface TotpParams {
  kind: TotpKind;
  algorithm: TotpAlgorithm;
  digits: number;
  period: number;
  /**
   * The next counter an `hotp` seed will use. Zero for the other two kinds.
   *
   * State, not configuration — the only number here a correct implementation
   * writes back, which is why advancing it is an explicit action rather than a
   * side effect of reading a code.
   */
  counter: number;
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

/** Read the kind an `otpauth://` path or a stored field names. */
export function parseTotpKind(raw: string): TotpKind | null {
  const low = raw.trim().toLowerCase();
  return low === 'totp' || low === 'hotp' || low === 'steam' ? low : null;
}

/**
 * Force the shape Steam fixes, whatever the file said.
 *
 * Steam issues one shape — SHA-1, five characters, a 30-second step — and a
 * generic exporter that wrote `digits: 6` beside a Steam seed would otherwise
 * produce six characters no Steam login accepts.
 */
function steamNormalised(p: TotpParams): TotpParams {
  if (p.kind !== 'steam') return p;
  return { kind: 'steam', algorithm: 'SHA1', digits: STEAM_DIGITS, period: 30, counter: 0 };
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

  // Phase 22 refused everything but `totp` here, because an `hotp` seed with
  // nowhere to keep its counter shows a code that never changes. The entry can
  // hold one now; anything that is still not one of the three is refused by name.
  const parsedKind = parseTotpKind(kind);
  if (!parsedKind)
    throw new Error(
      `only otpauth://totp/, //hotp/ and //steam/ are supported, got 'otpauth://${kind}/'`,
    );

  let seedKind: TotpKind = parsedKind;
  let secret = '';
  let issuerParam: string | null = null;
  let algorithm: TotpAlgorithm = TOTP_DEFAULTS.algorithm;
  let digits: number = TOTP_DEFAULTS.digits;
  let period: number = TOTP_DEFAULTS.period;
  let counter = 0;

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
    } else if (k === 'counter') {
      // RFC 4226 calls it the initial counter value; every exporter writes the
      // *next* value to use, which is what the entry stores.
      const c = Number(pctDecode(v).trim());
      if (Number.isInteger(c) && c >= 0) counter = c;
    } else if (k === 'encoder') {
      // Aegis writes `encoder=steam` on an `otpauth://totp/` URI rather than
      // using the `steam` path. Reading only one of the two spellings imports
      // the seed as an ordinary six-digit TOTP, which Steam rejects with no
      // explanation. Never inferred from the issuer *name*, which is text a user
      // can edit into anything.
      if (pctDecode(v).trim().toLowerCase() === 'steam') seedKind = 'steam';
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

  // `encoder=steam` can arrive after `digits=6`, and the `steam` path arrives
  // before any parameter at all, so the shape Steam fixes is forced once the
  // whole query has been read rather than in whichever arm saw it first.
  const params = steamNormalised({
    kind: seedKind,
    algorithm,
    digits,
    period,
    counter: seedKind === 'hotp' ? counter : 0,
  });

  return {
    secret,
    ...params,
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
  // Steam is written as `otpauth://totp/…&encoder=steam` rather than as
  // `otpauth://steam/`: both spellings exist, Aegis reads either, and the `totp`
  // path is the one every *other* authenticator will at least import as a
  // working — if wrongly rendered — seed instead of rejecting the line outright.
  const path = stored.kind === 'hotp' ? 'hotp' : 'totp';
  let uri = `otpauth://${path}/${label}?secret=${stored.secret}`;
  if (issuer) uri += `&issuer=${pct(issuer)}`;
  uri += `&algorithm=${stored.algorithm}&digits=${stored.digits}`;
  if (stored.kind === 'hotp') {
    // A counter-based URI carries its position instead of a period. Dropping it
    // hands the next phone a seed starting from zero, which is a second factor
    // that fails until the account is resynced.
    uri += `&counter=${stored.counter}`;
  } else {
    uri += `&period=${stored.period}`;
    if (stored.kind === 'steam') uri += '&encoder=steam';
  }
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
  const kind = parseTotpKind(String(entry.totp_kind ?? '')) ?? TOTP_DEFAULTS.kind;
  const algorithm = parseAlgorithm(String(entry.totp_algorithm ?? '')) ?? TOTP_DEFAULTS.algorithm;
  const rawDigits = Number(entry.totp_digits);
  const rawPeriod = Number(entry.totp_period);
  const rawCounter = Number(entry.totp_counter);
  return steamNormalised({
    kind,
    algorithm,
    digits:
      Number.isInteger(rawDigits) && rawDigits >= MIN_DIGITS && rawDigits <= MAX_DIGITS
        ? rawDigits
        : TOTP_DEFAULTS.digits,
    period:
      Number.isInteger(rawPeriod) && rawPeriod > 0 && rawPeriod <= MAX_PERIOD_SECS
        ? rawPeriod
        : TOTP_DEFAULTS.period,
    // A counter is only ever read for an `hotp` seed. Carrying one on a
    // time-based entry would be a number that looks like state and is never
    // used, which is the kind of field a later reader trusts.
    counter: kind === 'hotp' && Number.isInteger(rawCounter) && rawCounter >= 0 ? rawCounter : 0,
  });
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
  /**
   * The code that replaces `code`, when it was asked for.
   *
   * Absent unless requested: it is a second working credential with a longer
   * life than the one on screen, so a panel that always painted one would put
   * two live codes in every screenshot.
   */
  next_code?: string | null;
  kind: TotpKind;
  /** The counter this code came from — an `hotp` entry's stored position. */
  counter: number;
  /** Seconds until `code` is replaced, or **0 for `hotp`**, which has no clock. */
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
const codeCache = new Map<
  string,
  { code: string; next: string | null; expiresAt: number; period: number }
>();

/**
 * How long a counter-based code stays cached.
 *
 * It has no expiry of its own — it stands until the counter moves, and moving
 * the counter changes the cache key — so this is only a ceiling on how long a
 * stale entry survives a vault edited elsewhere. Five minutes rather than
 * forever, and rather than one second, which would ask Rust for an unchanged
 * answer sixty times a minute per card.
 */
const HOTP_CACHE_MS = 5 * 60 * 1000;
/** Seeds a request is already outstanding for, so a slow IPC call is not queued once a second. */
const inFlight = new Set<string>();

/**
 * The last refusal reason per cache key, so a card can *say* why it is blank.
 *
 * A1 (2026-09-14): `liveCodeFor` used to swallow the Rust error entirely and
 * return `null`, indistinguishable from "still fetching" — so a permanent
 * refusal looked the same as a slow tick, forever. `tickTotp` reads this to
 * set the slot's `title`.
 */
const lastError = new Map<string, string>();

function cacheKey(secret: string, p: TotpParams, withNext: boolean): string {
  // The counter is part of the key: advancing an `hotp` entry must show the new
  // code immediately rather than the cached one for the position it just left.
  return `${secret}|${p.kind}|${p.algorithm}|${p.digits}|${p.period}|${p.counter}|${withNext ? 'n' : ''}`;
}

/** Drops every cached code. Called on lock and on vault switch — see invariant 3. */
export function resetTotpCache(): void {
  codeCache.clear();
  inFlight.clear();
  lastError.clear();
}

/**
 * The current code for an entry, or `null` while one is being fetched.
 *
 * Never throws: this is called from a one-second timer, and a rejected promise
 * per tick per card is a console nobody can read.
 */
export async function liveCodeFor(entry: VaultEntry, withNext = false): Promise<LiveCode | null> {
  if (!hasTotp(entry) || !inTauri) return null;
  // `entry_totp_code` is pure over its arguments (A11, 2026-09-14) — it no
  // longer checks the *local* SQLCipher key, which used to refuse every call
  // on a remote-only session and paint every remote 2FA code blank. The gate
  // that matters is "does the renderer hold a decrypted vault at all", which
  // is `st.vaultOpen` regardless of whether that vault is local or remote.
  if (!st.vaultOpen) return null;
  const params = totpParamsOf(entry);
  const secret = normalizeB32(entry.totp_secret || '');
  const key = cacheKey(secret, params, withNext);
  const hit = codeCache.get(key);
  if (hit && hit.expiresAt > Date.now()) {
    return {
      code: hit.code,
      next_code: hit.next,
      kind: params.kind,
      counter: params.counter,
      // A counter-based code is not replaced by the passage of time, so there is
      // no countdown to recompute — and a ring whose number never moves reads as
      // a frozen UI.
      remaining_secs:
        params.kind === 'hotp' ? 0 : Math.max(1, Math.ceil((hit.expiresAt - Date.now()) / 1000)),
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
      kind: params.kind,
      algorithm: params.algorithm,
      digits: params.digits,
      period: params.period,
      counter: params.counter,
      withNext,
    })) as LiveCode | undefined;
    if (!res) return null;
    lastError.delete(key);
    codeCache.set(key, {
      code: res.code,
      next: res.next_code ?? null,
      // An `hotp` code has no expiry: it stands until somebody advances the
      // counter, and advancing changes the cache key. Holding it for one period
      // anyway would mean re-asking Rust once a minute for an answer that cannot
      // have changed.
      expiresAt:
        res.kind === 'hotp' ? Date.now() + HOTP_CACHE_MS : Date.now() + res.remaining_secs * 1000,
      period: res.period,
    });
    return res;
  } catch (err) {
    // Still never throws — but the reason is kept, not dropped, so a slot that
    // will never produce a code stops looking identical to one that is just
    // slow. See `lastError` above.
    lastError.set(key, err instanceof Error ? err.message : String(err));
    return null;
  } finally {
    inFlight.delete(key);
  }
}

/** The reason the last request for this entry's code failed, if any. */
export function lastTotpError(entry: VaultEntry, withNext = false): string | null {
  if (!hasTotp(entry)) return null;
  const params = totpParamsOf(entry);
  const secret = normalizeB32(entry.totp_secret || '');
  return lastError.get(cacheKey(secret, params, withNext)) ?? null;
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
    // The panel asks for the next code by marking its slots; a card does not.
    const wantNext = slot.dataset.totpNext === '1';
    const live = await liveCodeFor(entry, wantNext);
    if (!live) {
      // A1: name the refusal instead of leaving the placeholder unexplained —
      // a blank code and a slow tick used to look identical, forever.
      const reason = lastTotpError(entry, wantNext);
      if (reason) {
        if (codeEl) codeEl.textContent = '— — —';
        slot.title = `Code not available: ${reason}`;
        slot.dataset.totpCode = '';
      } else if (!st.vaultOpen) {
        if (codeEl) codeEl.textContent = '— — —';
        slot.title = 'Vault is locked.';
        slot.dataset.totpCode = '';
      }
      continue;
    }
    slot.title = '';
    if (codeEl) codeEl.textContent = groupCode(live.code);
    const nextEl = slot.querySelector<HTMLElement>('.totp-next');
    if (nextEl) {
      nextEl.textContent = live.next_code ? groupCode(live.next_code) : '';
      nextEl.hidden = !live.next_code;
    }
    // A counter-based entry has no clock: no ring, no seconds, and its position
    // shown instead so the user can see what they are about to advance past.
    slot.dataset.totpKind = live.kind;
    if (live.kind === 'hotp') {
      const counterEl = slot.querySelector<HTMLElement>('.totp-counter');
      if (counterEl) counterEl.textContent = `#${live.counter}`;
      if (secsEl) secsEl.textContent = '';
      if (barEl) barEl.style.width = '100%';
      slot.dataset.totpCode = live.code;
      slot.setAttribute(
        'aria-label',
        `Counter-based code for ${entry.provider}: ${live.code}, counter ${live.counter}`,
      );
      continue;
    }
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
