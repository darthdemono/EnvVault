/**
 * @file
 * Rate limits: parsing the free-text form, and rendering the structured one.
 *
 * A `VaultEntry` carries the limit twice on purpose. `rate_limit_count` +
 * `rate_limit_period` are the structured pair everything reads; `rate_limit` is
 * a human string kept alongside it so that a vault edited by a current build
 * still means something to an older one, and so a limit nobody can express as
 * `<n> per <period>` ("varies by endpoint") is not thrown away.
 *
 * This module is the only thing that converts between the two. It has a twin —
 * `envv-cli/src/ratelimit.rs` — and the two are pinned against the same golden
 * table in `tests/fixtures/parity/rate-limit.json`, for the same reason the
 * config exporters are: two implementations of one format drift silently.
 */

import type { RateLimitPeriod } from './types';

/** The canonical periods, in ascending order of length. */
export const RATE_LIMIT_PERIODS: readonly RateLimitPeriod[] = [
  'second',
  'minute',
  'hour',
  'day',
  'week',
  'month',
  'year',
];

/**
 * Every spelling of a period this parser accepts, mapped to its canonical form.
 *
 * Deliberately generous on input and strict on output. The strings already in
 * people's vaults were typed by hand over years — `/min`, `per hr`, `a day`,
 * `req/mo` — and a migration that only understood its own output would drop
 * most of them into {@link parseRateLimit}'s `null` branch.
 */
const PERIOD_ALIASES: Record<string, RateLimitPeriod> = {
  s: 'second',
  sec: 'second',
  secs: 'second',
  second: 'second',
  seconds: 'second',
  m: 'minute',
  min: 'minute',
  mins: 'minute',
  minute: 'minute',
  minutes: 'minute',
  h: 'hour',
  hr: 'hour',
  hrs: 'hour',
  hour: 'hour',
  hours: 'hour',
  d: 'day',
  day: 'day',
  days: 'day',
  daily: 'day',
  w: 'week',
  wk: 'week',
  week: 'week',
  weeks: 'week',
  weekly: 'week',
  mo: 'month',
  mon: 'month',
  month: 'month',
  months: 'month',
  monthly: 'month',
  y: 'year',
  yr: 'year',
  yrs: 'year',
  year: 'year',
  years: 'year',
  annual: 'year',
  annually: 'year',
};

/**
 * Noise words that may sit between the number and the period: `100 req/min`,
 * `5000 requests per hour`, `60 calls/minute`.
 *
 * `request` and `call` are here; a unit that changes the meaning — `tokens`,
 * `GB` — deliberately is not, because "40000 tokens/min" is not a request limit
 * and silently recording it as one would be wrong. Those fall through to
 * {@link parseRateLimit} returning `null` and are preserved verbatim as a note.
 */
const NOISE = /^(?:req|reqs|request|requests|call|calls|hit|hits|api)$/;

/** A limit that could be read as a number and a window. */
export interface StructuredRateLimit {
  count: number;
  period: RateLimitPeriod;
}

/**
 * Read a free-text rate limit into a count and a period.
 *
 * Returns `null` for anything it cannot read with confidence — including a
 * count with no period, which is not a rate limit but a number.
 *
 * Vault data is untrusted input, so this takes `unknown`: an old vault, a
 * remote server, or an imported backup can put anything in the field, and the
 * TypeScript type saying `string | null` is erased at runtime.
 */
export function parseRateLimit(raw: unknown): StructuredRateLimit | null {
  if (typeof raw !== 'string') return null;
  const text = raw.trim().toLowerCase();
  if (!text) return null;

  // The number: optional thousands separators, no decimals. "1.5k/min" is
  // ambiguous enough to be worth refusing rather than guessing at.
  const numMatch = /^([0-9][0-9,_ ]*)/.exec(text);
  if (!numMatch) return null;
  const count = Number(numMatch[1].replace(/[,_ ]/g, ''));
  if (!Number.isSafeInteger(count) || count < 0) return null;

  // Everything after the number, with separators and noise words removed.
  const rest = text
    .slice(numMatch[0].length)
    .replace(/[/-]/g, ' ')
    .split(/\s+/)
    .filter((w) => w && w !== 'per' && w !== 'a' && w !== 'every' && !NOISE.test(w));

  // Exactly one token must remain, and it must name a period. Anything else —
  // "100 tokens min", "60 per user per minute" — means the string is saying
  // more than this schema can hold, and guessing at it loses the difference.
  if (rest.length !== 1) return null;
  const period = PERIOD_ALIASES[rest[0]];
  return period ? { count, period } : null;
}

/**
 * Render the structured pair as the canonical human string.
 *
 * Uses the full period name rather than an abbreviation so the output round
 * trips through {@link parseRateLimit} — a format that cannot read its own
 * output is how the two halves of an entry drift apart.
 */
export function formatRateLimit(
  count: number | null | undefined,
  period: RateLimitPeriod | null | undefined,
): string {
  if (count == null || !period) return '';
  return `${count}/${period}`;
}

/**
 * Normalise whatever an entry carries into the three fields it should carry.
 *
 * This is the migration, and it runs on read rather than as a one-off pass over
 * the vault: an entry can arrive from an older desktop build, from a remote
 * server running a different version, or from a backup restored years later,
 * and there is no single moment when "the vault has been migrated" is true.
 *
 * Precedence is structured-wins. If a caller has set `count`/`period` those are
 * authoritative and the legacy string is regenerated from them; only when they
 * are absent is the string consulted. Otherwise editing the number in the UI
 * would be silently reverted by a stale string sitting beside it.
 */
export function normalizeRateLimit(entry: {
  rate_limit?: unknown;
  rate_limit_count?: unknown;
  rate_limit_period?: unknown;
  rate_limit_note?: unknown;
}): {
  rate_limit: string | null;
  rate_limit_count: number | null;
  rate_limit_period: RateLimitPeriod | null;
  rate_limit_note: string | null;
} {
  const rawCount = entry.rate_limit_count;
  const rawPeriod = entry.rate_limit_period;

  const countOk = typeof rawCount === 'number' && Number.isSafeInteger(rawCount) && rawCount >= 0;
  const periodOk =
    typeof rawPeriod === 'string' && (RATE_LIMIT_PERIODS as readonly string[]).includes(rawPeriod);

  // The note is *derived*, never authored. It exists only to hold text that
  // could not be read as a limit, so once a limit can be read the note has
  // nothing left to say and is dropped. Carrying it forward produced an entry
  // reading "100/minute" with a note beside it saying "varies by endpoint" —
  // two contradictory answers to one question, the newer one silently
  // undermined by the older.
  //
  // A count without a period is not a rate limit; both halves or neither.
  if (countOk && periodOk) {
    const period = rawPeriod as RateLimitPeriod;
    return {
      rate_limit: formatRateLimit(rawCount, period),
      rate_limit_count: rawCount,
      rate_limit_period: period,
      rate_limit_note: null,
    };
  }

  const parsed = parseRateLimit(entry.rate_limit);
  if (parsed) {
    return {
      rate_limit: formatRateLimit(parsed.count, parsed.period),
      rate_limit_count: parsed.count,
      rate_limit_period: parsed.period,
      rate_limit_note: null,
    };
  }

  // Unparseable, but not empty: keep the human's words. They knew something the
  // schema does not express, and dropping the text on first save under a new
  // version is data loss nobody asked for.
  const legacy = typeof entry.rate_limit === 'string' ? entry.rate_limit.trim() : '';
  return {
    rate_limit: legacy || null,
    rate_limit_count: null,
    rate_limit_period: null,
    rate_limit_note: legacy || null,
  };
}
