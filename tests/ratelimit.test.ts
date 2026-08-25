/**
 * The TypeScript half of the rate-limit parser's cross-implementation parity.
 *
 * Cases live in `tests/fixtures/parity/rate-limit.json`, and
 * `envv-cli/tests/ratelimit.rs` asserts the Rust parser against the identical
 * file. Reviewing two parsers for agreement does not work; the fixture is what
 * makes a divergence a test failure instead of a support ticket.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  parseRateLimit,
  formatRateLimit,
  normalizeRateLimit,
  RATE_LIMIT_PERIODS,
} from '../src/ts/ratelimit';

const HERE = dirname(fileURLToPath(import.meta.url));
const TABLE = JSON.parse(
  readFileSync(join(HERE, 'fixtures', 'parity', 'rate-limit.json'), 'utf8'),
) as {
  parse: { in: string; out: { count: number; period: string } | null }[];
  format: { count: number; period: string; out: string }[];
};

describe('parseRateLimit — golden table', () => {
  for (const c of TABLE.parse) {
    it(`${JSON.stringify(c.in)} -> ${JSON.stringify(c.out)}`, () => {
      expect(parseRateLimit(c.in)).toEqual(c.out);
    });
  }
});

describe('formatRateLimit — golden table', () => {
  for (const c of TABLE.format) {
    it(`${c.count} ${c.period} -> ${c.out}`, () => {
      expect(formatRateLimit(c.count, c.period as never)).toBe(c.out);
    });
  }

  it('round-trips: everything format writes, parse reads back', () => {
    for (const period of RATE_LIMIT_PERIODS) {
      const text = formatRateLimit(42, period);
      expect(parseRateLimit(text), `${text} must round-trip`).toEqual({
        count: 42,
        period,
      });
    }
  });

  it('renders nothing when either half is missing', () => {
    // A count with no period is a number, not a rate limit. Emitting "100/"
    // would produce a legacy string that parses back to null, so the two halves
    // of the entry would disagree after one save.
    expect(formatRateLimit(100, null)).toBe('');
    expect(formatRateLimit(null, 'hour')).toBe('');
    expect(formatRateLimit(undefined, undefined)).toBe('');
  });
});

describe('parseRateLimit is defensive about the field it reads', () => {
  // Vault data is untrusted input (CLAUDE.md invariant 4) and TypeScript unions
  // are erased at runtime, so this field can hold anything.
  it.each([null, undefined, 42, {}, [], true])('%p is not a rate limit', (v) => {
    expect(parseRateLimit(v)).toBeNull();
  });
});

describe('normalizeRateLimit', () => {
  it('migrates a legacy string into the structured pair', () => {
    expect(normalizeRateLimit({ rate_limit: '100/min' })).toEqual({
      rate_limit: '100/minute',
      rate_limit_count: 100,
      rate_limit_period: 'minute',
      rate_limit_note: null,
    });
  });

  it('keeps unparseable text rather than dropping it', () => {
    // Regression: the first version discarded anything it could not parse, so
    // opening an entry that said "varies by endpoint" and pressing Save wiped
    // the only description of its limit.
    expect(normalizeRateLimit({ rate_limit: 'varies by endpoint' })).toEqual({
      rate_limit: 'varies by endpoint',
      rate_limit_count: null,
      rate_limit_period: null,
      rate_limit_note: 'varies by endpoint',
    });
  });

  it('lets the structured pair win over a stale legacy string', () => {
    // Regression: precedence the other way round meant editing the number in
    // the form was silently reverted on the next read by the old string sitting
    // beside it.
    expect(
      normalizeRateLimit({
        rate_limit: '100/min',
        rate_limit_count: 5000,
        rate_limit_period: 'hour',
      }),
    ).toEqual({
      rate_limit: '5000/hour',
      rate_limit_count: 5000,
      rate_limit_period: 'hour',
      rate_limit_note: null,
    });
  });

  it('a parseable limit clears a stale note', () => {
    // Regression: the note is derived from unparseable text, but it used to be
    // carried forward unconditionally. Setting a real limit on an entry that
    // previously said "varies by endpoint" left BOTH — the card showed
    // "100/minute" with a note beside it flatly contradicting it.
    expect(
      normalizeRateLimit({
        rate_limit: '100 req/min',
        rate_limit_note: 'varies by endpoint',
      }),
    ).toEqual({
      rate_limit: '100/minute',
      rate_limit_count: 100,
      rate_limit_period: 'minute',
      rate_limit_note: null,
    });

    expect(
      normalizeRateLimit({
        rate_limit_count: 60,
        rate_limit_period: 'minute',
        rate_limit_note: 'varies by endpoint',
      }).rate_limit_note,
    ).toBeNull();
  });

  it('rejects a count with no period, and a period with no count', () => {
    expect(normalizeRateLimit({ rate_limit_count: 100 })).toEqual({
      rate_limit: null,
      rate_limit_count: null,
      rate_limit_period: null,
      rate_limit_note: null,
    });
    expect(normalizeRateLimit({ rate_limit_period: 'hour' })).toEqual({
      rate_limit: null,
      rate_limit_count: null,
      rate_limit_period: null,
      rate_limit_note: null,
    });
  });

  it('refuses a period the union does not contain', () => {
    // The union is erased at runtime; a remote server or an imported backup can
    // put "fortnight" here.
    expect(normalizeRateLimit({ rate_limit_count: 10, rate_limit_period: 'fortnight' })).toEqual({
      rate_limit: null,
      rate_limit_count: null,
      rate_limit_period: null,
      rate_limit_note: null,
    });
  });

  it('is empty for an entry that has no limit at all', () => {
    expect(normalizeRateLimit({})).toEqual({
      rate_limit: null,
      rate_limit_count: null,
      rate_limit_period: null,
      rate_limit_note: null,
    });
  });
});
