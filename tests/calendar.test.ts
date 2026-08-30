/**
 * The iCalendar feed.
 *
 * Cross-implementation agreement with `envv-cli/src/calendar.rs` is pinned by
 * the golden file in `tests/cli-parity.test.ts`. What this suite covers is the
 * behaviour that golden cannot show: what happens to entries with missing,
 * malformed or awkward dates, and the two properties the format has to keep —
 * no secret values, and stable UIDs.
 */
import { describe, it, expect } from 'vitest';
import {
  buildIcs,
  eventsForEntry,
  icsEscape,
  icsFold,
  nextDay,
  rotationDue,
  toIcsDate,
  entryLabel,
} from '../src/ts/calendar';
import type { VaultEntry } from '../src/ts/types';

const entry = (over: Partial<VaultEntry>): VaultEntry =>
  ({
    id: 'e1',
    provider: 'GitHub',
    api_key: 'ghp_value',
    price_type: 'free',
    categories: [],
    projectIds: ['Universal'],
    scopes: [],
    ...over,
  }) as VaultEntry;

describe('escaping and folding', () => {
  it('escapes the four reserved characters', () => {
    // Note the doubled backslashes in the expectation: `'\;'` in a JavaScript
    // string literal is just `;`, which is the same trap that made the escaper
    // itself a no-op for semicolons before this test existed.
    expect(icsEscape('a,b;c\\d\ne')).toBe('a\\,b\\;c\\\\d\\ne');
  });

  it('folds on octets, not characters', () => {
    // Ninety é: 90 characters, 180 bytes. Folding by string length leaves a
    // line that JavaScript calls short and a parser calls illegal.
    const line = 'é'.repeat(90);
    const folded = icsFold(line);
    for (const seg of folded.split('\r\n')) {
      const content = seg.startsWith(' ') ? seg.slice(1) : seg;
      expect(new TextEncoder().encode(content).length).toBeLessThanOrEqual(75);
    }
    // Unfolding must reproduce the input exactly — including the multi-byte
    // characters a naive split would have cut in half.
    expect(folded.replace(/\r\n /g, '')).toBe(line);
  });

  it('leaves a short line alone', () => {
    expect(icsFold('SUMMARY:short')).toBe('SUMMARY:short');
  });
});

describe('dates', () => {
  it('rejects an unparseable date instead of emitting one', () => {
    // A `DTSTART:NaN` is not a date a calendar can import; the event simply
    // must not exist.
    expect(toIcsDate('not a date')).toBeNull();
    expect(toIcsDate(null)).toBeNull();
    expect(toIcsDate(undefined)).toBeNull();
  });

  it('rolls over month and year boundaries', () => {
    // An all-day DTEND is exclusive, so it is always the following day —
    // including on 31 December, where naive arithmetic produces 20261232.
    expect(nextDay('20261231')).toBe('20270101');
    expect(nextDay('20260228')).toBe('20260301');
  });

  it('accepts a date-only string, as a hand-edited vault contains', () => {
    expect(toIcsDate('2026-06-01')).toBe('20260601');
  });
});

describe('rotation due dates', () => {
  it('counts from the last rotation when there is one', () => {
    const e = entry({ last_rotated_at: '2026-06-01T00:00:00Z', rotation_days: 30 });
    expect(toIcsDate(rotationDue(e))).toBe('20260701');
  });

  it('falls back to the creation date for a key never rotated', () => {
    // Otherwise a 90-day cadence on a key nobody has touched produces no
    // deadline at all, which is the case the cadence exists for.
    const e = entry({ created_at: '2026-01-01T00:00:00Z', rotation_days: 90 });
    expect(toIcsDate(rotationDue(e))).toBe('20260401');
  });

  it('produces nothing when there is no anchor to count from', () => {
    expect(rotationDue(entry({ rotation_days: 90 }))).toBeNull();
  });

  it('ignores a zero or negative cadence', () => {
    expect(rotationDue(entry({ created_at: '2026-01-01T00:00:00Z', rotation_days: 0 }))).toBeNull();
  });
});

describe('events', () => {
  it('emits nothing for an entry with no dates at all', () => {
    expect(eventsForEntry(entry({}), ['created', 'expires', 'rotation'])).toHaveLength(0);
  });

  it('honours the requested kinds', () => {
    const e = entry({ created_at: '2026-01-01T00:00:00Z', expires_at: '2026-06-01T00:00:00Z' });
    const kinds = eventsForEntry(e, ['expires']).map((x) => x.kind);
    expect(kinds).toEqual(['expires']);
  });

  it('labels an entry by whatever distinguishes it', () => {
    expect(entryLabel(entry({ key_id: 'ci', account_name: 'team' }))).toBe('GitHub (ci / team)');
    expect(entryLabel(entry({}))).toBe('GitHub');
  });

  it('warns before an expiry rather than on the day', () => {
    // A reminder that fires the morning a credential dies arrives during the
    // outage it was supposed to prevent.
    const [ev] = eventsForEntry(entry({ expires_at: '2026-06-01T00:00:00Z' }), ['expires']);
    expect(ev.alarmDaysBefore).toBe(7);
  });
});

describe('the whole calendar', () => {
  const dated = [
    entry({ id: 'a', provider: 'GitHub', created_at: '2026-03-01T00:00:00Z' }),
    entry({ id: 'b', provider: 'AWS', api_key: 'AKIA_SECRET', expires_at: '2026-01-15T00:00:00Z' }),
  ];

  it('carries no secret value', () => {
    const ics = buildIcs(dated, { now: '2026-08-26T12:00:00Z' });
    expect(ics).not.toContain('ghp_value');
    expect(ics).not.toContain('AKIA_SECRET');
  });

  it('carries no fingerprint either', () => {
    // A fingerprint is stable per value, so a feed full of them tells anyone
    // holding two feeds which secrets are identical — an equality oracle
    // published to a third-party calendar service.
    expect(buildIcs(dated, { now: '2026-08-26T12:00:00Z' })).not.toContain('sha256:');
  });

  it('is byte-stable across runs, so a re-export is not a diff', () => {
    const a = buildIcs(dated, { now: '2026-08-26T12:00:00Z' });
    const b = buildIcs([...dated].reverse(), { now: '2026-08-26T12:00:00Z' });
    expect(a).toBe(b);
  });

  it('gives each entry and kind a stable UID so re-import updates', () => {
    const ics = buildIcs(dated, { now: '2026-08-26T12:00:00Z' });
    expect(ics).toContain('UID:a-created@envvault');
    expect(ics).toContain('UID:b-expires@envvault');
  });

  it('ends every line with CRLF, including the last', () => {
    const ics = buildIcs(dated, { now: '2026-08-26T12:00:00Z' });
    expect(ics.endsWith('END:VCALENDAR\r\n')).toBe(true);
    expect(ics.replace(/\r\n/g, '')).not.toContain('\n');
  });

  it('produces a valid empty calendar rather than nothing', () => {
    // The pane refuses to download an empty feed, but the builder must still
    // return a well-formed document — a caller that writes it anyway must not
    // produce a file no parser accepts.
    const ics = buildIcs([entry({})], { now: '2026-08-26T12:00:00Z' });
    expect(ics).toContain('BEGIN:VCALENDAR');
    expect(ics).toContain('END:VCALENDAR');
    expect(ics).not.toContain('BEGIN:VEVENT');
  });
});
