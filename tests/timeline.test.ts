/**
 * The Secret Timeline pane and the creation-date backfill behind it.
 *
 * The property under test throughout is honesty about what is known. A vault
 * written before `created_at` existed has entries whose age nothing can
 * recover, and the failure mode worth guarding is not a crash — it is a
 * plausible date appearing where there is no evidence for one, because that
 * date then flows into the calendar feed and into whatever the user plans
 * around it.
 */
import { describe, it, expect, beforeAll, beforeEach } from 'vitest';
import { st, backfillCreatedAt, earliestEvidence } from '../src/ts/state';
import { createdCell, sortEntries, renderTimeline, initTimelinePane } from '../src/ts/timeline';
import { mountToolsPanes } from '../src/ts/tools-markup';
import { loadRealIndexHtml, makeEntry, makeVault, resetState } from './helpers';
import type { AuditRow, VaultEntry } from '../src/ts/types';

let panes: ChildNode[] = [];

beforeAll(() => {
  loadRealIndexHtml();
  mountToolsPanes();
  initTimelinePane();
  panes = [...document.body.childNodes];
});

beforeEach(() => {
  document.body.innerHTML = '';
  panes.forEach((n) => document.body.appendChild(n));
  resetState(st);
});

const row = (over: Partial<AuditRow>): AuditRow =>
  ({
    id: 1,
    action: 'add',
    entry_provider: 'GitHub',
    timestamp: '2026-01-05T09:30:00Z',
    details: null,
    entry_hash: null,
    prev_hash: null,
    actor: null,
    ...over,
  }) as AuditRow;

describe('backfillCreatedAt', () => {
  it('dates an entry from the audit row that recorded its creation', () => {
    const e = makeEntry({ provider: 'GitHub' });
    expect(backfillCreatedAt([e], [row({})])).toBe(true);
    expect(e.created_at).toBe('2026-01-05T09:30:00.000Z');
  });

  it('uses the oldest add row when a name was deleted and re-added', () => {
    const e = makeEntry({ provider: 'GitHub' });
    backfillCreatedAt(
      [e],
      [
        row({ id: 9, timestamp: '2026-05-01T00:00:00Z' }),
        row({ id: 2, timestamp: '2026-01-05T09:30:00Z' }),
      ],
    );
    expect(e.created_at).toBe('2026-01-05T09:30:00.000Z');
  });

  it('refuses to guess when two entries share a provider', () => {
    // Audit rows identify an entry by provider alone. Attributing one entry's
    // creation to its namesake is the array-index bug in another costume, and
    // the CLI refuses ambiguous lookups for the same reason.
    const a = makeEntry({ provider: 'GitHub', key_id: 'ci' });
    const b = makeEntry({ provider: 'GitHub', key_id: 'personal' });
    expect(backfillCreatedAt([a, b], [row({})])).toBe(false);
    expect(a.created_at).toBeUndefined();
    expect(b.created_at).toBeUndefined();
  });

  it('never overwrites a date the entry already carries', () => {
    const e = makeEntry({ provider: 'GitHub', created_at: '2020-01-01T00:00:00Z' });
    expect(backfillCreatedAt([e], [row({})])).toBe(false);
    expect(e.created_at).toBe('2020-01-01T00:00:00Z');
  });

  it('ignores rows for other actions', () => {
    // An `update` row says when a value changed, not when the entry appeared.
    const e = makeEntry({ provider: 'GitHub' });
    expect(backfillCreatedAt([e], [row({ action: 'update' })])).toBe(false);
    expect(e.created_at).toBeUndefined();
  });

  it('ignores an unparseable timestamp rather than storing NaN', () => {
    const e = makeEntry({ provider: 'GitHub' });
    expect(backfillCreatedAt([e], [row({ timestamp: 'whenever' })])).toBe(false);
    expect(e.created_at).toBeUndefined();
  });

  it('does nothing at all with no audit rows', () => {
    const e = makeEntry({ provider: 'GitHub' });
    expect(backfillCreatedAt([e], [])).toBe(false);
  });
});

describe('earliestEvidence', () => {
  it('returns the oldest revision timestamp', () => {
    const e = makeEntry({
      version_history: [
        { value: 'v2', saved_at: '2026-04-01T00:00:00Z' },
        { value: 'v1', saved_at: '2025-09-01T00:00:00Z' },
      ],
    });
    expect(earliestEvidence(e)).toBe('2025-09-01T00:00:00Z');
  });

  it('returns null when there is no history', () => {
    expect(earliestEvidence(makeEntry({}))).toBeNull();
  });
});

describe('the Created column', () => {
  it('marks a real date as known', () => {
    const c = createdCell(makeEntry({ created_at: '2026-03-04T08:00:00Z' }));
    expect(c.certainty).toBe('known');
  });

  it('shows a revision date as a bound, never as a creation date', () => {
    // This is the distinction the pane exists to preserve: the oldest revision
    // is when a value was *replaced*, so the entry existed at least that long —
    // which is not the same claim as "created then".
    const c = createdCell(
      makeEntry({ version_history: [{ value: 'v1', saved_at: '2025-09-01T00:00:00Z' }] }),
    );
    expect(c.certainty).toBe('bound');
    expect(c.text).toMatch(/^before /);
  });

  it('says unknown when there is no evidence at all', () => {
    const c = createdCell(makeEntry({}));
    expect(c).toEqual({ text: 'unknown', certainty: 'unknown' });
  });
});

describe('sorting', () => {
  const dated = (id: string, created?: string): VaultEntry =>
    makeEntry({ id, provider: id, created_at: created });

  it('keeps undated entries last in both directions', () => {
    // `a ?? Infinity` would sink them one way and float them the other, putting
    // the least informative rows at the top of the ascending view.
    const rows = [
      dated('none'),
      dated('old', '2025-01-01T00:00:00Z'),
      dated('new', '2026-01-01T00:00:00Z'),
    ];
    expect(sortEntries(rows, 'created-desc').map((e) => e.id)).toEqual(['new', 'old', 'none']);
    expect(sortEntries(rows, 'created-asc').map((e) => e.id)).toEqual(['old', 'new', 'none']);
  });

  it('sorts by soonest expiry, non-expiring last', () => {
    const rows = [
      makeEntry({ id: 'never', provider: 'never' }),
      makeEntry({ id: 'late', provider: 'late', expires_at: '2027-01-01T00:00:00Z' }),
      makeEntry({ id: 'soon', provider: 'soon', expires_at: '2026-09-01T00:00:00Z' }),
    ];
    expect(sortEntries(rows, 'expires-asc').map((e) => e.id)).toEqual(['soon', 'late', 'never']);
  });

  it('does not mutate the array it was given', () => {
    const rows = [dated('b', '2025-01-01T00:00:00Z'), dated('a', '2026-01-01T00:00:00Z')];
    sortEntries(rows, 'created-desc');
    expect(rows.map((e) => e.id)).toEqual(['b', 'a']);
  });
});

describe('rendering', () => {
  it('paints a row per entry with its dates', () => {
    st.vault = makeVault({
      api_keys: [
        makeEntry({
          provider: 'GitHub',
          created_at: '2026-03-04T08:00:00Z',
          expires_at: '2027-01-01T00:00:00Z',
        }),
      ],
    });
    renderTimeline();
    const html = document.getElementById('tl-rows')!.innerHTML;
    expect(html).toContain('GitHub');
    expect(html).toContain('2026');
  });

  it('never prints a secret value into the table', () => {
    st.vault = makeVault({
      api_keys: [
        makeEntry({
          provider: 'GitHub',
          api_key: 'ghp_LEAKED',
          created_at: '2026-03-04T08:00:00Z',
        }),
      ],
    });
    renderTimeline();
    expect(document.getElementById('tl-rows')!.innerHTML).not.toContain('ghp_LEAKED');
  });

  it('escapes a provider name rather than rendering it as markup', () => {
    // Vault data is untrusted input — invariant 4. A provider name comes from
    // an imported backup or a remote server just as often as from a keyboard.
    st.vault = makeVault({
      api_keys: [makeEntry({ provider: '<img src=x onerror=alert(1)>' })],
    });
    renderTimeline();
    const body = document.getElementById('tl-rows')!;
    expect(body.querySelector('img')).toBeNull();
    expect(body.innerHTML).toContain('&lt;img');
  });

  it('says the vault is empty instead of painting an empty table', () => {
    st.vault = makeVault({ api_keys: [] });
    renderTimeline();
    expect(document.getElementById('tl-rows')!.textContent).toMatch(/No secrets/i);
  });

  it('counts only entries with a real creation date as dated', () => {
    st.vault = makeVault({
      api_keys: [
        makeEntry({ provider: 'A', created_at: '2026-03-04T08:00:00Z' }),
        makeEntry({ provider: 'B' }),
      ],
    });
    renderTimeline();
    const summary = document.getElementById('tl-summary')!.textContent!;
    expect(summary).toContain('2 secrets');
    expect(summary).toContain('1 with a known creation date');
  });
});
