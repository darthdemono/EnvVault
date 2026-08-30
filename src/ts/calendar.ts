/**
 * @file
 * iCalendar (RFC 5545) feed for the vault's dates.
 *
 * Every secret carries dates that matter on a calendar rather than in an app
 * nobody opens: when it was created, when it expires, when it is next due for
 * rotation. The health scan already knows all three, but it only speaks when
 * you go looking, and an expiry you learn about by reading the health pane is
 * an expiry you learn about after the outage.
 *
 * So this emits a `.ics` — the one format every calendar on every platform
 * reads — and the desktop app and `envv calendar` both produce it. That makes
 * it the fourth twin pair in the project, and like the other three it is pinned
 * by a golden fixture asserted from both sides
 * (`tests/fixtures/parity/calendar.ics`).
 *
 * # What must never be in here
 *
 * **No secret values, ever.** An `.ics` is the least private artefact this
 * program produces: its whole purpose is to be handed to Google Calendar,
 * Outlook or a phone, which means it is stored unencrypted on servers this
 * project has no relationship with. Names and dates travel; nothing else does.
 * That includes fingerprints — `sha256:ab12…` is stable per value, so a feed
 * carrying them tells anyone holding two feeds which secrets are identical.
 *
 * The names *do* travel, and the UI says so before writing a file. "AWS root
 * key" appearing in a shared work calendar is a real disclosure even with no
 * value attached, and the person exporting is the only one who can judge it.
 */

import type { VaultEntry } from './types';

/** One calendar entry, before it becomes VEVENT text. */
export interface CalendarEvent {
  /** Stable across exports — see {@link buildIcs}. */
  uid: string;
  /** All-day date in `YYYYMMDD` form. */
  date: string;
  summary: string;
  description: string;
  /** `created` | `expires` | `rotation`, used for CATEGORIES and filtering. */
  kind: EventKind;
  /** Days before `date` to fire an alarm, or 0 for none. */
  alarmDaysBefore: number;
}

export type EventKind = 'created' | 'expires' | 'rotation';

export interface IcsOptions {
  /** Which event kinds to emit. Default: all three. */
  kinds?: EventKind[];
  /**
   * Value for `DTSTAMP`, as an ISO string. Defaults to now.
   *
   * Injectable because a fixture that embeds the wall clock cannot be compared
   * against anything — the parity test would fail one second after it was
   * written, and the CLI and the app can never produce the same bytes.
   */
  now?: string;
  /** Calendar display name (`X-WR-CALNAME`). */
  calendarName?: string;
}

/** RFC 5545 §3.3.11: backslash, semicolon, comma and newline are escaped. */
export function icsEscape(text: string): string {
  return text
    .replace(/\\/g, '\\\\')
    .replace(/;/g, '\\;')
    .replace(/,/g, '\\,')
    .replace(/\r?\n/g, '\\n');
}

/**
 * RFC 5545 §3.1: no line may exceed 75 octets, and a continuation begins with
 * one space.
 *
 * Counted in **octets, not characters**. A provider name with an emoji or an
 * accent is several bytes per character, and folding by character length
 * produces a line that is legal by the count JavaScript reports and illegal by
 * the count the parser applies — which is how a feed ends up rejected by one
 * calendar client and accepted by another.
 */
export function icsFold(line: string): string {
  const enc = new TextEncoder();
  const dec = new TextDecoder();
  const bytes = enc.encode(line);
  if (bytes.length <= 75) return line;

  const out: string[] = [];
  let start = 0;
  // 75 for the first line, 74 for the rest — the leading space counts.
  let limit = 75;
  while (start < bytes.length) {
    let end = Math.min(start + limit, bytes.length);
    // Never split a UTF-8 sequence: continuation bytes are 0b10xxxxxx.
    while (end > start && end < bytes.length && (bytes[end] & 0xc0) === 0x80) end--;
    out.push((out.length ? ' ' : '') + dec.decode(bytes.slice(start, end)));
    start = end;
    limit = 74;
  }
  return out.join('\r\n');
}

/** `2026-08-26T21:00:00Z` → `20260826`. Returns null for anything unparseable. */
export function toIcsDate(iso: string | null | undefined): string | null {
  if (!iso) return null;
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return null;
  const p = (n: number) => String(n).padStart(2, '0');
  return `${d.getUTCFullYear()}${p(d.getUTCMonth() + 1)}${p(d.getUTCDate())}`;
}

/** `2026-08-26T21:00:00Z` → `20260826T210000Z`, for DTSTAMP. */
export function toIcsStamp(iso: string): string {
  const d = new Date(iso);
  const safe = Number.isNaN(d.getTime()) ? new Date(0) : d;
  const p = (n: number) => String(n).padStart(2, '0');
  return (
    `${safe.getUTCFullYear()}${p(safe.getUTCMonth() + 1)}${p(safe.getUTCDate())}` +
    `T${p(safe.getUTCHours())}${p(safe.getUTCMinutes())}${p(safe.getUTCSeconds())}Z`
  );
}

/** The day after `YYYYMMDD`, which is what an all-day DTEND must be. */
export function nextDay(yyyymmdd: string): string {
  const y = Number(yyyymmdd.slice(0, 4));
  const m = Number(yyyymmdd.slice(4, 6));
  const d = Number(yyyymmdd.slice(6, 8));
  const next = new Date(Date.UTC(y, m - 1, d + 1));
  const p = (n: number) => String(n).padStart(2, '0');
  return `${next.getUTCFullYear()}${p(next.getUTCMonth() + 1)}${p(next.getUTCDate())}`;
}

/** Display name for an entry: provider, plus whatever disambiguates it. */
export function entryLabel(e: VaultEntry): string {
  const extra = [e.key_id, e.account_name].filter(Boolean).join(' / ');
  return extra ? `${e.provider} (${extra})` : e.provider;
}

/**
 * The date a rotation is next due, or null when the entry has no cadence.
 *
 * Counts from `last_rotated_at` when there is one and from `created_at`
 * otherwise: a key with a 90-day cadence that has never been rotated is due 90
 * days after it was issued, not never. An entry with neither date has no
 * anchor, and inventing one would put a deadline in someone's calendar that no
 * evidence supports.
 */
export function rotationDue(e: VaultEntry): string | null {
  if (!e.rotation_days || e.rotation_days <= 0) return null;
  const anchor = e.last_rotated_at || e.created_at;
  if (!anchor) return null;
  const d = new Date(anchor);
  if (Number.isNaN(d.getTime())) return null;
  d.setUTCDate(d.getUTCDate() + e.rotation_days);
  return d.toISOString();
}

/** Turns one entry into the events it warrants (zero to three). */
export function eventsForEntry(e: VaultEntry, kinds: EventKind[]): CalendarEvent[] {
  const out: CalendarEvent[] = [];
  // `id` is guaranteed by `ensureEntryIds`; the fallback keeps a hand-edited
  // vault from producing two events that share a UID, which calendars treat as
  // one event updating itself.
  const id = e.id || `${e.provider}:${e.key_id ?? ''}:${e.account_name ?? ''}`;
  const label = entryLabel(e);
  const meta = [
    e.secretType ? `Type: ${e.secretType}` : '',
    e.environment ? `Environment: ${e.environment}` : '',
    e.categories?.length ? `Categories: ${e.categories.join(', ')}` : '',
  ]
    .filter(Boolean)
    .join('\n');

  if (kinds.includes('created')) {
    const d = toIcsDate(e.created_at);
    if (d) {
      out.push({
        uid: `${id}-created@envvault`,
        date: d,
        summary: `Created: ${label}`,
        description: [`${label} was added to the vault.`, meta].filter(Boolean).join('\n'),
        kind: 'created',
        alarmDaysBefore: 0,
      });
    }
  }

  if (kinds.includes('expires')) {
    const d = toIcsDate(e.expires_at);
    if (d) {
      out.push({
        uid: `${id}-expires@envvault`,
        date: d,
        summary: `Expires: ${label}`,
        description: [`${label} expires on this day.`, meta].filter(Boolean).join('\n'),
        kind: 'expires',
        // A reminder on the morning it dies is a reminder you get during the
        // outage. Seven days is enough to request a replacement.
        alarmDaysBefore: 7,
      });
    }
  }

  if (kinds.includes('rotation')) {
    const d = toIcsDate(rotationDue(e));
    if (d) {
      out.push({
        uid: `${id}-rotation@envvault`,
        date: d,
        summary: `Rotate: ${label}`,
        description: [`${label} is due for rotation (every ${e.rotation_days} days).`, meta]
          .filter(Boolean)
          .join('\n'),
        kind: 'rotation',
        alarmDaysBefore: 3,
      });
    }
  }

  return out;
}

/**
 * Builds the whole calendar.
 *
 * UIDs are stable per entry and per kind, which is the property that makes a
 * re-export an *update* rather than a duplicate: importing a second time moves
 * the existing event instead of leaving the user with two "Expires: GitHub"
 * entries a week apart.
 */
export function buildIcs(entries: VaultEntry[], opts: IcsOptions = {}): string {
  const kinds = opts.kinds ?? ['created', 'expires', 'rotation'];
  const stamp = toIcsStamp(opts.now ?? new Date().toISOString());
  const name = opts.calendarName ?? 'EnvVault';

  const events = entries
    .flatMap((e) => eventsForEntry(e, kinds))
    // Sorted by date then UID so two runs over the same vault produce the same
    // bytes. Without it the file's order follows the entry array, and a
    // reordered vault looks like a changed calendar to anything diffing it.
    .sort((a, b) => a.date.localeCompare(b.date) || a.uid.localeCompare(b.uid));

  const lines: string[] = [
    'BEGIN:VCALENDAR',
    'VERSION:2.0',
    'PRODID:-//EnvVault//Secrets Calendar//EN',
    'CALSCALE:GREGORIAN',
    'METHOD:PUBLISH',
    `X-WR-CALNAME:${icsEscape(name)}`,
    'X-WR-TIMEZONE:UTC',
  ];

  for (const ev of events) {
    lines.push(
      'BEGIN:VEVENT',
      `UID:${icsEscape(ev.uid)}`,
      `DTSTAMP:${stamp}`,
      `DTSTART;VALUE=DATE:${ev.date}`,
      `DTEND;VALUE=DATE:${nextDay(ev.date)}`,
      `SUMMARY:${icsEscape(ev.summary)}`,
      `DESCRIPTION:${icsEscape(ev.description)}`,
      `CATEGORIES:${ev.kind.toUpperCase()}`,
      // The events are markers, not commitments: a day with three expiries
      // should not show the owner as busy.
      'TRANSP:TRANSPARENT',
    );
    if (ev.alarmDaysBefore > 0) {
      lines.push(
        'BEGIN:VALARM',
        'ACTION:DISPLAY',
        `DESCRIPTION:${icsEscape(ev.summary)}`,
        `TRIGGER:-P${ev.alarmDaysBefore}D`,
        'END:VALARM',
      );
    }
    lines.push('END:VEVENT');
  }

  lines.push('END:VCALENDAR');
  // CRLF is not optional in RFC 5545, and the trailing one is what makes the
  // last line a line.
  return lines.map(icsFold).join('\r\n') + '\r\n';
}
