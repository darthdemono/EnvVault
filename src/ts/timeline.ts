/**
 * @file
 * The Secret Timeline tool pane — when every secret was created, when it
 * expires, when it is next due for rotation, and a calendar feed of all three.
 *
 * The vault has always known these dates; nothing ever showed them together.
 * "How old is this key?" was answerable only by expanding a card, and "what
 * lands next quarter?" was not answerable at all.
 *
 * # Two truths this pane is careful about
 *
 * **A missing creation date stays missing.** `created_at` only exists for
 * entries created after the field did, plus those `backfillCreatedAt()` could
 * date from an unambiguous audit row. For the rest this shows "unknown", or
 * "before <date>" when `version_history` proves the entry already existed then.
 * That bound is displayed, never stored — see `earliestEvidence()`.
 *
 * **An exported `.ics` leaves the vault.** It goes to Google Calendar, a phone,
 * a shared work calendar. It carries no secret values and no fingerprints, but
 * it does carry provider names, and "AWS root key" on a shared calendar is a
 * disclosure. The export confirms before writing, and the confirmation says
 * what travels.
 */

import { st, earliestEvidence } from './state';
import type { VaultEntry } from './types';
import { esc, showToast, showConfirm } from './utils';
import { relativeTime } from './ui-qol';
import { buildIcs, rotationDue, type EventKind } from './calendar';
import { downloadText } from './import-export';

/** Sort orders offered by the pane. */
type SortKey = 'created-desc' | 'created-asc' | 'expires-asc' | 'provider';

let _sort: SortKey = 'created-desc';

/** `2026-03-04T…` → `4 Mar 2026`. Empty string for anything unparseable. */
function shortDate(iso: string | null | undefined): string {
  if (!iso) return '';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return '';
  return d.toLocaleDateString(undefined, { day: 'numeric', month: 'short', year: 'numeric' });
}

/**
 * What the Created column says for one entry, and how sure it is.
 *
 * The distinction is the whole point of the column: `known` came from the
 * entry's own record, `bound` is the earliest date it can be *proved* to have
 * existed, and `unknown` is an honest absence. Rendering the second as if it
 * were the first is the lie this pane exists not to tell.
 */
export function createdCell(e: VaultEntry): {
  text: string;
  certainty: 'known' | 'bound' | 'unknown';
} {
  if (e.created_at && !Number.isNaN(Date.parse(e.created_at))) {
    return { text: shortDate(e.created_at), certainty: 'known' };
  }
  const bound = earliestEvidence(e);
  if (bound) return { text: `before ${shortDate(bound)}`, certainty: 'bound' };
  return { text: 'unknown', certainty: 'unknown' };
}

/** Days between now and `iso`; negative when it is in the past. */
function daysUntil(iso: string): number {
  const ms = new Date(iso).getTime() - Date.now();
  return Math.ceil(ms / 86_400_000);
}

/** Expiry cell plus the class that colours it. */
function expiryCell(e: VaultEntry): { text: string; cls: string } {
  if (!e.expires_at || Number.isNaN(Date.parse(e.expires_at))) {
    return { text: '—', cls: 'tl-muted' };
  }
  const days = daysUntil(e.expires_at);
  const when = shortDate(e.expires_at);
  if (days < 0) return { text: `${when} (expired)`, cls: 'tl-bad' };
  if (days <= 30) return { text: `${when} (${days}d)`, cls: 'tl-warn' };
  return { text: when, cls: '' };
}

/** Rotation cell: due date derived from the cadence, or an em dash. */
function rotationCell(e: VaultEntry): { text: string; cls: string } {
  const due = rotationDue(e);
  if (!due) return { text: '—', cls: 'tl-muted' };
  const days = daysUntil(due);
  const when = shortDate(due);
  if (days < 0) return { text: `${when} (overdue)`, cls: 'tl-bad' };
  if (days <= 14) return { text: `${when} (${days}d)`, cls: 'tl-warn' };
  return { text: when, cls: '' };
}

/** Sort value for the Created column; undated entries sort last in both directions. */
function createdSortKey(e: VaultEntry): number | null {
  if (e.created_at && !Number.isNaN(Date.parse(e.created_at))) return Date.parse(e.created_at);
  const bound = earliestEvidence(e);
  return bound ? Date.parse(bound) : null;
}

/** Applies `_sort`, keeping undated and non-expiring entries at the bottom. */
export function sortEntries(entries: VaultEntry[], sort: SortKey): VaultEntry[] {
  const rows = [...entries];
  const nullsLast = (a: number | null, b: number | null, dir: number) => {
    if (a === null && b === null) return 0;
    // Not `a ?? Infinity`: an undated entry must sink whichever way the column
    // is sorted, and arithmetic on a sentinel flips it on the ascending pass.
    if (a === null) return 1;
    if (b === null) return -1;
    return (a - b) * dir;
  };
  switch (sort) {
    case 'created-asc':
      return rows.sort((a, b) => nullsLast(createdSortKey(a), createdSortKey(b), 1));
    case 'expires-asc':
      return rows.sort((a, b) =>
        nullsLast(
          a.expires_at ? Date.parse(a.expires_at) : null,
          b.expires_at ? Date.parse(b.expires_at) : null,
          1,
        ),
      );
    case 'provider':
      return rows.sort((a, b) => a.provider.localeCompare(b.provider));
    case 'created-desc':
    default:
      return rows.sort((a, b) => nullsLast(createdSortKey(a), createdSortKey(b), -1));
  }
}

/** Which event kinds the export checkboxes currently select. */
function selectedKinds(): EventKind[] {
  const kinds: EventKind[] = [];
  for (const k of ['created', 'expires', 'rotation'] as EventKind[]) {
    const box = document.getElementById(`tl-kind-${k}`) as HTMLInputElement | null;
    if (box?.checked !== false) kinds.push(k);
  }
  return kinds;
}

/** Repaints the table and the summary line. */
export function renderTimeline(): void {
  const body = document.getElementById('tl-rows');
  const summary = document.getElementById('tl-summary');
  if (!body) return;

  const entries = st.vault.api_keys ?? [];
  const rows = sortEntries(entries, _sort);

  const dated = entries.filter((e) => e.created_at && !Number.isNaN(Date.parse(e.created_at)));
  const expiring = entries.filter((e) => e.expires_at && !Number.isNaN(Date.parse(e.expires_at)));
  const rotating = entries.filter((e) => rotationDue(e));

  if (summary) {
    const oldest = dated.map((e) => Date.parse(e.created_at!)).sort((a, b) => a - b)[0];
    summary.innerHTML =
      `<strong>${entries.length}</strong> secrets · ` +
      `<strong>${dated.length}</strong> with a known creation date · ` +
      `<strong>${expiring.length}</strong> with an expiry · ` +
      `<strong>${rotating.length}</strong> on a rotation cadence` +
      (oldest ? ` · oldest dated ${esc(relativeTime(new Date(oldest).toISOString()))}` : '');
  }

  if (!rows.length) {
    body.innerHTML = `<tr><td colspan="5" class="tl-muted" style="padding:16px">No secrets in this vault yet.</td></tr>`;
    return;
  }

  body.innerHTML = rows
    .map((e) => {
      const created = createdCell(e);
      const exp = expiryCell(e);
      const rot = rotationCell(e);
      const label = [e.provider, e.key_id, e.account_name].filter(Boolean).join(' · ');
      const age = created.certainty === 'known' ? relativeTime(e.created_at as string) : '';
      return `<tr>
        <td>${esc(label)}</td>
        <td class="${created.certainty === 'known' ? '' : 'tl-muted'}">${esc(created.text)}</td>
        <td class="tl-muted">${esc(age)}</td>
        <td class="${exp.cls}">${esc(exp.text)}</td>
        <td class="${rot.cls}">${esc(rot.text)}</td>
      </tr>`;
    })
    .join('');
}

/** Builds and downloads the `.ics`, after saying what will be in it. */
export async function exportCalendar(): Promise<void> {
  const kinds = selectedKinds();
  if (!kinds.length) {
    showToast('Pick at least one kind of event', 'err');
    return;
  }
  const entries = st.vault.api_keys ?? [];
  const ics = buildIcs(entries, { kinds, calendarName: 'EnvVault Secrets' });
  const count = (ics.match(/BEGIN:VEVENT/g) || []).length;
  if (!count) {
    showToast('Nothing to export — no entry has any of the selected dates', 'err', 3500);
    return;
  }

  // The names are the disclosure, and the person exporting is the only one who
  // can weigh it. Said plainly rather than buried in a tooltip.
  const ok = await showConfirm(
    `Export ${count} calendar event${count === 1 ? '' : 's'}?\n\n` +
      `The file contains secret NAMES and dates — never values, never fingerprints. ` +
      `A calendar you import it into stores those names unencrypted, on someone else's servers ` +
      `if it syncs.`,
  );
  if (!ok) return;

  downloadText(ics, 'envvault-secrets.ics', `Exported ${count} events ✓`);
}

let _inited = false;

/** Wires the pane. Idempotent — invariant 9: assign, never accumulate. */
export function initTimelinePane(): void {
  if (_inited) return;
  _inited = true;

  const sortSel = document.getElementById('tl-sort') as HTMLSelectElement | null;
  if (sortSel) {
    sortSel.onchange = () => {
      _sort = (sortSel.value as SortKey) || 'created-desc';
      renderTimeline();
    };
  }
  const exportBtn = document.getElementById('tl-export-ics');
  if (exportBtn) (exportBtn as HTMLButtonElement).onclick = () => void exportCalendar();
  const refresh = document.getElementById('tl-refresh');
  if (refresh) (refresh as HTMLButtonElement).onclick = () => renderTimeline();
}
