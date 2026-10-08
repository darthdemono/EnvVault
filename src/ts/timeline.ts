import { st, earliestEvidence, inTauri, RemoteVaultStore } from './state';
import type { VaultEntry } from './types';
import { showToast, showConfirm, clipboardWrite } from './utils';
import { relativeTime } from './ui-qol';
import { downloadText } from './import-export';
import { invokeTauri } from './tauri';
import { html, setHtml } from './html';

/** Sort orders offered by the pane. */
type SortKey = 'created-desc' | 'created-asc' | 'expires-asc' | 'provider';

/** Which kinds of calendar event this pane can produce. Mirrors
 * `vault_core::calendar::EventKind` — the string spelling is the contract
 * between the two, asserted by `calendar_build_ics` on the Rust side rather
 * than by a shared type, since nothing here crosses a type boundary. */
type EventKind = 'created' | 'expires' | 'rotation';

const invoke = invokeTauri;

/**
 * The date a rotation is next due, or null when the entry has no cadence.
 *
 * A pure display computation — "which date is next" — not part of the `.ics`
 * byte format, so it stays local rather than round-tripping through IPC for
 * every row in the table on every render. `vault_core::calendar::rotation_due`
 * computes the same thing for the same reason `build_ics` needs it; the two
 * are not a twin pair the way `icsEscape`/`build_ics` were, because neither
 * produces bytes the other has to match — only a date used to sort and colour
 * one column.
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
  renderFeedSection();
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
    setHtml(
      summary,
      html`<strong>${entries.length}</strong> secrets · <strong>${dated.length}</strong> with a known creation date ·
        <strong>${expiring.length}</strong> with an expiry · <strong>${rotating.length}</strong> on a
        rotation cadence${oldest ? ` · oldest dated ${relativeTime(new Date(oldest).toISOString())}` : ''}`,
    );
  }

  if (!rows.length) {
    setHtml(
      body,
      html`<tr>
        <td colspan="5" class="tl-muted" style="padding:16px">No secrets in this vault yet.</td>
      </tr>`,
    );
    return;
  }

  setHtml(
    body,
    html`${rows.map((e) => {
      const created = createdCell(e);
      const exp = expiryCell(e);
      const rot = rotationCell(e);
      const label = [e.provider, e.key_id, e.account_name].filter(Boolean).join(' · ');
      const age = created.certainty === 'known' ? relativeTime(e.created_at as string) : '';
      return html`<tr>
        <td>${label}</td>
        <td class="${created.certainty === 'known' ? '' : 'tl-muted'}">${created.text}</td>
        <td class="tl-muted">${age}</td>
        <td class="${exp.cls}">${exp.text}</td>
        <td class="${rot.cls}">${rot.text}</td>
      </tr>`;
    })}`,
  );
}

/** Builds and downloads the `.ics`, after saying what will be in it. */
export async function exportCalendar(): Promise<void> {
  const kinds = selectedKinds();
  if (!kinds.length) {
    showToast('Pick at least one kind of event', 'err');
    return;
  }
  // The builder lives in Rust now (see the module doc): `npm run dev` in a
  // plain browser cannot reach it, and says so rather than silently doing
  // nothing — the same trade Phase 22's TOTP code generation made.
  if (!inTauri) {
    showToast(
      'Calendar export needs the desktop app — a plain browser has nothing to build it with.',
      'err',
      4000,
    );
    return;
  }
  const entries = st.vault.api_keys ?? [];
  const ics = (await invoke('calendar_build_ics', {
    entries,
    kinds,
    calendarName: 'EnvVault Secrets',
  })) as string | undefined;
  if (typeof ics !== 'string') {
    showToast('Could not build the calendar', 'err');
    return;
  }
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

  void downloadText(ics, 'envvault-secrets.ics', `Exported ${count} events ✓`);
}

// ── Calendar feeds (Phase 24.3) — server-side only, so this whole section is
// hidden against a local vault (see `renderFeedSection`).

/** Re-fetches and repaints the feed list from the server. */
async function renderFeedList(): Promise<void> {
  const list = document.getElementById('tl-feed-list');
  if (!list || !(st.store instanceof RemoteVaultStore)) return;
  const feeds = await st.store.listCalendarFeeds();
  if (!feeds.length) {
    setHtml(list, html`<li class="tl-muted">No feeds yet.</li>`);
    return;
  }
  setHtml(
    list,
    html`${feeds.map((f) => {
      const revoked = !!f.revoked_at;
      const nameCls = revoked ? 'tl-feed-name tl-feed-revoked' : 'tl-feed-name';
      const kinds = Array.isArray(f.kinds) ? f.kinds.join(', ') : '';
      return html`<li>
        <span class="${nameCls}">${f.name || 'Untitled'} — ${kinds}</span>${revoked ? html`<span class="tl-muted">revoked</span>` : html`<button class="btn btn-ghost btn-sm" type="button" data-action="tl-feed-revoke" data-id="${String(f.id)}">Revoke</button>`}</li>`;
    })}`,
  );
  list.querySelectorAll<HTMLButtonElement>('[data-action="tl-feed-revoke"]').forEach((btn) => {
    btn.onclick = () => void revokeFeed(btn.dataset.id ?? '');
  });
}

async function revokeFeed(id: string): Promise<void> {
  if (!id || !(st.store instanceof RemoteVaultStore)) return;
  const ok = await showConfirm(
    'Revoke this feed? The URL stops working immediately and cannot be un-revoked.',
  );
  if (!ok) return;
  const success = await st.store.revokeCalendarFeed(id);
  showToast(success ? 'Feed revoked' : 'Could not revoke feed', success ? 'ok' : 'err');
  void renderFeedList();
}

/** Mints a feed and copies its URL — the token is shown once, server-side. */
async function subscribeFeed(): Promise<void> {
  if (!(st.store instanceof RemoteVaultStore)) return;
  const kinds = selectedKinds();
  if (!kinds.length) {
    showToast('Pick at least one kind of event', 'err');
    return;
  }
  const includeAccountNames =
    (document.getElementById('tl-feed-account-names') as HTMLInputElement | null)?.checked ?? false;
  const url = await st.store.createCalendarFeed('EnvVault', kinds as string[], includeAccountNames);
  if (!url) {
    showToast('Could not create feed', 'err');
    return;
  }
  await clipboardWrite(url);
  showToast('Feed URL copied — paste it into your calendar app to subscribe', 'ok', 5000);
  void renderFeedList();
}

/** Shows the Subscribe section only against a remote vault — there is
 * nothing local to serve a feed from. */
function renderFeedSection(): void {
  const section = document.getElementById('tl-feeds-section');
  if (!section) return;
  const isRemote = st.store instanceof RemoteVaultStore;
  section.style.display = isRemote ? '' : 'none';
  if (isRemote) void renderFeedList();
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
  const subscribeBtn = document.getElementById('tl-feed-subscribe');
  if (subscribeBtn) (subscribeBtn as HTMLButtonElement).onclick = () => void subscribeFeed();
}
